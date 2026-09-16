package main

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-ip/internal/audit"
	"github.com/exemt/placitum-ip/internal/config"
	"github.com/exemt/placitum-ip/internal/decide"
	"github.com/exemt/placitum-ip/internal/dyn"
	"github.com/exemt/placitum-ip/internal/protocol"
	"github.com/exemt/placitum-ip/internal/queue"
	"github.com/exemt/placitum-ip/internal/store"
	"github.com/exemt/placitum-shared/netinfo"
)

const (
	codeUnsupportedVersion = "IP_UNSUPPORTED_VERSION"
	codeMalformed          = "IP_MALFORMED_REQUEST"
	codeInternalError      = "IP_INTERNAL_ERROR"
	codeWrongPhase         = "IP_PHASE_NOT_SUPPORTED"
	codeGeoUnavailable     = "IP_GEO_UNAVAILABLE"
)

type handler struct {
	cfg      *config.Config
	log      *slog.Logger
	nc       *nats.Conn
	audit    *audit.Sink
	store    *store.Store
	live     *dyn.Store
	pool     *queue.Pool
	resolver *netinfo.Resolver
}

func (h *handler) receive(msg *nats.Msg) {
	defer h.recoverInto(msg.Reply, "")

	req, err := protocol.Parse(msg.Data)
	if err != nil {
		rid := ""

		var pe *protocol.ParseError
		if errors.As(err, &pe) {
			rid = pe.RID
		}

		h.log.Warn("message rejected", "error", err.Error(), "bytes", len(msg.Data))
		h.send(msg.Reply, protocol.FallbackReply(rid, h.cfg.Name, codeMalformed), nil, audit.Details{})

		return
	}

	if !h.cfg.Supports(req.V) {
		reply := protocol.ErrorReply(req, codeUnsupportedVersion)
		reply.V = protocol.Version
		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	if req.Phase != protocol.PhaseRequest {
		h.send(msg.Reply, protocol.ErrorReply(req, codeWrongPhase), req,
			audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{Req: req, Reply: msg.Reply})
}

func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		reply := protocol.ShedReply(t.Req, shed)
		det := audit.Details{
			Engine: map[string]any{
				"shed":      shed,
				"budget_ms": float64(budget.Microseconds()) / 1000,
			},
		}

		asks, lists := h.overloadOnShed(t, shed, reply, det)

		h.log.Warn("shed", "rid", t.Req.RID, "reason", shed, "budget_ms", budget.Milliseconds(),
			"asks", asks, "lists", lists)
		h.send(t.Reply, reply, t.Req, det)

		return
	}

	reply, det := h.inspect(t.Req, t.Fill, budget)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) inspect(req *protocol.Request, fill int, budget time.Duration) (*protocol.Reply, audit.Details) {
	start := time.Now()
	snap := h.store.Current()
	result := decide.Check(snap, h.live, req.Route.Profile, req.Conn.ClientIP)

	if asks, bans, fired := decide.FireOverload(snap, req.Route.Profile, req.Conn.ClientIP,
		fill, false, queue.ReasonQueueLimit); len(fired) != 0 {
		result.Actions = append(result.Actions, asks...)
		result.Bans = append(result.Bans, bans...)

		if result.Engine == nil {
			result.Engine = map[string]any{}
		}

		result.Engine["overload"] = fired
	}

	elapsed := time.Since(start)

	reply := decide.ToReply(req, result)

	if len(result.Bans) != 0 && h.live != nil {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		err := writeLists(ctx, h.resolver, h.live, h.log, req.RID, req.Node, req.Ray, result.Bans)
		cancel()

		if err != nil {
			h.log.Error("geo unavailable for a list write", "rid", req.RID,
				"profile", req.Route.Profile, "error", err.Error())

			if result.Engine == nil {
				result.Engine = map[string]any{}
			}

			result.Engine["geo"] = err.Error()

			return protocol.ErrorReply(req, codeGeoUnavailable), audit.Details{
				EngineMS: float64(elapsed.Microseconds()) / 1000,
				Findings: result.Findings,
				Engine:   result.Engine,
			}
		}
	}

	if result.Code == decide.CodeUnknownProfile {
		h.log.Error("unknown profile",
			"rid", req.RID,
			"profile", req.Route.Profile,
			"client_ip", req.Conn.ClientIP,
		)
	}

	h.log.Info("verdict",
		"rid", req.RID,
		"inspector", req.Inspector,
		"profile", req.Route.Profile,
		"client_ip", req.Conn.ClientIP,
		"verdict", reply.Verdict,
		"reason", result.Code,
		"text", result.Text,
		"actions", len(result.Actions),
	)

	return reply, audit.Details{
		EngineMS: float64(elapsed.Microseconds()) / 1000,
		Findings: result.Findings,
		Engine:   result.Engine,
	}
}

func (h *handler) send(subject string, reply *protocol.Reply, req *protocol.Request,
	det audit.Details) {

	if subject == "" {
		h.log.Error("no reply subject in message", "rid", reply.RID)
		return
	}

	payload, err := reply.Marshal()
	if err != nil {
		h.log.Error("reply marshal failed", "rid", reply.RID, "error", err.Error())

		payload, err = protocol.FallbackReply(reply.RID, reply.Inspector,
			codeInternalError).Marshal()
		if err != nil {
			return
		}
	}

	if err := h.nc.Publish(subject, payload); err != nil {
		h.log.Error("respond failed", "rid", reply.RID, "error", err.Error())
	}

	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

func (h *handler) recoverInto(subject, rid string) {
	r := recover()
	if r == nil {
		return
	}

	h.log.Error("handler panicked", "rid", rid, "panic", r, "stack", string(debug.Stack()))

	if subject != "" {
		h.send(subject, protocol.FallbackReply(rid, h.cfg.Name, codeInternalError), nil,
			audit.Details{})
	}
}

func (h *handler) overloadOnShed(t *queue.Task, shed string, reply *protocol.Reply,
	det audit.Details) (int, int) {

	if shed != queue.ReasonQueueLimit || t.Req.Phase != protocol.PhaseRequest {
		return 0, 0
	}

	asks, bans, fired := decide.FireOverload(h.store.Current(), t.Req.Route.Profile,
		t.Req.Conn.ClientIP, t.Fill, true, shed)

	if len(fired) == 0 {
		return 0, 0
	}

	reply.Actions = asks
	det.Engine["overload"] = fired

	if len(bans) != 0 && h.live != nil {
		err := writeLists(context.Background(), h.resolver, h.live, h.log, t.Req.RID,
			t.Req.Node, t.Req.Ray, bans)
		if err != nil {
			h.log.Error("geo unavailable for a list write", "rid", t.Req.RID,
				"profile", t.Req.Route.Profile, "error", err.Error())

			det.Engine["geo"] = err.Error()
		}
	}

	return len(asks), len(bans)
}
