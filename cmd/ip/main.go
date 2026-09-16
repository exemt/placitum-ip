package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"

	"github.com/exemt/placitum-ip/internal/audit"
	"github.com/exemt/placitum-ip/internal/config"
	"github.com/exemt/placitum-ip/internal/desired"
	"github.com/exemt/placitum-ip/internal/dyn"
	"github.com/exemt/placitum-ip/internal/queue"
	"github.com/exemt/placitum-ip/internal/store"
	"github.com/exemt/placitum-shared/flow"
	"github.com/exemt/placitum-shared/logkit"
	"github.com/exemt/placitum-shared/netinfo"
	"github.com/exemt/placitum-shared/pulse"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	var (
		logs  *logkit.Sink
		logIO *flow.Counter
	)

	if config.LogShip() {
		logIO = flow.New()
		logs = logkit.NewSink(config.LogWriter(cfg.Name), cfg.Name, logIO)

		defer logs.Close()
	}

	level := new(slog.LevelVar)
	level.Set(cfg.LogLevel)

	log := slog.New(slog.NewJSONHandler(logs.Tee(os.Stdout),
		&slog.HandlerOptions{Level: level}))

	log.Info("build", "version", version, "revision", revision)
	slog.SetDefault(log)

	data, err := store.Load(store.Paths{
		Policy: cfg.PolicyDir,
		Geo:    cfg.GeoDir,
	}, log)
	if err != nil {
		return err
	}

	st := data.Current().Stats()
	log.Info("policy loaded",
		"profiles", st.Profiles,
		"sets", st.Sets,
		"live_sets", st.LiveSets,
		"geo_countries", st.GeoCountries,
		"geo_prefixes", st.GeoPrefixes,
		"skipped", st.Skipped,
	)

	nc, err := nats.Connect(joined(cfg.Servers),
		nats.Name("waf-inspector-"+cfg.Name),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("bus disconnected", "error", errText(err))
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info("bus reconnected", "server", c.ConnectedUrl())
		}),
	)
	if err != nil {
		return err
	}

	defer nc.Close()

	if err := audit.Ensure(nc); err != nil {
		log.Warn("audit stream", "error", err.Error())
	} else {
		log.Info("audit stream", "stream", audit.Stream, "subjects", "waf.audit.>")
	}

	if logs != nil {
		if err := logkit.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err.Error())
		}

		logs.Attach(nc)
		log.Info("log stream", "stream", logkit.Stream,
			"subject", logkit.Subject(logs.Writer()))
	}

	config.LogInternalRedis(log, cfg.BlobsURL, cfg.BlobsFrom)

	var rdb *redis.Client

	if cfg.BlobsURL != "" {
		if rdb, err = desired.OpenBlobs(cfg.BlobsURL); err != nil {
			return err
		}

		defer rdb.Close()
	}

	live := dyn.New(nc, dyn.NewBlobs(rdb), log)
	defer live.Close()

	applied, err := startDesired(cfg, nc, rdb, data, live, level, log)
	if err != nil {
		return err
	}

	if snap := data.Current(); snap != nil {
		if err := live.Sync(snap.Live); err != nil {
			log.Warn("live datasets sync failed", "error", err.Error())
		}
	}

	auditSink := audit.NewSink(nc, log)

	var resolver *netinfo.Resolver

	if cfg.GeoAddr != "" {
		var rerr error

		resolver, rerr = netinfo.New(cfg.GeoAddr, cfg.GeoTimeout, cfg.GeoNegMax, log)
		if rerr != nil {
			return fmt.Errorf("geo resolver: %w", rerr)
		}

		defer resolver.Close()
	}

	h := &handler{cfg: cfg, log: log, nc: nc,
		audit: auditSink, store: data, live: live, resolver: resolver}
	pool := queue.New(cfg.Workers, cfg.QueueDepth, cfg.ReserveMS, cfg.MinBudgetMS, cfg.QueueFull, h.evaluate)
	h.pool = pool

	sub, err := nc.QueueSubscribe(cfg.Subject, cfg.Queue, h.receive)
	if err != nil {
		return err
	}

	if err := sub.SetPendingLimits(cfg.QueueDepth+cfg.Workers+2, 4*1024*1024); err != nil {
		return err
	}

	log.Info("connected",
		"server", nc.ConnectedUrl(),
		"subject", cfg.Subject,
		"queue", cfg.Queue,
		"inspector", cfg.Name,
		"workers", cfg.Workers,
		"queue_max", cfg.QueueDepth,
		"queue_full", cfg.QueueFull,
		"queue_expand", cfg.QueueExpand,
		"conf", cfg.ConfPath,
		"reload_every", cfg.ReloadEvery.String(),
	)

	watchCtx, stopWatch := context.WithCancel(context.Background())
	defer stopWatch()

	go data.Watch(watchCtx, cfg.ReloadEvery)

	inspectorID := pulse.NewID()
	stopBeat := startHeartbeat(nc, cfg, inspectorID, pool, data, live, applied, logIO, log)
	defer stopBeat()

	waitForSignal(data, log)
	stopWatch()

	if err := sub.Drain(); err != nil {
		log.Warn("drain failed", "error", err.Error())
	}

	pool.Close()
	auditSink.Close()

	log.Info("drained",
		"accepted", pool.Accepted.Load(),
		"shed", pool.Shed.Load(),
		"expired", pool.Expired.Load(),
	)

	return nil
}

func startDesired(
	cfg *config.Config,
	nc *nats.Conn,
	rdb *redis.Client,
	data *store.Store,
	live *dyn.Store,
	level *slog.LevelVar,
	log *slog.Logger,
) (*desired.Applied, error) {
	if cfg.DataDir == "" {
		return nil, nil
	}

	desired.Bootstrap(data, live, cfg.DataDir, log)

	applied, err := desired.Watch(context.Background(), nc, rdb, data, live,
		cfg.DataDir, level, log)
	if err != nil {
		return nil, err
	}

	log.Info("desired watch on", "key", desired.PackKey, "data", cfg.DataDir)

	return applied, nil
}

func startHeartbeat(
	nc *nats.Conn,
	cfg *config.Config,
	id string,
	pool *queue.Pool,
	data *store.Store,
	live *dyn.Store,
	applied *desired.Applied,
	logIO *flow.Counter,
	log *slog.Logger,
) func() {
	subject := pulse.Subject(cfg.Name, id)
	log.Info("heartbeat on",
		"subject", subject,
		"id", id,
		"every", cfg.HeartbeatEvery.String(),
	)

	beat := func() {
		work := &pulse.Work{
			Workers:    cfg.Workers,
			QueueDepth: cfg.QueueDepth,
			Queued:     pool.Queued(),
			Accepted:   pool.Accepted.Load(),
			Shed:       pool.Shed.Load(),
			Expired:    pool.Expired.Load(),
		}
		io := map[string]flow.Flow{"inspect": pool.IO()}

		if logIO != nil {
			io["log"] = logIO.Snapshot()
		}

		msg := pulse.Build(id, cfg.Name, cfg.Subject, cfg.Queue, work, io)
		msg.Version, msg.Revision = version, revision
		if snap := data.Current(); snap != nil {
			st := snap.Stats()
			msg.Rev = int(st.Gen)
			msg.ConfigHash = st.Fingerprint
			msg.Apply = "ok"
			msg.Profiles = st.Profiles
		}

		if hash, rev, apply, names := applied.Snapshot(); apply != "" {
			msg.Rev = rev
			msg.ConfigHash = hash
			msg.Apply = apply

			if len(names) != 0 {
				msg.Profiles = names
			}
		}

		if err := pulse.PublishFrame(nc, subject,
			frame{Message: msg, Live: liveStats(live)}); err != nil {
			log.Warn("heartbeat failed", "error", err.Error())
		}
	}

	beat()
	tick := time.NewTicker(cfg.HeartbeatEvery)

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				beat()
			}
		}
	}()

	return func() {
		tick.Stop()
		close(done)
	}
}

type frame struct {
	pulse.Message

	Live []liveSet `json:"live,omitempty"`
}

type liveSet struct {
	UUID  string `json:"uuid"`
	Seq   uint64 `json:"seq"`
	Base  int    `json:"base"`
	Live  int    `json:"live"`
	Ready bool   `json:"ready"`
}

func liveStats(live *dyn.Store) []liveSet {
	stats := live.Stats()
	if len(stats) == 0 {
		return nil
	}

	out := make([]liveSet, 0, len(stats))

	for _, st := range stats {
		out = append(out, liveSet{
			UUID:  st.UUID,
			Seq:   st.Seq,
			Base:  st.Base,
			Live:  st.Live,
			Ready: st.Ready,
		})
	}

	return out
}

func waitForSignal(data *store.Store, log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-ch
		if sig == syscall.SIGHUP {
			if _, err := data.Reload(); err != nil {
				log.Warn("sighup reload failed", "error", err.Error())
			}

			continue
		}

		log.Info("draining", "signal", sig.String())

		return
	}
}

func joined(servers []string) string {
	out := ""

	for i, s := range servers {
		if i > 0 {
			out += ","
		}

		out += s
	}

	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
