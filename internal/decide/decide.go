package decide

import (
	"net/netip"
	"strconv"

	"github.com/exemt/placitum-ip/internal/audit"
	"github.com/exemt/placitum-ip/internal/overload"
	"github.com/exemt/placitum-ip/internal/policy"
	"github.com/exemt/placitum-ip/internal/protocol"
	"github.com/exemt/placitum-ip/internal/store"
)

const (
	CodeOK             = "IP_OK"
	CodeMalformed      = "IP_MALFORMED"
	CodeAllowlist      = "IP_ALLOWLIST"
	CodeList           = "IP_LIST"
	CodeGeo            = "IP_GEO"
	CodeUnknownProfile = "IP_UNKNOWN_PROFILE"
	CodeMissingSet     = "IP_MISSING_SET"
)

const (
	FindingDenylist       = "ip-denylist"
	FindingGeo            = "ip-geo"
	FindingUnknownProfile = "ip-unknown-profile"
	FindingMalformed      = "ip-malformed-address"
	FindingMissingSet     = "ip-missing-set"
)

type Ban struct {
	Dataset string
	Write   string
	Value   string
	TTL     int
	Reason  string
}

type Result struct {
	Verdict  string
	Code     string
	Text     string
	Response string
	Findings []audit.Finding
	Scope    string
	Subject  string
	Engine   map[string]any
	Actions  []protocol.Action
	Bans     []Ban
}

func Check(snap *store.Snapshot, live store.Live, profileName, raw string) Result {
	if profileName == "" {
		profileName = policy.DefaultName
	}

	engine := map[string]any{}

	if snap != nil {
		engine["gen"] = snap.Gen
	}

	prof, ok := snap.Profile(profileName)
	if !ok {
		return Result{
			Verdict:  protocol.VerdictError,
			Code:     CodeUnknownProfile,
			Text:     profileName,
			Response: policyDefaultResponse(),
			Findings: []audit.Finding{{
				Code:     FindingUnknownProfile,
				Severity: audit.SeverityCritical,
				Target:   audit.TargetConn,
				Rule:     profileName,
			}},
			Engine: engine,
		}
	}

	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.IsValid() {
		return Result{
			Verdict:  protocol.VerdictError,
			Code:     CodeMalformed,
			Text:     raw,
			Response: policyDefaultResponse(),
			Findings: []audit.Finding{{
				Code:     FindingMalformed,
				Severity: audit.SeverityHigh,
				Target:   audit.TargetConn,
				Rule:     raw,
			}},
			Engine: engine,
		}
	}

	ip = ip.Unmap()

	if name, kind := missing(snap, prof); name != "" {
		return Result{
			Verdict:  protocol.VerdictError,
			Code:     CodeMissingSet,
			Text:     name,
			Response: policyDefaultResponse(),
			Findings: []audit.Finding{{
				Code:     FindingMissingSet,
				Severity: audit.SeverityCritical,
				Target:   audit.TargetConn,
				Rule:     kind + ":" + name,
			}},
			Engine: engine,
		}
	}

	country, geoOK := snap.LookupGeo(ip)
	if geoOK {
		engine["geo"] = country
	}

	res := Result{Engine: engine}

	where := policy.OnNone
	decided := false

	for i, rule := range prof.Rules {
		if rule.Action != policy.ActionAllow {
			continue
		}

		set := snap.Set(rule.Set)

		ok, hit := set.Explain(ip, country, geoOK, live)
		if !ok {
			continue
		}

		mark(engine, i, rule.Set, hit.Kind, hit.Name)
		res = terminal(res, rule, hit, ip)
		where = policy.OnWhite
		decided = true

		break
	}

	if !decided {
		for i, rule := range prof.Rules {
			if rule.Action != policy.ActionDeny {
				continue
			}

			set := snap.Set(rule.Set)

			ok, hit := set.Explain(ip, country, geoOK, live)
			if !ok {
				continue
			}

			mark(engine, i, rule.Set, hit.Kind, hit.Name)
			res = terminal(res, rule, hit, ip)
			where = policy.OnBlack
			decided = true

			break
		}
	}

	if !decided {
		res = fallback(res, prof)
	}

	for _, rule := range prof.Rules {
		if policy.Terminal(rule.Action) {
			continue
		}

		if snap.List(rule.Dataset).Contains(ip, live) == rule.Not {
			continue
		}

		if rule.Action == policy.ActionRequest {
			res.Actions = append(res.Actions, action(rule))

			continue
		}

		res.Bans = append(res.Bans, Ban{
			Dataset: rule.List,
			Write:   rule.Write,
			Value:   ip.String(),
			TTL:     rule.TTL,
			Reason:  banReason(rule),
		})
	}

	var fired []string

	for _, o := range prof.Outcomes {
		if !o.Matches(where) {
			continue
		}

		if o.Do != "" {
			res.Actions = append(res.Actions, outcomeAction(o))
			fired = append(fired, o.Do)

			continue
		}

		res.Bans = append(res.Bans, Ban{
			Dataset: o.List,
			Write:   o.Write,
			Value:   ip.String(),
			TTL:     o.TTL,
			Reason:  code(o.Code, res.Code),
		})

		fired = append(fired, o.List)
	}

	if len(fired) != 0 {
		engine["outcomes"] = fired
	}

	return res
}

func missing(snap *store.Snapshot, prof *store.Profile) (name, kind string) {
	for _, rule := range prof.Rules {
		if rule.Set != "" {
			set := snap.Set(rule.Set)
			if set == nil {
				return rule.Set, "set"
			}

			if set.UsesCountries() && !snap.GeoLoaded() {
				return rule.Set, "geo"
			}
		}

		if rule.Dataset != "" && snap.List(rule.Dataset) == nil {
			return rule.Dataset, "list"
		}
	}

	return "", ""
}

func mark(engine map[string]any, index int, set, kind, name string) {
	engine["rule"] = index + 1
	engine["set"] = set

	if kind != "" {
		engine["match"] = kind
	}

	if name != "" {
		engine["list"] = name
	}
}

func terminal(res Result, rule policy.Rule, hit store.Hit, ip netip.Addr) Result {
	switch rule.Action {
	case policy.ActionAllow:
		res.Verdict = protocol.VerdictAllow
		res.Code = code(rule.Code, CodeAllowlist)

		return res

	case policy.ActionDeny:
		res.Verdict = protocol.VerdictDeny
		res.Code = code(rule.Code, denyCode(hit.Kind))
		res.Response = code(rule.Response, policyDefaultResponse())

		if hit.Kind == store.KindCountry {
			res.Text = hit.Name
		}

		res.Scope, res.Subject = publicReason(hit, ip)
		res.Findings = append(res.Findings, finding(hit.Kind, hit.Name, audit.SeverityHigh, ip))

		return res
	}

	res.Verdict = protocol.VerdictAllow
	res.Code = CodeOK

	return res
}

func publicReason(hit store.Hit, ip netip.Addr) (scope, subject string) {
	switch hit.Kind {
	case store.KindCountry:
		return protocol.ScopeCountry, hit.Name

	case store.KindAsn:
		if n, err := strconv.ParseUint(hit.Name, 10, 32); err == nil {
			return protocol.ScopeASN, "AS" + strconv.FormatUint(n, 10)
		}

		return "", ""

	case store.KindList:
		span, ok := hit.Span.Prefix()
		if !ok {
			return "", ""
		}

		if span.Bits() == ip.BitLen() {
			return protocol.ScopeAddress, span.Addr().String()
		}

		return protocol.ScopeNetwork, span.String()
	}

	return "", ""
}

func fallback(res Result, prof *store.Profile) Result {
	switch prof.Default {
	case policy.ActionDeny:
		res.Verdict = protocol.VerdictDeny
		res.Code = code(prof.DefaultCode, CodeList)
		res.Response = policyDefaultResponse()
		res.Findings = append(res.Findings, audit.Finding{
			Code:     FindingDenylist,
			Severity: audit.SeverityHigh,
			Target:   audit.TargetConn,
			Rule:     "default",
		})

	default:
		res.Verdict = protocol.VerdictAllow
		res.Code = CodeOK
	}

	return res
}

func finding(kind, name string, severity string, ip netip.Addr) audit.Finding {
	code := FindingDenylist

	if kind == store.KindCountry {
		code = FindingGeo
	}

	return audit.Finding{
		Code:     code,
		Severity: severity,
		Target:   audit.TargetConn,
		Rule:     name,
		Evidence: ip.String(),
	}
}

func outcomeAction(o policy.Outcome) protocol.Action {
	out := protocol.Action{
		To:      o.To,
		Do:      o.Do,
		Apply:   o.Apply,
		Phase:   o.Phase,
		Code:    o.Code,
		Counter: o.Counter,
		Marker:  o.Marker,
		Group:   o.Group,
		Set:     o.Side,
		Headers: o.Objects.Headers,
		Args:    o.Objects.Args,
		Body:    o.Objects.Body,
	}

	if o.Do == "archive" && o.Side == "on" && o.TTL > 0 {
		ttl := int64(o.TTL)
		out.TTL = &ttl
	}

	if o.Do == "archive" && o.Side == "on" && len(o.When) > 0 {
		when, _ := protocol.CheckArchiveWhen(o.When)
		out.When = when
	}

	if o.HasDelta {
		delta := o.Delta
		out.Delta = &delta
	}

	if o.HasValue {
		value := o.Value
		out.Value = &value
	}

	return out
}

func action(rule policy.Rule) protocol.Action {
	out := protocol.Action{
		To:      rule.To,
		Do:      rule.Do,
		Apply:   rule.Apply,
		Phase:   rule.Phase,
		Code:    rule.Code,
		Counter: rule.Counter,
		Marker:  rule.Marker,
		Group:   rule.Group,
		Set:     rule.Side,
		Headers: rule.Objects.Headers,
		Args:    rule.Objects.Args,
		Body:    rule.Objects.Body,
	}

	if rule.Do == "archive" && rule.Side == "on" && rule.TTL > 0 {
		ttl := int64(rule.TTL)
		out.TTL = &ttl
	}

	if rule.Do == "archive" && rule.Side == "on" && len(rule.When) > 0 {
		when, _ := protocol.CheckArchiveWhen(rule.When)
		out.When = when
	}

	if rule.HasDelta {
		delta := rule.Delta
		out.Delta = &delta
	}

	if rule.HasValue {
		value := rule.Value
		out.Value = &value
	}

	return out
}

func banReason(rule policy.Rule) string {
	if rule.Code != "" {
		return rule.Code
	}

	return "IP_LIST"
}

func denyCode(kind string) string {
	if kind == store.KindCountry {
		return CodeGeo
	}

	return CodeList
}

func code(explicit, fallback string) string {
	if explicit != "" {
		return explicit
	}

	return fallback
}

func policyDefaultResponse() string {
	return "blocked"
}

func ToReply(req *protocol.Request, r Result) *protocol.Reply {
	reply := protocol.NewReply(req, r.Verdict)
	reply.Reason = &protocol.Reason{Code: r.Code}

	if r.Verdict == protocol.VerdictDeny && r.Response != "" {
		reply.Response = &protocol.ResponseRef{Name: r.Response}
	}

	if r.Verdict == protocol.VerdictDeny {
		reply.Reason.Scope = r.Scope
		reply.Reason.Subject = r.Subject
	}

	reply.Actions = r.Actions

	return reply
}

func FireOverload(snap *store.Snapshot, profileName, raw string, fill int, shed bool,
	reason string) ([]protocol.Action, []Ban, []string) {

	if snap == nil {
		return nil, nil, nil
	}

	if profileName == "" {
		profileName = policy.DefaultName
	}

	prof, ok := snap.Profile(profileName)
	if !ok {
		return nil, nil, nil
	}

	addr, err := netip.ParseAddr(raw)
	valid := err == nil && addr.IsValid()

	var (
		actions []protocol.Action
		bans    []Ban
		fired   []string
	)

	for _, o := range prof.Outcomes {
		if o.On != overload.On || !overload.Fires(o.At, fill, shed) {
			continue
		}

		if o.Do != "" {
			actions = append(actions, outcomeAction(o))
			fired = append(fired, o.Do)

			continue
		}

		if !valid {
			continue
		}

		bans = append(bans, Ban{
			Dataset: o.List,
			Write:   o.Write,
			Value:   addr.Unmap().String(),
			TTL:     o.TTL,
			Reason:  code(o.Code, reason),
		})

		fired = append(fired, o.List)
	}

	return actions, bans, fired
}
