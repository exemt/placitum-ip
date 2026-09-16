package policy

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-ip/internal/overload"
	"github.com/exemt/placitum-ip/internal/protocol"
)

const DefaultName = "default"

const (
	ActionAllow = "allow"
	ActionDeny  = "deny"

	ActionRequest = "request"
	ActionList    = "list"
)

const (
	OnWhite = "white"
	OnBlack = "black"
	OnNone  = "none"
)

func knownOn(on string) bool {
	return on == OnWhite || on == OnBlack || on == OnNone
}

func Terminal(action string) bool {
	return action == ActionAllow || action == ActionDeny
}

var verbs = map[string][]string{
	"challenge": {"request"},
	"threshold": {"request"},
	"skip":      {"request"},
	"mutate":    {"request"},
	"reauth":    {"session"},
	"note":      {"request", "ip", "asn", "session"},
	"active":    {"request", "conn"},
	"passive":   {"request", "conn"},
	"off":       {"request", "conn"},
	"vote":      {"request", "conn"},
	"audit":     {"request", "response"},
	"archive":   {"request", "response"},
	"mark":      {"request"},
	"score":     {"request"},
}

func controlVerb(do string) bool {
	return do == "active" || do == "passive" || do == "off" || do == "vote"
}

func checkPhaseAsk(do, phase, apply string) error {
	if phase == "" {
		return nil
	}

	if !controlVerb(do) {
		return fmt.Errorf("phase is only for active, passive, vote and off")
	}

	switch phase {
	case protocol.PhaseRequest, protocol.PhaseResponse, protocol.PhaseFrame:
	default:
		return fmt.Errorf("phase must be request, response or frame, got %q", phase)
	}

	if apply == protocol.ApplyConn && phase != protocol.PhaseFrame {
		return fmt.Errorf("apply conn needs phase frame")
	}

	return nil
}

func auditVerb(do string) bool {
	return do == "audit" || do == "archive"
}

func recordVerb(do string) bool {
	return auditVerb(do) || do == "mark" || do == "score"
}

func checkMutateAsk(do, group, side string) error {
	if do != "mutate" {
		if group != "" {
			return fmt.Errorf("group is only for mutate")
		}

		return nil
	}

	if group == "" {
		return fmt.Errorf("mutate needs a group")
	}

	if !counterNameOK(group) {
		return fmt.Errorf("bad group name %q", group)
	}

	if side != "on" && side != "off" {
		return fmt.Errorf("mutate needs side: on or off, got %q", side)
	}

	return nil
}

func checkMarkAsk(do, to, marker string) error {
	if do != "mark" {
		if marker != "" {
			return fmt.Errorf("marker is only for mark")
		}

		return nil
	}

	if to != "" && to != "*" {
		return fmt.Errorf("mark takes no to: the module marks the route's own record")
	}

	return protocol.CheckMarker(marker)
}

type recordObjects struct {
	Headers *protocol.ObjectSpec
	Args    *protocol.ObjectSpec
	Body    *protocol.ObjectSpec
}

func (r recordObjects) any() bool {
	return r.Headers != nil || r.Args != nil || r.Body != nil
}

func checkAuditAsk(do, to, apply, set string, ttl int, objs recordObjects, when []string) error {
	if !auditVerb(do) {
		if len(when) != 0 || objs.any() {
			return fmt.Errorf("when, headers, args and body are only for audit and archive")
		}

		if set != "" && do != "mutate" {
			return fmt.Errorf("set is only for mutate, audit and archive")
		}

		return nil
	}

	if to != "" && to != "*" {
		return fmt.Errorf("%s takes no to: the module writes the route's own record", do)
	}

	if set != "on" && set != "off" {
		return fmt.Errorf("%s needs set: on or off, got %q", do, set)
	}

	if set == "off" && (ttl != 0 || len(when) != 0 || objs.any()) {
		return fmt.Errorf("ttl, when and objects are only for set on")
	}

	if do == "audit" && (ttl != 0 || len(when) != 0) {
		return fmt.Errorf("ttl and when are only for archive")
	}

	if _, err := protocol.CheckArchiveWhen(when); err != nil {
		return err
	}

	if apply == "response" && objs.Args != nil {
		return fmt.Errorf("args has no meaning for the response record")
	}

	for _, item := range []struct {
		name string
		spec *protocol.ObjectSpec
	}{{"headers", objs.Headers}, {"args", objs.Args}, {"body", objs.Body}} {
		if err := protocol.CheckObjectSpec(item.name, item.spec, do == "audit"); err != nil {
			return err
		}
	}

	return nil
}

type Match struct {
	Lists     []string
	Live      []string
	Countries []string
	Asns      []uint32
}

func (m Match) empty() bool {
	return len(m.Lists) == 0 && len(m.Live) == 0 &&
		len(m.Countries) == 0 && len(m.Asns) == 0
}

type Set struct {
	Name    string
	Match   Match
	Inverse bool
	Exclude Match
}

type Rule struct {
	Set     string
	Dataset string
	Not     bool
	Action  string

	Response string

	Code string

	To      string
	Do      string
	Apply   string
	Phase   string
	Delta   int
	Value   int
	Counter string
	Marker  string
	Group   string
	Side    string
	Objects recordObjects
	When    []string

	HasDelta bool
	HasValue bool

	List  string
	Write string
	TTL   int
}

type Profile struct {
	Name        string
	Rules       []Rule
	Default     string
	DefaultCode string
	Outcomes    []Outcome
}

type Outcome struct {
	On string
	At int

	To       string
	Do       string
	Apply    string
	Phase    string
	Delta    int
	HasDelta bool
	Value    int
	HasValue bool
	Counter  string
	Marker   string
	Group    string
	Side     string
	Objects  recordObjects
	When     []string

	List  string
	Write string
	TTL   int

	Code string
}

func (o Outcome) Matches(where string) bool {
	return o.On == where
}

type fileMatch struct {
	Lists     []string `yaml:"lists"`
	Live      []string `yaml:"live"`
	Countries []string `yaml:"countries"`
	Asns      []uint32 `yaml:"asns"`
}

type fileSet struct {
	Lists     []string  `yaml:"lists"`
	Live      []string  `yaml:"live"`
	Countries []string  `yaml:"countries"`
	Asns      []uint32  `yaml:"asns"`
	Inverse   bool      `yaml:"inverse"`
	Exclude   fileMatch `yaml:"exclude"`
}

type fileRule struct {
	Set      string               `yaml:"set"`
	Dataset  string               `yaml:"dataset"`
	Not      bool                 `yaml:"not"`
	Action   string               `yaml:"action"`
	Response string               `yaml:"response"`
	Code     string               `yaml:"code"`
	To       string               `yaml:"to"`
	Do       string               `yaml:"do"`
	Apply    string               `yaml:"apply"`
	Phase    string               `yaml:"phase"`
	Delta    *int                 `yaml:"delta"`
	Value    *int                 `yaml:"value"`
	Counter  string               `yaml:"counter"`
	Marker   string               `yaml:"marker"`
	Group    string               `yaml:"group"`
	Side     string               `yaml:"side"`
	Headers  *protocol.ObjectSpec `yaml:"headers"`
	Args     *protocol.ObjectSpec `yaml:"args"`
	Body     *protocol.ObjectSpec `yaml:"body"`
	When     []string             `yaml:"when"`
	List     string               `yaml:"list"`
	Write    string               `yaml:"write"`
	TTL      string               `yaml:"ttl"`
}

type fileOutcome struct {
	On      string               `yaml:"on"`
	At      *int                 `yaml:"at"`
	To      string               `yaml:"to"`
	Do      string               `yaml:"do"`
	Apply   string               `yaml:"apply"`
	Phase   string               `yaml:"phase"`
	Delta   *int                 `yaml:"delta"`
	Value   *int                 `yaml:"value"`
	Counter string               `yaml:"counter"`
	Marker  string               `yaml:"marker"`
	Group   string               `yaml:"group"`
	Side    string               `yaml:"set"`
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	When    []string             `yaml:"when"`
	List    string               `yaml:"list"`
	Write   string               `yaml:"write"`
	TTL     string               `yaml:"ttl"`
	Code    string               `yaml:"code"`
}

type fileProfile struct {
	Rules    []fileRule    `yaml:"rules"`
	Default  string        `yaml:"default"`
	Code     string        `yaml:"default_code"`
	Outcomes []fileOutcome `yaml:"outcomes"`
}

func LoadSets(path string) (map[string]Set, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParseSets(raw)
}

func ParseSets(raw []byte) (map[string]Set, error) {
	var f map[string]fileSet

	if len(raw) > 0 {
		if err := yaml.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("sets: %w", err)
		}
	}

	out := make(map[string]Set, len(f))

	for name, spec := range f {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			return nil, fmt.Errorf("sets: empty set name")
		}

		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("sets: duplicate set %q", key)
		}

		main, err := normalizeMatch(key, fileMatch{
			Lists:     spec.Lists,
			Live:      spec.Live,
			Countries: spec.Countries,
			Asns:      spec.Asns,
		})
		if err != nil {
			return nil, err
		}

		ex, err := normalizeMatch(key+".exclude", spec.Exclude)
		if err != nil {
			return nil, err
		}

		if main.empty() {
			return nil, fmt.Errorf("sets: %s is empty", key)
		}

		out[key] = Set{Name: key, Match: main, Inverse: spec.Inverse, Exclude: ex}
	}

	return out, nil
}

func LoadProfile(path, name string) (Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}

	return ParseProfile(raw, name)
}

func ParseProfile(raw []byte, name string) (Profile, error) {
	var f fileProfile

	if len(raw) > 0 {
		if err := yaml.Unmarshal(raw, &f); err != nil {
			return Profile{}, fmt.Errorf("profile %q: %w", name, err)
		}
	}

	p := Profile{Name: name, Default: ActionAllow}

	if f.Default != "" {
		if !Terminal(f.Default) {
			return Profile{}, fmt.Errorf("profile %q: default action %q is not terminal",
				name, f.Default)
		}

		p.Default = f.Default
	}

	p.DefaultCode = f.Code

	for i, src := range f.Rules {
		rule, err := normalizeRule(src)
		if err != nil {
			return Profile{}, fmt.Errorf("profile %q rule %d: %w", name, i+1, err)
		}

		p.Rules = append(p.Rules, rule)
	}

	for i, src := range f.Outcomes {
		outcome, err := normalizeOutcome(src)
		if err != nil {
			return Profile{}, fmt.Errorf("profile %q outcome %d: %w", name, i+1, err)
		}

		p.Outcomes = append(p.Outcomes, outcome)
	}

	return p, nil
}

func normalizeOutcome(src fileOutcome) (Outcome, error) {
	out := Outcome{
		On:   strings.ToLower(strings.TrimSpace(src.On)),
		List: strings.TrimSpace(src.List),
		Code: src.Code,
	}

	switch {
	case out.On == overload.On:
		if err := overload.Check(src.At); err != nil {
			return Outcome{}, err
		}

		out.At = overload.At(src.At)

	case !knownOn(out.On):
		return Outcome{}, fmt.Errorf("on must be white, black, none or overload, got %q", src.On)

	case src.At != nil:
		return Outcome{}, fmt.Errorf("at is only for on: overload")
	}

	out.To = strings.TrimSpace(src.To)
	out.Do = strings.ToLower(strings.TrimSpace(src.Do))

	if (out.Do == "") == (out.List == "") {
		return Outcome{}, fmt.Errorf("exactly one of do or list is required")
	}

	if err := checkCode(src.Code); err != nil {
		return Outcome{}, err
	}

	if out.List != "" {
		if src.Apply != "" || src.Delta != nil || src.Value != nil ||
			src.Counter != "" {

			return Outcome{}, fmt.Errorf(
				"apply, delta, value and counter are only for do")
		}

		ttl, err := parseTTL(src.TTL)
		if err != nil {
			return Outcome{}, err
		}

		out.TTL = ttl

		if out.Write, err = parseWrite(src.Write); err != nil {
			return Outcome{}, err
		}

		return out, nil
	}

	if strings.TrimSpace(src.Write) != "" {
		return Outcome{}, fmt.Errorf("write is only for a list write")
	}

	if src.TTL != "" && out.Do != "archive" {
		return Outcome{}, fmt.Errorf("ttl is only for list and archive")
	}

	axes, ok := verbs[out.Do]
	if !ok {
		return Outcome{}, fmt.Errorf("unknown verb %q", out.Do)
	}

	out.Apply = strings.ToLower(strings.TrimSpace(src.Apply))

	if out.Apply == "" {
		if len(axes) != 1 && !recordVerb(out.Do) {
			return Outcome{}, fmt.Errorf("%s without apply", out.Do)
		}

		out.Apply = axes[0]
	}

	axisOK := false

	for _, a := range axes {
		if a == out.Apply {
			axisOK = true
		}
	}

	if !axisOK {
		return Outcome{}, fmt.Errorf("verb %q does not take apply %q", out.Do, out.Apply)
	}

	if src.Delta != nil {
		if *src.Delta < -100 || *src.Delta > 900 {
			return Outcome{}, fmt.Errorf("delta is out of -100..900 percent")
		}

		out.Delta, out.HasDelta = *src.Delta, true
	}

	if src.Value != nil {
		if *src.Value < -100 || *src.Value > 100 {
			return Outcome{}, fmt.Errorf("value is out of -100..100 percent")
		}

		out.Value, out.HasValue = *src.Value, true
	}

	if out.Do == "threshold" && !out.HasDelta {
		return Outcome{}, fmt.Errorf("threshold without delta")
	}

	if controlVerb(out.Do) && (out.To == "" || out.To == "*") {
		return Outcome{}, fmt.Errorf("%s needs to: the module switches one call, not everyone", out.Do)
	}

	if out.Do == "score" {
		if out.To != "" && out.To != "*" {
			return Outcome{}, fmt.Errorf("score takes no to: the module adds to the route's own sum")
		}

		if !out.HasValue || out.Value == 0 {
			return Outcome{}, fmt.Errorf("score needs a non-zero value")
		}
	}

	out.Counter = strings.TrimSpace(src.Counter)

	if out.Counter != "" {
		if out.Do != "note" {
			return Outcome{}, fmt.Errorf("counter is only for note")
		}

		if !counterNameOK(out.Counter) {
			return Outcome{}, fmt.Errorf("bad counter name %q", out.Counter)
		}
	}

	out.Side = strings.ToLower(strings.TrimSpace(src.Side))
	out.Objects = recordObjects{Headers: src.Headers, Args: src.Args, Body: src.Body}
	out.When = src.When

	if src.TTL != "" {
		ttl, err := parseTTL(src.TTL)
		if err != nil {
			return Outcome{}, err
		}

		out.TTL = ttl
	}

	out.Marker = strings.TrimSpace(src.Marker)
	out.Group = strings.TrimSpace(src.Group)
	out.Phase = strings.TrimSpace(src.Phase)

	if err := checkMutateAsk(out.Do, out.Group, out.Side); err != nil {
		return Outcome{}, err
	}

	if err := checkPhaseAsk(out.Do, out.Phase, out.Apply); err != nil {
		return Outcome{}, err
	}

	if err := checkMarkAsk(out.Do, out.To, out.Marker); err != nil {
		return Outcome{}, err
	}

	if err := checkAuditAsk(out.Do, out.To, out.Apply, out.Side, out.TTL, out.Objects, out.When); err != nil {
		return Outcome{}, err
	}

	return out, nil
}

func normalizeRule(src fileRule) (Rule, error) {
	rule := Rule{
		Set:      strings.ToLower(strings.TrimSpace(src.Set)),
		Dataset:  strings.ToLower(strings.TrimSpace(src.Dataset)),
		Not:      src.Not,
		Action:   strings.ToLower(strings.TrimSpace(src.Action)),
		Response: src.Response,
		Code:     src.Code,
	}

	if Terminal(rule.Action) {
		if rule.Set == "" {
			return Rule{}, fmt.Errorf("%s needs set", rule.Action)
		}

		if rule.Dataset != "" {
			return Rule{}, fmt.Errorf("dataset is only for request and list")
		}
	} else {
		if rule.Dataset == "" {
			return Rule{}, fmt.Errorf("%s needs dataset", rule.Action)
		}

		if rule.Set != "" {
			return Rule{}, fmt.Errorf("set is only for allow and deny")
		}
	}

	if rule.Not && Terminal(rule.Action) {
		return Rule{}, fmt.Errorf("not is only for request and list")
	}

	switch rule.Action {
	case ActionAllow, ActionDeny:

	case ActionRequest:
		rule.To = strings.TrimSpace(src.To)
		rule.Do = strings.ToLower(strings.TrimSpace(src.Do))

		axes, ok := verbs[rule.Do]
		if !ok {
			return Rule{}, fmt.Errorf("unknown verb %q", src.Do)
		}

		rule.Apply = strings.ToLower(strings.TrimSpace(src.Apply))

		if rule.Apply == "" {
			if len(axes) != 1 && !recordVerb(rule.Do) {
				return Rule{}, fmt.Errorf("%s without apply", rule.Do)
			}

			rule.Apply = axes[0]
		}

		if !allowedAxis(axes, rule.Apply) {
			return Rule{}, fmt.Errorf("verb %q does not take apply %q",
				rule.Do, rule.Apply)
		}

		if err := checkCode(src.Code); err != nil {
			return Rule{}, err
		}

		if src.Delta != nil {
			if *src.Delta < -100 || *src.Delta > 900 {
				return Rule{}, fmt.Errorf("delta is out of -100..900 percent")
			}

			rule.Delta, rule.HasDelta = *src.Delta, true
		}

		if src.Value != nil {
			if *src.Value < -100 || *src.Value > 100 {
				return Rule{}, fmt.Errorf("value is out of -100..100 percent")
			}

			rule.Value, rule.HasValue = *src.Value, true
		}

		if rule.Do == "threshold" && !rule.HasDelta {
			return Rule{}, fmt.Errorf("threshold without delta")
		}

		if controlVerb(rule.Do) && (rule.To == "" || rule.To == "*") {
			return Rule{}, fmt.Errorf("%s needs to: the module switches one call, not everyone", rule.Do)
		}

		if rule.Do == "score" {
			if rule.To != "" && rule.To != "*" {
				return Rule{}, fmt.Errorf("score takes no to: the module adds to the route's own sum")
			}

			if !rule.HasValue || rule.Value == 0 {
				return Rule{}, fmt.Errorf("score needs a non-zero value")
			}
		}

		rule.Counter = strings.TrimSpace(src.Counter)

		if rule.Counter != "" {
			if rule.Do != "note" {
				return Rule{}, fmt.Errorf("counter is only for note")
			}

			if !counterNameOK(rule.Counter) {
				return Rule{}, fmt.Errorf("bad counter name %q", rule.Counter)
			}
		}

		rule.Side = strings.ToLower(strings.TrimSpace(src.Side))
		rule.Objects = recordObjects{Headers: src.Headers, Args: src.Args, Body: src.Body}
		rule.When = src.When

		if src.TTL != "" {
			if rule.Do != "archive" {
				return Rule{}, fmt.Errorf("ttl is only for list and archive")
			}

			ttl, err := parseTTL(src.TTL)
			if err != nil {
				return Rule{}, err
			}

			rule.TTL = ttl
		}

		rule.Marker = strings.TrimSpace(src.Marker)
		rule.Group = strings.TrimSpace(src.Group)
		rule.Phase = strings.TrimSpace(src.Phase)

		if err := checkMutateAsk(rule.Do, rule.Group, rule.Side); err != nil {
			return Rule{}, err
		}

		if err := checkPhaseAsk(rule.Do, rule.Phase, rule.Apply); err != nil {
			return Rule{}, err
		}

		if err := checkMarkAsk(rule.Do, rule.To, rule.Marker); err != nil {
			return Rule{}, err
		}

		if err := checkAuditAsk(rule.Do, rule.To, rule.Apply, rule.Side, rule.TTL, rule.Objects, rule.When); err != nil {
			return Rule{}, err
		}

	case ActionList:
		rule.List = strings.TrimSpace(src.List)
		if rule.List == "" {
			return Rule{}, fmt.Errorf("list action without a dataset")
		}

		ttl, err := parseTTL(src.TTL)
		if err != nil {
			return Rule{}, err
		}

		rule.TTL = ttl

		if rule.Write, err = parseWrite(src.Write); err != nil {
			return Rule{}, err
		}

	default:
		return Rule{}, fmt.Errorf("unknown action %q", src.Action)
	}

	if rule.Action != ActionList && strings.TrimSpace(src.Write) != "" {
		return Rule{}, fmt.Errorf("write is only for the list action")
	}

	return rule, nil
}

func allowedAxis(axes []string, axis string) bool {
	for _, allowed := range axes {
		if allowed == axis {
			return true
		}
	}

	return false
}

func counterNameOK(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}

	for i := 0; i < len(name); i++ {
		c := name[i]

		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') {
			continue
		}

		if i > 0 && (c == '.' || c == '_' || c == '-') {
			continue
		}

		return false
	}

	return true
}

func checkCode(code string) error {
	if code == "" {
		return nil
	}

	if len(code) > 64 {
		return fmt.Errorf("code is longer than 64 bytes")
	}

	for i := 0; i < len(code); i++ {
		c := code[i]

		switch {
		case c >= 'A' && c <= 'Z':
		case i > 0 && c >= '0' && c <= '9':
		case i > 0 && c == '_':
		default:
			return fmt.Errorf("code %q is not [A-Z][A-Z0-9_]*", code)
		}
	}

	return nil
}

const (
	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"
)

func parseWrite(raw string) (string, error) {
	switch w := strings.ToLower(strings.TrimSpace(raw)); w {
	case "", WriteAddr:
		return WriteAddr, nil

	case WriteNet, WriteNetAll, WriteASN:
		return w, nil
	}

	return "", fmt.Errorf("write must be addr, net, net_all or asn, got %q", raw)
}

func parseTTL(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	mult := 1

	switch s[len(s)-1] {
	case 's':
		s = s[:len(s)-1]
	case 'm':
		mult, s = 60, s[:len(s)-1]
	case 'h':
		mult, s = 3600, s[:len(s)-1]
	case 'd':
		mult, s = 86400, s[:len(s)-1]
	}

	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad ttl")
	}

	return n * mult, nil
}

func normalizeMatch(label string, src fileMatch) (Match, error) {
	lists, err := normalizeNames(label+".lists", src.Lists)
	if err != nil {
		return Match{}, err
	}

	live, err := normalizeNames(label+".live", src.Live)
	if err != nil {
		return Match{}, err
	}

	countries, err := normalizeNames(label+".countries", src.Countries)
	if err != nil {
		return Match{}, err
	}

	seen := map[uint32]struct{}{}
	asns := make([]uint32, 0, len(src.Asns))

	for _, asn := range src.Asns {
		if _, dup := seen[asn]; dup {
			return Match{}, fmt.Errorf("%s: duplicate asn %d", label, asn)
		}

		seen[asn] = struct{}{}
		asns = append(asns, asn)
	}

	return Match{Lists: lists, Live: live, Countries: countries, Asns: asns}, nil
}

func normalizeNames(label string, names []string) ([]string, error) {
	out := make([]string, 0, len(names))
	seen := map[string]struct{}{}

	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return nil, fmt.Errorf("%s: empty name", label)
		}

		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("%s: duplicate %q", label, name)
		}

		seen[name] = struct{}{}
		out = append(out, name)
	}

	return out, nil
}
