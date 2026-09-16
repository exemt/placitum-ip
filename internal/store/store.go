package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-ip/internal/netset"
	"github.com/exemt/placitum-ip/internal/policy"
)

const (
	setsFile     = "sets.yaml"
	liveFile     = "live.yaml"
	listsDir     = "lists"
	asnsDir      = "asns"
	profilesDir  = "profiles"
	profileSufix = ".yaml"
)

type Paths struct {
	Policy string
	Geo    string
}

type Live interface {
	Contains(uuid string, ip netip.Addr) bool
}

type NamedTable struct {
	Kind  string
	Name  string
	Table *netset.Table
	Count int
}

const (
	KindList    = "list"
	KindAsn     = "asn"
	KindCountry = "country"
	KindLive    = "live"
	KindInverse = "inverse"
)

type Hit struct {
	Kind string
	Name string
	Span netset.Interval
}

type Match struct {
	Table     *netset.Table
	Sources   []NamedTable
	Countries []string
	Live      []string
}

func (s *Set) UsesCountries() bool {
	if s == nil {
		return false
	}

	return len(s.Match.Countries) != 0 || len(s.Exclude.Countries) != 0
}

func (m Match) hits(ip netip.Addr, country string, geoOK bool, live Live) bool {
	hit, ok := m.locate(ip, country, geoOK, live)

	return ok && hit.Kind != ""
}

func (m Match) locate(ip netip.Addr, country string, geoOK bool, live Live) (Hit, bool) {
	for _, src := range m.Sources {
		if span, ok := src.Table.Locate(ip); ok {
			return Hit{Kind: src.Kind, Name: src.Name, Span: span}, true
		}
	}

	for _, uuid := range m.Live {
		if live != nil && live.Contains(uuid, ip) {
			return Hit{Kind: KindLive, Name: uuid}, true
		}
	}

	if !geoOK {
		return Hit{}, false
	}

	for _, cc := range m.Countries {
		if cc == country {
			return Hit{Kind: KindCountry, Name: cc}, true
		}
	}

	return Hit{}, false
}

type List struct {
	UUID  string
	Table *netset.Table
	Live  bool
}

func (l *List) Contains(ip netip.Addr, live Live) bool {
	if l == nil {
		return false
	}

	if l.Live {
		return live != nil && live.Contains(l.UUID, ip)
	}

	_, ok := l.Table.Locate(ip)

	return ok
}

type Set struct {
	Name    string
	Match   Match
	Inverse bool
	Exclude Match
}

func (s *Set) Explain(ip netip.Addr, country string, geoOK bool, live Live) (bool, Hit) {
	if s == nil {
		return false, Hit{}
	}

	hit, in := s.Match.locate(ip, country, geoOK, live)

	if in && s.Exclude.hits(ip, country, geoOK, live) {
		in = false
	}

	if s.Inverse {
		if in {
			return false, Hit{}
		}

		return true, Hit{Kind: KindInverse, Name: s.Name}
	}

	return in, hit
}

type Profile struct {
	Name        string
	Rules       []policy.Rule
	Default     string
	DefaultCode string
	Outcomes    []policy.Outcome
}

type Snapshot struct {
	Gen         uint64
	Sets        map[string]*Set
	Profiles    map[string]*Profile
	Lists       map[string]*List
	Geo         []NamedTable
	Live        map[string]string
	Fingerprint string
	LoadedAt    time.Time
	Skipped     int
}

func (s *Snapshot) Profile(name string) (*Profile, bool) {
	if s == nil || s.Profiles == nil {
		return nil, false
	}

	if name == "" {
		name = policy.DefaultName
	}

	p, ok := s.Profiles[strings.ToLower(name)]

	return p, ok
}

func (s *Snapshot) Set(name string) *Set {
	if s == nil || s.Sets == nil {
		return nil
	}

	return s.Sets[name]
}

func (s *Snapshot) List(uuid string) *List {
	if s == nil || s.Lists == nil {
		return nil
	}

	return s.Lists[uuid]
}

func (s *Snapshot) Names() []string {
	if s == nil {
		return nil
	}

	out := make([]string, 0, len(s.Profiles))
	for name := range s.Profiles {
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}

func (s *Snapshot) GeoLoaded() bool {
	return s != nil && len(s.Geo) != 0
}

func (s *Snapshot) LookupGeo(ip netip.Addr) (string, bool) {
	if s == nil {
		return "", false
	}

	for _, g := range s.Geo {
		if g.Table.Contains(ip) {
			return g.Name, true
		}
	}

	return "", false
}

type Stats struct {
	Gen          uint64   `json:"gen"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	Profiles     []string `json:"profiles,omitempty"`
	Sets         int      `json:"sets"`
	LiveSets     int      `json:"live_sets"`
	GeoCountries int      `json:"geo_countries"`
	GeoPrefixes  int      `json:"geo_prefixes"`
	Skipped      int      `json:"skipped"`
}

func (s *Snapshot) Stats() Stats {
	if s == nil {
		return Stats{}
	}

	st := Stats{
		Gen:          s.Gen,
		Fingerprint:  s.Fingerprint,
		Profiles:     s.Names(),
		Sets:         len(s.Sets),
		LiveSets:     len(s.Live),
		GeoCountries: len(s.Geo),
		Skipped:      s.Skipped,
	}

	for _, g := range s.Geo {
		st.GeoPrefixes += g.Count
	}

	return st
}

type Store struct {
	paths atomic.Pointer[Paths]
	log   *slog.Logger
	cur   atomic.Pointer[Snapshot]
	gen   atomic.Uint64
}

func Load(paths Paths, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}

	s := &Store{log: log}
	s.paths.Store(&paths)

	snap, err := s.build(paths)
	if err != nil {
		return nil, err
	}

	s.cur.Store(snap)

	return s, nil
}

func (s *Store) Current() *Snapshot {
	return s.cur.Load()
}

func (s *Store) Paths() Paths {
	if p := s.paths.Load(); p != nil {
		return *p
	}

	return Paths{}
}

func (s *Store) Reload() (changed bool, err error) {
	return s.reload(s.Paths())
}

func (s *Store) ReloadFrom(policyDir, geoDir string) error {
	paths := Paths{Policy: policyDir, Geo: geoDir}

	if _, err := s.reload(paths); err != nil {
		return err
	}

	s.paths.Store(&paths)

	return nil
}

func (s *Store) reload(paths Paths) (changed bool, err error) {
	fp, err := fingerprint(paths)
	if err != nil {
		return false, err
	}

	if cur := s.cur.Load(); cur != nil && cur.Fingerprint == fp {
		return false, nil
	}

	snap, err := s.build(paths)
	if err != nil {
		return false, err
	}

	if cur := s.cur.Load(); cur != nil && cur.Fingerprint == snap.Fingerprint {
		return false, nil
	}

	s.cur.Store(snap)
	s.log.Info("policy reloaded",
		"gen", snap.Gen,
		"profiles", snap.Names(),
		"sets", len(snap.Sets),
		"live", len(snap.Live),
		"geo", len(snap.Geo),
		"skipped", snap.Skipped,
	)

	return true, nil
}

func (s *Store) Watch(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Second
	}

	tick := time.NewTicker(every)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if _, err := s.Reload(); err != nil {
				s.log.Warn("reload failed, keeping current snapshot", "error", err.Error())
			}
		}
	}
}

func (s *Store) build(paths Paths) (*Snapshot, error) {
	fp, err := fingerprint(paths)
	if err != nil {
		return nil, err
	}

	lists, err := indexFiles(filepath.Join(paths.Policy, listsDir))
	if err != nil {
		return nil, fmt.Errorf("lists: %w", err)
	}

	asns, err := indexFiles(filepath.Join(paths.Policy, asnsDir))
	if err != nil {
		return nil, fmt.Errorf("asns: %w", err)
	}

	live, err := loadLive(filepath.Join(paths.Policy, liveFile))
	if err != nil {
		return nil, fmt.Errorf("live: %w", err)
	}

	specs, err := policy.LoadSets(filepath.Join(paths.Policy, setsFile))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	sets, skipped, err := compileSets(specs, lists, asns, live)
	if err != nil {
		return nil, err
	}

	raw, rawSkip, err := compileLists(lists, live)
	if err != nil {
		return nil, err
	}

	profiles, err := loadProfiles(filepath.Join(paths.Policy, profilesDir), sets, raw, live)
	if err != nil {
		return nil, fmt.Errorf("profiles: %w", err)
	}

	if _, ok := profiles[policy.DefaultName]; !ok {
		return nil, fmt.Errorf("profiles: %s is missing and is mandatory", policy.DefaultName)
	}

	geo, geoSkip, err := loadGeo(paths.Geo)
	if err != nil {
		return nil, fmt.Errorf("geo: %w", err)
	}

	return &Snapshot{
		Gen:         s.gen.Add(1),
		Sets:        sets,
		Profiles:    profiles,
		Lists:       raw,
		Geo:         geo,
		Live:        usedLive(sets, profiles, live),
		Fingerprint: fp,
		LoadedAt:    time.Now().UTC(),
		Skipped:     skipped + rawSkip + geoSkip,
	}, nil
}

func usedLive(
	sets map[string]*Set,
	profiles map[string]*Profile,
	declared map[string]string,
) map[string]string {
	out := map[string]string{}

	want := func(uuid string) {
		if uuid == "" {
			return
		}

		if _, ok := declared[uuid]; !ok {
			return
		}

		out[uuid] = declared[uuid]
	}

	for _, set := range sets {
		for _, uuid := range append(append([]string{}, set.Match.Live...), set.Exclude.Live...) {
			want(uuid)
		}
	}

	for _, profile := range profiles {
		for _, rule := range profile.Rules {
			want(rule.Dataset)

			if rule.Action == policy.ActionList {
				want(rule.List)
			}
		}

		for _, outcome := range profile.Outcomes {
			want(outcome.List)
		}
	}

	return out
}

func compileLists(
	lists map[string][]string,
	live map[string]string,
) (map[string]*List, int, error) {
	out := make(map[string]*List, len(lists)+len(live))
	skipped := 0

	for uuid, paths := range lists {
		ps, skip, err := readAll(paths)
		if err != nil {
			return nil, 0, fmt.Errorf("list %q: %w", uuid, err)
		}

		out[uuid] = &List{UUID: uuid, Table: netset.Build(ps)}
		skipped += skip
	}

	for uuid := range live {
		if _, dup := out[uuid]; dup {
			return nil, 0, fmt.Errorf("dataset %q arrived both as a body and as a live subject", uuid)
		}

		out[uuid] = &List{UUID: uuid, Live: true}
	}

	return out, skipped, nil
}

func compileSets(
	specs map[string]policy.Set,
	lists, asns map[string][]string,
	live map[string]string,
) (map[string]*Set, int, error) {
	out := make(map[string]*Set, len(specs))
	skipped := 0

	for name, spec := range specs {
		main, mainSkip, err := compileMatch(spec.Match, lists, asns, live)
		if err != nil {
			return nil, 0, fmt.Errorf("set %q: %w", name, err)
		}

		ex, exSkip, err := compileMatch(spec.Exclude, lists, asns, live)
		if err != nil {
			return nil, 0, fmt.Errorf("set %q exclude: %w", name, err)
		}

		out[name] = &Set{Name: name, Match: main, Inverse: spec.Inverse, Exclude: ex}
		skipped += mainSkip + exSkip
	}

	return out, skipped, nil
}

func compileMatch(
	spec policy.Match,
	lists, asns map[string][]string,
	live map[string]string,
) (Match, int, error) {
	var (
		all     []netip.Prefix
		sources []NamedTable
		skipped int
	)

	for _, name := range spec.Lists {
		paths, ok := lists[name]
		if !ok {
			return Match{}, 0, fmt.Errorf("list %q is missing", name)
		}

		ps, skip, err := readAll(paths)
		if err != nil {
			return Match{}, 0, err
		}

		all = append(all, ps...)
		sources = append(sources, NamedTable{
			Kind:  KindList,
			Name:  name,
			Table: netset.Build(ps),
			Count: len(ps),
		})
		skipped += skip
	}

	for _, asn := range spec.Asns {
		name := fmt.Sprintf("%d", asn)

		paths, ok := asns[name]
		if !ok {
			return Match{}, 0, fmt.Errorf("asn %s is missing", name)
		}

		ps, skip, err := readAll(paths)
		if err != nil {
			return Match{}, 0, err
		}

		all = append(all, ps...)
		sources = append(sources, NamedTable{
			Kind:  KindAsn,
			Name:  name,
			Table: netset.Build(ps),
			Count: len(ps),
		})
		skipped += skip
	}

	for _, uuid := range spec.Live {
		if _, ok := live[uuid]; !ok {
			return Match{}, 0, fmt.Errorf("live dataset %q is not declared in %s", uuid, liveFile)
		}
	}

	return Match{
		Table:     netset.Build(all),
		Sources:   sources,
		Countries: append([]string(nil), spec.Countries...),
		Live:      append([]string(nil), spec.Live...),
	}, skipped, nil
}

func loadProfiles(
	root string,
	sets map[string]*Set,
	raw map[string]*List,
	live map[string]string,
) (map[string]*Profile, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	out := map[string]*Profile{}

	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}

		if !strings.HasSuffix(e.Name(), profileSufix) {
			continue
		}

		name := strings.ToLower(strings.TrimSuffix(e.Name(), profileSufix))

		spec, err := policy.LoadProfile(filepath.Join(root, e.Name()), name)
		if err != nil {
			return nil, err
		}

		for i, rule := range spec.Rules {
			if policy.Terminal(rule.Action) {
				if _, ok := sets[rule.Set]; !ok {
					return nil, fmt.Errorf("profile %q rule %d: unknown set %q",
						name, i+1, rule.Set)
				}
			} else if _, ok := raw[rule.Dataset]; !ok {
				return nil, fmt.Errorf(
					"profile %q rule %d: dataset %q did not arrive with the generation",
					name, i+1, rule.Dataset)
			}

			if rule.Action == policy.ActionList {
				if _, ok := live[rule.List]; !ok {
					return nil, fmt.Errorf(
						"profile %q rule %d: dataset %q is not declared in %s",
						name, i+1, rule.List, liveFile)
				}
			}
		}

		for i, o := range spec.Outcomes {
			if o.List == "" {
				continue
			}

			if _, ok := live[o.List]; !ok {
				return nil, fmt.Errorf(
					"profile %q outcome %d: dataset %q is not declared in %s",
					name, i+1, o.List, liveFile)
			}
		}

		out[name] = &Profile{
			Name:    name,
			Rules:   spec.Rules,
			Default: spec.Default,

			DefaultCode: spec.DefaultCode,
			Outcomes:    spec.Outcomes,
		}
	}

	return out, nil
}

func loadLive(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}

		return nil, err
	}

	var f map[string]string

	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, err
	}

	out := make(map[string]string, len(f))

	for uuid, subject := range f {
		out[strings.ToLower(strings.TrimSpace(uuid))] = strings.TrimSpace(subject)
	}

	return out, nil
}

func readAll(paths []string) ([]netip.Prefix, int, error) {
	var (
		all     []netip.Prefix
		skipped int
	)

	for _, path := range paths {
		ps, n, err := netset.LoadFile(path)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", path, err)
		}

		all = append(all, ps...)
		skipped += n
	}

	return all, skipped, nil
}

func loadFileList(files []string) (*netset.Table, int, error) {
	ps, skip, err := readAll(files)
	if err != nil {
		return nil, 0, err
	}

	return netset.Build(ps), skip, nil
}

func indexFiles(root string) (map[string][]string, error) {
	paths, err := listFiles(root)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]string{}, nil
		}

		return nil, err
	}

	byName := map[string][]string{}

	for _, path := range paths {
		base := filepath.Base(path)
		name := strings.ToLower(strings.TrimSuffix(base, filepath.Ext(base)))
		byName[name] = append(byName[name], path)
	}

	return byName, nil
}

func loadGeo(root string) ([]NamedTable, int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, 0, err
	}

	var (
		out     []NamedTable
		skipped int
	)

	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}

		name := strings.ToLower(e.Name())
		files, err := listFiles(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", name, err)
		}

		tab, skip, err := loadFileList(files)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", name, err)
		}

		count := 0
		if tab != nil {
			count = tab.Len()
		}

		out = append(out, NamedTable{Kind: KindCountry, Name: name, Table: tab, Count: count})
		skipped += skip
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out, skipped, nil
}

func listFiles(root string) ([]string, error) {
	var out []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != root {
				return fs.SkipDir
			}

			return nil
		}

		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}

		out = append(out, path)

		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(out)

	return out, nil
}

func fingerprint(p Paths) (string, error) {
	h := sha256.New()

	var paths []string

	for _, root := range []string{p.Policy, p.Geo} {
		files, err := listFiles(root)
		if err != nil {
			return "", err
		}

		paths = append(paths, files...)
	}

	sort.Strings(paths)

	for _, path := range paths {
		fi, err := os.Stat(path)
		if err != nil {
			return "", err
		}

		fmt.Fprintf(h, "%s\t%d\t%d\n", filepath.ToSlash(path), fi.Size(), fi.ModTime().UnixNano())
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
