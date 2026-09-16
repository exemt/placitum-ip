package desired

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/exemt/placitum-ip/internal/protocol"
)

const (
	Bucket     = "WAF_DESIRED"
	PackKey    = "policy/ip-pack"
	BlobPrefix = "waf.blob."

	DefaultProfile = "default"

	ApplyOK     = "ok"
	ApplyFailed = "apply_failed"
)

type Match struct {
	Lists     []string `json:"lists,omitempty"     yaml:"lists,omitempty"`
	Live      []string `json:"live,omitempty"      yaml:"live,omitempty"`
	Countries []string `json:"countries,omitempty" yaml:"countries,omitempty"`
	Asns      []uint32 `json:"asns,omitempty"      yaml:"asns,omitempty"`
}

type Set struct {
	Lists     []string `json:"lists,omitempty"     yaml:"lists,omitempty"`
	Live      []string `json:"live,omitempty"      yaml:"live,omitempty"`
	Countries []string `json:"countries,omitempty" yaml:"countries,omitempty"`
	Asns      []uint32 `json:"asns,omitempty"      yaml:"asns,omitempty"`
	Inverse   bool     `json:"inverse,omitempty"   yaml:"inverse,omitempty"`
	Exclude   *Match   `json:"exclude,omitempty"   yaml:"exclude,omitempty"`
}

type Rule struct {
	Set      string               `json:"set,omitempty"      yaml:"set,omitempty"`
	Dataset  string               `json:"dataset,omitempty"  yaml:"dataset,omitempty"`
	Not      bool                 `json:"not,omitempty"      yaml:"not,omitempty"`
	Action   string               `json:"action"             yaml:"action"`
	Response string               `json:"response,omitempty" yaml:"response,omitempty"`
	Code     string               `json:"code,omitempty"     yaml:"code,omitempty"`
	To       string               `json:"to,omitempty"       yaml:"to,omitempty"`
	Do       string               `json:"do,omitempty"       yaml:"do,omitempty"`
	Apply    string               `json:"apply,omitempty" yaml:"apply,omitempty"`
	Delta    *int                 `json:"delta,omitempty"    yaml:"delta,omitempty"`
	Value    *int                 `json:"value,omitempty"    yaml:"value,omitempty"`
	Counter  string               `json:"counter,omitempty"  yaml:"counter,omitempty"`
	Marker   string               `json:"marker,omitempty"   yaml:"marker,omitempty"`
	Side     string               `json:"side,omitempty"    yaml:"side,omitempty"`
	Headers  *protocol.ObjectSpec `json:"headers,omitempty" yaml:"headers,omitempty"`
	Args     *protocol.ObjectSpec `json:"args,omitempty"    yaml:"args,omitempty"`
	Body     *protocol.ObjectSpec `json:"body,omitempty"    yaml:"body,omitempty"`
	When     []string             `json:"when,omitempty"    yaml:"when,omitempty"`
	List     string               `json:"list,omitempty"    yaml:"list,omitempty"`
	Write    string               `json:"write,omitempty"   yaml:"write,omitempty"`
	TTL      string               `json:"ttl,omitempty"     yaml:"ttl,omitempty"`
}

type Outcome struct {
	On      string               `json:"on"              yaml:"on"`
	At      *int                 `json:"at,omitempty"    yaml:"at,omitempty"`
	To      string               `json:"to,omitempty"    yaml:"to,omitempty"`
	Do      string               `json:"do,omitempty"    yaml:"do,omitempty"`
	Apply   string               `json:"apply,omitempty" yaml:"apply,omitempty"`
	Delta   *int                 `json:"delta,omitempty" yaml:"delta,omitempty"`
	Value   *int                 `json:"value,omitempty" yaml:"value,omitempty"`
	Counter string               `json:"counter,omitempty" yaml:"counter,omitempty"`
	Marker  string               `json:"marker,omitempty"  yaml:"marker,omitempty"`
	Set     string               `json:"set,omitempty"     yaml:"set,omitempty"`
	Headers *protocol.ObjectSpec `json:"headers,omitempty" yaml:"headers,omitempty"`
	Args    *protocol.ObjectSpec `json:"args,omitempty"    yaml:"args,omitempty"`
	Body    *protocol.ObjectSpec `json:"body,omitempty"    yaml:"body,omitempty"`
	When    []string             `json:"when,omitempty"    yaml:"when,omitempty"`
	List    string               `json:"list,omitempty"    yaml:"list,omitempty"`
	Write   string               `json:"write,omitempty"   yaml:"write,omitempty"`
	TTL     string               `json:"ttl,omitempty"     yaml:"ttl,omitempty"`
	Code    string               `json:"code,omitempty"    yaml:"code,omitempty"`
}

type Profile struct {
	Rules    []Rule    `json:"rules"                  yaml:"rules"`
	Default  string    `json:"default,omitempty"      yaml:"default,omitempty"`
	Code     string    `json:"default_code,omitempty" yaml:"default_code,omitempty"`
	Outcomes []Outcome `json:"outcomes,omitempty" yaml:"outcomes,omitempty"`
}

type Pack struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"`
	Rev    int    `json:"rev"`
	SHA256 string `json:"sha256"`
	Prefix string `json:"prefix"`

	Lists     map[string]string `json:"lists"`
	Countries map[string]string `json:"countries"`
	Asns      map[string]string `json:"asns"`

	Live map[string]string `json:"live"`

	Sets     map[string]Set     `json:"sets"`
	Profiles map[string]Profile `json:"profiles"`

	Blobs int `json:"blobs"`
	Bytes int `json:"bytes"`

	Settings *Settings `json:"settings,omitempty"`
}

func ParsePack(raw []byte) (*Pack, error) {
	var p Pack

	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	if p.V != 1 || p.Kind != "ip-pack" {
		return nil, fmt.Errorf("pack: unsupported v/kind")
	}

	if p.Rev < 1 {
		return nil, fmt.Errorf("pack: rev must be positive")
	}

	if p.SHA256 == "" || !strings.HasPrefix(p.SHA256, "sha256:") {
		return nil, fmt.Errorf("pack: sha256 is missing")
	}

	if p.Prefix == "" {
		p.Prefix = BlobPrefix
	}

	empty(&p.Lists)
	empty(&p.Countries)
	empty(&p.Asns)
	empty(&p.Live)

	if p.Sets == nil {
		p.Sets = map[string]Set{}
	}

	if _, ok := p.Profiles[DefaultProfile]; !ok {
		return nil, fmt.Errorf("pack: profile %q is missing", DefaultProfile)
	}

	for name := range p.Profiles {
		if err := safeName(name); err != nil {
			return nil, fmt.Errorf("pack: profile %q: %w", name, err)
		}
	}

	for name := range p.Sets {
		if err := safeName(name); err != nil {
			return nil, fmt.Errorf("pack: set %q: %w", name, err)
		}
	}

	for _, group := range []map[string]string{p.Lists, p.Countries, p.Asns, p.Live} {
		for name := range group {
			if err := safeName(name); err != nil {
				return nil, fmt.Errorf("pack: %q: %w", name, err)
			}
		}
	}

	if err := p.check(); err != nil {
		return nil, err
	}

	if err := p.Settings.validate(); err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	if got := Hash(&p); got != p.SHA256 {
		return nil, fmt.Errorf("pack: sha256 mismatch: got %s want %s", got, p.SHA256)
	}

	return &p, nil
}

func (p *Pack) check() error {
	for name, set := range p.Sets {
		matches := []Match{
			{Lists: set.Lists, Live: set.Live, Countries: set.Countries, Asns: set.Asns},
		}

		if set.Exclude != nil {
			matches = append(matches, *set.Exclude)
		}

		for _, m := range matches {
			for _, id := range m.Lists {
				if _, ok := p.Lists[id]; !ok {
					return fmt.Errorf("pack: set %q references unknown list %s", name, id)
				}
			}

			for _, id := range m.Live {
				if _, ok := p.Live[id]; !ok {
					return fmt.Errorf("pack: set %q references unknown live dataset %s", name, id)
				}
			}

			for _, cc := range m.Countries {
				if _, ok := p.Countries[cc]; !ok {
					return fmt.Errorf("pack: set %q references unknown country %s", name, cc)
				}
			}

			for _, asn := range m.Asns {
				if _, ok := p.Asns[fmt.Sprintf("%d", asn)]; !ok {
					return fmt.Errorf("pack: set %q references unknown asn %d", name, asn)
				}
			}
		}
	}

	for name, profile := range p.Profiles {
		for i, rule := range profile.Rules {
			if rule.Action == "allow" || rule.Action == "deny" {
				if _, ok := p.Sets[rule.Set]; !ok {
					return fmt.Errorf("pack: profile %q rule %d references unknown set %q",
						name, i+1, rule.Set)
				}
			} else {
				_, body := p.Lists[rule.Dataset]
				_, subject := p.Live[rule.Dataset]

				if !body && !subject {
					return fmt.Errorf(
						"pack: profile %q rule %d references dataset %q that is not in the pack",
						name, i+1, rule.Dataset)
				}
			}

			if rule.Action != "list" {
				continue
			}

			if _, ok := p.Live[rule.List]; !ok {
				return fmt.Errorf("pack: profile %q rule %d writes to a dataset that is not live",
					name, i+1)
			}
		}

		for i, o := range profile.Outcomes {
			if o.List == "" {
				continue
			}

			if _, ok := p.Live[o.List]; !ok {
				return fmt.Errorf("pack: profile %q outcome %d writes to a dataset that is not live",
					name, i+1)
			}
		}
	}

	return nil
}

func (p *Pack) BlobKey(hash string) string {
	return p.Prefix + strings.TrimPrefix(hash, "sha256:")
}

func (p *Pack) Names() []string {
	out := make([]string, 0, len(p.Profiles))

	for name := range p.Profiles {
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}

func (p *Pack) Hashes() []string {
	seen := map[string]struct{}{}
	out := []string{}

	for _, group := range []map[string]string{p.Lists, p.Countries, p.Asns} {
		for _, hash := range group {
			if _, ok := seen[hash]; ok {
				continue
			}

			seen[hash] = struct{}{}
			out = append(out, hash)
		}
	}

	sort.Strings(out)

	return out
}

func Hash(p *Pack) string {
	sum := sha256.New()

	writeMap := func(label string, m map[string]string) {
		_, _ = sum.Write([]byte(label))
		_, _ = sum.Write([]byte{0})

		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		for _, k := range keys {
			_, _ = sum.Write([]byte(k))
			_, _ = sum.Write([]byte{0})
			_, _ = sum.Write([]byte(m[k]))
			_, _ = sum.Write([]byte{0})
		}
	}

	writeMap("lists", p.Lists)
	writeMap("countries", p.Countries)
	writeMap("asns", p.Asns)
	writeMap("live", p.Live)

	setNames := make([]string, 0, len(p.Sets))
	for name := range p.Sets {
		setNames = append(setNames, name)
	}

	sort.Strings(setNames)

	_, _ = sum.Write([]byte("sets"))
	_, _ = sum.Write([]byte{0})

	for _, name := range setNames {
		body, _ := json.Marshal(p.Sets[name])

		_, _ = sum.Write([]byte(name))
		_, _ = sum.Write([]byte{0})
		_, _ = sum.Write(body)
		_, _ = sum.Write([]byte{0})
	}

	_, _ = sum.Write([]byte("profiles"))
	_, _ = sum.Write([]byte{0})

	for _, name := range p.Names() {
		body, _ := json.Marshal(p.Profiles[name])

		_, _ = sum.Write([]byte(name))
		_, _ = sum.Write([]byte{0})
		_, _ = sum.Write(body)
		_, _ = sum.Write([]byte{0})
	}

	writeSettings(sum, p.Settings)

	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

func hashOf(body []byte) string {
	sum := sha256.Sum256(body)

	return "sha256:" + hex.EncodeToString(sum[:])
}

func safeName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("bad name")
	}

	return nil
}

func empty(m *map[string]string) {
	if *m == nil {
		*m = map[string]string{}
	}
}
