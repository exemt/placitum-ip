package netset

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
)

type Interval struct {
	Start netip.Addr
	End   netip.Addr
}

type Table struct {
	v4 []Interval
	v6 []Interval
}

func (t *Table) Len() int {
	if t == nil {
		return 0
	}

	return len(t.v4) + len(t.v6)
}

func (t *Table) Contains(ip netip.Addr) bool {
	if t == nil {
		return false
	}

	ip = ip.Unmap()

	if ip.Is4() {
		return contains(t.v4, ip)
	}

	if ip.Is6() {
		return contains(t.v6, ip)
	}

	return false
}

func contains(s []Interval, ip netip.Addr) bool {
	_, ok := locate(s, ip)

	return ok
}

func (t *Table) Locate(ip netip.Addr) (Interval, bool) {
	if t == nil {
		return Interval{}, false
	}

	ip = ip.Unmap()

	if ip.Is4() {
		return locate(t.v4, ip)
	}

	if ip.Is6() {
		return locate(t.v6, ip)
	}

	return Interval{}, false
}

func locate(s []Interval, ip netip.Addr) (Interval, bool) {
	i := sort.Search(len(s), func(i int) bool {
		return s[i].Start.Compare(ip) > 0
	})

	if i == 0 {
		return Interval{}, false
	}

	if ip.Compare(s[i-1].End) > 0 {
		return Interval{}, false
	}

	return s[i-1], true
}

func (iv Interval) Prefix() (netip.Prefix, bool) {
	if !iv.Start.IsValid() || iv.Start.Is4() != iv.End.Is4() {
		return netip.Prefix{}, false
	}

	for bits := iv.Start.BitLen(); bits >= 0; bits-- {
		p := netip.PrefixFrom(iv.Start, bits)

		if p.Masked().Addr() != iv.Start {
			continue
		}

		if lastAddr(p) == iv.End {
			return p, true
		}
	}

	return netip.Prefix{}, false
}

func Build(prefixes []netip.Prefix) *Table {
	t := &Table{}

	for _, p := range prefixes {
		p = p.Masked()
		iv := Interval{Start: p.Addr().Unmap(), End: lastAddr(p)}

		if iv.Start.Is4() {
			t.v4 = append(t.v4, iv)
			continue
		}

		t.v6 = append(t.v6, iv)
	}

	t.v4 = merge(t.v4)
	t.v6 = merge(t.v6)

	return t
}

func merge(in []Interval) []Interval {
	if len(in) == 0 {
		return nil
	}

	sort.Slice(in, func(i, j int) bool {
		if c := in[i].Start.Compare(in[j].Start); c != 0 {
			return c < 0
		}

		return in[i].End.Compare(in[j].End) < 0
	})

	out := make([]Interval, 0, len(in))
	cur := in[0]

	for _, next := range in[1:] {
		if overlapsOrTouches(cur, next) {
			if next.End.Compare(cur.End) > 0 {
				cur.End = next.End
			}

			continue
		}

		out = append(out, cur)
		cur = next
	}

	return append(out, cur)
}

func overlapsOrTouches(a, b Interval) bool {
	if a.End.Compare(b.Start) >= 0 {
		return true
	}

	n, ok := nextAddr(a.End)

	return ok && n == b.Start
}

func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	addr := p.Addr().Unmap()
	bits := p.Bits()

	if addr.Is4() {
		n := uint32From4(addr.As4())
		if bits < 32 {
			n |= uint32(1)<<(32-uint(bits)) - 1
		}

		return netip.AddrFrom4(uint32To4(n))
	}

	hi, lo := uint128From16(addr.As16())
	host := 128 - bits

	switch {
	case host <= 0:
	case host < 64:
		lo |= uint64(1)<<uint(host) - 1
	case host == 64:
		lo = ^uint64(0)
	case host < 128:
		lo = ^uint64(0)
		hi |= uint64(1)<<uint(host-64) - 1
	default:
		hi, lo = ^uint64(0), ^uint64(0)
	}

	return netip.AddrFrom16(uint128To16(hi, lo))
}

func nextAddr(a netip.Addr) (netip.Addr, bool) {
	a = a.Unmap()

	if a.Is4() {
		n := uint32From4(a.As4())
		if n == ^uint32(0) {
			return netip.Addr{}, false
		}

		return netip.AddrFrom4(uint32To4(n + 1)), true
	}

	hi, lo := uint128From16(a.As16())
	if lo == ^uint64(0) {
		if hi == ^uint64(0) {
			return netip.Addr{}, false
		}

		return netip.AddrFrom16(uint128To16(hi+1, 0)), true
	}

	return netip.AddrFrom16(uint128To16(hi, lo+1)), true
}

func uint32From4(a [4]byte) uint32 {
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

func uint32To4(n uint32) [4]byte {
	return [4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func uint128From16(a [16]byte) (hi, lo uint64) {
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(a[i])
		lo = lo<<8 | uint64(a[i+8])
	}

	return hi, lo
}

func uint128To16(hi, lo uint64) [16]byte {
	var out [16]byte

	for i := 7; i >= 0; i-- {
		out[i] = byte(hi)
		hi >>= 8
		out[i+8] = byte(lo)
		lo >>= 8
	}

	return out
}

var errSkip = fmt.Errorf("skip")

func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return netip.Prefix{}, errSkip
	}

	if i := strings.Index(s, "#"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}

	fields := strings.Fields(s)
	if len(fields) == 0 {
		return netip.Prefix{}, errSkip
	}

	tok := fields[0]

	if p, err := netip.ParsePrefix(tok); err == nil {
		return p.Masked(), nil
	}

	if a, err := netip.ParseAddr(tok); err == nil {
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}

	return netip.Prefix{}, fmt.Errorf("not an ip or cidr: %q", tok)
}

func IsSkip(err error) bool {
	return err == errSkip
}

func ReadPrefixes(r io.Reader) (prefixes []netip.Prefix, skipped int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNo := 0

	for sc.Scan() {
		lineNo++

		p, perr := ParsePrefix(sc.Text())
		if perr == nil {
			prefixes = append(prefixes, p)
			continue
		}

		if IsSkip(perr) {
			continue
		}

		skipped++
	}

	if err := sc.Err(); err != nil {
		return prefixes, skipped, err
	}

	return prefixes, skipped, nil
}

func LoadFile(path string) ([]netip.Prefix, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}

	defer f.Close()

	return ReadPrefixes(f)
}
