package dyn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

const (
	Version = 3

	subjectPrefix   = "waf.sets."
	opResync        = "resync"
	opDiff          = "diff"
	opTick          = "tick"
	opSnapshot      = "snapshot"
	opAdd           = "add"
	requestTimeout  = 5 * time.Second
	objectTimeout   = 30 * time.Second
	resyncEvery     = 2 * time.Second
	silenceAfter    = 6 * time.Second
	queueDepth      = 1024
	packagesPerRead = 256
)

type Blobs interface {
	Object(ctx context.Context, key string) ([]byte, error)
	Objects(ctx context.Context, keys []string) ([][]byte, error)
}

type redisBlobs struct {
	client *redis.Client
}

func NewBlobs(client *redis.Client) Blobs {
	if client == nil {
		return nil
	}

	return &redisBlobs{client: client}
}

func (b *redisBlobs) Object(ctx context.Context, key string) ([]byte, error) {
	data, err := b.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}

	return data, err
}

func (b *redisBlobs) Objects(ctx context.Context, keys []string) ([][]byte, error) {
	vals, err := b.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	out := make([][]byte, len(vals))

	for i, v := range vals {
		if s, ok := v.(string); ok {
			out[i] = []byte(s)
		}
	}

	return out, nil
}

func diffKey(name string, seq uint64) string {
	return "waf:diff:" + name + ":" + strconv.FormatUint(seq, 10)
}

type frame struct {
	V       int    `json:"v"`
	Set     string `json:"set"`
	Epoch   string `json:"epoch"`
	Seq     uint64 `json:"seq"`
	Op      string `json:"op"`
	Hash    string `json:"hash"`
	Key     string `json:"key"`
	Package string `json:"package"`
	Object  string `json:"object"`
	Count   int    `json:"count"`
}

type composition struct {
	nets map[netip.Prefix]int64
	lens [2][129]int
	hash uint64
}

func newComposition() *composition {
	return &composition{nets: map[netip.Prefix]int64{}}
}

func family(p netip.Prefix) int {
	if p.Addr().Is4() {
		return 0
	}

	return 1
}

func (c *composition) apply(key Key, r packRecord) {
	p := r.prefix
	_, had := c.nets[p]

	switch {
	case r.op == recAdd:
		if !had {
			c.hash ^= SipHashBytes(key, prefixMaterial(p))
			c.lens[family(p)][p.Bits()]++
		}

		c.nets[p] = r.exp

	case had:
		c.hash ^= SipHashBytes(key, prefixMaterial(p))
		c.lens[family(p)][p.Bits()]--
		delete(c.nets, p)
	}
}

func (c *composition) contains(ip netip.Addr, now int64) bool {
	ip = ip.Unmap()
	fam := 0
	if !ip.Is4() {
		fam = 1
	}

	for bits := ip.BitLen(); bits >= 0; bits-- {
		if c.lens[fam][bits] == 0 {
			continue
		}

		if exp, ok := c.nets[netip.PrefixFrom(ip, bits).Masked()]; ok && (exp == 0 || exp > now) {
			return true
		}
	}

	return false
}

func (c *composition) size() (prefixes, addrs int) {
	for fam := 0; fam < 2; fam++ {
		full := 32
		if fam == 1 {
			full = 128
		}

		for bits, n := range c.lens[fam] {
			if bits == full {
				addrs += n
			} else {
				prefixes += n
			}
		}
	}

	return prefixes, addrs
}

type Set struct {
	UUID string
	Name string

	mu    sync.RWMutex
	ready bool
	epoch uint64
	seq   uint64
	key   Key
	comp  *composition

	lastSeen time.Time
	silent   bool

	in      chan frame
	stop    chan struct{}
	syncing bool
	refused string
	snapBad bool
}

func newSet(uuid, name string) *Set {
	return &Set{
		UUID:     uuid,
		Name:     name,
		comp:     newComposition(),
		lastSeen: time.Now(),
		in:       make(chan frame, queueDepth),
		stop:     make(chan struct{}),
	}
}

func (s *Set) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.ready
}

func (s *Set) Seq() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.seq
}

func (s *Set) Contains(ip netip.Addr) bool {
	if s == nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.ready {
		return false
	}

	return s.comp.contains(ip, time.Now().UnixMilli())
}

func (s *Set) Size() (base, live int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.comp.size()
}

type Store struct {
	nc    *nats.Conn
	blobs Blobs
	log   *slog.Logger
	from  string

	mu   sync.RWMutex
	sets map[string]*Set
	subs map[string]*nats.Subscription

	done chan struct{}
	once sync.Once
}

func New(nc *nats.Conn, blobs Blobs, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}

	host, _ := os.Hostname()

	s := &Store{
		nc:    nc,
		blobs: blobs,
		log:   log,
		from:  host,
		sets:  map[string]*Set{},
		subs:  map[string]*nats.Subscription{},
		done:  make(chan struct{}),
	}

	go s.resync()

	return s
}

func (s *Store) Contains(uuid string, ip netip.Addr) bool {
	if s == nil {
		return false
	}

	s.mu.RLock()
	set := s.sets[uuid]
	s.mu.RUnlock()

	return set.Contains(ip)
}

func (s *Store) Get(uuid string) *Set {
	if s == nil {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.sets[uuid]
}

func NameOf(uuid, name string) string {
	if name == "" {
		return uuid
	}

	return name
}

func (s *Store) Sync(want map[string]string) error {
	if s == nil || s.nc == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for uuid, name := range want {
		if _, ok := s.sets[uuid]; ok {
			continue
		}

		set := newSet(uuid, NameOf(uuid, name))
		s.sets[uuid] = set

		sub, err := s.nc.Subscribe(subjectPrefix+set.Name, func(m *nats.Msg) {
			var f frame
			if err := json.Unmarshal(m.Data, &f); err != nil {
				s.log.Warn("live dataset frame is not json", "set", set.Name)

				return
			}

			select {
			case set.in <- f:
			default:
			}
		})
		if err != nil {
			delete(s.sets, uuid)

			return fmt.Errorf("subscribe %s: %w", set.Name, err)
		}

		s.subs[uuid] = sub

		go s.run(set)

		s.log.Info("live dataset attached", "uuid", uuid, "set", set.Name)
	}

	for uuid, sub := range s.subs {
		if _, ok := want[uuid]; ok {
			continue
		}

		_ = sub.Unsubscribe()

		if set := s.sets[uuid]; set != nil {
			close(set.stop)
		}

		delete(s.subs, uuid)
		delete(s.sets, uuid)

		s.log.Info("live dataset detached", "uuid", uuid)
	}

	return nil
}

func (s *Store) Close() {
	if s == nil {
		return
	}

	s.once.Do(func() { close(s.done) })

	s.mu.Lock()
	defer s.mu.Unlock()

	for uuid, sub := range s.subs {
		_ = sub.Unsubscribe()
		delete(s.subs, uuid)
	}
}

func (s *Store) run(set *Set) {
	s.snapshot(set)

	for {
		select {
		case <-s.done:
			return
		case <-set.stop:
			return
		case f := <-set.in:
			s.onFrame(set, f)
		}
	}
}

func (s *Store) onFrame(set *Set, f frame) {
	if f.V != Version {
		s.log.Warn("unsupported dataset message version", "set", set.Name, "v", f.V)

		return
	}

	set.mu.Lock()
	ready, myEpoch, mySeq := set.ready, set.epoch, set.seq
	if f.Op != opResync {
		set.lastSeen = time.Now()
		set.silent = false
	}
	set.mu.Unlock()

	if !ready {
		s.snapshot(set)

		return
	}

	if f.Op == opResync {
		return
	}

	epoch, err := strconv.ParseUint(f.Epoch, 16, 64)
	if err != nil {
		return
	}

	if epoch != myEpoch {
		s.log.Info("live dataset new epoch", "set", set.Name, "epoch", f.Epoch)
		set.snapBad = false
		s.snapshot(set)

		return
	}

	switch {
	case f.Seq < mySeq:
	case f.Seq == mySeq:
		if f.Op == opTick || f.Op == opDiff {
			s.verify(set, f.Hash, f.Op)
		}
	default:
		s.catchUp(set, f.Seq, f.Hash)
	}
}

func (s *Store) catchUp(set *Set, upto uint64, hash string) {
	if s.blobs == nil {
		s.log.Error("packages cannot be read: no internal redis (internal in the redis block or REDIS_INTERNAL_URL)", "set", set.Name)

		return
	}

	for {
		set.mu.RLock()
		mySeq := set.seq
		set.mu.RUnlock()

		if mySeq >= upto {
			break
		}

		n := upto - mySeq
		if n > packagesPerRead {
			n = packagesPerRead
		}

		keys := make([]string, n)
		for i := range keys {
			keys[i] = diffKey(set.Name, mySeq+1+uint64(i))
		}

		ctx, cancel := context.WithTimeout(context.Background(), objectTimeout)
		objs, err := s.blobs.Objects(ctx, keys)
		cancel()

		if err != nil {
			s.log.Warn("packages unavailable", "set", set.Name, "from", mySeq+1, "error", err.Error())

			return
		}

		for i, data := range objs {
			if data == nil {
				s.log.Info("package gone, taking a snapshot", "set", set.Name, "seq", mySeq+1+uint64(i))
				s.snapshot(set)

				return
			}

			if !s.applyPackage(set, data, mySeq+1+uint64(i)) {
				return
			}
		}
	}

	s.verify(set, hash, "catch-up")
}

func (s *Store) applyPackage(set *Set, data []byte, want uint64) bool {
	head, recs, err := unpack(data)
	if err != nil {
		s.log.Warn("package is malformed", "set", set.Name, "seq", want, "error", err.Error())
		s.snapshot(set)

		return false
	}

	set.mu.Lock()

	if head.kind != kindPackage || head.epoch != set.epoch || head.seq != want || head.typ != typeCIDR {
		set.mu.Unlock()
		s.log.Warn("package does not match the set", "set", set.Name, "seq", want,
			"kind", head.kind, "type", head.typ, "epoch", hexOf(head.epoch), "got_seq", head.seq)
		s.snapshot(set)

		return false
	}

	for _, r := range recs {
		set.comp.apply(set.key, r)
	}

	set.seq = head.seq
	set.mu.Unlock()

	return s.verify(set, hexOf(head.hash), "package")
}

func (s *Store) verify(set *Set, want, where string) bool {
	set.mu.RLock()
	got, seq := set.comp.hash, set.seq
	set.mu.RUnlock()

	if want == "" || hexOf(got) == want {
		return true
	}

	if set.snapBad {
		s.log.Debug("still diverged after a bad snapshot", "set", set.Name, "at", where, "seq", seq)

		return false
	}

	s.log.Warn("live dataset diverged", "set", set.Name, "at", where, "seq", seq,
		"want", want, "got", hexOf(got))
	s.snapshot(set)

	return false
}

func (s *Store) snapshot(set *Set) {
	if set.syncing {
		return
	}

	set.syncing = true
	defer func() { set.syncing = false }()

	if set.snapBad {
		return
	}

	body, _ := json.Marshal(map[string]any{"from": s.from})

	msg, err := s.nc.Request(subjectPrefix+set.Name+".snapshot", body, requestTimeout)
	if err != nil {
		s.log.Warn("snapshot request failed", "set", set.Name, "error", err.Error())

		return
	}

	var ref frame
	if err := json.Unmarshal(msg.Data, &ref); err != nil || ref.Op != opSnapshot || ref.Object == "" {
		op := ref.Op
		if op == "" {
			op = "bad reply"
		}

		if set.refused == op {
			s.log.Debug("snapshot refused", "set", set.Name, "reply", op)
		} else {
			s.log.Warn("snapshot refused", "set", set.Name, "reply", op)
			set.refused = op
		}

		return
	}

	set.refused = ""

	if s.blobs == nil {
		s.log.Error("snapshot object cannot be read: no internal redis (internal in the redis block or REDIS_INTERNAL_URL)",
			"set", set.Name, "object", ref.Object)

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), objectTimeout)
	data, err := s.blobs.Object(ctx, ref.Object)
	cancel()

	if err != nil {
		s.log.Warn("snapshot object unavailable", "set", set.Name, "object", ref.Object, "error", err.Error())

		return
	}

	if data == nil {
		s.log.Warn("snapshot object already gone", "set", set.Name, "object", ref.Object)

		return
	}

	head, recs, err := unpack(data)
	if err != nil || head.kind != kindSnapshot {
		s.log.Warn("snapshot object is malformed", "set", set.Name, "object", ref.Object, "error", errText(err))

		return
	}

	if head.typ != typeCIDR {
		if set.refused != "not an address set" {
			s.log.Error("live dataset is not an address set", "set", set.Name, "type", head.typ)
			set.refused = "not an address set"
		}

		return
	}

	comp := newComposition()

	for _, r := range recs {
		comp.apply(head.key, r)
	}

	bad := comp.hash != head.hash

	set.mu.Lock()
	set.epoch, set.key, set.seq, set.comp = head.epoch, head.key, head.seq, comp
	set.ready = true
	set.snapBad = bad
	base, live := comp.size()
	set.mu.Unlock()

	if bad {
		s.log.Error("snapshot hash mismatch: mirror cannot reproduce keeper's set, "+
			"further divergence is logged, not resynced",
			"set", set.Name, "seq", head.seq, "want", hexOf(head.hash), "got", hexOf(comp.hash))
	}

	s.log.Info("live dataset snapshot", "set", set.Name, "seq", head.seq, "prefixes", base,
		"addrs", live, "bytes", len(data))
}

func (s *Store) resync() {
	tick := time.NewTicker(resyncEvery)
	defer tick.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
		}

		s.mu.RLock()
		sets := make([]*Set, 0, len(s.sets))
		for _, set := range s.sets {
			sets = append(sets, set)
		}
		s.mu.RUnlock()

		now := time.Now()

		for _, set := range sets {
			set.mu.Lock()
			ready := set.ready
			quiet := !set.silent && now.Sub(set.lastSeen) > silenceAfter
			if ready && quiet {
				set.silent = true
			}
			last := set.lastSeen
			set.mu.Unlock()

			if !ready {
				select {
				case set.in <- frame{V: Version, Op: opResync}:
				default:
				}

				continue
			}

			if quiet {
				s.log.Warn("keeper silent", "set", set.Name, "since", last.Format(time.RFC3339))
			}
		}
	}
}

func (s *Store) Publish(uuid, value string, ttl int, origin, reason, ray string) error {
	if s == nil || s.nc == nil {
		return nil
	}

	set := s.Get(uuid)
	if set == nil {
		return fmt.Errorf("unknown live dataset %q", uuid)
	}

	body, err := json.Marshal(struct {
		V      int    `json:"v"`
		Set    string `json:"set"`
		Op     string `json:"op"`
		Value  string `json:"value"`
		TTL    int    `json:"ttl,omitempty"`
		Origin string `json:"origin,omitempty"`
		Reason string `json:"reason,omitempty"`
		Ray    string `json:"ray,omitempty"`
	}{
		V: Version, Set: set.Name, Op: opAdd,
		Value: value, TTL: ttl, Origin: origin, Reason: reason, Ray: ray,
	})
	if err != nil {
		return err
	}

	go func() {
		msg, err := s.nc.Request(subjectPrefix+set.Name+".event", body, requestTimeout)
		if err != nil {
			s.log.Warn("live dataset write failed", "set", set.Name, "value", value, "error", err.Error())

			return
		}

		var reply struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}

		if json.Unmarshal(msg.Data, &reply) == nil && !reply.OK {
			s.log.Warn("live dataset write rejected", "set", set.Name, "value", value, "error", reply.Error)
		}
	}()

	return nil
}

type Stats struct {
	UUID  string `json:"uuid"`
	Seq   uint64 `json:"seq"`
	Base  int    `json:"base"`
	Live  int    `json:"live"`
	Ready bool   `json:"ready"`
}

func (s *Store) Stats() []Stats {
	if s == nil {
		return nil
	}

	s.mu.RLock()
	sets := make([]*Set, 0, len(s.sets))
	for _, set := range s.sets {
		sets = append(sets, set)
	}
	s.mu.RUnlock()

	out := make([]Stats, 0, len(sets))

	for _, set := range sets {
		base, live := set.Size()
		out = append(out, Stats{UUID: set.UUID, Seq: set.Seq(), Base: base, Live: live, Ready: set.Ready()})
	}

	return out
}

func hexOf(v uint64) string {
	return fmt.Sprintf("%016x", v)
}

func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
