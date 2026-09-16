package desired

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"

	"github.com/exemt/placitum-ip/internal/dyn"
	"github.com/exemt/placitum-ip/internal/store"
)

const fetchRetry = 30 * time.Second

type Applied struct {
	mu    sync.RWMutex
	hash  string
	rev   int
	apply string
	names []string
}

func (a *Applied) Snapshot() (hash string, rev int, apply string, names []string) {
	if a == nil {
		return "", 0, "", nil
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.hash, a.rev, a.apply, append([]string(nil), a.names...)
}

func (a *Applied) set(hash string, rev int, apply string, names []string) {
	a.mu.Lock()
	a.hash = hash
	a.rev = rev
	a.apply = apply
	a.names = append([]string(nil), names...)
	a.mu.Unlock()
}

func Watch(
	ctx context.Context,
	nc *nats.Conn,
	rdb *redis.Client,
	st *store.Store,
	live *dyn.Store,
	dataDir string,
	level *slog.LevelVar,
	log *slog.Logger,
) (*Applied, error) {
	applied := &Applied{}

	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}

	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  Bucket,
		History: 5,
	})
	if err != nil {
		return nil, err
	}

	watcher, err := kv.Watch(ctx, PackKey)
	if err != nil {
		return nil, err
	}

	go func() {
		defer watcher.Stop()

		var (
			pending []byte
			retry   <-chan time.Time
		)

		for {
			select {
			case <-ctx.Done():
				return

			case <-retry:
				retry = nil

				if pending == nil {
					continue
				}

				if handle(ctx, pending, rdb, st, live, dataDir, applied, level, log) {
					retry = time.After(fetchRetry)
				} else {
					pending = nil
				}

			case entry, ok := <-watcher.Updates():
				if !ok {
					return
				}

				if entry == nil {
					continue
				}

				switch entry.Operation() {
				case jetstream.KeyValueDelete, jetstream.KeyValuePurge:
					continue
				}

				pending, retry = nil, nil
				raw := entry.Value()

				if handle(ctx, raw, rdb, st, live, dataDir, applied, level, log) {
					pending = raw
					retry = time.After(fetchRetry)
				}
			}
		}
	}()

	return applied, nil
}

func handle(
	ctx context.Context,
	raw []byte,
	rdb *redis.Client,
	st *store.Store,
	live *dyn.Store,
	dataDir string,
	applied *Applied,
	level *slog.LevelVar,
	log *slog.Logger,
) (retry bool) {
	p, err := ParsePack(raw)
	if err != nil {
		log.Warn("desired rejected", "error", err.Error())

		return
	}

	hash, rev, apply, names := applied.Snapshot()

	if apply == ApplyOK && hash == p.SHA256 && rev == p.Rev {
		return
	}

	if rdb == nil {
		log.Warn("desired skipped: no blob store configured", "rev", p.Rev)
		applied.set(hash, rev, ApplyFailed, names)

		return
	}

	blobs, err := FetchBlobs(ctx, rdb, p)
	if err != nil {
		log.Error("desired blobs failed",
			"rev", p.Rev, "retry_in", fetchRetry.String(), "error", err.Error())
		applied.set(hash, rev, ApplyFailed, names)

		return true
	}

	if err := Apply(st, dataDir, p, blobs); err != nil {
		log.Error("desired apply failed",
			"rev", p.Rev, "hash", p.SHA256, "error", err.Error())
		applied.set(hash, rev, ApplyFailed, names)

		return
	}

	if err := live.Sync(p.Live); err != nil {
		log.Warn("live datasets sync failed", "rev", p.Rev, "error", err.Error())
	}

	applied.set(p.SHA256, p.Rev, ApplyOK, p.Names())

	p.Settings.apply(level, log)

	log.Info("desired applied",
		"rev", p.Rev,
		"hash", p.SHA256,
		"profiles", p.Names(),
		"live", len(p.Live),
	)

	return false
}

func Bootstrap(st *store.Store, live *dyn.Store, dataDir string, log *slog.Logger) bool {
	if dataDir == "" {
		return false
	}

	tree := TreePath(dataDir)

	if err := st.ReloadFrom(tree, GeoPath(tree)); err != nil {
		if !isMissing(err) {
			log.Warn("applied generation is unusable, falling back to bootstrap policy",
				"dir", tree, "error", err.Error())
		}

		return false
	}

	if snap := st.Current(); snap != nil {
		if err := live.Sync(snap.Live); err != nil {
			log.Warn("live datasets sync failed", "error", err.Error())
		}
	}

	log.Info("applied generation restored", "dir", tree)

	return true
}

func isMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
