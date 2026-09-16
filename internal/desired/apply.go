package desired

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-ip/internal/store"
)

const (
	treeDir = "policy"

	blobTimeout = 15 * time.Second
)

func OpenBlobs(url string) (*redis.Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	opt.ReadTimeout = blobTimeout
	opt.WriteTimeout = blobTimeout
	opt.DialTimeout = blobTimeout

	return redis.NewClient(opt), nil
}

func FetchBlobs(ctx context.Context, rdb *redis.Client, p *Pack) (map[string][]byte, error) {
	hashes := p.Hashes()

	if len(hashes) == 0 {
		return map[string][]byte{}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, blobTimeout)
	defer cancel()

	keys := make([]string, len(hashes))
	for i, hash := range hashes {
		keys[i] = p.BlobKey(hash)
	}

	vals, err := rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}

	out := make(map[string][]byte, len(hashes))

	for i, raw := range vals {
		if raw == nil {
			return nil, fmt.Errorf("redis: missing %s", keys[i])
		}

		body, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("redis: %s: unexpected type %T", keys[i], raw)
		}

		buf := []byte(body)

		if hashOf(buf) != hashes[i] {
			return nil, fmt.Errorf("redis: %s hash mismatch", keys[i])
		}

		out[hashes[i]] = buf
	}

	return out, nil
}

func TreePath(dataDir string) string { return filepath.Join(dataDir, treeDir) }

func GeoPath(tree string) string { return filepath.Join(tree, "geo") }

func Apply(st *store.Store, dataDir string, p *Pack, blobs map[string][]byte) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}

	staging := filepath.Join(dataDir, ".next")
	prev := filepath.Join(dataDir, ".prev")
	live := TreePath(dataDir)

	_ = os.RemoveAll(staging)

	if err := write(staging, p, blobs); err != nil {
		_ = os.RemoveAll(staging)

		return err
	}

	_ = os.RemoveAll(prev)

	lived := true

	if err := os.Rename(live, prev); err != nil {
		if !os.IsNotExist(err) {
			_ = os.RemoveAll(staging)

			return fmt.Errorf("park live: %w", err)
		}

		lived = false
	}

	if err := os.Rename(staging, live); err != nil {
		if lived {
			_ = os.Rename(prev, live)
		}

		_ = os.RemoveAll(staging)

		return fmt.Errorf("promote staging: %w", err)
	}

	if err := st.ReloadFrom(live, GeoPath(live)); err != nil {
		_ = os.RemoveAll(live)

		if lived {
			if restore := os.Rename(prev, live); restore == nil {
				_ = st.ReloadFrom(live, GeoPath(live))
			}
		}

		return err
	}

	_ = os.RemoveAll(prev)

	return nil
}

func write(dir string, p *Pack, blobs map[string][]byte) error {
	for _, sub := range []string{"lists", "asns", "profiles", "geo"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			return err
		}
	}

	for id, hash := range p.Lists {
		if err := writeBlob(filepath.Join(dir, "lists", id+".txt"), hash, blobs); err != nil {
			return fmt.Errorf("list %s: %w", id, err)
		}
	}

	for asn, hash := range p.Asns {
		if err := writeBlob(filepath.Join(dir, "asns", asn+".txt"), hash, blobs); err != nil {
			return fmt.Errorf("asn %s: %w", asn, err)
		}
	}

	for code, hash := range p.Countries {
		sub := filepath.Join(dir, "geo", code)

		if err := os.MkdirAll(sub, 0o750); err != nil {
			return err
		}

		if err := writeBlob(filepath.Join(sub, "ranges.txt"), hash, blobs); err != nil {
			return fmt.Errorf("country %s: %w", code, err)
		}
	}

	sets, err := yaml.Marshal(p.Sets)
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, "sets.yaml"), sets, 0o640); err != nil {
		return err
	}

	live, err := yaml.Marshal(p.Live)
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, "live.yaml"), live, 0o640); err != nil {
		return err
	}

	for name, profile := range p.Profiles {
		body, err := yaml.Marshal(profile)
		if err != nil {
			return err
		}

		if err := os.WriteFile(filepath.Join(dir, "profiles", name+".yaml"), body, 0o640); err != nil {
			return err
		}
	}

	return nil
}

func writeBlob(path, hash string, blobs map[string][]byte) error {
	body, ok := blobs[hash]
	if !ok {
		return fmt.Errorf("blob %s is missing", hash)
	}

	return os.WriteFile(path, body, 0o640)
}
