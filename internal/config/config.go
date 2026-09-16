package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/exemt/placitum-shared/loglevel"
)

type Config struct {
	Servers []string
	Subject string
	Name    string
	Queue   string

	PolicyDir string
	GeoDir    string
	DataDir   string
	BlobsURL  string
	BlobsFrom string

	ReloadEvery time.Duration

	Workers     int
	QueueDepth  int
	QueueFull   string
	QueueExpand string
	ConfPath    string
	ReserveMS   int
	MinBudgetMS int

	Versions []int
	LogLevel slog.Level

	HeartbeatEvery time.Duration

	GeoAddr    string
	GeoTimeout time.Duration
	GeoNegMax  int
}

func Load() (*Config, error) {
	c := &Config{
		Servers:   splitList(env("NATS_URL", "nats://127.0.0.1:4222")),
		Subject:   env("WAF_IP_SUBJECT", "waf.req.ip"),
		Name:      env("WAF_IP_NAME", "ip"),
		PolicyDir: env("WAF_IP_POLICY", "./policy"),
		GeoDir:    env("WAF_IP_GEO", "./data/geo"),
		DataDir:   env("WAF_IP_DATA", ""),
		GeoAddr:   env("WAF_IP_GEO_ADDR", ""),
	}

	c.Queue = env("WAF_IP_QUEUE", c.Name)

	var err error

	if c.Workers, err = envInt("WAF_IP_WORKERS", runtime.GOMAXPROCS(0)); err != nil {
		return nil, err
	}

	q := queueSettings{
		Max:    256,
		Full:   QueueFullDrop,
		Expand: QueueExpandOff,
	}

	var file queueFile

	c.ConfPath = confPath("WAF_IP_CONF")
	if c.ConfPath != "" {
		var ferr error
		if file, ferr = loadQueueFile(c.ConfPath); ferr != nil {
			return nil, ferr
		}

		applyQueueFile(&q, file)
	}

	if ferr := noExchangeRedis(c.ConfPath, file); ferr != nil {
		return nil, ferr
	}

	c.BlobsURL, c.BlobsFrom = internalRedis(c.ConfPath, file, "")

	if q.Max, err = envIntIfSet("WAF_IP_QUEUE_DEPTH", q.Max); err != nil {
		return nil, err
	}

	c.QueueDepth = q.Max
	c.QueueFull = envOverride("WAF_IP_QUEUE_FULL", q.Full)
	c.QueueExpand = envOverride("WAF_IP_QUEUE_EXPAND", q.Expand)

	if c.ReserveMS, err = envInt("WAF_IP_RESERVE_MS", 1); err != nil {
		return nil, err
	}

	if c.MinBudgetMS, err = envInt("WAF_IP_MIN_BUDGET_MS", 1); err != nil {
		return nil, err
	}

	if c.Versions, err = envIntList("WAF_IP_VERSIONS", []int{2}); err != nil {
		return nil, err
	}

	if c.LogLevel, err = parseLevel(env("WAF_IP_LOG", "info")); err != nil {
		return nil, err
	}

	if c.HeartbeatEvery, err = envDuration("WAF_HEARTBEAT_EVERY", 4*time.Second); err != nil {
		return nil, err
	}

	if c.ReloadEvery, err = envDuration("WAF_IP_RELOAD_EVERY", time.Second); err != nil {
		return nil, err
	}

	if c.GeoTimeout, err = envDuration("WAF_IP_GEO_TIMEOUT", 500*time.Millisecond); err != nil {
		return nil, err
	}

	if c.GeoNegMax, err = envInt("WAF_IP_GEO_NEG_MAX", 0); err != nil {
		return nil, err
	}

	return c, c.validate()
}

func (c *Config) validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("NATS_URL is empty")
	}

	if c.Subject == "" || c.Name == "" || c.Queue == "" {
		return fmt.Errorf("subject, name and queue must not be empty")
	}

	if c.Workers < 1 {
		return fmt.Errorf("WAF_IP_WORKERS must be positive, got %d", c.Workers)
	}

	if c.QueueDepth < 1 {
		return fmt.Errorf("queue_max must be positive, got %d", c.QueueDepth)
	}

	switch c.QueueFull {
	case QueueFullDrop, QueueFullWait:
	default:
		return fmt.Errorf("queue_full must be drop or wait, got %q", c.QueueFull)
	}

	switch c.QueueExpand {
	case QueueExpandOff, QueueExpandAsk:
	default:
		return fmt.Errorf("queue_expand must be off or ask, got %q", c.QueueExpand)
	}

	if c.ReserveMS < 0 || c.MinBudgetMS < 0 {
		return fmt.Errorf("WAF_IP_RESERVE_MS and WAF_IP_MIN_BUDGET_MS must not be negative")
	}

	if len(c.Versions) == 0 {
		return fmt.Errorf("WAF_IP_VERSIONS is empty")
	}

	for _, pair := range []struct {
		name, path string
		dir        bool
	}{
		{"WAF_IP_POLICY", c.PolicyDir, true},
		{"WAF_IP_GEO", c.GeoDir, true},
	} {
		abs, err := filepath.Abs(pair.path)
		if err != nil {
			return fmt.Errorf("%s: %w", pair.name, err)
		}

		st, err := os.Stat(abs)
		if err != nil {
			return fmt.Errorf("%s: %w", pair.name, err)
		}

		if pair.dir && !st.IsDir() {
			return fmt.Errorf("%s: %s is not a directory", pair.name, abs)
		}

		if !pair.dir && st.IsDir() {
			return fmt.Errorf("%s: %s is a directory", pair.name, abs)
		}

		switch pair.name {
		case "WAF_IP_POLICY":
			c.PolicyDir = abs
		case "WAF_IP_GEO":
			c.GeoDir = abs
		}
	}

	return nil
}

func (c *Config) Supports(v int) bool {
	for _, known := range c.Versions {
		if known == v {
			return true
		}
	}

	return false
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}

func envInt(name string, def int) (int, error) {
	return envIntIfSet(name, def)
}

func envIntIfSet(name string, def int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	return v, nil
}

func envIntList(name string, def []int) ([]int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	var out []int

	for _, part := range splitList(raw) {
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		out = append(out, v)
	}

	return out, nil
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return d, nil
}

func splitList(s string) []string {
	var out []string

	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}

	return out
}

func parseLevel(s string) (slog.Level, error) {
	level, err := loglevel.Parse(s)
	if err != nil {
		return 0, fmt.Errorf("WAF_IP_LOG: %w", err)
	}

	return level, nil
}
