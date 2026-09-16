package main

import (
	"context"
	"log/slog"

	"github.com/exemt/placitum-ip/internal/decide"
	"github.com/exemt/placitum-shared/netinfo"
)

type geoWriter interface {
	Write(ctx context.Context, write, addr string) ([]string, error)
}

type listWriter interface {
	PublishMany(uuid string, values []string, ttl int, origin, reason, ray string) error
}

func writeLists(ctx context.Context, geo geoWriter, lists listWriter, log *slog.Logger,
	rid, node, ray string, bans []decide.Ban) error {

	var failed error

	for _, ban := range bans {
		values := []string{ban.Value}

		if netinfo.Networked(ban.Write) {
			got, err := geo.Write(ctx, ban.Write, ban.Value)
			if err != nil {
				if failed == nil {
					failed = err
				}

				continue
			}

			if len(got) == 0 {
				log.Warn("list write skipped: coder knows nothing about the address",
					"rid", rid, "dataset", ban.Dataset, "write", ban.Write, "addr", ban.Value)

				continue
			}

			values = got
		}

		if err := lists.PublishMany(ban.Dataset, values, ban.TTL, node, ban.Reason, ray); err != nil {
			log.Warn("list publish failed", "rid", rid, "dataset", ban.Dataset, "error", err.Error())
		}
	}

	return failed
}
