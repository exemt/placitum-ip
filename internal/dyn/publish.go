package dyn

import (
	"encoding/json"
	"fmt"
)

func (s *Store) PublishMany(uuid string, values []string, ttl int, origin, reason, ray string) error {
	if s == nil || s.nc == nil {
		return nil
	}

	switch len(values) {
	case 0:
		return nil

	case 1:
		return s.Publish(uuid, values[0], ttl, origin, reason, ray)
	}

	set := s.Get(uuid)
	if set == nil {
		return fmt.Errorf("unknown live dataset %q", uuid)
	}

	body, err := json.Marshal(struct {
		V      int      `json:"v"`
		Set    string   `json:"set"`
		Op     string   `json:"op"`
		Values []string `json:"values"`
		TTL    int      `json:"ttl,omitempty"`
		Origin string   `json:"origin,omitempty"`
		Reason string   `json:"reason,omitempty"`
		Ray    string   `json:"ray,omitempty"`
	}{
		V: Version, Set: set.Name, Op: opAdd,
		Values: values, TTL: ttl, Origin: origin, Reason: reason, Ray: ray,
	})
	if err != nil {
		return err
	}

	go func() {
		msg, err := s.nc.Request(subjectPrefix+set.Name+".event", body, requestTimeout)
		if err != nil {
			s.log.Warn("live dataset write failed", "set", set.Name, "first", values[0],
				"count", len(values), "error", err.Error())

			return
		}

		var reply struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}

		if json.Unmarshal(msg.Data, &reply) == nil && !reply.OK {
			s.log.Warn("live dataset write rejected", "set", set.Name, "first", values[0],
				"count", len(values), "error", reply.Error)
		}
	}()

	return nil
}
