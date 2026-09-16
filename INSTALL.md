# Installation

English · [Русский](INSTALL.ru.md)

The inspector does not listen on the network: it is a queue subscriber on the bus. It needs no
address and no service, and adding a copy touches neither the protection node nor the
configuration. Usually `placitum-core` installs it.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS | yes | the `waf.req.ip` queue, audit, log, profile generations, live set notices |
| Internal Redis | yes | generation list bodies, live set packs and snapshots |
| Controller | yes | sends profiles as generations |
| `keeper` | for live sets | keeps their content; the inspector mirrors it and sends `list` writes there |
| `geo` | for `net`, `net_all` and `asn` writes | announcements and AS number by address |

The inspector does not need the exchange: the address comes in the message.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | bus; several addresses are comma-separated |
| `REDIS_INTERNAL_URL` | from `inspector.conf` | internal Redis; there is no fallback to the exchange |
| `WAF_IP_SUBJECT` | `waf.req.ip` | subscription; must match `subject=` in the inspector declaration |
| `WAF_IP_NAME` | `ip` | name in the inspector registry and the presence frame |
| `WAF_IP_QUEUE` | the name | queue group on the bus |
| `WAF_IP_POLICY` | `./policy`; `/app/policy` in the image | policy tree used until the first generation |
| `WAF_IP_GEO` | `./data/geo`; `/app/data/geo` in the image | country ranges until the first generation; empty in the image, countries come with the generation |
| `WAF_IP_DATA` | empty; `/app/state` in the image | where rollout puts the applied generation; empty turns generations off |
| `WAF_IP_RELOAD_EVERY` | `1s` | how often to check the policy files; `SIGHUP` reloads at once |
| `WAF_IP_CONF` | `inspector.conf` in the working directory, then `/app/inspector.conf` | queue and Redis settings |
| `WAF_IP_WORKERS` | number of CPUs | check workers |
| `WAF_IP_QUEUE_DEPTH`, `WAF_IP_QUEUE_FULL`, `WAF_IP_QUEUE_EXPAND` | `256`, `drop`, `off` | queue and overflow behaviour; the same through `inspector.conf` |
| `WAF_IP_RESERVE_MS`, `WAF_IP_MIN_BUDGET_MS` | `1`, `1` | reserve for the answer and the minimum budget below which a check does not start |
| `WAF_IP_VERSIONS` | `2` | accepted message schema versions |
| `WAF_IP_GEO_ADDR` | empty | geo coder (`host:port`); empty makes `net`, `net_all` and `asn` writes answer `error` |
| `WAF_IP_GEO_TIMEOUT`, `WAF_IP_GEO_NEG_MAX` | `500ms`, `0` | coder wait within the message budget and negative cache limit (`0` means a million entries) |
| `WAF_IP_LOG` | `info` | starting log level; the panel changes it live |
| `WAF_HEARTBEAT_EVERY` | `4s` | presence frame interval |
| `WAF_LOG_SHIP` | `on` | whether the process log goes to the bus; `off` keeps it on stdout only |

## Docker Compose

```yaml
services:
  inspector-ip:
    image: placitum/ip
    scale: 4
    environment:
      NATS_URL: nats://nats:4222
      REDIS_INTERNAL_URL: redis://redis-internal:6379
      WAF_IP_SUBJECT: waf.req.ip
      WAF_IP_NAME: ip
      WAF_IP_GEO_ADDR: geo:50051
    depends_on: [nats, redis-internal]
```

Run as many copies as you need: the bus queue spreads messages between them, and the copies do not
coordinate.

## Checking

The inspector has no port of its own, so it is checked the way it works, with a bus message:

```sh
docker exec <container> ip-probe --quiet --timeout 1s
```

The image `HEALTHCHECK` does exactly this. A healthy start logs the bus connection, the queue name,
the loaded profiles and the worker count. After that a presence frame goes out every four seconds,
and it carries the live set state too.

## Pitfalls

- **An empty `WAF_IP_GEO_ADDR`** makes network and system writes answer `error` rather than pass
  silently: "could not check" and "checked, all clean" are different answers.
- **Live sets do not come with the generation.** The generation carries profiles, keeper keeps the
  content. A converged generation does not mean the content has arrived; the presence frame shows it.
- **A copy keeps no state.** After a restart it fetches live set snapshots again; until they warm up,
  list rules answer with what has already arrived.
- **The policy and geo directories must exist.** A typo in `WAF_IP_POLICY` or `WAF_IP_GEO` stops the
  start instead of surfacing on the first message.
