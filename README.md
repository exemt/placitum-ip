# Placitum ip

English · [Русский](README.ru.md)

Placitum address inspector. It decides by the client address: the address itself, its network, its
country and its autonomous system, plus live lists that change on the fly.

It is the cheapest inspector and usually goes first in the wave: it answers in a fraction of a
millisecond and cuts off what the expensive checks do not need to see. It reads neither headers nor
the body and works only in the request phase.

```
module ──► waf.req.ip ──►  ip  ──► allow | deny
                            │
                            ├── profile: rules over address sets
                            └── live sets: keeper mirror, updated over the bus
```

## Sets

A set is a named expression over raw data: address lists, live lists, countries and autonomous
systems, minus exclusions. It says who the address is and decides nothing.

```yaml
# sets.yaml
office:
  lists: [office]                # lists/office.txt
  exclude: { countries: [ru] }
datacenters:
  live: [7b1d0a44-…]             # a live set from live.yaml
  asns: [14061, 16509]
not-ru:
  countries: [ru]
  inverse: true                  # everything except the result
```

`exclude` takes the same four blocks and is subtracted from the union; `inverse` applies after the
subtraction. Sets do not nest. An empty set fails the load: it matches nothing, and its inverse
matches everything.

## Profiles

The profile comes from the route tag `route.profile`; an empty tag means `default`, and the process
does not start without a `default` profile.

```yaml
# profiles/default.yaml
rules:
  - set: office
    action: allow
  - set: datacenters
    action: deny
    response: blocked
  - dataset: tor
    action: request
    to: captcha
    do: challenge
    code: IP_GREYLIST
  - dataset: office
    not: true
    action: list
    list: suspects-uuid
    write: net
    ttl: 10m
default: allow
outcomes:
  - on: black
    list: banned-uuid
    write: asn
    ttl: 1h
    code: AUTO_BAN
```

The verdict takes three steps:

1. **Allow rows** are checked first, wherever they stand: a match gives `allow` at once. An exception
   must beat a block however the rows are ordered.
2. **Deny rows** go top to bottom, and the first match gives `deny`. `response` names the deny page
   record (`blocked` by default), `code` the reason.
3. **`default`** answers when nothing matched: `allow` (the default) or `deny`.

There is no score: the verdict is one of the two.

**Request and list rows** do not decide and work with either verdict, allow included: "this address
is ours, go easy on it" is a statement about the allow list. They check a raw list (`dataset`) rather
than a set, and `not: true` fires when the address is not in it.

- `request` puts a request for a neighbour into the answer: `to`, a `do` verb from the action channel,
  `apply`, `code`, `delta` or `value`. After `deny` the phase ends and later waves never see it; the
  record verbs `mark`, `audit` and `archive` are carried out by the module and always work.
- `list` writes into a live set from `live.yaml` for `ttl` (`300`, `5m`, `1h`, `1d`). `write` says what
  to write: the address (`addr`, the default), its effective announcement (`net`), every announcement
  over it, including wider ones of other systems (`net_all`), or the whole autonomous system (`asn`).

**Outcome rows** (`outcomes`) take the same actions and fire on where the address ended up: `white`
(an allow row matched), `black` (a deny row matched) or `none` (`default` answered). `overload` fires
on the inspector's own queue: with `at` (25–100) once the queue is `at` percent full, without it only
when the request is dropped.

When the inspector cannot check, it answers `error`, and the route decides with `waf_exception`:

| Code | Why |
| --- | --- |
| `IP_UNKNOWN_PROFILE` | the route names a profile that does not exist |
| `IP_MALFORMED` | the client address is empty or does not parse |
| `IP_MISSING_SET` | a set or list named by the profile has not arrived |
| `IP_GEO_UNAVAILABLE` | a `net`, `net_all` or `asn` write needs the geo coder, and it does not answer |

## Where the data comes from

| What | From | When it changes |
| --- | --- | --- |
| profiles, sets, static lists, countries, system prefixes | controller generation | with a new generation |
| live sets | keeper, `waf.sets.<name>` | at once, without a generation |

The image holds only what the installation does not let you delete in the panel: the `default`
profile with no rules and the empty `default_allowlist` and `default_blocklist` presets. A generation
replaces this tree as a whole:

```
lists/<name>.txt        static lists: one prefix or address per line, # starts a comment
asns/<number>.txt       autonomous system prefixes
geo/<code>/             country ranges
sets.yaml               sets
live.yaml               live sets: uuid: name
profiles/<name>.yaml    profiles
```

In a generation the file names are uuids; a hand-written tree with readable names is read by the same
code. A read error keeps the current snapshot, and a rule that names an unknown set fails the whole
load: half a policy is worse than the old one.

**Live sets** (lists marked active in the panel) never travel in a generation: it carries only their
uuid and name. keeper keeps the content and the inspector mirrors it: notices over `waf.sets.<name>`,
change packs and snapshots from the internal Redis, a hash check at every step. A ban set by a
neighbour works here within milliseconds. A set that has not warmed up is a miss, not a denial: a list
that has not arrived must not close a route. `list` writes go to keeper after the answer, so a failed
write does not cost the verdict.

## In the audit

Finding codes stay the same between versions, because exceptions are built on them: `ip-denylist`,
`ip-geo`, `ip-unknown-profile`, `ip-malformed-address`, `ip-missing-set`. The `engine` section of the
inspector event names the generation (`gen`), the rule position (`rule`), the set (`set`) and what
matched (`match`: `list`, `live`, `country`, `asn`, `inverse`). A deny also tells the client what was closed: the
address, network, country or system goes to the deny page.

The probe in the image sends a real message over the bus:

```sh
ip-probe --client-ip 203.0.113.10 --profile default --expect allow
```

What it needs and all settings are in [INSTALL.md](INSTALL.md).

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
