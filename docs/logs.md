# Logs: reviewing and forwarding the audit log

Everything that happens in SDL is an audit event: every API call and who
made it, every rollover step on every system, every inventory change, modules
failing to start, inventories and log destinations going down and coming
back. [architecture.md](architecture.md#audit) lists what is recorded. Events
are stored by the audit module (`audit.jsonl`, hash-chained) and copied to any
number of forwarder modules.

Reading the log needs the `audit:read` permission (roles `admin` and
`auditor`). Reading it is itself recorded, with the filters used.

## Reviewing the log

Every filter is optional, every filter given must match, and repeating one
matches any of its values.

| Filter        | Matches                                                                 |
|---------------|-------------------------------------------------------------------------|
| system        | Events about that system (resource), e.g. `web1`                        |
| action type   | `rollover` matches `rollover` and everything under it (`rollover.target.change`); `*` is a wildcard (`*.change`) |
| outcome       | `success`, `failure`, `denied`, `started`, `info`                       |
| user          | Events by that user, service or component, **and** those done on their behalf (the rollover steps SDL runs for the user who asked) |
| module        | A module instance, e.g. `linux`, `netbox`, `graylog`                    |
| from / to     | A time range; from is inclusive, to is exclusive                        |
| run           | One rollover run                                                        |
| search        | Words in the action or message                                          |

The most recent matching events are returned (200 by default); narrow the
date range to look further back.

### Web page

The **Log** section of the page at `/ui/` has these filters as drop-downs
filled from the values present in the log, a **Log** button on every system
to see its history, the integrity check, and the state of each forwarder.

### CLI

`sdl logs` (also `sdl audit`):

```bash
sdl logs --system web1 --since 7d                    # all that happened to web1 this week
sdl logs -t web1 -t web2 --action rollover.target --outcome failure
sdl logs --user alice --since 2026-10-01 --until 2026-10-31   # until a date includes that day
sdl logs --action api --outcome denied --since today
sdl logs --module netbox --action inventory -v       # -v prints each event's details
sdl logs --search "pre-flight" --json
sdl logs --facets                                    # systems, users, actions to filter by
sdl logs --verify                                    # check the hash chain
sdl forwarders                                       # forwarding status
```

Times accept `2026-10-01`, `2026-10-01T14:00`, `2026-10-01T14:00+02:00`,
`30m`, `24h`, `7d`, `2w`, `today` and `yesterday`; without a zone they are
local time.

### API

```
GET /api/v1/audit?target=web1&action=rollover&actor=bob&outcome=failure
                 &since=2026-10-01T00:00:00Z&until=2026-11-01T00:00:00Z
                 &module=linux&run_id=...&q=words&limit=500&order=newest
GET /api/v1/audit/facets     # distinct systems, modules, actions, actors with counts
GET /api/v1/audit/verify     # hash chain check
GET /api/v1/forwarders       # per forwarder: ok, sent, queued, dropped, last error
```

## Forwarding

Forwarders are modules of kind `forwarder`. Any number can be configured;
each receives a copy of every event, after it has been stored locally. The
copy is exactly the stored event, including `hash` and `prev_hash`, so the
chain can be checked on the receiving side too.

**Forwarding never gets in the way of the local log.** Events are handed to
each forwarder through an in-memory queue and delivered by a background task,
in batches. When a destination is unreachable, SDL keeps retrying with
back-off (up to `retry_max_delay`), records `forwarder.unavailable` once,
and `forwarder.available` when delivery resumes. Up to `queue_size` events
wait meanwhile; beyond that the oldest are dropped from the queue (they are
still in the local log) and counted in `sdl forwarders`. On shutdown a
reachable destination gets `flush_timeout` seconds to take what is queued.
Events still queued when SDL stops are not re-sent later.

Settings every forwarder has:

| Setting           | Default  | Meaning                                                  |
|-------------------|----------|----------------------------------------------------------|
| `actions`         | all      | Only forward these action types (same matching as the filters) |
| `exclude_actions` | none     | Never forward these, e.g. `[api.request]` to skip read-only calls |
| `queue_size`      | 10000    | Events held while the destination is down                |
| `batch_size`      | 100      | Events per delivery                                      |
| `retry_max_delay` | 60       | Longest wait between attempts, in seconds                |
| `flush_timeout`   | 5        | Seconds to keep delivering on shutdown                   |

### Syslog: `forwarder.syslog`

RFC 5424 messages over UDP (RFC 5426), TCP (RFC 6587) or TLS (RFC 5425).

```yaml
syslog:
  type: forwarder.syslog
  config:
    host: logs.example.com
    protocol: tls              # udp, tcp (default) or tls
    port: 6514                 # default 514, or 6514 for tls
    ca_cert: /etc/sdl/logs-ca.pem
    client_cert: /etc/sdl/sdl.pem   # optional, mutual TLS
    client_key: /etc/sdl/sdl.key
    facility: authpriv         # default
    framing: octet-counting    # or newline, for TCP and TLS
    body: json                 # or text: a one-line summary
```

A message looks like this (wrapped here):

```
<85>1 2026-10-03T12:00:00.123456Z sdl-1 sdl 4242 rollover.target
  [sdl@32473 event_id="..." action="rollover.target" outcome="success" actor="orchestrator"
   actor_type="system" initiated_by="bob" target="web1" module="linux" run_id="..." hash="..."]
  {"id": "...", "ts": "...", "actor": {...}, "action": "rollover.target", ...}
```

The severity follows the outcome: `failure` is err, `denied` warning,
`success` notice, `started` and `info` informational. MSGID is the action.
`32473` is the example enterprise number reserved for documentation; set
`sd_id` to `sdl@<your IANA enterprise number>` if you have one. Over UDP a
message larger than `max_udp_size` (8192) carries the one-line summary
instead of the JSON, and UDP gives no delivery guarantee: prefer TCP or TLS.

### Graylog: `forwarder.gelf`

GELF 1.1 to a Graylog input (or anything else that reads GELF).

```yaml
graylog:
  type: forwarder.gelf
  config:
    transport: http            # http (default), tcp, tls or udp
    url: https://graylog.example.com:12201/gelf   # for http
    # host: graylog.example.com  # for tcp, tls, udp
    # port: 12201
    ca_cert: /etc/sdl/graylog-ca.pem
    # auth_header: Authorization        # if the HTTP input requires a header
    # auth_value_env: GRAYLOG_INPUT_AUTH
```

Use a GELF HTTP input when you can: Graylog acknowledges every message, so
nothing is lost silently. Each message has a readable `short_message`
(`rollover.target failure web1 by system:orchestrator for bob: ...`), the
event's message as `full_message`, `level` from the outcome, and the fields
`_sdl_action`, `_sdl_outcome`, `_sdl_actor`, `_sdl_actor_type`,
`_sdl_initiated_by`, `_sdl_target`, `_sdl_module`, `_sdl_run_id`,
`_sdl_event_id`, `_sdl_hash`, `_sdl_prev_hash`, `_sdl_ts`, and the details
as JSON in `_sdl_details`. Over UDP, large messages are chunked
(`chunk_size`, default 1420 bytes) and can be gzip-compressed (`compress`).

### Splunk: `forwarder.splunk_hec`

The HTTP Event Collector, in batches.

```yaml
splunk:
  type: forwarder.splunk_hec
  config:
    url: https://splunk.example.com:8088
    token_env: SPLUNK_HEC_TOKEN   # or token_file: /etc/sdl/hec-token
    index: security               # default: the token's index
    sourcetype: sdl:audit         # default
    ca_cert: /etc/sdl/splunk-ca.pem
```

Each event is sent whole as JSON with its own timestamp, so searches work
without extraction rules:

```
sourcetype="sdl:audit" action="rollover.target" outcome="failure"
sourcetype="sdl:audit" initiated_by.id="bob" | stats count by action
```

### Writing another forwarder

Subclass `ForwarderModule`, give it a config that extends `ForwarderConfig`,
implement `async send(events)` (raise to have the batch retried), and register
it under the `sdl.modules` entry points as `forwarder.<name>`. Helpers for
formatting and connections are in `sdl.core.forwarding` (`summary`, `fields`,
`SEVERITY`, `tls_context`, `StreamConnection`, `DatagramSender`).
