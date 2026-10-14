# C09 Phase 3 Telemetry Schema v1.0

Security telemetry for the Phase 1 stack (`src/master.py`, `src/gameserver.py`), forwarded to Splunk for detection engineering. Status: approved design; implementation tracked in the `phase3-telemetry` branch.

Design reviewed by an independent reviewer twice (v0.1: 13 findings, 5 blockers; v0.2: delta review). This version resolves the open items from both reviews.

## 1. Scope

| In scope | Out of scope |
|---|---|
| `src/master.py` (UDP 9999), `src/gameserver.py` (UDP 10000) | `phase2/cleanroom_master.py` (its debug output prints secrets; must be redacted before any ingestion) |
| Server-side events only | Network-level detection of passive credential sniffing (T1040); would need a network sensor |
| | Multi-IP / impossible-travel detection (single client IP in the lab) |

## 2. Transport

| Item | Spec |
|---|---|
| Format | JSON Lines: one JSON object per line, UTF-8, `\n` terminated, flushed per event |
| Writer | Append-only (`O_APPEND`); never truncate or rewrite |
| Files | lab-master: `/mnt/c09logs/master.jsonl`; lab-game: `/mnt/c09logs/gameserver.jsonl` (configurable with `--log-path`) |
| Host folders | Mac `~/c09-logs/master/` mounted only into lab-master; `~/c09-logs/game/` mounted only into lab-game. **Never mounted into lab-client** (the attack-traffic VM). Outside the Git repo. |
| Splunk | Index `c09`; sourcetypes `c09:master:json`, `c09:game:json`; `KV_MODE = json`; timestamp from `ts` |
| Console | Existing human-readable prints may remain for interactive use. The Universal Forwarder monitors **only** the two `.jsonl` paths, never stdout. |

## 3. Common fields (every event)

| Field | Type | Notes |
|---|---|---|
| `ts` | string | RFC 3339 UTC, millisecond precision, e.g. `2026-10-15T14:02:11.482Z` |
| `schema_version` | int | `1` |
| `event_id` | string | UUID4, unique per event |
| `server_instance_id` | string | UUID4 generated at process start; distinguishes restarts |
| `component` | string | `master` or `gameserver` |
| `host` | string | VM hostname |
| `event` | string | One of the event names below |
| `outcome` | string | `success`, `failure`, or `info` |
| `reason` | string or null | Fixed enum per event; null unless `outcome` is `failure` (or noted) |
| `protocol` | string | `udp` |
| `src_ip`, `src_port` | string, int | Remote client endpoint (null for lifecycle events) |
| `dst_ip`, `dst_port` | string, int | This server's lab address and listen port. `dst_ip` from `--host-ip`, else auto-detected; never `0.0.0.0` |
| `session_id` | string or null | Master: `<server_instance_id>:<client_id>` after HELLO from that endpoint. Game: `<server_instance_id>:<player_id>`. Null when no session applies. |

## 4. Event allowlist

Each event may contain **only** the common fields plus the extra fields listed. Any other key is a bug. Unknown or unexpected data is never serialized.

### Master (`component = master`)

| `event` | `outcome` / `reason` | Extra fields |
|---|---|---|
| `server_start` | `info` | none |
| `server_stop` | `info`, reason `signal` or `shutdown` | none |
| `hello` | `success` | `client_id` |
| `auth` | `success`, or `failure` / `invalid_credentials` | `user_ref`, `user_ref_key_id` |
| `lobby_create` | `success` | `lobby_id`, `lobby_name`, `lobby_count_after`, `authenticated` |
| `lobby_list` | `success` | `lobby_count`, `authenticated` |
| `join_handoff` | `success` | `lobby_id`, `game_ip`, `game_port`, `authenticated` |
| `malformed` | `failure` / `short`, `bad_length`, `unknown_type` | `byte_count` |
| `internal_error` | `failure` / `exception` | `error_class` (exception class name only) |

### Game server (`component = gameserver`)

| `event` | `outcome` / `reason` | Extra fields |
|---|---|---|
| `server_start` | `info` | `tick_s` |
| `server_stop` | `info`, reason `signal` or `shutdown` | none |
| `player_join` | `success` | `player_id`, `players_after` |
| `player_rejoin` | `success` | `player_id` |
| `state_from_unknown` | `failure` / `not_joined` | none |
| `player_timeout` | `info` | `player_id`, `players_after`, `duration_s`, `updates_received` |
| `malformed` | `failure` / `short`, `bad_length`, `unknown_type` | `byte_count` |
| `internal_error` | `failure` / `exception` | `error_class` |

### Field definitions

| Field | Definition |
|---|---|
| `authenticated` | `true` if this exact `src_ip:src_port` produced an `auth` success since `server_start`. Instrumentation only: the v1 master does **not** enforce authentication. |
| `user_ref` | `hmac-sha256:` + first 32 hex chars (128 bits) of HMAC-SHA256(key, username bytes exactly as received). No normalization, matching the master's exact-match authentication. |
| `user_ref_key_id` | Non-secret label of the key generation, e.g. `k1` |
| `lobby_name` | Attacker-controlled. Logged only after sanitizing: printable ASCII (0x20-0x7E) kept, anything else replaced with `?`, truncated to 32 characters. |
| `byte_count` | Datagram length only; no content |
| `duration_s`, `updates_received` | One summary per game session at timeout; per-tick `G_STATE`/`G_SNAPSHOT` traffic is not logged |

**No `player_leave` event.** The v1 protocol has no leave message; game sessions end only by timeout or server stop. `SIGKILL` produces no `server_stop`; a new `server_instance_id` marks the restart.

## 5. Never logged

Raw usernames, passwords, password lengths, raw datagrams or bodies (hex or otherwise), exception messages or arguments, Python object reprs, and any field not in the allowlist. (The v1 protocol has no keys or tokens; the rule carries forward to any future clean-room instrumentation.)

## 6. HMAC key management

| Item | Spec |
|---|---|
| Generation | `openssl rand -hex 32` (256-bit key) |
| Location | lab-master only (only the master hashes usernames): `/etc/c09/user_ref.key`, mode `0400`, owned by the server account. Never in Git, never in the log folder. Path configurable with `--user-ref-key-file`. |
| Missing key | Master refuses to start (no fallback to raw usernames) |
| Stability | Same key across master restarts so `user_ref` stays stable |
| Rotation | Manual. New key gets a new `user_ref_key_id` (`k2`, ...). Detections compare `user_ref` only within one key id; rotation boundaries are documented in the README. |
| Analyst mapping | Restricted Splunk lookup `c09_lab_users.csv` (`user_ref`, `user_ref_key_id`, `lab_account`) for synthetic lab accounts only |

## 7. Correlation evidence

Verified from `captures/phase1-multiplayer.pcapng` (two concurrent reference clients):

| Client | AUTH source | G_JOIN source |
|---|---|---|
| 1 | 192.168.252.3:41384 | 192.168.252.3:41384 |
| 2 | 192.168.252.3:41139 | 192.168.252.3:41139 |

The reference `client.py` uses one UDP socket for master and game traffic, so `src_ip:src_port` matches across servers, and concurrent instances use distinct ports. The lab has no NAT. **This holds for the tested reference client only**; a client that opens a new socket for the game server will not match, and that is a documented false-positive case for D4. The JOIN request (master type 8) port is confirmed during implementation acceptance.

`G_JOIN` carries no identity, so any link from a game session to an account is inferred, never proven.

## 8. Detections

| ID | Name | Logic (lab thresholds, not production-tuned) | Confidence | `attack_technique` | `cwe` |
|---|---|---|---|---|---|
| D1 | Password guessing | Same `src_ip` + same `user_ref`: >= 5 `auth` failures in 5 min | High | T1110.001 | - |
| D2 | Password spraying | Same `src_ip`: >= 5 distinct `user_ref` with `auth` failures in 5 min | High | T1110.003 | - |
| D3a | Multiple successful authentications from distinct endpoints | Same `user_ref`: `auth` success from >= 2 distinct `src_ip:src_port` within 10 min. Does **not** assert overlapping sessions. | High (for the fact observed) | - (T1078 only with other evidence) | - |
| D3b | Probable concurrent game sessions for one account | Chain per endpoint: `auth` success -> `join_handoff` -> `player_join` on the same `src_ip:src_port` within 5 min; two chains with the same `user_ref` whose game sessions overlap (join before the other's timeout) | Probabilistic | - | - |
| D4 | Game join without observed matching handoff | `player_join` with no `join_handoff` to that game endpoint from the same `src_ip:src_port` in the prior 5 min. Same-IP-only match downgrades to low confidence. | Medium (reference client) | - | CWE-306 |
| D5 | Master action without prior authentication | `lobby_create` or `join_handoff` with `authenticated = false` | High | - | CWE-306 |
| D6 | Lobby creation burst | Same `src_ip`: >= 10 `lobby_create` in 1 min. Suspicious activity, **not** proof of denial of service. | Medium | T1499.003 (conditional) | CWE-770 (master stores lobbies in an unbounded dict) |

## 9. Validation (required for every detection)

| ID | Positive test | Negative test |
|---|---|---|
| D1 | 6 wrong passwords for one account | 1 wrong password, then success |
| D2 | One source fails as 6 different usernames | 3 different usernames each fail once |
| D3a | Same account authenticates from 2 client instances | One instance authenticates twice sequentially from the same endpoint |
| D3b | Two concurrent reference clients, same account | Two clients run sequentially (first times out before second joins) |
| D4 | Direct `G_JOIN` to the game server with no master interaction | Normal reference-client flow. Plus a **known-false-positive** test: a client using a new socket for the game server, documented as expected D4 noise |
| D5 | `CREATE_LOBBY` with no prior AUTH | Authenticated `CREATE_LOBBY` |
| D6 | 15 lobby creates in under 1 min | 3 creates over 5 min |

Platform checks:

| Check | Pass condition |
|---|---|
| Secret canaries | Tests use synthetic canary credentials (e.g. username `canary-user-7f3a`, password `canary-pw-7f3a`); neither string appears in any `.jsonl` file or Splunk event |
| Allowlist | Every emitted event contains only its allowlisted keys |
| Clocks | lab-master, lab-game, and the Splunk host are NTP-synced; `_indextime - _time` reviewed for ingestion delay |
| Forwarder scope | UF `inputs.conf` monitors only the two `.jsonl` paths |
| Wire compatibility | Protocol bytes unchanged; Phase 1 client flow and multiplayer behave as before |

## 10. Log integrity and residual risk

| Control | Purpose |
|---|---|
| No log mount on lab-client | The attack-traffic VM cannot read, modify, or delete evidence |
| Separate host folder per server VM | A server VM can only affect its own log |
| Servers run as a non-root account | Limits damage from a server-process compromise |
| Prompt forwarding; Splunk retains independent copies | Evidence survives deletion of the source file |

**Residual risk:** a compromised server VM can modify or fabricate its own source log, and filesystem permissions cannot prevent that for the account that writes it. Server-VM compromise is outside this lab's threat model; Splunk's copy is the evidence of record.
