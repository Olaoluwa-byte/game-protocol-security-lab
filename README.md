# Game Server Protocol Lab

A home-lab project that builds a small multiplayer backend from scratch (master/directory server, game server, client) over a custom binary UDP protocol, then uses it to practice protocol analysis, service emulation, and detection engineering.

Everything here is original code with a protocol I designed. No vendor firmware, binaries, game assets, or network captures from commercial services are used. The goal is to learn the skills behind private-server and protocol-reversing work in a fully legal, self-owned environment.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Build the stack: protocol, master server, game server, client, Wireshark dissector | Complete |
| 2 | Reverse the protocol from packet captures alone; write a clean-room master server | Complete |
| 3 | Forward server logs to Splunk; build detections for abuse of the protocol | Pipeline live; isolated detection scenarios validated; package schedules disabled |

## Architecture

Three Ubuntu 24.04 VMs on Multipass (Apple Silicon Mac), on a shared bridge network. Wireshark runs on the host.

```
Mac host (Wireshark on vmenet interfaces)
   |
   bridge (192.168.252.0/24)
   |-- lab-client  192.168.252.3   client.py
   |-- lab-master  192.168.252.2   master.py      UDP 9999
   |-- lab-game    192.168.252.4   gameserver.py  UDP 10000
```

Flow: the client authenticates and picks a lobby on the master server. The master's `JOIN_ACK` hands the client the game server's address. The client then talks to the game server directly for the live session.

## Protocol

Every message, on both ports, starts with a 4-byte header:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version (1) |
| 1 | 1 | msg_type |
| 2 | 2 | body_length, unsigned big-endian |

Strings are length-prefixed: one length byte, then that many UTF-8 bytes.

### Master protocol (UDP 9999)

| Code | Name | Direction | Body |
|---|---|---|---|
| 1 | HELLO | client to master | none |
| 2 | HELLO_ACK | master to client | client_id (4) |
| 3 | AUTH | client to master | username, password (length-prefixed) |
| 4 | AUTH_ACK | master to client | status (1): 0 ok, 1 fail |
| 5 | LIST_LOBBIES | client to master | none |
| 6 | LOBBY_LIST | master to client | count (1), then lobby_id (4) + name per lobby |
| 7 | CREATE_LOBBY | client to master | name (length-prefixed) |
| 8 | JOIN | client to master | lobby_id (4) |
| 9 | JOIN_ACK | master to client | game host (length-prefixed), port (2) |

### Game protocol (UDP 10000)

| Code | Name | Direction | Body |
|---|---|---|---|
| 1 | G_JOIN | client to game | none |
| 2 | G_JOIN_ACK | game to client | player_id (4) |
| 3 | G_STATE | client to game | x (2), y (2), signed |
| 4 | G_SNAPSHOT | game to clients | count (1), then player_id (4) + x (2) + y (2) per player |

The game server runs a receive-and-tick loop: it broadcasts a snapshot every 0.5 s and drops players silent for 10 s.

## Repository layout

```
src/master.py         master/directory server
src/gameserver.py     game server
src/client.py         test client (full flow: auth, lobby, join, gameplay)
wireshark/labproto.lua  dissector for the master protocol
captures/             Phase 1 packet captures
captures/phase1-multiplayer.pcapng  Phase 1 two-player session evidence
```

## Running it

```
brew install --cask multipass wireshark
multipass launch 24.04 --name lab-master --cpus 1 --memory 1G --disk 5G
multipass launch 24.04 --name lab-client --cpus 1 --memory 1G --disk 5G
multipass launch 24.04 --name lab-game   --cpus 1 --memory 1G --disk 5G
multipass list

multipass transfer src/master.py lab-master:
multipass transfer src/gameserver.py lab-game:
multipass transfer src/client.py lab-client:

multipass exec lab-master -- python3 master.py <lab-game IP>
multipass exec lab-game   -- python3 gameserver.py
multipass exec lab-client -- python3 client.py <lab-master IP> 20
```

Run the client in two terminals at once to see two players in the same session.
The committed [multiplayer capture](captures/phase1-multiplayer.pcapng) provides evidence: filter `labgame.player_count >= 2` to see snapshots containing both players.

### Capture note (macOS)

VM-to-VM traffic does not appear on `bridge100`. Multipass VMs attach through `vmenetN` member interfaces, and frames switched between members are not seen on the bridge interface itself. Capture on all `vmenet` interfaces at once with the filter `udp.port == 9999 || udp.port == 10000`.

### Dissector

```
mkdir -p ~/.local/lib/wireshark/plugins
ln -s "$PWD/wireshark/labproto.lua" ~/.local/lib/wireshark/plugins/labproto.lua
```

Reload with Cmd+Shift+L. Useful filters: `labproto.type == 3` (AUTH), `labproto.status == 1` (failed logins), `labproto.password`.

## Findings (Phase 1)

| Finding | Detail | Mapping |
|---|---|---|
| Cleartext credentials | AUTH sends username and password unencrypted. The `labproto.password` filter recovers them from any capture on the path. | MITRE T1040 Network Sniffing |
| Unauthenticated game join | The game server accepts `G_JOIN` from any address. A client can skip the master entirely if it knows the game server's address. | Detection candidate for Phase 3 |
| Concurrent sessions | The same account can authenticate and hold two live game sessions at once. Evidence: [multiplayer capture](captures/phase1-multiplayer.pcapng), filter `labgame.player_count >= 2`. | Detection candidate for Phase 3 (session hijack / credential sharing) |

The credentials in this repo (`player1` / `labdemo-only`) exist only in this lab.

## Roadmap

Phase 2 is complete: the unknown protocol was reconstructed from packet captures, and the clean-room master server passed all four black-box client compatibility scenarios.

Phase 3 forwards server telemetry to Splunk and packages detections for password guessing and spraying, multiple authentication endpoints, probable concurrent sessions, unauthenticated actions, and lobby creation bursts.

Stretch: add TLS to the auth path and practice interception against a self-issued certificate.

## Phase 2 — Black-Box Protocol Reverse Engineering

Phase 2 uses a separate, self-owned black-box UDP protocol. The original Python bytecode files are treated as opaque executables: they are run to generate network traffic, but never opened, decompiled, or disassembled.

The protocol was reconstructed using seven controlled Wireshark captures, known client inputs, packet comparisons, and black-box compatibility testing.

### Phase 2 architecture

| Component | Host | Port |
|---|---|---|
| Original black-box client | `lab-client` — `192.168.252.3` | Ephemeral UDP |
| Clean-room master | `lab-master` — `192.168.252.2` | UDP 7777 |
| Game-server endpoint returned by JOIN | `lab-game` — `192.168.252.4` | UDP 10000 |

Phase 1 remains a separate implementation using UDP 9999. Its packet format and Wireshark dissector should not be assumed to decode the Phase 2 protocol.

### Recovered packet format

| Offset | Size | Field |
|---|---|---|
| 0–1 | 2 bytes | Magic: `c0 9e` |
| 2 | 1 byte | Stage/counter |
| 3 | 1 byte | Opcode |
| 4–5 | 2 bytes | Body length, unsigned little-endian |
| 6 onward | Variable | Message body |
| Final byte | 1 byte | Additive checksum |

The checksum is `sum(header + body) & 0xff`. This rule matched all 64 captured packets, and the clean-room parser/builder passed 64/64 packet round-trip tests.

### Recovered message types

| Request | Response | Purpose |
|---|---|---|
| `0x21` | `0xA1` | HELLO / handshake |
| `0x22` | `0xA2` | Authentication |
| `0x23` | `0xA3` | Create lobby |
| `0x24` | `0xA4` | List lobbies |
| `0x25` | `0xA5` | Join lobby |

The server supplies a four-byte key during the HELLO exchange. Password bytes are XORed with this key repeatedly before transmission. Successful authentication returns an eight-byte session token used by subsequent lobby requests.

The XOR transformation is reversible and does not provide password confidentiality. The additive checksum is not cryptographic integrity protection.

### Running the clean-room master

From the repository root on the Mac host:

```bash
multipass transfer phase2/cleanroom_master.py lab-master:
multipass exec lab-master -- python3 cleanroom_master.py --serve 192.168.252.4
```

Ensure that the original black-box master is stopped before launching the clean-room master, because both use UDP port 7777.

In another terminal, run the original black-box client against `lab-master`:

```bash
multipass exec lab-client -- python3 bb_client.pyc 192.168.252.2 player1 labdemo-only
```

The `.pyc` black-box executables are not included in the repository.

### Compatibility validation

All four required scenarios passed against the original black-box client, with the clean-room server running on `lab-master`.

| Scenario | Expected result | Observed result |
|---|---|---|
| `player1 labdemo-only` | `SUCCESS` | PASS |
| `player2 labdemo-two` | `SUCCESS` | PASS |
| `player1 wrongpass` | `login failed` | PASS |
| `player1 labdemo-only tiny 0` | `join refused` | PASS |

The four scenarios were rerun successfully after refactoring opcode dispatch and making the game-server IP configurable.

### Phase 2 artifacts

- `phase2/cleanroom_master.py` — clean-room protocol emulator
- `phase2/protocol-notes.md` — protocol findings, evidence, confidence levels, and limitations
- `phase2/captures/p2-01.pcapng` through `p2-07.pcapng` — controlled packet captures
- `phase2/p2-XX-payloads.txt` and `phase2/p2-XX.hex` — extracted packet evidence

### Limitations and future work

The clean-room server is a lab prototype, not a production authentication service. It uses hardcoded lab credentials, in-memory lobby state, and the recovered protocol's reversible password obfuscation.

The stage field's behavior outside the observed request sequence has not been independently confirmed against the original black-box server. Additional malformed-packet, replay, token-reuse, and capacity tests are future work.

Phase 3 uses these findings to develop Splunk detections and investigate protocol abuse in the isolated lab environment.

## Changelog

| Version | Changes |
|---|---|
| v1.0 | Phase 1 master and game servers, client, Wireshark master-protocol dissector, and captures. |
| v1.1 | Wireshark game-protocol dissector for UDP 10000. |
| v2.0 | Phase 2 clean-room master, recovered protocol notes and capture evidence, and four passing black-box client compatibility scenarios. |
| v2.1 | Docs: emulator design decisions, client-validation findings, known logging limitation, and Phase 1 multiplayer capture. |
| v3.0 | Live JSONL telemetry pipeline, real-server attack generators, and seven detection scenarios with isolated-window validation; Splunk detection package with schedules disabled and corrected, validated D3b account correlation. |

## Phase 3 telemetry

The Phase 1 master and game server emit append-only JSONL events using the
[telemetry schema v1.0](docs/telemetry-schema.md). Authentication state is observed
for telemetry only; protocol behavior and access controls are unchanged.

Generate the master-only HMAC key in an existing `/etc/c09` directory owned by
its server account (keep the key outside Git and the log folder):

```bash
openssl rand -hex 32 > /etc/c09/user_ref.key
chmod 0400 /etc/c09/user_ref.key
```

Create the log directories before starting the servers. Both accept `--log-path`
and `--host-ip` (the address recorded as `dst_ip`, not a bind-address change).
Without `--host-ip`, hostname resolution supplies the address, with loopback as
the fallback; specify the lab address explicitly for accurate VM telemetry.
The master also accepts `--user-ref-key-file` and `--user-ref-key-id` (default `k1`),
and refuses to start without a readable 256-bit hex key.

```bash
python3 src/master.py 192.168.252.4 --host-ip 192.168.252.2 --log-path /mnt/c09logs/master.jsonl --user-ref-key-file /etc/c09/user_ref.key --user-ref-key-id k1
python3 src/gameserver.py --host-ip 192.168.252.4 --log-path /mnt/c09logs/gameserver.jsonl
```

Retain the same key across restarts. For manual rotation, generate a new key and
change its label to `k2` (then `k3`, etc.); record each rotation boundary and compare
`user_ref` values only within one `user_ref_key_id`. Monitor only the `.jsonl`
files for forwarding; interactive console output remains separate.

## Phase 3 — Detection engineering

The live telemetry pipeline carries server **JSONL → Universal Forwarder over
Tailscale → Splunk index `c09`**. The
[telemetry schema](docs/telemetry-schema.md) defines the allowlisted fields;
[detections/](detections/) packages seven searches, with a
[Splunk app](splunk/c09_detections/) whose schedules are intentionally disabled
pending the Developer license. [Attack generators](phase3/attack/) drive real
protocol traffic. The lab operator reports positive-fired/negative-silent checks
on 2026-10-14 against isolated case windows.

- **D1 — Password guessing:** flags five or more failed authentications for one
  account and source endpoint in a five-minute bucket.
- **D2 — Password spraying:** flags failures for five or more distinct accounts
  from one source IP in a five-minute bucket.
- **D3a — Multiple endpoint authentication:** flags successful authentication for
  one account from two or more source ports in a ten-minute bucket.
- **D3b — Probable concurrent sessions:** carries successful auth account identity
  onto endpoint game events and flags a join that raises the account's running
  live-session count to two or more; the corrected SPL passed isolated validation.
- **D4 — Game join without handoff:** flags a game join without a matching source
  endpoint handoff observed during the prior five minutes.
- **D5 — Unauthenticated master action:** flags lobby creation or handoff with
  telemetry reporting no prior successful authentication at that endpoint.
- **D6 — Lobby creation burst:** flags ten or more lobby creations from one source
  IP in a one-minute bucket.

Key security findings are credentials exposed by cleartext Phase 1 AUTH or
reversible Phase 2 XOR obfuscation (**T1040**, Network Sniffing), unauthenticated
master/game actions (**CWE-306**), and unbounded lobby growth (**CWE-770**).
Passive credential sniffing is a protocol finding, not a detection established
by server JSONL alone. D6 maps conditionally to T1499.003; a creation burst is not
proof of denial of service. Production D3b/D4 correlation remains heuristic
because there is no shared protocol identity. See the detection README for the
scope of validation and correlation limitations.
