# Game Server Protocol Lab

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 Samson Amosu.

A home-lab project that builds a small multiplayer backend from scratch (master/directory server, game server, client) over a custom binary UDP protocol, then uses it to practice protocol analysis, service emulation, and detection engineering.

The lab protocol and implementations are original project work. Phase 2 treats the project's own black-box executables as opaque inputs; no vendor firmware, game binaries, game assets, or commercial-service protocol is required. The goal is defensive protocol analysis and detection engineering in a self-owned, isolated environment.

The deliberately insecure authentication and bounded attack-traffic scenarios are teaching fixtures, not production services. Run them only against lab systems you own or have explicit permission to test. See [security scope and public evidence](SECURITY.md) for limitations, capture handling, and secret-management rules.

---

## Executive Summary

**Problem.** Authentication and session abuse are hard to detect when a custom
protocol exposes credentials, omits access checks, and carries no shared account
identity between services. Detection quality depends on understanding the wire
format and producing telemetry that preserves evidence without logging secrets.

**What I built.** A three-VM UDP game lab, a Wireshark Lua dissector, a capture-driven
clean-room master for a separate self-owned protocol, and a JSONL → Universal
Forwarder → Tailscale → Splunk pipeline with seven packaged detections.

**What validation uncovered.**

1. **Credential exposure:** Phase 1 sends cleartext credentials; Phase 2 sends a
   repeating XOR key before the transformed password, making it recoverable.
2. **Access-control gaps:** game joins and master actions can occur without prior
   authentication; lobby creation can grow unbounded server state.
3. **Correlation limits:** concurrent-session and handoff detections need endpoint
   correlation. NAT, socket changes, missing events, or key rotation can break
   assumptions that hold in this lab.

**Outcome.** Released v3.0: a working telemetry pipeline and seven detection
scenarios reported validated with positive-fired/negative-silent checks. The
Splunk app is deployable with **scheduling disabled**; v3.1 scheduled alerts remain
deferred pending the Developer license.

### Results

| Measure | Result |
|---|---|
| Phase 1 stack | Authentication, matchmaking, game state, and multiplayer capture evidence |
| Protocol reconstruction | Seven controlled captures; framing/checksum validated on **64/64** unique packets |
| Clean-room compatibility | **4/4** original-client scenarios passed, including failed auth and refused join |
| Telemetry verification | **9/9** local automated tests pass; includes allowlists, HMAC, canary privacy, and wire behavior |
| Detection validation | **7 scenarios** reported validated in Splunk against isolated positive/negative case windows |
| Public packet evidence | Nine sanitized captures; unrelated traffic removed and retained packet bytes/timing preserved |
| Alert scheduling | **Disabled** in every packaged search; no scheduled-alert completion claim |

### Coverage & Limitations

| Gap | Impact / current status |
|---|---|
| Endpoint-based identity | D3b/D4 are heuristic; no shared protocol account identity across services |
| Lab-tuned thresholds | Fixed buckets can split bursts; distributed or low-and-slow activity may evade grouping |
| HMAC key rotation | Supplied account searches do not group by key generation; avoid mixing rotations in a window |
| Validation scope | Live Splunk checks are operator-reported; the nine Python tests are telemetry tests, not a Splunk CI suite |
| Black-box executables | Intentionally excluded; captures and notes are public, but original-client replay needs the private lab files |
| Scheduled alerts | Deferred to v3.1; current cron settings express intent only |

### Framework Mapping

| Framework | Finding / detection mapping |
|---|---|
| MITRE ATT&CK | T1040 Network Sniffing (packet finding); T1110.001 Password Guessing; T1110.003 Password Spraying |
| MITRE ATT&CK, conditional | T1499.003 Application Exhaustion Flood for D6 context; a lobby burst alone does not prove denial of service |
| CWE | CWE-306 Missing Authentication for Critical Function; CWE-770 Allocation of Resources Without Limits or Throttling |

[Detection logic and validation limits](detections/README.md) ·
[Telemetry schema](docs/telemetry-schema.md) · [Security scope](SECURITY.md)

---

## Appendix

<details>
<summary><b>A. Lab architecture and project status</b></summary>

| Phase | Scope | State |
|---|---|---|
| 1 | Build the stack: protocol, master server, game server, client, Wireshark dissector | Complete |
| 2 | Reverse the protocol from packet captures alone; write a clean-room master server | Complete |
| 3 | Forward server logs to Splunk; build detections for abuse of the protocol | Pipeline live; isolated detection scenarios validated; package schedules disabled |

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

</details>

<details>
<summary><b>B. Phase 1 — wire protocol</b></summary>

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

</details>

<details>
<summary><b>C. Phase 2 — black-box analysis and clean-room emulator</b></summary>

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

</details>

<details>
<summary><b>D. Security findings</b></summary>

| Finding | Detail | Mapping |
|---|---|---|
| Cleartext credentials | AUTH sends username and password unencrypted. The `labproto.password` filter recovers them from any capture on the path. | MITRE T1040 Network Sniffing |
| Unauthenticated game join | The game server accepts `G_JOIN` from any address. A client can skip the master entirely if it knows the game server's address. | Detection candidate for Phase 3 |
| Concurrent sessions | The same account can authenticate and hold two live game sessions at once. Evidence: [multiplayer capture](captures/phase1-multiplayer.pcapng), filter `labgame.player_count >= 2`. | Detection candidate for Phase 3 (session hijack / credential sharing) |

The credentials in this repo (`player1` / `labdemo-only`) exist only in this lab.

The Phase 2 XOR transformation and additive checksum are described in Appendix C.
The detection mappings and their limitations appear in Appendix F.

</details>

<details>
<summary><b>E. Telemetry and ingestion</b></summary>

### Verification

Run `python3 -m unittest -v` from the repository root with local UDP sockets
available and ports 9999/10000 free. The compatibility test compares the current
servers with the pre-telemetry `v2.1` release; clone tags as well as the source.
Test keys and logs are generated in the operating system's temporary directory.

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
Without `--host-ip`, the server probes its outbound-interface address and warns
before falling back to loopback if detection fails; specify the lab address
explicitly for accurate VM telemetry.
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

</details>

<details>
<summary><b>F. Detection logic and deployment</b></summary>

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

</details>

<details>
<summary><b>G. Validation evidence</b></summary>

### Telemetry tests

```bash
python3 -m unittest -v
```

Run from the repository root with tags available and local UDP ports 9999/10000
free. The compatibility test uses `v2.1` as its pre-telemetry baseline. All nine
tests passed during publication preparation; this repository does not currently
include the Splunk-container CI used in the two SSH projects.

### Detection scenarios

The lab operator reports all seven scenarios validated on **2026-10-14** against
isolated case windows. These are scenario quantities, not counts of returned SPL
rows; see [the validation record](detections/README.md#validation).

| Detection | Positive scenario evidence | Negative result reported |
|---|---|---|
| D1 — Password guessing | 6 failed authentications | Silent |
| D2 — Password spraying | 6 distinct failed accounts | Silent |
| D3a — Multiple endpoint auth | 2 successful source endpoints | Silent |
| D3b — Probable concurrent sessions | Corrected account-correlated SPL reaches `live_sessions=2` | Silent |
| D4 — Game join without handoff | 1 game join without matching handoff | Silent |
| D5 — Unauthenticated master action | 1 unauthenticated lobby creation | Silent |
| D6 — Lobby creation burst | 15 lobby creations | Silent |

The default eight-second generator gaps do not isolate five-/ten-minute detection
lookbacks. Pin searches to case windows; D3b also needs the relevant session and
timeout history. No live Splunk query was rerun for this README change.

### Packet evidence

- [Phase 1 game capture](captures/phase1-game.pcapng): 330 retained lab packets.
- [Phase 1 multiplayer capture](captures/phase1-multiplayer.pcapng): 300 packets;
  `labgame.player_count >= 2` matches 168 observations, including interface duplicates.
- [Phase 2 captures](phase2/captures/): 128 observations, 64 unique packets on
  interface 1. The recorded checksum rule matched all 64 unique packets.
- [Payloads and protocol notes](phase2/protocol-notes.md): field layouts,
  confidence, tested behavior, and emulator assumptions.

Public captures intentionally contain synthetic lab credentials and protocol
session material. Do not reuse those credentials. See [SECURITY.md](SECURITY.md).

</details>

<details>
<summary><b>H. Reproduce the lab and inspect captures</b></summary>

### Phase 1 VM setup

The commands below preserve the original pre-telemetry Phase 1 startup sequence
(as available at `v2.1`). For the current instrumented servers, use the key and
`--log-path` startup commands in **Appendix E** after provisioning the VMs.

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

Public captures contain only UDP traffic between the three lab VM addresses on ports 7777, 9999, or 10000. The publication cleanup reduced `captures/phase1-game.pcapng` from 2,671 to 330 packets by removing 2,341 unrelated packets. The multiplayer capture retains all 300 packets; the seven Phase 2 captures retain all 128 observations (64 unique packets on interface 1).

All nine captures have capture comments, host/interface descriptions, statistics, and packet options removed. Retained packet bytes, timestamps, lengths, interface IDs, and timestamp resolution are preserved. Filtering renumbers frames in the Phase 1 game capture; older frame numbers refer to the original private capture. Prefer protocol fields or payloads when identifying evidence. Multi-interface duplicate observations remain intentional.

VM-to-VM traffic does not appear on `bridge100`. Multipass VMs attach through `vmenetN` member interfaces, and frames switched between members are not seen on the bridge interface itself. Capture on all `vmenet` interfaces at once with the filter `udp.port == 9999 || udp.port == 10000`.

### Dissector

```
mkdir -p ~/.local/lib/wireshark/plugins
ln -s "$PWD/wireshark/labproto.lua" ~/.local/lib/wireshark/plugins/labproto.lua
```

Reload with Cmd+Shift+L. Useful filters: `labproto.type == 3` (AUTH), `labproto.status == 1` (failed logins), `labproto.password`.

### Phase 3 traffic and detection validation

With the instrumented lab servers and ingestion pipeline running, generate
real protocol traffic from the Mac:

```bash
python3 phase3/attack/run_all.py --master-ip 192.168.252.2 --game-ip 192.168.252.4
```

This generates traffic; it does not run the detection SPL or establish that an
alert fired. Validate each positive/negative against its saved case window and
account for session timeout tails. See the [generator instructions](phase3/attack/README.md).

For manual Splunk validation, use [the seven searches](detections/), removing
leading `#` documentation lines before pasting SPL. For deployment, follow the
[Splunk app instructions](splunk/c09_detections/README.md); schedules remain off.

</details>

<details>
<summary><b>I. Repository structure</b></summary>

```
src/master.py         master/directory server
src/gameserver.py     game server
src/client.py         test client (full flow: auth, lobby, join, gameplay)
wireshark/labproto.lua  dissector for the master protocol
captures/             Phase 1 packet captures
captures/phase1-multiplayer.pcapng  Phase 1 two-player session evidence
```

Additional artifacts:

```text
phase2/                     clean-room server, protocol notes, captures, and payload dumps
docs/telemetry-schema.md    common fields, per-event allowlists, privacy rules
detections/                 seven SPL searches and validation/limitation notes
phase3/attack/              real-server scenario generators and case-window metadata
splunk/c09_detections/      deployable Splunk app; all schedules disabled
tests/test_telemetry.py     nine local telemetry and wire-behavior tests
SECURITY.md                lab scope, public artifacts, and private-material rules
LICENSE                    MIT License
```

</details>

<details>
<summary><b>J. Releases and next steps</b></summary>

| Version | Changes |
|---|---|
| v1.0 | Phase 1 master and game servers, client, Wireshark master-protocol dissector, and captures. |
| v1.1 | Wireshark game-protocol dissector for UDP 10000. |
| v2.0 | Phase 2 clean-room master, recovered protocol notes and capture evidence, and four passing black-box client compatibility scenarios. |
| v2.1 | Docs: emulator design decisions, client-validation findings, known logging limitation, and Phase 1 multiplayer capture. |
| v3.0 | Live JSONL telemetry pipeline, real-server attack generators, and seven detection scenarios with isolated-window validation; Splunk detection package with schedules disabled and corrected, validated D3b account correlation. |

### Next steps

- **v3.1:** enable and validate scheduled alerts after the Developer license is available.
- Preserve the documented correlation and threshold limitations when extending detections.

### Original roadmap and stretch work

Phase 2 is complete: the unknown protocol was reconstructed from packet captures, and the clean-room master server passed all four black-box client compatibility scenarios.

Phase 3 forwards server telemetry to Splunk and packages detections for password guessing and spraying, multiple authentication endpoints, probable concurrent sessions, unauthenticated actions, and lobby creation bursts.

Stretch: add TLS to the auth path and practice interception against a self-issued certificate.

</details>

---

**Samson Amosu** — Security Engineer (detection engineering, Splunk ES) · [LinkedIn](https://www.linkedin.com/in/samson-amosu) · [GitHub](https://github.com/Olaoluwa-byte)
