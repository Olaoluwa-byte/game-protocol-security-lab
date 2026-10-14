# Phase 2: Black-Box Protocol Notes

## Scope and methodology

Clean-room reconstruction of a private UDP game-master protocol from observed traffic and controlled client inputs. Neither `bb_master.pyc` nor `bb_client.pyc` was opened, decompiled, or disassembled. Evidence comprises seven packet captures (`phase2/captures/p2-01.pcapng` through `p2-07.pcapng`), extracted UDP payloads (`phase2/p2-XX-payloads.txt`), and compatibility tests against the original client.

**Evidence convention:** `p2-01 P3` means the third UDP payload in the filtered exchange, not necessarily Wireshark `frame.number`. Capture frame numbers remain to be mapped before claiming frame-level citations. Observed fields are distinguished from interpretations and untested behavior.

## Capture log

| Capture | Controlled input / condition | Result / distinguishing observation |
|---|---|---|
| `p2-01` | `player1 labdemo-only` | Baseline success, lobby `my-lobby`, capacity 4, lobby ID 1 |
| `p2-02` | Repeat valid `player1` | Success; lobby state persisted across client runs while original server remained running |
| `p2-03` | `player1 wrongpass` | Authentication failure, four packets only |
| `p2-04` | `player2 labdemo-two` | Success for second account |
| `p2-05` | `player1 labdemo-only aaaaaaaa 4` | Eight-character name, lobby ID 4 |
| `p2-06` | `player1 labdemo-only aaaaaaaa 9` | Capacity 9, lobby ID 5 |
| `p2-07` | `player1 labdemo-only tiny 0` | Zero-capacity lobby ID 6; JOIN refusal |

The lobby IDs above refer to the original black-box server's uninterrupted state, not a fresh emulator process.

## Transport and exchange

- **Observed:** UDP, original master on port **7777**, client initiates each request. In successful captures the exchange contains ten packets: five requests and five responses. The failed-login capture has four packets (`p2-03 P1–P4`).
- **Observed in lab:** master VM `192.168.252.2`; client VM `192.168.252.3`; game-server endpoint returned on success `192.168.252.4:10000`.
- **Not established:** retransmission behavior, timeouts, concurrent sessions, unsolicited messages, or broader network deployment semantics.

## Framing

| Offset | Size | Field | Encoding | Evidence / confidence |
|---|---:|---|---|---|
| 0–1 | 2 | Magic | `c0 9e` | All 64 extracted packets; confirmed for captured corpus |
| 2 | 1 | Stage / sequence-like byte | `01` through `05` in observed workflow | `p2-01 P1–P10`; observed; semantics beyond normal workflow unverified |
| 3 | 1 | Opcode | Requests `21`–`25`; responses `a1`–`a5` | `p2-01 P1–P10`; confirmed for workflow |
| 4–5 | 2 | Body length | Unsigned little-endian, excludes header and trailing byte | 64/64 frame round-trip tests |
| 6 ... | N | Message body | Opcode-specific | All captured exchanges |
| 6+N | 1 | Check byte | `sum(packet_without_check) & 0xff` | 64/64 captured packets matched |

Total packet length is `6 + body_length + 1`. Parser/builder round-trip reproduced **64/64** captured packets exactly. Candidate checksum results: `sum8` 64/64, `neg_sum8` 0/64, `xor8` 1/64, `sum_body` 0/64, `xor_body` 0/64. This is an additive error check, **not cryptographic integrity protection**.

Example HELLO request: `c09e012101000081` (`p2-01 P1`).

## Message types and body layouts

| Stage | Request → reply | Label | Body structure | Evidence |
|---|---|---|---|---|
| 1 | `0x21` → `0xA1` | HELLO | Request: `00` (observed). Reply: 8 bytes, first four variable/unknown, last four form XOR key | `p2-01 P1–P2`, `p2-03 P1–P2`; XOR verification |
| 2 | `0x22` → `0xA2` | AUTH | Request: `u16le username_length`, username bytes, `u16le password_length`, XOR-transformed password bytes. Success reply: `00` + 8-byte token. Wrong-password reply: `03` | `p2-01 P3–P4`, `p2-03 P3–P4` |
| 3 | `0x23` → `0xA3` | CREATE_LOBBY | Request: 8-byte session token, `u16le name_length`, name bytes, `u8 max_players`. Reply: `u16le lobby_id` | `p2-01 P5–P6`, `p2-05 P5–P6`, `p2-06 P5–P6`, `p2-07 P5–P6` |
| 4 | `0x24` → `0xA4` | LIST_LOBBIES | Request: 8-byte token. Reply: `u8 lobby_count`, followed by variable-length lobby records | `p2-01 P7–P8`, `p2-05 P7–P8`, `p2-06 P7–P8`, `p2-07 P7–P8` |
| 5 | `0x25` → `0xA5` | JOIN_LOBBY | Request: 8-byte token + `u16le lobby_id`. Success reply: `00` + four IPv4 octets + `u16be port`; refusal: `04` | `p2-01 P9–P10`, `p2-05 P9–P10`, `p2-06 P9–P10`, `p2-07 P9–P10` |

### Lobby-list record

Each record is interpreted as `u16le lobby_id`, `u8 current_players`, `u8 max_players`, `u8 name_length`, followed by name bytes. This layout consistently parses observed records; **the high byte of lobby ID has only been observed as zero**, so a >255 lobby ID test would strengthen the two-byte interpretation. `p2-07 P8` includes lobby ID 6 with name `tiny`, current 0, maximum 0.

### Strings

Username and CREATE_LOBBY name use two-byte little-endian length prefixes in their respective request bodies. Lobby-list records use one-byte name lengths. Captured names are ASCII-compatible; UTF-8 handling in the emulator is an implementation choice, not established for non-ASCII names.

## Credentials and XOR challenge

The username is transmitted in clear bytes. The password is **reversibly obfuscated**, not encrypted securely. The last four bytes of the eight-byte HELLO_ACK body provide a four-byte repeating XOR key:

`transformed[i] = password[i] XOR key[i mod 4]`

For `p2-01`, the 12-byte transformed password `849294198d9e9950879d9a04` XOR plaintext `labdemo-only` produces repeated key `e8f3f67d`. For `p2-03`, HELLO_ACK key `9e14b7ec` transforms `wrongpass` to `e966d882f964d69fed`; the independently generated bytes matched the capture exactly. Keys vary across sessions. The meaning of the first four HELLO_ACK body bytes is unresolved.

## Session state

On successful AUTH the reply body is status `00` followed by an eight-byte token (`p2-01 P4`). The same token appears at the start of subsequent CREATE and JOIN requests and constitutes the entire LIST request body (`p2-01 P5, P7, P9`). The clean-room server validates tokens against the originating client address. **Whether the original server enforces the same address binding, token expiry, or rejection behavior has not been tested.**

## Error cases and edge behavior

| Condition | Input | Observed reply | Evidence |
|---|---|---|---|
| Wrong password | `player1 wrongpass` | AUTH body `03`; client `login failed` | `p2-03 P3–P4` |
| Zero-capacity lobby | `player1 labdemo-only tiny 0` | CREATE succeeds, LIST includes `tiny 0/0`, JOIN body `04`; client `join refused` | `p2-07 P5–P10` |
| Valid JOIN | Lobby with free capacity | JOIN body `00c0a8fc042710`; client reports `192.168.252.4:10000` | `p2-01 P9–P10` |

`04` is confirmed as a refusal status for the zero-capacity scenario; using the same status for nonexistent IDs or other full-lobby cases is an emulator assumption, not directly demonstrated by the captures.

## Clean-room implementation and validation

`phase2/cleanroom_master.py` implements UDP packet parsing/building, HELLO, AUTH, CREATE, LIST and JOIN based on captured traffic. Framing round-tripped all 64 extracted packets. The original `bb_client.pyc`, pointed at the clean-room server on `lab-master:7777`, passed the following **four** compatibility scenarios, both before and after a refactor that dispatched by opcode and echoed the incoming stage:

| Client invocation arguments | Observed result |
|---|---|
| `player1 labdemo-only` | `SUCCESS` |
| `player2 labdemo-two` | `SUCCESS` |
| `player1 wrongpass` | `login failed` |
| `player1 labdemo-only tiny 0` | `join refused` |

The clean-room server's successful JOIN response was byte-for-byte `c09e05a5070000c0a8fc042710ae`, matching the original capture; its refusal response was `c09e05a50100040d`, also matching the original. After refactoring, the emulator accepts a game-server IP from the CLI (`--serve 192.168.252.4`).

## Open questions and limitations

- The semantic meaning of the first four bytes of HELLO_ACK is unknown.
- The exact semantics of the stage byte beyond the observed sequence are unverified against the original server. Echoing arbitrary request stage values is an emulator hypothesis.
- Token validation, expiry, duplicate joins, capacity limits beyond tested examples, non-ASCII strings, lobby ID rollover, malformed packets, and concurrent clients need controlled black-box tests.
- Lobby state is in memory; restart resets it. Credentials are lab fixtures. The game-server endpoint is a lab configuration value.
- XOR password obfuscation and additive checksum provide **no production-grade confidentiality or authentication/integrity**.
- The source captures may include non-protocol frames; inspect before publishing and map filtered packet indices to actual `frame.number` values for precise citations.

## Reproducibility

Captured payloads: `phase2/p2-01-payloads.txt` through `phase2/p2-07-payloads.txt`. Packet captures: `phase2/captures/p2-01.pcapng` through `p2-07.pcapng`. Start clean-room server on `lab-master` after stopping the black-box master:

```bash
multipass transfer phase2/cleanroom_master.py lab-master:
multipass exec lab-master -- python3 cleanroom_master.py --serve 192.168.252.4
```

Then invoke the original client from `lab-client` with the arguments shown in the validation table. No black-box bytecode is committed or required for the clean-room source distribution.
