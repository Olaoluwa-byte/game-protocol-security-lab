# Game Server Protocol Lab

A home-lab project that builds a small multiplayer backend from scratch (master/directory server, game server, client) over a custom binary UDP protocol, then uses it to practice protocol analysis, service emulation, and detection engineering.

Everything here is original code with a protocol I designed. No vendor firmware, binaries, game assets, or network captures from commercial services are used. The goal is to learn the skills behind private-server and protocol-reversing work in a fully legal, self-owned environment.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Build the stack: protocol, master server, game server, client, Wireshark dissector | Complete |
| 2 | Reverse the protocol from packet captures alone; write a clean-room master server | Planned |
| 3 | Forward server logs to Splunk; build detections for abuse of the protocol | Planned |

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
| Concurrent sessions | The same account can authenticate and hold two live game sessions at once. | Detection candidate for Phase 3 (session hijack / credential sharing) |

The credentials in this repo (`player1` / `labdemo-only`) exist only in this lab.

## Roadmap

Phase 2 treats the captures as an unknown protocol: document offsets, types, and the handshake from packets alone, then write a clean-room master server and confirm the original client works against it.

Phase 3 forwards the servers' logs to Splunk and builds detections for brute-force authentication, multi-IP logins per account, lobby flooding, unauthenticated game joins, and concurrent sessions per account.

Stretch: add TLS to the auth path and practice interception against a self-issued certificate.
