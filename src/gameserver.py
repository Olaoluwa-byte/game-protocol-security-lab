"""C09 Phase 1 - game server (UDP 10000).

Receive-and-tick loop: accepts players, takes position updates,
broadcasts a world snapshot to every player twice a second.

Usage: python3 gameserver.py
"""
import argparse
from telemetry import Telemetry, Shutdown
import socket
import struct
import time

HOST, PORT = "0.0.0.0", 10000
HEADER = struct.Struct("!BBH")

# Game protocol message types (separate namespace from the master's)
G_JOIN, G_JOIN_ACK = 1, 2   # client -> server: join; server -> client: player_id
G_STATE = 3                  # client -> server: x(2) y(2), signed
G_SNAPSHOT = 4               # server -> clients: count(1) + [id(4) x(2) y(2)] * count

TICK = 0.5        # seconds between snapshots
TIMEOUT = 10      # drop a player after this many seconds of silence


def log(event, **kv):
    # Interactive console only; security forwarding uses the allowlisted JSONL file.
    fields = " ".join(f"{k}={v}" for k, v in kv.items())
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} event={event} {fields}", flush=True)


def pack(msg_type, body=b""):
    return HEADER.pack(1, msg_type, len(body)) + body


class Session:
    def __init__(self):
        self.players = {}   # addr -> {"id", "x", "y", "last_seen"}
        self.next_id = 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-path', default='/mnt/c09logs/gameserver.jsonl')
    parser.add_argument('--host-ip')
    args = parser.parse_args()
    telemetry = Telemetry(args.log_path, 'gameserver', args.host_ip, PORT)
    shutdown = Shutdown()
    s = Session()
    sock = None
    addr = None
    session_id = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((HOST, PORT))
        sock.settimeout(0.1)   # short wait so the tick runs on schedule
        log("server_start", listen=f"{HOST}:{PORT}", tick=TICK)

        telemetry.emit('server_start', tick_s=TICK)
        last_tick = time.time()
        while not shutdown.stopped:
            # --- receive phase ---
            try:
                data, addr = sock.recvfrom(4096)
                session_id = telemetry.session(s.players.get(addr, {}).get('id'))
                if len(data) < 4:
                    telemetry.emit('malformed', addr=addr, session_id=session_id,
                                   outcome='failure', reason='short', byte_count=len(data))
                if len(data) >= 4:
                    _, msg_type, body_len = HEADER.unpack(data[:4])
                    body = data[4:4 + body_len]
                    src = f"{addr[0]}:{addr[1]}"
                    if len(data) != 4 + body_len or (msg_type == G_STATE and len(body) < 4):
                        telemetry.emit('malformed', addr=addr, session_id=session_id,
                                       outcome='failure', reason='bad_length', byte_count=len(data))
                    elif msg_type not in (G_JOIN, G_STATE):
                        telemetry.emit('malformed', addr=addr, session_id=session_id,
                                       outcome='failure', reason='unknown_type', byte_count=len(data))

                    if msg_type == G_JOIN:
                        if addr in s.players:
                            pid = s.players[addr]["id"]          # rejoin from same addr
                            telemetry.emit('player_rejoin', addr=addr, session_id=telemetry.session(pid), player_id=pid)
                        else:
                            pid = s.next_id
                            s.next_id += 1
                            s.players[addr] = {"id": pid, "x": 0, "y": 0,
                                               "last_seen": time.time(), "joined_at": time.time(), "updates_received": 0}
                            telemetry.emit('player_join', addr=addr, session_id=telemetry.session(pid),
                                           player_id=pid, players_after=len(s.players))
                            log("join", player_id=pid, src=src, players=len(s.players))
                        sock.sendto(pack(G_JOIN_ACK, struct.pack("!I", pid)), addr)

                    elif msg_type == G_STATE and addr in s.players and len(body) >= 4:
                        x, y = struct.unpack("!hh", body[:4])
                        s.players[addr]['updates_received'] += 1
                        s.players[addr].update(x=x, y=y, last_seen=time.time())

                    elif msg_type == G_STATE and addr not in s.players:
                        telemetry.emit('state_from_unknown', addr=addr, session_id=session_id,
                                       outcome='failure', reason='not_joined')
                        log("state_from_unknown", src=src)       # not joined: ignore
            except socket.timeout:
                pass

            # --- tick phase ---
            now = time.time()
            if now - last_tick >= TICK:
                last_tick = now

                for addr in [a for a, p in s.players.items() if now - p["last_seen"] > TIMEOUT]:
                    p = s.players.pop(addr)
                    telemetry.emit('player_timeout', addr=addr, session_id=telemetry.session(p['id']),
                                   player_id=p['id'], players_after=len(s.players),
                                   duration_s=round(now - p['joined_at'], 3), updates_received=p['updates_received'])
                    log("timeout", player_id=p["id"], src=f"{addr[0]}:{addr[1]}",
                        players=len(s.players))

                body = bytes([len(s.players)])
                for p in s.players.values():
                    body += struct.pack("!Ihh", p["id"], p["x"], p["y"])
                for addr in s.players:
                    sock.sendto(pack(G_SNAPSHOT, body), addr)
    except Exception as exc:
        telemetry.error(exc, addr=addr, session_id=session_id)
        raise
    finally:
        telemetry.emit('server_stop', reason='signal' if shutdown.stopped else 'shutdown')
        if sock is not None:
            sock.close()
        telemetry.close()
        shutdown.restore()


if __name__ == "__main__":
    main()
