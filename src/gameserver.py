"""C09 Phase 1 - game server (UDP 10000).

Receive-and-tick loop: accepts players, takes position updates,
broadcasts a world snapshot to every player twice a second.

Usage: python3 gameserver.py
"""
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
    # key=value lines so Splunk can extract fields without custom parsing (Phase 3)
    fields = " ".join(f"{k}={v}" for k, v in kv.items())
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} event={event} {fields}", flush=True)


def pack(msg_type, body=b""):
    return HEADER.pack(1, msg_type, len(body)) + body


class Session:
    def __init__(self):
        self.players = {}   # addr -> {"id", "x", "y", "last_seen"}
        self.next_id = 1


def main():
    s = Session()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    sock.settimeout(0.1)   # short wait so the tick runs on schedule
    log("server_start", listen=f"{HOST}:{PORT}", tick=TICK)

    last_tick = time.time()
    while True:
        # --- receive phase ---
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) >= 4:
                _, msg_type, body_len = HEADER.unpack(data[:4])
                body = data[4:4 + body_len]
                src = f"{addr[0]}:{addr[1]}"

                if msg_type == G_JOIN:
                    if addr in s.players:
                        pid = s.players[addr]["id"]          # rejoin from same addr
                    else:
                        pid = s.next_id
                        s.next_id += 1
                        s.players[addr] = {"id": pid, "x": 0, "y": 0,
                                           "last_seen": time.time()}
                        log("join", player_id=pid, src=src, players=len(s.players))
                    sock.sendto(pack(G_JOIN_ACK, struct.pack("!I", pid)), addr)

                elif msg_type == G_STATE and addr in s.players and len(body) >= 4:
                    x, y = struct.unpack("!hh", body[:4])
                    s.players[addr].update(x=x, y=y, last_seen=time.time())

                elif msg_type == G_STATE:
                    log("state_from_unknown", src=src)       # not joined: ignore
        except socket.timeout:
            pass

        # --- tick phase ---
        now = time.time()
        if now - last_tick >= TICK:
            last_tick = now

            for addr in [a for a, p in s.players.items() if now - p["last_seen"] > TIMEOUT]:
                p = s.players.pop(addr)
                log("timeout", player_id=p["id"], src=f"{addr[0]}:{addr[1]}",
                    players=len(s.players))

            body = bytes([len(s.players)])
            for p in s.players.values():
                body += struct.pack("!Ihh", p["id"], p["x"], p["y"])
            for addr in s.players:
                sock.sendto(pack(G_SNAPSHOT, body), addr)


if __name__ == "__main__":
    main()
