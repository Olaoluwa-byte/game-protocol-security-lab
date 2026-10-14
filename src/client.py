"""C09 Phase 1 - test client.

Walks the master handshake, then follows JOIN_ACK to the game server,
sends position updates and prints the snapshots it gets back.

Usage: python3 client.py <master_ip> [moves]
"""
import socket
import struct
import sys
import time

MASTER = (sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1", 9999)
MOVES = int(sys.argv[2]) if len(sys.argv) > 2 else 10
HEADER = struct.Struct("!BBH")


def pack(msg_type, body=b""):
    return HEADER.pack(1, msg_type, len(body)) + body


def lp(s):
    b = s.encode()
    return bytes([len(b)]) + b


def recv(sock):
    # Next reply from the master: (msg_type, body).
    data, _ = sock.recvfrom(4096)
    _, msg_type, body_len = HEADER.unpack(data[:4])
    return msg_type, data[4:4 + body_len]


def recv_type(sock, want, wait):
    # Wait up to `wait` seconds for a message of type `want`; skip others.
    deadline = time.time() + wait
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return None
        _, msg_type, body_len = HEADER.unpack(data[:4])
        if msg_type == want:
            return data[4:4 + body_len]


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)   # a lost datagram raises socket.timeout instead of hanging

# ---------------- master handshake ----------------
sock.sendto(pack(1), MASTER)                                   # HELLO
_, body = recv(sock)
print("client_id:", struct.unpack("!I", body)[0])

sock.sendto(pack(3, lp("player1") + lp("labdemo-only")), MASTER)           # AUTH
_, body = recv(sock)
print("auth:", "ok" if body[0] == 0 else "failed")

sock.sendto(pack(7, lp("test-lobby")), MASTER)                 # CREATE_LOBBY
sock.sendto(pack(5), MASTER)                                   # LIST_LOBBIES
_, body = recv(sock)
count = body[0]
print("lobby count:", count)
lobby_id = struct.unpack("!I", body[1:5])[0] if count else 0

sock.sendto(pack(8, struct.pack("!I", lobby_id)), MASTER)      # JOIN
_, body = recv(sock)
hlen = body[0]
host = body[1:1 + hlen].decode()
port = struct.unpack("!H", body[1 + hlen:3 + hlen])[0]
print(f"join lobby {lobby_id} -> game server {host}:{port}")

# ---------------- game session ----------------
GAME = (host, port)
sock.sendto(pack(1), GAME)                                     # G_JOIN
body = recv_type(sock, 2, 3)                                   # G_JOIN_ACK
if body is None:
    sys.exit("no G_JOIN_ACK from game server (is gameserver.py running?)")
pid = struct.unpack("!I", body)[0]
print(f"in game as player {pid}")

x, y = pid * 10, 0
for step in range(MOVES):
    x += 1
    y += 1 if step % 2 == 0 else -1
    sock.sendto(pack(3, struct.pack("!hh", x, y)), GAME)       # G_STATE
    snap = recv_type(sock, 4, 1.0)                             # G_SNAPSHOT
    if snap is None:
        print(f"step {step + 1}: no snapshot")
        continue
    n = snap[0]
    players = [struct.unpack_from("!Ihh", snap, 1 + i * 8) for i in range(n)]
    view = ", ".join(f"p{p}@({px},{py})" for p, px, py in players)
    print(f"step {step + 1}: {n} player(s) -> {view}")
    time.sleep(0.5)

print("done; server will time this player out after 10s of silence")
