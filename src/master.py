"""C09 Phase 1 - master/directory server (UDP 9999).

Usage: python3 master.py <game_server_ip>
"""
import socket
import struct
import sys

HOST, PORT = "0.0.0.0", 9999
GAME_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
GAME_PORT = 10000

# Header: version(1) + msg_type(1) + body_length(2, big-endian)
HEADER = struct.Struct("!BBH")

HELLO, HELLO_ACK = 1, 2
AUTH, AUTH_ACK = 3, 4
LIST_LOBBIES, LOBBY_LIST = 5, 6
CREATE_LOBBY = 7
JOIN, JOIN_ACK = 8, 9
NAMES = {1: "HELLO", 3: "AUTH", 5: "LIST_LOBBIES", 7: "CREATE_LOBBY", 8: "JOIN"}

# Lab-only fake user store. Never do plaintext creds in anything real.
USERS = {"player1": "labdemo-only"}


class State:
    def __init__(self):
        self.clients = {}      # client_id -> addr
        self.lobbies = {}      # lobby_id -> name
        self.next_client = 1
        self.next_lobby = 1


def pack(msg_type, body=b""):
    return HEADER.pack(1, msg_type, len(body)) + body


def read_lp(data, offset):
    # One length byte, then that many bytes. Returns (value, new_offset).
    length = data[offset]
    start = offset + 1
    return data[start:start + length], start + length


def main():
    st = State()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"master listening on {HOST}:{PORT}, game server = {GAME_HOST}:{GAME_PORT}")

    while True:
        data, addr = sock.recvfrom(4096)
        if len(data) < 4:
            print(f"{addr} short packet ignored")
            continue
        _, msg_type, body_len = HEADER.unpack(data[:4])
        body = data[4:4 + body_len]
        print(f"{addr[0]}:{addr[1]} -> {NAMES.get(msg_type, msg_type)}")

        if msg_type == HELLO:
            cid = st.next_client
            st.next_client += 1
            st.clients[cid] = addr
            sock.sendto(pack(HELLO_ACK, struct.pack("!I", cid)), addr)

        elif msg_type == AUTH:
            user, off = read_lp(body, 0)
            pw, _ = read_lp(body, off)
            ok = USERS.get(user.decode()) == pw.decode()
            print(f"  auth user={user.decode()} result={'ok' if ok else 'fail'}")
            sock.sendto(pack(AUTH_ACK, bytes([0 if ok else 1])), addr)

        elif msg_type == CREATE_LOBBY:
            name, _ = read_lp(body, 0)
            st.lobbies[st.next_lobby] = name.decode()
            print(f"  lobby {st.next_lobby} created: {name.decode()}")
            st.next_lobby += 1

        elif msg_type == LIST_LOBBIES:
            out = bytes([len(st.lobbies)])
            for lid, name in st.lobbies.items():
                nb = name.encode()
                out += struct.pack("!I", lid) + bytes([len(nb)]) + nb
            sock.sendto(pack(LOBBY_LIST, out), addr)

        elif msg_type == JOIN:
            host = GAME_HOST.encode()
            out = bytes([len(host)]) + host + struct.pack("!H", GAME_PORT)
            sock.sendto(pack(JOIN_ACK, out), addr)


if __name__ == "__main__":
    main()
