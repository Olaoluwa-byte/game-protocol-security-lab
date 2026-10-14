"""C09 Phase 1 - master/directory server (UDP 9999).

Usage: python3 master.py <game_server_ip>
"""
import socket
import struct
import argparse
from telemetry import Telemetry, Shutdown, load_key, user_ref

HOST, PORT = "0.0.0.0", 9999
GAME_HOST = "127.0.0.1"
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
    parser = argparse.ArgumentParser()
    parser.add_argument('game_server_ip', nargs='?', default=GAME_HOST)
    parser.add_argument('--log-path', default='/mnt/c09logs/master.jsonl')
    parser.add_argument('--host-ip')
    parser.add_argument('--user-ref-key-file', default='/etc/c09/user_ref.key')
    parser.add_argument('--user-ref-key-id', default='k1')
    args = parser.parse_args()
    game_host = args.game_server_ip
    key = load_key(args.user_ref_key_file)
    telemetry = Telemetry(args.log_path, 'master', args.host_ip, PORT)
    shutdown = Shutdown()
    endpoint_ids = {}
    authenticated = set()
    st = State()
    sock = None
    addr = None
    session_id = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((HOST, PORT))
        sock.settimeout(0.1)
        print(f"master listening on {HOST}:{PORT}, game server = {game_host}:{GAME_PORT}")
        telemetry.emit('server_start')

        while not shutdown.stopped:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            session_id = telemetry.session(endpoint_ids.get(addr))
            if len(data) < 4:
                telemetry.emit('malformed', addr=addr, session_id=session_id,
                               outcome='failure', reason='short', byte_count=len(data))
                print(f"{addr} short packet ignored")
                continue
            _, msg_type, body_len = HEADER.unpack(data[:4])
            body = data[4:4 + body_len]
            if len(data) != 4 + body_len:
                telemetry.emit('malformed', addr=addr, session_id=session_id,
                               outcome='failure', reason='bad_length', byte_count=len(data))
            elif msg_type not in NAMES:
                telemetry.emit('malformed', addr=addr, session_id=session_id,
                               outcome='failure', reason='unknown_type', byte_count=len(data))
            print(f"{addr[0]}:{addr[1]} -> {NAMES.get(msg_type, msg_type)}")

            if msg_type == HELLO:
                cid = st.next_client
                st.next_client += 1
                st.clients[cid] = addr
                endpoint_ids[addr] = cid
                telemetry.emit('hello', addr=addr, session_id=telemetry.session(cid), client_id=cid)
                sock.sendto(pack(HELLO_ACK, struct.pack("!I", cid)), addr)

            elif msg_type == AUTH:
                user, off = read_lp(body, 0)
                pw, _ = read_lp(body, off)
                ok = USERS.get(user.decode()) == pw.decode()
                if ok:
                    authenticated.add(addr)
                telemetry.emit('auth', addr=addr, session_id=session_id,
                               outcome='success' if ok else 'failure',
                               reason=None if ok else 'invalid_credentials',
                               user_ref=user_ref(key, user), user_ref_key_id=args.user_ref_key_id)
                print(f"  auth user={user.decode()} result={'ok' if ok else 'fail'}")
                sock.sendto(pack(AUTH_ACK, bytes([0 if ok else 1])), addr)

            elif msg_type == CREATE_LOBBY:
                name, _ = read_lp(body, 0)
                st.lobbies[st.next_lobby] = name.decode()
                print(f"  lobby {st.next_lobby} created: {name.decode()}")
                telemetry.emit('lobby_create', addr=addr, session_id=session_id,
                               lobby_id=st.next_lobby, lobby_name=name.decode(),
                               lobby_count_after=len(st.lobbies), authenticated=addr in authenticated)
                st.next_lobby += 1

            elif msg_type == LIST_LOBBIES:
                telemetry.emit('lobby_list', addr=addr, session_id=session_id,
                               lobby_count=len(st.lobbies), authenticated=addr in authenticated)
                out = bytes([len(st.lobbies)])
                for lid, name in st.lobbies.items():
                    nb = name.encode()
                    out += struct.pack("!I", lid) + bytes([len(nb)]) + nb
                sock.sendto(pack(LOBBY_LIST, out), addr)

            elif msg_type == JOIN:
                host = game_host.encode()
                out = bytes([len(host)]) + host + struct.pack("!H", GAME_PORT)
                sock.sendto(pack(JOIN_ACK, out), addr)
                # Observe the requested ID without adding a validation gate.
                lobby_id = int.from_bytes(body[:4], 'big') if len(body) >= 4 else None
                telemetry.emit('join_handoff', addr=addr, session_id=session_id,
                               lobby_id=lobby_id, game_ip=game_host, game_port=GAME_PORT,
                               authenticated=addr in authenticated)
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
