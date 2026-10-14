"""D1-D6 scenarios. Only protocol traffic; no telemetry imports or writes."""
import struct
import time
from contextlib import ExitStack

try:
    from .lib import client_socket, exchange, lp
except ImportError:
    from lib import client_socket, exchange, lp


def hello(sock, master_ip):
    body = exchange(sock, (master_ip, 9999), 1, expected=2)
    if len(body) != 4:
        raise RuntimeError('invalid HELLO_ACK')


def auth(sock, master_ip, user='player1', password='labdemo-only', ok=True):
    body = exchange(sock, (master_ip, 9999), 3, lp(user) + lp(password), expected=4)
    if body != bytes([0 if ok else 1]):
        raise RuntimeError('unexpected AUTH_ACK result')


def create(sock, master_ip, name):
    exchange(sock, (master_ip, 9999), 7, lp(name))
    time.sleep(0.02)


def game_join(sock, game_ip):
    body = exchange(sock, (game_ip, 10000), 1, expected=2)
    if len(body) != 4:
        raise RuntimeError('invalid G_JOIN_ACK')


def states(sock, game_ip):
    for position in range(3):
        exchange(sock, (game_ip, 10000), 3, struct.pack('!hh', position, position))
        time.sleep(0.02)


def full_flow(sock, master_ip, game_ip, name):
    hello(sock, master_ip)
    auth(sock, master_ip)
    create(sock, master_ip, name)
    body = exchange(sock, (master_ip, 9999), 5, expected=6)
    if not body or not body[0]:
        raise RuntimeError('LOBBY_LIST contains no lobby')
    offset, lobby_id = 1, None
    for _ in range(body[0]):
        if offset + 5 > len(body):
            raise RuntimeError('truncated LOBBY_LIST')
        lid, length = struct.unpack('!IB', body[offset:offset + 5])
        offset += 5
        if offset + length > len(body):
            raise RuntimeError('truncated lobby name')
        if body[offset:offset + length] == name.encode():
            lobby_id = lid
        offset += length
    if lobby_id is None:
        raise RuntimeError('created lobby absent from LOBBY_LIST')
    handoff = exchange(sock, (master_ip, 9999), 8, struct.pack('!I', lobby_id), expected=9)
    if not handoff or len(handoff) != 1 + handoff[0] + 2:
        raise RuntimeError('invalid JOIN_ACK')
    # Explicit CLI destination drives the game VM; handoff still comes from master.
    game_join(sock, game_ip)
    states(sock, game_ip)


def d1_positive(master_ip, game_ip):
    with client_socket() as sock:
        hello(sock, master_ip)
        for i in range(6):
            auth(sock, master_ip, password=f'wrong-{i}', ok=False)


def d1_negative(master_ip, game_ip):
    with client_socket() as sock:
        hello(sock, master_ip)
        auth(sock, master_ip, password='wrong', ok=False)
        auth(sock, master_ip)


def d2_positive(master_ip, game_ip):
    with client_socket() as sock:
        hello(sock, master_ip)
        for i in range(6):
            auth(sock, master_ip, user=f'c09-missing-positive-{i}', password='wrong', ok=False)


def d2_negative(master_ip, game_ip):
    with ExitStack() as stack:
        for i in range(3):
            sock = stack.enter_context(client_socket())
            hello(sock, master_ip)
            auth(sock, master_ip, user=f'c09-missing-negative-{i}', password='wrong', ok=False)


def d3a_positive(master_ip, game_ip):
    with ExitStack() as stack:
        for _ in range(2):
            sock = stack.enter_context(client_socket())
            hello(sock, master_ip)
            auth(sock, master_ip)


def d3a_negative(master_ip, game_ip):
    with client_socket() as sock:
        hello(sock, master_ip)
        auth(sock, master_ip)
        auth(sock, master_ip)


def d3b_positive(master_ip, game_ip):
    with client_socket() as first, client_socket() as second:
        full_flow(first, master_ip, game_ip, 'd3b-positive-first')
        full_flow(second, master_ip, game_ip, 'd3b-positive-second')
        time.sleep(3)
        states(first, game_ip)
        states(second, game_ip)


def d3b_negative(master_ip, game_ip):
    with client_socket() as first:
        full_flow(first, master_ip, game_ip, 'd3b-negative-first')
        time.sleep(11)  # Server expires silence after 10 s, on a 0.5 s tick.
    with client_socket() as second:
        full_flow(second, master_ip, game_ip, 'd3b-negative-second')


def d4_positive(master_ip, game_ip):
    with client_socket() as sock:
        game_join(sock, game_ip)
        states(sock, game_ip)


def d4_negative(master_ip, game_ip):
    with client_socket() as sock:
        full_flow(sock, master_ip, game_ip, 'd4-negative')


def d5_positive(master_ip, game_ip):
    with client_socket() as sock:
        hello(sock, master_ip)
        create(sock, master_ip, 'd5-positive')


def d5_negative(master_ip, game_ip):
    with client_socket() as sock:
        hello(sock, master_ip)
        auth(sock, master_ip)
        create(sock, master_ip, 'd5-negative')


def d6_positive(master_ip, game_ip):
    with client_socket() as sock:
        hello(sock, master_ip)
        auth(sock, master_ip)
        for i in range(15):
            create(sock, master_ip, f'd6-positive-{i}')


def d6_negative(master_ip, game_ip):
    with client_socket() as sock:
        hello(sock, master_ip)
        auth(sock, master_ip)
        for i in range(3):
            create(sock, master_ip, f'd6-negative-{i}')
            if i < 2:
                time.sleep(1)


CASES = [
    (d1_positive, 'Six failed AUTH_ACKs for one account and endpoint.'),
    (d1_negative, 'One failed AUTH_ACK followed by a successful AUTH_ACK.'),
    (d2_positive, 'Six nonexistent accounts fail from one endpoint.'),
    (d2_negative, 'Three endpoints each fail once for a distinct account.'),
    (d3a_positive, 'One account authenticates from two distinct endpoints.'),
    (d3a_negative, 'One account authenticates twice from the same endpoint.'),
    (d3b_positive, 'Two full game flows for one account overlap with 3 s of activity.'),
    (d3b_negative, 'First game session waits 11 s to expire before the second starts.'),
    (d4_positive, 'Direct game join and states; G_JOIN_ACK checked, no master flow.'),
    (d4_negative, 'Full master handoff and game flow from the same endpoint.'),
    (d5_positive, 'HELLO then lobby creation without authentication.'),
    (d5_negative, 'HELLO and successful authentication before lobby creation.'),
    (d6_positive, 'Fifteen authenticated lobby creates in a burst.'),
    (d6_negative, 'Three authenticated lobby creates spaced about 1 s apart.'),
]
