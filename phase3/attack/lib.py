"""Small stdlib-only helpers for the real C09 UDP protocol."""
import socket
import struct
import time

HEADER = struct.Struct('!BBH')
TIMEOUT = 0.75
_USED_PORTS = set()


def pack(msg_type, body=b''):
    return HEADER.pack(1, msg_type, len(body)) + body


def lp(value):
    data = value.encode('utf-8')
    if len(data) > 255:
        raise ValueError('length-prefixed string exceeds 255 bytes')
    return bytes([len(data)]) + data


def client_socket():
    """A distinct endpoint per logical client, including sequential cases."""
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        if port not in _USED_PORTS:
            _USED_PORTS.add(port)
            return sock
        sock.close()


def exchange(sock, endpoint, msg_type, body=b'', expected=None, timeout=TIMEOUT):
    """Send once; optionally await a validated reply, ignoring game snapshots.

    No retries: a retransmission would change the scenario's event counts.
    """
    sock.sendto(pack(msg_type, body), endpoint)
    if expected is None:
        return None
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f'no reply type {expected} from {endpoint}')
        sock.settimeout(remaining)
        try:
            data, source = sock.recvfrom(65535)
        except socket.timeout:
            raise TimeoutError(f'no reply type {expected} from {endpoint}') from None
        if source != endpoint or len(data) < HEADER.size:
            continue
        version, kind, length = HEADER.unpack(data[:HEADER.size])
        if version != 1 or len(data) != HEADER.size + length:
            continue
        if kind == expected:
            return data[HEADER.size:]
