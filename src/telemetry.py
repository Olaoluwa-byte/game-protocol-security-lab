"""Allowlisted C09 schema-v1 JSONL telemetry."""
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import signal
import socket
import sys
import uuid

COMMON = set('ts schema_version event_id server_instance_id component host event outcome reason protocol src_ip src_port dst_ip dst_port session_id'.split())
EVENTS = {
    'master': {
        'server_start': (), 'server_stop': (), 'hello': ('client_id',),
        'auth': ('user_ref', 'user_ref_key_id'),
        'lobby_create': ('lobby_id', 'lobby_name', 'lobby_count_after', 'authenticated'),
        'lobby_list': ('lobby_count', 'authenticated'),
        'join_handoff': ('lobby_id', 'game_ip', 'game_port', 'authenticated'),
        'malformed': ('byte_count',), 'internal_error': ('error_class',),
    },
    'gameserver': {
        'server_start': ('tick_s',), 'server_stop': (),
        'player_join': ('player_id', 'players_after'), 'player_rejoin': ('player_id',),
        'state_from_unknown': (),
        'player_timeout': ('player_id', 'players_after', 'duration_s', 'updates_received'),
        'malformed': ('byte_count',), 'internal_error': ('error_class',),
    },
}
FAILURES = {'auth': {'invalid_credentials'}, 'malformed': {'short', 'bad_length', 'unknown_type'},
            'internal_error': {'exception'}, 'state_from_unknown': {'not_joined'}}


def user_ref(key, username):
    return 'hmac-sha256:' + hmac.new(key, username, hashlib.sha256).hexdigest()[:32]


def load_key(path):
    try:
        with open(path, 'r', encoding='ascii') as stream:
            key = bytes.fromhex(stream.read().strip())
        if len(key) != 32:
            raise ValueError()
        return key
    except (OSError, ValueError, UnicodeError):
        raise SystemExit('Cannot read user-ref key file: expected a readable 256-bit hex key') from None


def sanitize_name(name):
    return ''.join(c if 32 <= ord(c) <= 126 else '?' for c in name[:32])


def host_ip(explicit=None):
    if explicit:
        result = str(ipaddress.IPv4Address(explicit))
        if result == '0.0.0.0':
            raise ValueError('--host-ip must not be 0.0.0.0')
        return result
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(('192.0.2.1', 9))  # Select a route; UDP connect sends no packet.
            result = ipaddress.IPv4Address(probe.getsockname()[0])
        if not result.is_unspecified and not result.is_loopback:
            return str(result)
    except (OSError, ValueError):
        pass
    print('Warning: could not detect a non-loopback host address; set --host-ip.', file=sys.stderr)
    return '127.0.0.1'


class Telemetry:
    def __init__(self, path, component, dst_ip, dst_port):
        self.component = component
        self.instance = str(uuid.uuid4())
        self.dst_ip = host_ip(dst_ip)
        self.dst_port = dst_port
        self.hostname = socket.gethostname()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self.stream = os.fdopen(fd, 'a', encoding='utf-8')

    def emit(self, event, *, addr=None, session_id=None, outcome=None, reason=None, **extra):
        allowed = EVENTS[self.component][event]
        if set(extra) - set(allowed):
            raise ValueError('Non-allowlisted telemetry field')
        if set(extra) != set(allowed):
            raise ValueError('Missing telemetry field')
        if outcome is None:
            outcome = 'info' if event in {'server_start', 'server_stop', 'player_timeout'} else 'success'
        if outcome == 'failure':
            if reason not in FAILURES.get(event, set()):
                raise ValueError('Invalid telemetry reason')
        elif event == 'server_stop':
            if outcome != 'info' or reason not in {'signal', 'shutdown'}:
                raise ValueError('Invalid stop reason')
        elif reason is not None or outcome != ('info' if event in {'server_start', 'player_timeout'} else 'success'):
            raise ValueError('Invalid telemetry outcome')
        if event in {'malformed', 'internal_error', 'state_from_unknown'} and outcome != 'failure':
            raise ValueError('Failure outcome required')
        if 'lobby_name' in extra:
            extra['lobby_name'] = sanitize_name(extra['lobby_name'])
        # Reject object reprs and bytes before serialization.
        if any(type(v) not in (str, int, float, bool, type(None)) for v in extra.values()):
            raise ValueError('Invalid telemetry value type')
        row = dict(ts=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                   schema_version=1, event_id=str(uuid.uuid4()), server_instance_id=self.instance,
                   component=self.component, host=self.hostname, event=event, outcome=outcome, reason=reason,
                   protocol='udp', src_ip=addr[0] if addr else None, src_port=addr[1] if addr else None,
                   dst_ip=self.dst_ip, dst_port=self.dst_port, session_id=session_id, **extra)
        self.stream.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n')
        self.stream.flush()

    def session(self, number):
        return f'{self.instance}:{number}' if number is not None else None

    def error(self, exc, **context):
        self.emit('internal_error', outcome='failure', reason='exception', error_class=type(exc).__name__, **context)

    def close(self):
        self.stream.close()


class Shutdown:
    """Signal handling lets the receive loop finish without interrupting writes."""
    def __init__(self):
        self.stopped = False
        self.previous = {s: signal.signal(s, self.stop) for s in (signal.SIGINT, signal.SIGTERM)}

    def stop(self, signum, frame):
        self.stopped = True

    def restore(self):
        for s, handler in self.previous.items():
            signal.signal(s, handler)
