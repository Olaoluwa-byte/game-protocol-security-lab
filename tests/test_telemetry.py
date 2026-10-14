import datetime
import importlib.util
import json
import ipaddress
import io
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from telemetry import COMMON, EVENTS, Telemetry, host_ip, load_key, sanitize_name, user_ref

ARTIFACTS = Path(tempfile.mkdtemp(prefix='c09-telemetry-tests-'))
print('JSONL test artifacts:', ARTIFACTS)


def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError('Timed out waiting for test condition')


def packet(kind, body=b'', version=1, length=None):
    return struct.pack('!BBH', version, kind, len(body) if length is None else length) + body


def lp(value):
    return bytes([len(value)]) + value


class LoggerTests(unittest.TestCase):
    def test_allowlists_and_metadata(self):
        values = dict(client_id=1, user_ref=user_ref(b'x'*32, b'player1'), user_ref_key_id='k1',
                      lobby_id=1, lobby_name='hello\n世界'+'x'*40, lobby_count_after=1, authenticated=True,
                      lobby_count=1, game_ip='127.0.0.1', game_port=10000, byte_count=3,
                      error_class='ValueError', tick_s=0.5, player_id=1, players_after=1,
                      duration_s=10.5, updates_received=2)
        for component, events in EVENTS.items():
            path = ARTIFACTS / (component + '-allowlist.jsonl')
            logger = Telemetry(path, component, '127.0.0.1', 9999 if component == 'master' else 10000)
            for event, fields in events.items():
                extras = {key: values[key] for key in fields}
                opts = {}
                if event == 'server_stop':
                    opts['reason'] = 'shutdown'
                if event in {'malformed', 'internal_error', 'state_from_unknown'}:
                    opts.update(outcome='failure', reason={'malformed':'short','internal_error':'exception','state_from_unknown':'not_joined'}[event])
                logger.emit(event, **opts, **extras)
                with self.assertRaises(ValueError):
                    logger.emit(event, **opts, **extras, password='never-serialize')
            logger.close()
            emitted = rows(path)
            self.assertEqual(len(emitted), len(events))
            for row in emitted:
                self.assertEqual(set(row), COMMON | set(events[row['event']]))
                self.assertEqual(uuid.UUID(row['event_id']).version, 4)
                self.assertEqual(uuid.UUID(row['server_instance_id']).version, 4)
                self.assertRegex(row['ts'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$')
                datetime.datetime.fromisoformat(row['ts'].replace('Z', '+00:00'))
            self.assertEqual(len(set(r['event_id'] for r in emitted)), len(emitted))
            second = Telemetry(path, component, '127.0.0.1', 9999)
            second.emit('server_stop', reason='shutdown')
            second.close()
            self.assertEqual(len(rows(path)), len(events)+1)
            self.assertNotEqual(rows(path)[-1]['server_instance_id'], emitted[0]['server_instance_id'])

    def test_host_ip_uses_outbound_interface(self):
        with patch('telemetry.socket.gethostname', return_value='local'), \
             patch('telemetry.socket.gethostbyname', return_value='127.0.1.1'), \
             patch('telemetry.socket.socket') as factory:
            probe = factory.return_value.__enter__.return_value
            probe.getsockname.return_value = ('192.168.252.2', 54321)
            result = host_ip()
            self.assertFalse(ipaddress.ip_address(result).is_loopback)
            self.assertNotEqual(result, '0.0.0.0')
            probe.connect.assert_called_once_with(('192.0.2.1', 9))
            probe.send.assert_not_called()
            probe.sendto.assert_not_called()
        self.assertEqual(host_ip('127.0.1.1'), '127.0.1.1')

    def test_host_ip_fallback_warns(self):
        for result in ('127.0.1.1', '0.0.0.0', 'not-an-address', OSError('no route')):
            with self.subTest(result=result), patch('telemetry.socket.socket') as factory, \
                 patch('sys.stderr', new_callable=io.StringIO) as stderr:
                probe = factory.return_value.__enter__.return_value
                if isinstance(result, Exception):
                    probe.connect.side_effect = result
                else:
                    probe.getsockname.return_value = (result, 1234)
                self.assertEqual(host_ip(), '127.0.0.1')
                self.assertEqual(len(stderr.getvalue().splitlines()), 1)
                self.assertIn('--host-ip', stderr.getvalue())

    def test_hmac_and_sanitization(self):
        first = user_ref(b'a'*32, b'user')
        self.assertEqual(first, user_ref(b'a'*32, b'user'))
        self.assertNotEqual(first, user_ref(b'b'*32, b'user'))
        self.assertEqual(len(bytes.fromhex(first.split(':')[1])), 16)
        self.assertEqual(sanitize_name('a\n\x7f界'+'b'*40), 'a???'+'b'*28)
        with self.assertRaises(ValueError):
            host_ip('0.0.0.0')
        with self.assertRaises(SystemExit):
            load_key(str(ARTIFACTS / 'missing-key'))


class ServerTests(unittest.TestCase):
    def start_servers(self, folder, baseline=False):
        folder.mkdir()
        key = folder / 'user-ref.key'
        key.write_text('ab'*32+'\n')
        scripts = ROOT / 'src'
        if baseline:
            scripts = folder
            for name in ('master.py', 'gameserver.py'):
                # v2.1 is the immutable pre-telemetry baseline; main moves forward.
                content = subprocess.check_output(['git','show',f'v2.1:src/{name}'], cwd=ROOT)
                (folder / name).write_bytes(content)
        processes = []
        for component in ('master', 'gameserver'):
            cmd = [sys.executable, '-B', '-u', str(scripts / (component+'.py'))]
            if component == 'master':
                cmd += ['127.0.0.1']
            if not baseline:
                cmd += ['--host-ip','127.0.0.1','--log-path',str(folder / (component+'.jsonl'))]
                if component == 'master':
                    cmd += ['--user-ref-key-file',str(key)]
            console = open(folder / (component+'.console'), 'w')
            proc = subprocess.Popen(cmd, cwd=ROOT, stdout=console, stderr=console)
            processes.append((proc, console))
        try:
            if baseline:
                wait_for(lambda: all('server' in (folder / (c+'.console')).read_text() for c in ('master','gameserver')))
            else:
                wait_for(lambda: all(any(r['event']=='server_start' for r in rows(folder / (c+'.jsonl'))) for c in ('master','gameserver')))
            self.assertTrue(all(p.poll() is None for p,_ in processes))
        except BaseException:
            self.stop_servers(processes)
            raise
        return processes

    def stop_servers(self, processes):
        for proc, console in processes:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT if len(processes) > 1 and proc is processes[1][0] else signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait()
            console.close()

    def client(self):
        result = subprocess.run([sys.executable,'-B',str(ROOT/'src/client.py'),'127.0.0.1','2'],
                                capture_output=True,text=True,timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('in game as player 1', result.stdout)
        self.assertIn('step 1: 1 player(s)', result.stdout)
        self.assertNotIn('no snapshot', result.stdout)
        return result.stdout

    def test_canary_correlation_and_wire(self):
        baseline = self.start_servers(ARTIFACTS/'baseline', baseline=True)
        try:
            original = self.client()
        finally:
            self.stop_servers(baseline)
        folder = ARTIFACTS/'integration'
        procs = self.start_servers(folder)
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(packet(3,lp(b'canary-user-7f3a')+lp(b'canary-pw-7f3a')),('127.0.0.1',9999))
                self.assertEqual(sock.recv(4096), packet(4,b'\x01'))
            current = self.client()
            # The unchanged asynchronous tick can return a queued prior snapshot.
            # Compare console format/flow, allowing only the coordinate timing variance.
            normalize = lambda text: re.sub(r'p1@\(\d+,-?\d+\)', 'p1@(x,y)', text)
            self.assertEqual(normalize(current), normalize(original))
            wait_for(lambda: any(r['event']=='join_handoff' for r in rows(folder/'master.jsonl')))
            master = rows(folder/'master.jsonl'); game = rows(folder/'gameserver.jsonl')
            auth = next(r for r in master if r['event']=='auth' and r['outcome']=='success')
            join = next(r for r in master if r['event']=='join_handoff')
            player = next(r for r in game if r['event']=='player_join')
            self.assertEqual((auth['src_ip'],auth['src_port']), (join['src_ip'],join['src_port']))
            self.assertEqual((auth['src_ip'],auth['src_port']), (player['src_ip'],player['src_port']))
            self.assertTrue(join['authenticated'])
            wait_for(lambda: any(r['event']=='player_timeout' for r in rows(folder/'gameserver.jsonl')), timeout=12)
            timeout = next(r for r in rows(folder/'gameserver.jsonl') if r['event']=='player_timeout')
            self.assertEqual(timeout['updates_received'],2)
            self.assertGreaterEqual(timeout['duration_s'],10)
        finally:
            self.stop_servers(procs)
        for component in ('master','gameserver'):
            text = (folder/(component+'.jsonl')).read_text()
            self.assertNotIn('canary-user-7f3a',text)
            self.assertNotIn('canary-pw-7f3a',text)
            self.assertEqual(rows(folder/(component+'.jsonl'))[-1]['reason'],'signal')

    def test_observation_does_not_enforce(self):
        folder = ARTIFACTS/'edge'
        procs = self.start_servers(folder)
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                master=('127.0.0.1',9999); game=('127.0.0.1',10000)
                for endpoint in (master,game):
                    for data in (b'x',packet(99),packet(99,length=4)):
                        sock.sendto(data,endpoint)
                # Historically accepted mismatched declared length/version; retain acceptance.
                sock.sendto(packet(1, version=9, length=7),master)
                self.assertEqual(sock.recv(4096),packet(2,struct.pack('!I',1)))
                sock.sendto(packet(7,lp(b'name\n')),master)
                sock.sendto(packet(5),master)
                self.assertEqual(sock.recv(4096),packet(6,b'\x01'+struct.pack('!I',1)+lp(b'name\n')))
                sock.sendto(packet(8,struct.pack('!I',777)),master)
                self.assertEqual(sock.recv(4096),packet(9,lp(b'127.0.0.1')+struct.pack('!H',10000)))
                sock.sendto(packet(3,struct.pack('!hh',1,2)),game)
                sock.sendto(packet(1),game); self.assertEqual(sock.recv(4096),packet(2,struct.pack('!I',1)))
                sock.sendto(packet(1),game); self.assertEqual(sock.recv(4096),packet(2,struct.pack('!I',1)))
                wait_for(lambda: any(r['event']=='player_rejoin' for r in rows(folder/'gameserver.jsonl')))
                sock.sendto(packet(3,b'\x00'),master)  # original parsing exception remains fatal
                wait_for(lambda: procs[0][0].poll() is not None)
            self.assertTrue(any(r['event']=='internal_error' and r['error_class']=='IndexError' for r in rows(folder/'master.jsonl')))
            self.assertFalse(next(r for r in rows(folder/'master.jsonl') if r['event']=='lobby_create')['authenticated'])
        finally:
            self.stop_servers(procs)

    def test_short_state_from_joined_player(self):
        folder = ARTIFACTS / 'short-state'
        procs = self.start_servers(folder)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as joined, \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unknown:
                joined.settimeout(2)
                game = ('127.0.0.1', 10000)
                joined.sendto(packet(1), game)
                self.assertEqual(joined.recv(4096), packet(2, struct.pack('!I', 1)))
                joined_port = joined.getsockname()[1]
                joined.sendto(packet(3, b'\x00'), game)
                wait_for(lambda: any(r['event'] == 'malformed' for r in rows(folder/'gameserver.jsonl')))
                # A subsequent rejoin is a processing barrier for that endpoint.
                joined.sendto(packet(1), game)
                joined.recv(4096)
                emitted = [r for r in rows(folder/'gameserver.jsonl') if r['src_port'] == joined_port]
                malformed = [r for r in emitted if r['event'] == 'malformed']
                self.assertEqual(len(malformed), 1)
                self.assertEqual(malformed[0]['reason'], 'bad_length')
                self.assertFalse(any(r['event'] == 'state_from_unknown' for r in emitted))
                unknown.sendto(packet(3, struct.pack('!hh', 1, 2)), game)
                unknown_port = unknown.getsockname()[1]
                wait_for(lambda: any(r['event'] == 'state_from_unknown' for r in rows(folder/'gameserver.jsonl')))
                unknown_rows = [r for r in rows(folder/'gameserver.jsonl') if r['src_port'] == unknown_port]
                self.assertEqual(len(unknown_rows), 1)
                self.assertEqual(unknown_rows[0]['reason'], 'not_joined')
        finally:
            self.stop_servers(procs)
        console = (folder/'gameserver.console').read_text()
        self.assertNotIn(f'event=state_from_unknown src=127.0.0.1:{joined_port}', console)
        self.assertIn(f'event=state_from_unknown src=127.0.0.1:{unknown_port}', console)

    def test_exception_privacy_both_components(self):
        key = ARTIFACTS / 'exception.key'
        key.write_text('ab'*32)
        for component in ('master', 'gameserver'):
            spec = importlib.util.spec_from_file_location('test_'+component, ROOT/'src'/(component+'.py'))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            path = ARTIFACTS / (component+'-exception.jsonl')
            argv = [component, '--log-path', str(path), '--host-ip', '127.0.0.1']
            if component == 'master':
                argv += ['--user-ref-key-file', str(key)]
            with patch.object(sys, 'argv', argv), patch.object(module.socket, 'socket') as sock:
                sock.return_value.bind.side_effect = ValueError('canary-user-7f3a canary-pw-7f3a')
                with self.assertRaises(ValueError):
                    module.main()
            emitted = rows(path)
            self.assertEqual([r['event'] for r in emitted], ['internal_error', 'server_stop'])
            self.assertEqual(emitted[0]['error_class'], 'ValueError')
            self.assertNotIn('canary-user-7f3a', path.read_text())
            self.assertNotIn('canary-pw-7f3a', path.read_text())

    def test_missing_key_refuses_start(self):
        result = subprocess.run([sys.executable,'-B',str(ROOT/'src/master.py'),
                                 '--user-ref-key-file',str(ARTIFACTS/'absent')],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Cannot read user-ref key file',result.stderr)
