from pathlib import Path
import csv, gzip, hashlib, json, os, pwd, re, subprocess, tarfile, time

backup = Path('/var/backups/c09-alerts-01-20261016')
out = Path('/home/yuji/c09-alerts-01-evidence')
out.mkdir(mode=0o700, exist_ok=True)
app = Path('/opt/splunk/etc/apps/c09_detections')
lines = [x for x in Path('/opt/splunk/var/log/splunk/scheduler.log').read_text().splitlines()
         if 'app="c09_detections"' in x]
rows = []
jobs = {}
for line in lines:
    fields = {k: v.strip('"') for k, v in re.findall(r'(?:^|, )([a-z_]+)=("[^"]*"|[^,]*)', line)}
    row = {k: fields[k] for k in ('savedsearch_name', 'status', 'scheduled_time', 'dispatch_time',
                                 'run_time', 'result_count', 'sid', 'suppressed', 'alert_actions') if k in fields}
    rows.append(row)
    sid = row.get('sid', '')
    if not sid.startswith('scheduler__nobody_YzA5X2RldGVjdGlvbnM__'):
        continue
    folder = Path('/opt/splunk/var/run/splunk/dispatch') / sid
    results = folder / 'results.csv.gz'
    job = {'files': sorted(p.name for p in folder.iterdir())} if folder.exists() else {'expired': True}
    if results.exists():
        with gzip.open(results, 'rt') as f:
            job['results'] = list(csv.DictReader(f))
    info = folder / 'info.csv'
    if info.exists():
        with info.open() as f:
            data = list(csv.DictReader(f))
        allowed = {'sid', 'resultcount', 'eventcount', 'scancount', 'earliesttime', 'latesttime', 'isdone', 'isfailed'}
        job['info'] = [{k:v for k,v in r.items() if k.strip('_').lower() in allowed} for r in data]
    jobs[sid] = job

raw = subprocess.check_output(['/opt/splunk/bin/splunk', 'btool', 'savedsearches', 'list', '--app=c09_detections'], text=True)
cfg = {}
section = None
allowed = {'search','enableSched','cron_schedule','dispatch.earliest_time','dispatch.latest_time',
           'counttype','relation','quantity','alert.track','alert.digest_mode','disabled'}
for line in raw.splitlines():
    if line.startswith('['):
        section = line.strip('[]') if re.match(r'\[D[1-6]', line) else None
        if section:
            cfg[section] = {}
    elif section and ' = ' in line:
        k,v = line.split(' = ', 1)
        if k in allowed or re.fullmatch(r'action\.[\w]+', k):
            cfg[section][k] = v
unchanged = {}
with tarfile.open(backup/'before.tgz') as t:
    for member in t.getmembers():
        if member.isfile():
            f = Path('/opt/splunk') / member.name
            unchanged[member.name] = f.read_bytes() == t.extractfile(member).read()
state = subprocess.check_output(['systemctl','show','Splunkd','-p','ActiveState','-p','SubState','-p','ActiveEnterTimestamp'],text=True)
snapshot = {'captured_epoch':time.time(),'service':state,'config_sha256':hashlib.sha256((app/'local/savedsearches.conf').read_bytes()).hexdigest(),
            'other_configuration_unchanged':unchanged,'effective_config':cfg,'scheduler':rows,'jobs':jobs}
target = out/'runtime.json'
target.write_text(json.dumps(snapshot,indent=2))
os.chmod(target,0o600)
user=pwd.getpwnam('yuji'); os.chown(target,user.pw_uid,user.pw_gid)
(backup/f'runtime-{int(time.time())}.json').write_text(target.read_text())
latest = {}
for row in rows: latest[row.get('savedsearch_name','unknown')] = row
print(json.dumps({'captured_epoch':snapshot['captured_epoch'],'service':state,'sha256':snapshot['config_sha256'],
                 'other_configuration_unchanged':unchanged,'latest':latest},indent=2))
