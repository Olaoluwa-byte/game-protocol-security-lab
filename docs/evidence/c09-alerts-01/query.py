from pathlib import Path
import configparser, csv, io, json, math, os, pwd, subprocess, time

out=Path('/home/yuji/c09-alerts-01-evidence')
cfg=configparser.ConfigParser(interpolation=None)
cfg.read('/opt/splunk/etc/apps/c09_detections/local/savedsearches.conf')
cases=[json.loads(x) for x in (out/'cases.jsonl').read_text().splitlines()]
records=[]
def run(query):
    p=subprocess.run(['sudo','-n','-u','splunk','/opt/splunk/bin/splunk','search',query,'-output','csv'],capture_output=True,text=True,timeout=90)
    return {'query':query,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr,
            'rows':list(csv.DictReader(io.StringIO(p.stdout))) if p.returncode==0 else []}
for case in cases:
    prefix=case['case'].split('_')[0]
    stanza=next(n for n in cfg.sections() if n.lower().startswith(prefix+'_'))
    context=301 if prefix=='d4' else (30 if prefix=='d3b' else 1)
    # Stanzas use uppercase detection names, cases lowercase.
    earliest=math.floor(case['start'])-context
    latest=math.ceil(case['end'])+(15 if prefix=='d3b' else 1)
    selectors=' OR '.join('(src_ip="'+e['src_ip']+'" AND src_port='+str(e['src_port'])+')' for e in case['endpoints'])
    query=cfg[stanza]['search'].replace('index=c09',f'index=c09 ({selectors}) earliest={earliest} latest={latest}',1)
    record={'case':case,'stanza':stanza,'earliest':earliest,'latest':latest,**run(query)}
    record['row_count']=len(record['rows'])
    records.append(record)
    print(case['case'],record['returncode'],record['row_count'],flush=True)
extras={
    'triggered_alerts':run('| rest /servicesNS/-/c09_detections/alerts/fired_alerts | table title triggered_alert_count'),
    'ingestion':run('index=c09 earliest=1792164600 latest=now | eval ingest_delay_s=_indextime-_time | stats count min(ingest_delay_s) as min_delay max(ingest_delay_s) as max_delay avg(ingest_delay_s) as avg_delay latest(_time) as latest_event by event')
}
data={'captured_epoch':time.time(),'cases':records,**extras}
p=out/'queries.json';p.write_text(json.dumps(data,indent=2));os.chmod(p,0o600)
u=pwd.getpwnam('yuji');os.chown(p,u.pw_uid,u.pw_gid)
print('QUERY_EVIDENCE_WRITTEN',str(p),flush=True)
