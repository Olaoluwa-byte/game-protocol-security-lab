from pathlib import Path
from datetime import datetime
import json

p=Path('/tmp/c09-alerts-01-evidence')
cases=[json.loads(x) for x in (p/'cases.jsonl').read_text().splitlines()]
def epoch(r): return datetime.fromisoformat(r['ts'].replace('Z','+00:00')).timestamp()
master=[json.loads(x) for x in Path('/Users/bossman/c09-logs/master/master.jsonl').read_text().splitlines()]
game=[json.loads(x) for x in Path('/Users/bossman/c09-logs/game/gameserver.jsonl').read_text().splitlines()]
master=[r for r in master if epoch(r)>1792164600]
game=[r for r in game if epoch(r)>1792164600]
hello=[r for r in master if r['event']=='hello']
def ep(r):return (r['src_ip'],r['src_port'])
all_master_eps={ep(r) for r in hello}
pointer=0;used=set();proof=[]
for case in cases:
    name=case['case']
    count={'d2_negative':3,'d3a_positive':2,'d3b_positive':2,'d3b_negative':2,'d4_positive':0}.get(name,1)
    selected=hello[pointer:pointer+count];pointer+=count
    assert len(selected)==count
    assert all(case['start']-.3 <= epoch(r) <= case['end']+.3 for r in selected),(name,selected)
    eps={ep(r) for r in selected}
    if name=='d4_positive':
        joins=[r for r in game if r['event']=='player_join' and ep(r) not in all_master_eps and case['start']-.3<=epoch(r)<=case['end']+.3]
        assert len(joins)==1,(name,joins)
        eps={ep(joins[0])}
    assert not used.intersection(eps),'endpoint reuse requires different isolation'
    used.update(eps)
    m=[r for r in master if r.get('src_ip') is not None and ep(r) in eps]
    g=[r for r in game if r.get('src_ip') is not None and ep(r) in eps]
    failures=[r for r in m if r['event']=='auth' and r['outcome']=='failure']
    success=[r for r in m if r['event']=='auth' and r['outcome']=='success']
    creates=[r for r in m if r['event']=='lobby_create']
    joins=[r for r in g if r['event']=='player_join']
    handoffs=[r for r in m if r['event']=='join_handoff']
    signature={'failed_auth':len(failures),'distinct_failed_accounts':len({r['user_ref'] for r in failures}),
               'distinct_successful_accounts':len({r['user_ref'] for r in success}),'key_ids':sorted({r['user_ref_key_id'] for r in failures+success}),'successful_auth':len(success),'success_endpoints':len({ep(r) for r in success}),
               'lobby_creates':len(creates),'game_joins':len(joins),'handoffs':len(handoffs)}
    if name=='d1_positive': assert len(failures)==6
    if name=='d1_negative': assert len(failures)==1 and len(success)==1
    if name=='d2_positive': assert signature['distinct_failed_accounts']==6
    if name=='d2_negative': assert signature['distinct_failed_accounts']==3
    if name=='d3a_positive': assert len(success)==2 and signature['success_endpoints']==2
    if name=='d3a_negative': assert len(success)==2 and signature['success_endpoints']==1
    if name.startswith('d3b_'):
        assert len(joins)==2 and len(success)==2 and signature['distinct_successful_accounts']==1
        first,second=sorted(joins,key=epoch)
        timeout=next(r for r in g if r['event']=='player_timeout' and ep(r)==ep(first))
        signature['first_timeout_before_second_join']=epoch(timeout)<epoch(second)
        assert signature['first_timeout_before_second_join']==name.endswith('_negative')
    if name=='d4_positive': assert len(joins)==1 and len(handoffs)==0
    if name=='d4_negative': assert len(joins)==1 and len(handoffs)==1
    if name=='d5_positive': assert len(creates)==1 and creates[0]['authenticated'] is False
    if name=='d5_negative': assert len(creates)==1 and creates[0]['authenticated'] is True
    if name=='d6_positive': assert len(creates)==15
    if name=='d6_negative': assert len(creates)==3
    case['endpoints']=[{'src_ip':ip,'src_port':port} for ip,port in sorted(eps)]
    case['endpoint_assignment']='derived from ordered HELLO events and generator socket counts; unmatched game endpoint for D4 positive; unique endpoints and ±0.3 s time bounds asserted'
    case['observed_signature']=signature
    proof.append({'case':case,'events':[{k:r[k] for k in ('ts','event','src_ip','src_port','outcome','authenticated') if k in r}
                                       for r in sorted(m+g,key=epoch)]})
assert pointer==len(hello),(pointer,len(hello))
(p/'cases-enriched.jsonl').write_text(''.join(json.dumps(c)+'\n' for c in cases))
(p/'case-signatures.json').write_text(json.dumps(proof,indent=2))
print('PASS: all case endpoint assignments and telemetry signatures',len(cases))
