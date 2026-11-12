"""Run labelled synthetic CAR boundary controls in a separate Elasticsearch index."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from run_training_analytics import queries

ROOT = Path(__file__).resolve().parents[1]


def run(output):
    if output.exists():
        raise ValueError("Completed control evidence is protected.")
    index = 'cti-synthetic-controls-' + uuid.uuid4().hex[:12]
    transcript = []

    def call(path, method='GET', body=None, ndjson=False):
        raw = body.encode() if ndjson else json.dumps(body).encode() if body is not None else None
        with urlopen(Request('http://127.0.0.1:19200' + path, data=raw, method=method, headers={'Content-Type':'application/x-ndjson' if ndjson else 'application/json'}), timeout=30) as response:
            value = json.load(response)
            transcript.append({'path':path,'method':method,'request':body,'status':response.status,'response':value})
            return value

    call('/'+index,'PUT',{'settings':{'number_of_replicas':0},'mappings':{'properties':{'process':{'properties':{'name':{'type':'keyword'},'parent':{'properties':{'name':{'type':'keyword'}}}}}}}})
    fixtures = {
        'non_explorer':{'process':{'name':'powershell.exe','parent':{'name':'cmd.exe'}}},
        'explorer':{'process':{'name':'powershell.exe','parent':{'name':'explorer.exe'}}},
        'missing_parent':{'process':{'name':'powershell.exe'}},
        'empty_parent':{'process':{'name':'powershell.exe','parent':{'name':''}}},
        'wrong_child':{'process':{'name':'cmd.exe','parent':{'name':'pwsh.exe'}}},
    }
    bulk=''.join(json.dumps({'create':{'_index':index,'_id':name}})+'\n'+json.dumps({**value,'evidence_kind':'synthetic_boundary_fixture'})+'\n' for name,value in fixtures.items())
    ingested=call('/_bulk?refresh=wait_for','POST',bulk,True)
    if ingested['errors']:
        raise RuntimeError('Control ingestion failed.')
    response=call('/'+index+'/_search','POST',queries('car')['car_2014_04_003'])
    if response['timed_out'] or response['_shards']['failed'] or {h['_id'] for h in response['hits']['hits']} != {'non_explorer'} or response['hits']['total'] != {'value':1,'relation':'eq'}:
        raise AssertionError('CAR boundary check failed.')
    result={'executed_at_utc':datetime.now(timezone.utc).isoformat(),'scope':'Five synthetic fixtures, separate index; not native events or malware efficacy evidence','index':index,'expected_matched_ids':['non_explorer'],'transcript':transcript,'status':'passed'}
    output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('Five synthetic CAR boundary controls: passed; only non_explorer matched.')


if __name__ == '__main__':
    run(ROOT/'docs/query-controls.json')
