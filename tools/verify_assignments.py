"""Check native-evidence provenance, actual response consistency and supporting artifacts."""
import argparse
import base64
import csv
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def verify():
    failures=[]
    counts={}
    def check(condition, message):
        if not condition:
            failures.append(message)
    collector_hash=hashlib.sha256((ROOT/'tools/collect_training.ps1').read_bytes()).hexdigest()
    for week, expected in [('week7',{'baseline':3,'car_2014_04_003':2}),('week9',{'baseline':2,'car_2014_04_003':1,'encoded_powershell':1,'batch_execution':1})]:
        data=ROOT/week/'data/live-run'
        manifest=read(data/'collection-manifest.json')
        check(manifest['collector_sha256']==collector_hash, f'{week}: collector changed after collection')
        for entry in manifest['artifacts']:
            check(hashlib.sha256((data/entry['path']).read_bytes()).hexdigest()==entry['sha256'],f'{week}: artifact digest mismatch {entry["path"]}')
        rows=[json.loads(line) for line in (data/'process-observations.jsonl').read_text(encoding='utf-8').splitlines()]
        check(len(rows)==manifest['count']==len(manifest['cases']),f'{week}: collection count mismatch')
        cases={c['case_id']:c for c in manifest['cases']}
        xml=ET.parse(data/'powershell-event400.xml')
        xml_pids={int(n.attrib['ProcessID']) for n in xml.findall('.//{*}Execution')}
        check(xml_pids=={r['process']['pid'] for r in rows if r['process']['name']=='powershell.exe'},f'{week}: native Event400 PID corroboration mismatch')
        for row in rows:
            case=cases[row['lab']['case_id']]
            check(row['process']['pid']==case['pid'] and case['exit_code']==0,f'{week}: execution/PID mismatch')
            check(row['lab']['run_id']==manifest['run_id'] and row['lab']['ground_truth']=='benign',f'{week}: run/ground truth mismatch')
            check(bool(row['process']['parent']['name']),f'{week}: missing native parent')
            parent_time=datetime.fromisoformat(row['observation']['parent_created_utc'].replace('Z','+00:00'))
            creation=datetime.fromisoformat(row['@timestamp'].replace('Z','+00:00'))
            sampled=datetime.fromisoformat(row['observation']['sampled_at_utc'].replace('Z','+00:00'))
            check(parent_time<=creation<=sampled,f'{week}: native timestamps do not support parent relationship')
        evidence=ROOT/week/'evidence/live-run'
        results=read(evidence/'results.json')
        check(results['dataset_sha256']==hashlib.sha256((data/'process-observations.jsonl').read_bytes()).hexdigest(),f'{week}: result data digest mismatch')
        transcript=read(evidence/'api-transcript.json')
        searches=[entry for entry in transcript if entry['path'].endswith('/_search')]
        queries=read(evidence/'queries.json')
        check(len(searches)==len(queries),f'{week}: search count mismatch')
        bulk=[entry for entry in transcript if entry['path'].startswith('/_bulk')]
        check(len(bulk)==1 and bulk[0]['response']['errors'] is False,f'{week}: ingestion not established')
        if bulk:
            source_rows=[json.loads(line) for line in bulk[0]['request'].splitlines()[1::2]]
            check(source_rows==rows,f'{week}: ingested records differ from collection')
        for (name,query),entry in zip(queries.items(),searches):
            response=entry['response']; saved=results['results'][name]
            check(entry['http_status']==200 and entry['request']==query and saved['response']==response,f'{week}: saved query/response mismatch {name}')
            check(not response['timed_out'] and response['_shards']['failed']==0,f'{week}: incomplete search {name}')
            check(response['hits']['total']=={'value':expected[name],'relation':'eq'} and saved['count']==expected[name],f'{week}: unexpected count {name}')
            check(sorted(h['_source']['lab']['case_id'] for h in response['hits']['hits'])==saved['case_ids'],f'{week}: case list differs {name}')
        counts[week]={k:v['count'] for k,v in results['results'].items()}
        summary=read(evidence/'ui-summary-check.json')
        check(summary['http_status']==200 and {k:v['doc_count'] for k,v in summary['response']['aggregations']['checks']['buckets'].items()}==expected,f'{week}: UI summary count mismatch')
        check(summary['request']['aggs']['checks']['filters']['filters']=={name:query['query'] for name,query in queries.items()},f'{week}: UI predicates differ from executed searches')
    selection=read(ROOT/'week9/data/live-run/atomic-selection.json')
    check({t['guid'] for t in selection['tests']}=={'a538de64-1c74-46ed-aa60-b995ed302598','9e8894c0-50bd-4525-a96c-d4ac78ece388'},'Atomic GUID mismatch')
    ps=selection['tests'][0]
    check(base64.b64decode(ps['actual_encoded_input']).decode('utf-16le')==ps['decoded_default']+'; Start-Sleep -Seconds 4','Atomic encoded input does not match disclosed override')
    check(selection['tests'][1]['cleanup_verified'] is True,'Batch cleanup not verified')
    ps_rows=[json.loads(x) for x in (ROOT/'week9/data/live-run/process-observations.jsonl').read_text().splitlines()]
    check(next(r for r in ps_rows if r['lab']['case_id']=='art_powershell')['process']['parent']['name']=='cmd.exe','Atomic command_prompt executor not established')
    for path in [ROOT/'week6/navigator/powershell-layer.json',ROOT/'week10/navigator/apt29-study-layer.json']:
        value=read(path)
        check(value['domain']=='enterprise-attack' and value['versions']['layer']=='4.5',f'Invalid layer envelope: {path.name}')
        check(all(re.fullmatch(r'T\d{4}(\.\d{3})?',t['techniqueID']) for t in value['techniques']),f'Invalid technique ID: {path.name}')
        check(all('score' not in t for t in value['techniques']),f'Unsupported numerical coverage score: {path.name}')
    with (ROOT/'week10/data/apt29-mapping.csv').open(encoding='utf-8',newline='') as stream:
        mapping=list(csv.DictReader(stream))
    check(len(mapping)==6 and all(r['source_url'].startswith('https://cloud.google.com/') for r in mapping),'APT source mapping incomplete')
    controls=read(ROOT/'docs/query-controls.json')
    check(controls['status']=='passed' and 'synthetic' in controls['scope'].lower(),'Synthetic controls not labelled/passed')
    last=controls['transcript'][-1]['response']
    check({h['_id'] for h in last['hits']['hits']}=={'non_explorer'},'CAR controls returned wrong boundary case')
    # Reject accidental publication of local account identifiers from CLIXML/output.
    for folder in ['week7','week9']:
        for path in (ROOT/folder).rglob('*'):
            if path.is_file() and path.suffix in {'.json','.jsonl','.xml','.txt'}:
                text=path.read_text(encoding='utf-8-sig')
                check(not re.search(r'[A-Z]:\\+Users\\+|<S N="User">(?!CTI-LAB-USER)',text,re.I),f'Unredacted local identity: {path.relative_to(ROOT)}')
    result={'checked_at_utc':datetime.now(timezone.utc).isoformat(),'counts':counts,'checks':['native child/parent/timestamp provenance','Event400 PID corroboration','collector and artifact SHA-256','bulk source equality','actual query/response/count consistency','Atomic input and cleanup','Navigator envelope and no numerical coverage claims','APT source locators','separate synthetic boundary controls','published text identity scan'],'failures':failures,'status':'passed' if not failures else 'failed'}
    print(json.dumps(result,indent=2))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', action='store_true', help='Refresh the committed validation summary after review')
    args=parser.parse_args()
    result=verify()
    if args.record:
        (ROOT/'docs/assignments-validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    raise SystemExit(bool(result['failures']))
