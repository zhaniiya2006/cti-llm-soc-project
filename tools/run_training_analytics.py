"""Execute the reviewed CAR and Atomic lab searches on an isolated loopback Elasticsearch."""
import argparse
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]


def queries(mode):
    # Missing parent names must not become apparent non-explorer matches.
    car = {"size": 100, "track_total_hits": True, "query": {"bool": {
        "filter": [{"term": {"process.name": "powershell.exe"}}, {"exists": {"field": "process.parent.name"}}],
        "must_not": [{"term": {"process.parent.name": "explorer.exe"}}, {"term": {"process.parent.name": ""}}]
    }}}
    all_processes = {"size": 100, "track_total_hits": True, "query": {"match_all": {}}}
    if mode == "car":
        return {"baseline": all_processes, "car_2014_04_003": car}
    # -e is valid; the old Week 5 full-flag query misses the official atomic executor.
    encoded = {"size": 100, "track_total_hits": True, "query": {"bool": {"filter": [
        {"term": {"process.name": "powershell.exe"}},
        {"regexp": {"process.command_line": {"value": ".*[-/]([Ee]|[Ee][Nn][Cc]|[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]) +[A-Za-z0-9+/=]+.*"}}}
    ]}}}
    return {"baseline": all_processes, "car_2014_04_003": car, "encoded_powershell": encoded,
            "batch_execution": {"size": 100, "track_total_hits": True, "query": {"bool": {"filter": [
                {"term": {"process.name": "cmd.exe"}},
                {"wildcard": {"process.command_line": {"value": "*T1059.003_script.bat*", "case_insensitive": True}}}
            ]}}}}


def run(mode, data, output, elastic="http://127.0.0.1:19200"):
    if urlparse(elastic).hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Only the local course lab is supported.")
    if output.exists() and any(output.iterdir()):
        raise ValueError("Select a new/empty evidence folder.")
    records = [json.loads(line) for line in data.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    expected_cases = {"plain", "encoded", "cmd_control"} if mode == "car" else {"art_powershell", "art_batch"}
    if {r["lab"]["case_id"] for r in records} != expected_cases or len(records) != len(expected_cases):
        raise ValueError("Unexpected or duplicate source cases.")
    for record in records:
        if not record["process"]["parent"]["name"] or record["lab"]["ground_truth"] != "benign":
            raise ValueError("Missing parent context or unreviewed ground truth.")
    output.mkdir(parents=True, exist_ok=True)
    transcript = []

    def request(path, method="GET", body=None, ndjson=False):
        raw = body.encode() if ndjson else (json.dumps(body).encode() if body is not None else None)
        with urlopen(Request(elastic + path, data=raw, method=method, headers={"Content-Type": "application/x-ndjson" if ndjson else "application/json"}), timeout=45) as response:
            result = json.load(response)
            transcript.append({"timestamp_utc": datetime.now(timezone.utc).isoformat(), "method": method, "path": path, "http_status": response.status, "request": body, "response": result})
        (output / "api-transcript.json").write_text(json.dumps(transcript, indent=2) + "\n", encoding="utf-8")
        return result

    version = request("/")["version"]["number"]
    index = f"cti-week{'7' if mode == 'car' else '9'}-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
    mapping = {"settings": {"number_of_shards": 1, "number_of_replicas": 0}, "mappings": {"properties": {
        "@timestamp": {"type": "date"}, "process": {"properties": {"name": {"type": "keyword"}, "pid": {"type": "long"}, "command_line": {"type": "keyword"}, "parent": {"properties": {"name": {"type": "keyword"}, "pid": {"type": "long"}}}}},
        "lab": {"properties": {"case_id": {"type": "keyword"}, "run_id": {"type": "keyword"}, "ground_truth": {"type": "keyword"}, "technique": {"type": "keyword"}}}
    }}}
    request("/" + index, "PUT", mapping)
    bulk = "".join(json.dumps({"create": {"_index": index, "_id": r["lab"]["case_id"]}}) + "\n" + json.dumps(r) + "\n" for r in records)
    response = request("/_bulk?refresh=wait_for", "POST", bulk, True)
    if response["errors"] or any(i["create"]["status"] != 201 for i in response["items"]):
        raise RuntimeError("Bulk ingestion failed.")
    request(f"/{index}/_mapping")
    expected = {"baseline": expected_cases, "car_2014_04_003": {"plain", "encoded"} if mode == "car" else {"art_powershell"}, "encoded_powershell": {"art_powershell"}, "batch_execution": {"art_batch"}}
    executed = queries(mode)
    results = {}
    for name, query in executed.items():
        response = request(f"/{index}/_search", "POST", query)
        cases = {h["_source"]["lab"]["case_id"] for h in response["hits"]["hits"]}
        total = response["hits"]["total"]
        if response["timed_out"] or response["_shards"]["failed"] or total["relation"] != "eq" or cases != expected[name] or total["value"] != len(cases):
            raise RuntimeError(f"Incomplete/unexpected search: {name}")
        results[name] = {"count": total["value"], "case_ids": sorted(cases), "response": response}
    result = {"executed_at_utc": datetime.now(timezone.utc).isoformat(), "elasticsearch_version": version, "index": index, "dataset_sha256": hashlib.sha256(data.read_bytes()).hexdigest(), "ingested_documents": len(records), "results": results, "scope": "Actual Elasticsearch searches on benign controlled native process observations. No production malware efficacy or deployed alert rule claim."}
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (output / "queries.json").write_text(json.dumps(executed, indent=2) + "\n", encoding="utf-8")
    (output / "kibana-console.txt").write_text("\n\n".join(f"# {name}\nGET {index}/_search\n" + json.dumps(query, indent=2) for name, query in executed.items()) + "\n", encoding="utf-8")
    print(json.dumps({"index": index, "counts": {k: v["count"] for k, v in results.items()}}, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["car", "atomic"])
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--elastic", default="http://127.0.0.1:19200")
    args = parser.parse_args()
    run(args.mode, args.data, args.output, args.elastic)
