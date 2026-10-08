"""Index the archived genuine lab events and execute queries in local Elasticsearch."""
import argparse
import hashlib
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent


def run(output, elastic="http://127.0.0.1:9200", kibana="http://127.0.0.1:5601", resume=False):
    for url in (elastic, kibana):
        if urlparse(url).hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("This runner supports only the existing local training lab.")
    if output.exists() and any(output.iterdir()) and not resume:
        raise ValueError("Existing evidence is protected; select a new output directory for replay.")
    output.mkdir(parents=True, exist_ok=True)
    transcript_path = output / "api-transcript.json"
    transcript = json.loads(transcript_path.read_text()) if resume else []
    if resume and (output / "hunt-results.json").exists():
        raise ValueError("Completed evidence is protected; use a new output directory.")

    def request(base, path, method="GET", data=None, ndjson=False):
        encoded = data.encode() if ndjson else (json.dumps(data).encode() if data is not None else None)
        headers = {"Content-Type": "application/x-ndjson" if ndjson else "application/json", "kbn-xsrf": "cti-week5"}
        try:
            with urlopen(Request(base + path, data=encoded, method=method, headers=headers), timeout=45) as response:
                status = response.status
                body = json.loads(response.read())
        except HTTPError as error:
            status = error.code
            body = json.loads(error.read())
        transcript.append({"timestamp_utc": datetime.now(timezone.utc).isoformat(), "method": method, "url": base + path, "request_body": data, "http_status": status, "response": body})
        (output / "api-transcript.json").write_text(json.dumps(transcript, indent=2) + "\n", encoding="utf-8")
        if status >= 400:
            raise RuntimeError(f"HTTP {status}: {body}")
        return body

    dataset = ROOT / "data/powershell-events.jsonl"
    records = [json.loads(line) for line in dataset.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    if len(records) != 4 or len({record["winlog"]["record_id"] for record in records}) != 4:
        raise ValueError("Expected four distinct archived native events.")
    queries_path = ROOT / "hunt-queries.json"
    queries = json.loads(queries_path.read_text())
    index = "cti-week5-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
    if resume:
        index_requests = [entry for entry in transcript if entry["method"] == "PUT" and entry["url"].startswith(elastic + "/cti-week5-") and entry["http_status"] == 200]
        if len(index_requests) != 1:
            raise ValueError("Resume requires one acknowledged lab index creation.")
        index = index_requests[0]["url"].removeprefix(elastic + "/")
    version = request(elastic, "/")
    license_info = request(elastic, "/_license")
    kibana_status = request(kibana, "/api/status")
    if kibana_status["status"]["overall"]["level"] != "available":
        raise RuntimeError("Kibana is not ready.")
    kibana_version = kibana_status.get("version", {}).get("number")
    version_source = "/api/status"
    if kibana_version is None:
        # The unauthenticated status endpoint may expose health only.
        # Obtain the actual installed version from the existing local container.
        installed = subprocess.run(["docker", "exec", "threat-hunting-week5-kibana-1", "cat", "/usr/share/kibana/package.json"], capture_output=True, text=True)
        kibana_version = json.loads(installed.stdout)["version"] if installed.returncode == 0 else "unavailable"
        version_source = "package.json in existing local Kibana container" if installed.returncode == 0 else "not exposed"
    mappings = {"settings": {"number_of_shards": 1, "number_of_replicas": 0}, "mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {"code": {"type": "keyword"}, "provider": {"type": "keyword"}, "action": {"type": "keyword"}}},
        "winlog": {"properties": {"channel": {"type": "keyword"}, "record_id": {"type": "long"}}},
        "host": {"properties": {"name": {"type": "keyword"}}},
        "process": {"properties": {"name": {"type": "keyword"}, "pid": {"type": "integer"}, "command_line": {"type": "keyword"}}},
        "lab": {"properties": {"run_id": {"type": "keyword"}, "case_id": {"type": "keyword"}, "ground_truth": {"type": "keyword"}}},
    }}}
    if not resume:
        request(elastic, "/" + index, "PUT", mappings)
    lines = []
    for record in records:
        lines.extend([json.dumps({"create": {"_index": index, "_id": str(record["winlog"]["record_id"])}}), json.dumps(record)])
    bulk_text = "\n".join(lines) + "\n"
    if resume:
        bulk_requests = [entry for entry in transcript if entry["url"] == elastic + "/_bulk?refresh=wait_for" and entry["http_status"] == 200]
        if len(bulk_requests) != 1 or bulk_requests[0]["request_body"] != bulk_text:
            raise ValueError("Archived dataset differs from the acknowledged ingestion.")
        bulk = bulk_requests[0]["response"]
        if request(elastic, f"/{index}/_count")["count"] != len(records):
            raise ValueError("Index contents changed since ingestion.")
    else:
        bulk = request(elastic, "/_bulk?refresh=wait_for", "POST", bulk_text, ndjson=True)
    if bulk["errors"] or any(item["create"]["status"] != 201 for item in bulk["items"]):
        raise RuntimeError("Indexing failed; inspect the saved transcript.")
    view = request(kibana, "/api/data_views/data_view", "POST", {"data_view": {"title": index, "name": "CTI Week 5 " + index, "timeFieldName": "@timestamp"}})
    expected = {"baseline": {"plain", "encoded", "hidden", "encoded_hidden"}, "encoded": {"encoded", "encoded_hidden"}, "encoded_hidden": {"encoded_hidden"}}
    results = {}
    for name, query in queries.items():
        response = request(elastic, f"/{index}/_search", "POST", query)
        if response.get("timed_out") or response["_shards"]["failed"]:
            raise RuntimeError("Search execution was incomplete.")
        actual = {hit["_source"]["lab"]["case_id"] for hit in response["hits"]["hits"]}
        if actual != expected[name] or response["hits"]["total"]["value"] != len(expected[name]):
            raise RuntimeError(f"Unexpected cases returned by {name}: {actual}")
        results[name] = {"count": response["hits"]["total"]["value"], "case_ids": sorted(actual), "query": query, "response": response}
    evidence = {
        "executed_at_utc": datetime.now(timezone.utc).isoformat(), "index": index,
        "data_view_id": view["data_view"]["id"], "elasticsearch_version": version["version"]["number"],
        "kibana_version": kibana_version, "kibana_version_source": version_source, "license_type": license_info["license"]["type"],
        "dataset_sha256": hashlib.sha256(dataset.read_bytes()).hexdigest(),
        "queries_sha256": hashlib.sha256(queries_path.read_bytes()).hexdigest(),
        "ingested_documents": len(records), "results": results,
        "scope": "Real Elasticsearch execution on four genuine events from benign controlled PowerShell launches; no malware detection efficacy claim",
    }
    (output / "hunt-results.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    (output / "executed-queries.json").write_text(json.dumps(queries, indent=2) + "\n", encoding="utf-8")
    console = "\n\n".join(f"# {name}\nGET {index}/_search\n" + json.dumps(query, indent=2) for name, query in queries.items())
    (output / "kibana-console.txt").write_text(console + "\n", encoding="utf-8")
    print(json.dumps({"index": index, "data_view_id": evidence["data_view_id"], "counts": {name: result["count"] for name, result in results.items()}, "versions": [evidence["elasticsearch_version"], evidence["kibana_version"]]}, indent=2))
    return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "evidence/live-run")
    parser.add_argument("--resume", action="store_true", help="Complete a partial run without reindexing; completed evidence remains protected")
    args = parser.parse_args()
    run(args.output_dir, resume=args.resume)
