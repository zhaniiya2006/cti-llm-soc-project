"""Verify provenance and agreement of archived Week 5 execution evidence, offline."""
import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify():
    week = ROOT / "week5"
    data = week / "data"
    evidence = week / "evidence/live-run"
    manifest = json.loads((data / "collection-manifest.json").read_text(encoding="utf-8-sig"))
    records = [json.loads(line) for line in (data / "powershell-events.jsonl").read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    cases = {case["case_id"]: case for case in manifest["cases"]}
    assert set(cases) == {"plain", "encoded", "hidden", "encoded_hidden"}
    assert len(records) == manifest["event_count"] == 4
    assert hashlib.sha256((week / "collect_lab_events.ps1").read_bytes()).hexdigest() == manifest["collector_sha256"]
    assert len({record["winlog"]["record_id"] for record in records}) == 4
    for artifact in manifest["artifacts"]:
        assert hashlib.sha256((data / artifact["path"]).read_bytes()).hexdigest() == artifact["sha256"]
    events = {int(event.find("{*}System/{*}EventRecordID").text): event for event in ET.parse(data / "windows-events.xml").getroot()}
    report = (week / "week5-report.md").read_text(encoding="utf-8-sig")
    for record in records:
        case = cases[record["lab"]["case_id"]]
        assert record["lab"]["run_id"] == manifest["run_id"]
        assert case["exit_code"] == 0 and case["ground_truth"] == record["lab"]["ground_truth"] == "benign"
        marker = f"CTIW5-{manifest['run_id']}-{case['case_id']}"
        assert case["stdout"] == marker and case["payload"] == f"Write-Output '{marker}'"
        assert record["process"]["pid"] == case["pid"]
        assert record["winlog"]["record_id"] == case["record_id"]
        assert record["process"]["command_line"] == case["command_line"]
        assert datetime.fromisoformat(record["@timestamp"]) == datetime.fromisoformat(case["timestamp_utc"])
        assert f"| `{case['case_id']}` | {case['record_id']} | {case['pid']} |" in report
        event = events[case["record_id"]]
        system = event.find("{*}System")
        assert system.find("{*}EventID").text == record["event"]["code"] == "400"
        assert int(system.find("{*}Execution").get("ProcessID")) == case["pid"]
        assert system.find("{*}Computer").text == record["host"]["name"] == "CTI-LAB-HOST"
        assert datetime.fromisoformat(system.find("{*}TimeCreated").get("SystemTime")) == datetime.fromisoformat(case["timestamp_utc"])
        security = system.find("{*}Security")
        assert security is None or security.get("UserID") in {None, "S-1-0-0"}
        context = "\n".join(node.text or "" for node in event.findall("{*}EventData/{*}Data"))
        assert re.search(r"(?m)^\s*HostApplication=([^\r\n]*)", context).group(1) == case["command_line"]
        encoded = re.search(r"-EncodedCommand\s+(\S+)", case["command_line"], re.I)
        if encoded:
            assert base64.b64decode(encoded.group(1), validate=True).decode("utf-16-le") == case["payload"]
        else:
            assert case["payload"] in case["command_line"]
    results = json.loads((evidence / "hunt-results.json").read_text())
    queries = json.loads((week / "hunt-queries.json").read_text())
    executed = json.loads((evidence / "executed-queries.json").read_text())
    transcript = json.loads((evidence / "api-transcript.json").read_text())
    assert results["dataset_sha256"] == hashlib.sha256((data / "powershell-events.jsonl").read_bytes()).hexdigest()
    assert results["queries_sha256"] == hashlib.sha256((week / "hunt-queries.json").read_bytes()).hexdigest()
    assert queries == executed and results["ingested_documents"] == 4
    expected = {"baseline": {"plain", "encoded", "hidden", "encoded_hidden"}, "encoded": {"encoded", "encoded_hidden"}, "encoded_hidden": {"encoded_hidden"}}
    for name, expected_cases in expected.items():
        result = results["results"][name]
        assert result["query"] == queries[name] and result["count"] == len(expected_cases)
        assert set(result["case_ids"]) == expected_cases
        response = result["response"]
        assert not response["timed_out"] and response["_shards"]["failed"] == 0
        assert response["hits"]["total"] == {"value": len(expected_cases), "relation": "eq"}
        returned = {hit["_source"]["lab"]["case_id"] for hit in response["hits"]["hits"]}
        assert returned == expected_cases
        for hit in response["hits"]["hits"]:
            assert hit["_index"] == results["index"]
            assert hit["_source"] in records
        assert any(entry["url"].endswith(f"/{results['index']}/_search") and entry["request_body"] == result["query"] and entry["response"] == response and entry["http_status"] == 200 for entry in transcript)
    runtime = json.loads((evidence / "runtime.json").read_text(encoding="utf-8-sig"))
    assert runtime["kibana_version"] == "9.5.5"
    assert runtime["host_bindings"] == ["127.0.0.1:9200", "127.0.0.1:5601"]
    result = {"status": "passed", "native_events": 4, "actual_query_counts": [4, 2, 1], "checks": ["manifest hashes", "native XML/derived JSON/PID/time agreement", "benign payload decoding and ground truth", "report record IDs and PIDs", "exact query/response/API transcript agreement"], "scope": "Offline consistency check of preserved real execution; does not query a live SIEM or establish detection efficacy"}
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    verify()
