"""Check local report paths, Markdown fences, sample reproducibility and evidence hashes."""

import argparse
import csv
import hashlib
import importlib.util
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

REPO = Path(__file__).resolve().parents[1]
ROLES = {
    "week2/images/osint-framework.png": "interface screenshot: source directory",
    "week2/images/sans-osint.png": "interface screenshot: educational article",
    "week2/images/shodan-search.png": "interface screenshot: broad text search; no host ownership proof",
    "week2/images/virustotal-search.png": "interface screenshot: historical domain result",
    "week2/images/maltego-graph.png": "interface screenshot: 5 manual nodes, 0 links",
    "week2/images/data-source-mapping.png": "diagram: conceptual data-source mapping",
    "week3/images/01-processing-results.png": "illustration: generated from checked processing outputs",
    "week3/images/02-misp-import-payload.png": "illustration: MISP JSON summary, not a live capture",
    "week3/images/03-misp-event-live.jpg": "interface screenshot: actual local MISP Event 1 view",
}


def exact_exists(target):
    try:
        parts = target.relative_to(REPO).parts
    except ValueError:
        return False
    current = REPO
    for part in parts:
        if not current.is_dir() or part not in {p.name for p in current.iterdir()}:
            return False
        current /= part
    return current.exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-manifest", action="store_true")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    failures = []
    local_links = 0
    reports = [p for p in REPO.rglob("*.md") if ".git" not in p.parts and ".venv" not in p.parts]
    for report in reports:
        text = report.read_text(encoding="utf-8-sig")
        visible_lines = []
        fence = None
        for line in text.splitlines():
            match = re.match(r"^\s*(`{3,}|~{3,})", line)
            if match:
                token = match.group(1)[0]
                fence = token if fence is None else (None if fence == token else fence)
                continue
            if fence is None:
                visible_lines.append(line)
        if fence:
            failures.append(f"Unclosed code fence: {report.relative_to(REPO)}")
        for match in re.finditer(r"!?\[[^\]]*\]\(([^)]+)\)", "\n".join(visible_lines)):
            href = match.group(1).strip().strip("<>")
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", href) or href.startswith("#"):
                continue
            local_links += 1
            target = (report.parent / unquote(href.split("#")[0])).resolve()
            if not exact_exists(target):
                failures.append(f"Missing or wrong-case link: {report.relative_to(REPO)} -> {href}")

    spec = importlib.util.spec_from_file_location("processor", REPO / "week3/process_iocs.py")
    processor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(processor)
    def contents(path):
        if path.suffix == ".json":
            return json.loads(path.read_text(encoding="utf-8-sig"))
        with path.open(newline="", encoding="utf-8-sig") as stream:
            return list(csv.DictReader(stream))

    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory)
        summary = processor.process(output_dir=out)
        for name in ["normalized_iocs.csv", "misp-event.json", "processing-summary.json"]:
            if contents(out / name) != contents(REPO / "week3/data" / name):
                failures.append(f"Stale generated output: week3/data/{name}")
    expected = [8, 4, 2, 2]
    counts = [summary[k] for k in ["input_records", "valid_unique_indicators", "duplicates_removed", "invalid_records_filtered"]]
    if counts != expected:
        failures.append(f"Included sample totals changed: {counts}")
    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory)
        collected = processor.process(REPO / "week2/data/collected-indicators.csv", out)
        for name in ["normalized_iocs.csv", "misp-event.json", "processing-summary.json"]:
            if contents(out / name) != contents(REPO / "week3/data/collected" / name):
                failures.append(f"Stale collected-data output: week3/data/collected/{name}")
        if collected["valid_unique_indicators"] != 1:
            failures.append("Collected screenshot domain was not processed")
    event = json.loads((REPO / "week3/data/misp-event.json").read_text())["Event"]
    with (REPO / "week3/data/normalized_iocs.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if {(r["type"], r["value"]) for r in rows} != {(a["type"], a["value"]) for a in event["Attribute"]}:
        failures.append("CSV and MISP attributes differ")
    if event["published"] or event["distribution"] != "0" or any(a["to_ids"] is not False for a in event["Attribute"]):
        failures.append("Training event flags are incorrect")
    enriched = json.loads((REPO / "week3/data/enrichment-correlation.json").read_text())
    if len(enriched["records"]) != 4 or len(enriched["relationships"]) != 1:
        failures.append("Enrichment/correlation sample output is incomplete")

    images = {p.relative_to(REPO).as_posix() for p in REPO.rglob("*") if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp"} and ".git" not in p.parts}
    if images != set(ROLES):
        failures.append(f"Unexpected/missing images: {sorted(images.symmetric_difference(ROLES))}")
    entries = [{"path": path, "kind_and_scope": ROLES[path], "sha256": hashlib.sha256((REPO / path).read_bytes()).hexdigest()} for path in sorted(images & set(ROLES))]
    manifest = REPO / "docs/evidence-manifest.json"
    if args.refresh_manifest:
        manifest.write_text(json.dumps({"images": entries}, indent=2) + "\n", encoding="utf-8")
    if not manifest.exists() or json.loads(manifest.read_text())["images"] != entries:
        failures.append("Evidence manifest is missing or stale")
    misplaced = ["week3-report.md", "process_iocs.py", "render_evidence.py", "misp-event.json", "normalized_iocs.csv", "raw_iocs.csv", "processing-summary.json", "example_domain_connection.yml", "01-processing-results.png", "02-misp-import-payload.png"]
    for name in misplaced:
        if (REPO / name).exists():
            failures.append(f"Misplaced Week 3 file remains at repository root: {name}")
    result = {"checked_at_utc": datetime.now(timezone.utc).isoformat(), "markdown_files_checked": len(reports), "local_links_checked": local_links, "image_count": len(images), "sample_counts": counts, "checks": ["relative paths and exact filename case", "closed Markdown code fences", "reproducible CSV and JSON", "CSV/MISP value agreement", "unpublished organization-only training event", "enrichment result presence", "image inventory and SHA-256 manifest", "no misplaced Week 3 root files"], "failures": failures, "status": "passed" if not failures else "failed", "scope_limit": "Local artifact checks; not a substitute for live tool execution or publication verification"}
    if args.record:
        (REPO / "docs/validation-results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
