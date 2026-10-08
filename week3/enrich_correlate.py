"""Add cited training context and derive local domain/URL relationships.

This does not call a reputation API, run Elastic, or create MISP correlations.
"""

import csv
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent


def main():
    with (ROOT / "data/normalized_iocs.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    records = []
    domain_ids = {r["value"]: r["record_id"] for r in rows if r["type"] == "domain"}
    relations = []
    for row in rows:
        context = []
        if row["type"] == "domain" and row["value"] == "example.com":
            context.append({"fact": "Maintained as a documentation example domain", "source": "https://www.iana.org/help/example-domains", "method": "official documentation reviewed during audit", "checked_on": "2026-10-08"})
        if row["type"] == "ip-dst" and row["value"] == "198.51.100.42":
            context.append({"fact": "Member of documentation block 198.51.100.0/24 (TEST-NET-2)", "source": "https://www.rfc-editor.org/rfc/rfc5737", "method": "documentation-range classification", "checked_on": "2026-10-08"})
        if row["type"] == "sha256" and row["value"] == hashlib.sha256(b"").hexdigest():
            context.append({"fact": "SHA-256 digest of the empty byte sequence", "source": "local hashlib.sha256(b'') calculation", "method": "deterministic local calculation"})
        if row["type"] == "url":
            host = urlsplit(row["value"]).hostname
            if host in domain_ids:
                relations.append({"from_record": row["record_id"], "to_record": domain_ids[host], "relation": "URL has this host", "evidence": row["value"], "method": "parse normalized URL; exact host equality", "threat_verdict": "none"})
                context.append({"fact": f"URL host equals normalized domain record {domain_ids[host]}", "source": "local normalized CSV", "method": "syntactic relationship"})
        records.append({"indicator": row, "added_context": context, "maliciousness": "not asserted"})
    result = {"scope": "Local training context and syntactic relationships; no reputation lookup or SIEM execution", "records": records, "relationships": relations}
    out = ROOT / "data/enrichment-correlation.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out.name}: {len(records)} contextualized records, {len(relations)} local relationship(s)")


if __name__ == "__main__":
    main()
