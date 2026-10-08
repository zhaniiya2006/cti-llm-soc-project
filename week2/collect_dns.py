"""Collect public DNS answers for the reserved training domain; no host scanning."""
import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

TYPES = {"A": 1, "NS": 2, "MX": 15, "AAAA": 28}


def collect(output):
    output.mkdir(parents=True, exist_ok=True)
    observations, edges = [], []
    for record_type, number in TYPES.items():
        url = "https://dns.google/resolve?" + urlencode({
            "name": "example.com", "type": record_type,
            "edns_client_subnet": "0.0.0.0/0", "do": "true",
        })
        with urlopen(Request(url, headers={"Accept": "application/dns-json"}), timeout=30) as response:
            raw = response.read()
        answer = json.loads(raw)
        if answer.get("Status") != 0 or answer.get("TC"):
            raise RuntimeError(f"Unusable DNS response for {record_type}")
        observed_at = datetime.now(timezone.utc).isoformat()
        name = f"example-com-{record_type.lower()}.json"
        (output / name).write_bytes(raw)
        observations.append({
            "record_type": record_type, "url": url, "observed_at_utc": observed_at,
            "raw_response": name, "sha256": hashlib.sha256(raw).hexdigest(),
            "dnssec_authenticated_data": answer.get("AD", False),
            "answers": answer.get("Answer", []),
        })
        for item in answer.get("Answer", []):
            if item["type"] != number or item["name"].rstrip(".").lower() != "example.com":
                continue
            target = item["data"]
            relation = f"DNS {record_type} answer"
            if record_type == "NS":
                target = target.rstrip(".")
            elif record_type == "MX":
                preference, target = target.split(maxsplit=1)
                if target == ".":  # RFC 7505 null MX is not a mail-server entity.
                    continue
                target = target.rstrip(".")
                relation += f" (preference {preference})"
            edges.append({
                "source": "example.com", "relation": relation, "target": target,
                "record_type": record_type, "ttl_seconds": item["TTL"],
                "observed_at_utc": observed_at, "evidence": name,
            })
    with (output / "relationships.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["source", "relation", "target", "record_type", "ttl_seconds", "observed_at_utc", "evidence"])
        writer.writeheader()
        writer.writerows(edges)
    manifest = {
        "domain": "example.com", "resolver": "Google Public DNS over HTTPS",
        "method_documentation": "https://developers.google.com/speed/public-dns/docs/doh/json",
        "observations": observations, "verified_relationships": len(edges),
        "scope": "Live DNS collection; not a Maltego client execution or ownership/reputation verdict",
    }
    (output / "collection-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).parent / "data/dns")
    args = parser.parse_args()
    result = collect(args.output_dir)
    print(json.dumps({"domain": result["domain"], "verified_relationships": result["verified_relationships"], "scope": result["scope"]}, indent=2))
