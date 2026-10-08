#!/usr/bin/env python3
"""Normalize a small, safe CTI IOC CSV and export MISP-compatible JSON."""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import sys
import uuid
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw_iocs.csv"
NORMALIZED = ROOT / "data" / "normalized_iocs.csv"
MISP_EVENT = ROOT / "data" / "misp-event.json"
SUMMARY = ROOT / "data" / "processing-summary.json"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if len(domain) > 253 or not domain or ".." in domain:
        raise ValueError("invalid domain syntax")
    labels = domain.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        raise ValueError("invalid domain syntax")
    return domain


def normalize_value(kind: str, value: str) -> str:
    value = value.strip()
    if kind == "domain":
        return normalize_domain(value)
    if kind == "ip-dst":
        address = ipaddress.ip_address(value)
        if address.version != 4:
            raise ValueError("expected IPv4 address")
        return str(address)
    if kind == "url":
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        if scheme not in {"http", "https"} or not host:
            raise ValueError("expected an absolute HTTP(S) URL")
        host = normalize_domain(host)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid URL port") from exc
        netloc = host if port is None or (scheme, port) in {("http", 80), ("https", 443)} else f"{host}:{port}"
        return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
    if kind == "sha256":
        if not SHA256_RE.fullmatch(value):
            raise ValueError("expected 64 hexadecimal characters")
        return value.lower()
    raise ValueError("unsupported indicator type")


def main() -> int:
    accepted: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    duplicate_count = 0

    with RAW.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))

    for row in rows:
        kind = row["type"].strip().lower()
        try:
            value = normalize_value(kind, row["value"])
        except (ValueError, TypeError) as exc:
            rejected.append({"record_id": row["record_id"], "reason": str(exc)})
            continue

        key = (kind, value)
        if key in seen:
            duplicate_count += 1
            continue
        seen.add(key)
        accepted.append(
            {
                "record_id": row["record_id"],
                "type": kind,
                "value": value,
                "source": row["source"].strip(),
                "first_seen": row["first_seen"].strip(),
                "confidence": row["confidence"].strip(),
                "to_ids": "false",
                "context": row["note"].strip(),
            }
        )

    NORMALIZED.parent.mkdir(parents=True, exist_ok=True)
    with NORMALIZED.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(accepted[0].keys()))
        writer.writeheader()
        writer.writerows(accepted)

    event = {
        "Event": {
            "info": "Week 3 CTI data processing lab - benign synthetic indicators",
            "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, "cti-llm-soc-project/week3/misp-event")),
            "date": date.today().isoformat(),
            "threat_level_id": "4",
            "analysis": "0",
            "distribution": "0",
            "Attribute": [
                {
                    "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cti-llm-soc-project/week3/{item['type']}/{item['value']}")),
                    "type": item["type"],
                    "category": "Network activity" if item["type"] in {"domain", "ip-dst", "url"} else "Payload delivery",
                    "value": item["value"],
                    "to_ids": False,
                    "comment": f"{item['context']} Source: {item['source']}; confidence: {item['confidence']}/100; first seen: {item['first_seen']}",
                }
                for item in accepted
            ],
        }
    }
    MISP_EVENT.write_text(json.dumps(event, indent=2) + "\n", encoding="utf-8")

    summary = {
        "input_records": len(rows),
        "valid_unique_indicators": len(accepted),
        "duplicates_removed": duplicate_count,
        "invalid_records_filtered": len(rejected),
        "rejected_records": rejected,
        "indicator_counts_by_type": {
            kind: sum(item["type"] == kind for item in accepted)
            for kind in sorted({item["type"] for item in accepted})
        },
        "safety": "Training-only indicators. MISP to_ids is false for every attribute.",
        "misp_event_uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, "cti-llm-soc-project/week3/misp-event")),
    }
    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    if len(rows) != len(accepted) + duplicate_count + len(rejected):
        raise RuntimeError("processing counts do not balance")
    if len(accepted) != 4 or duplicate_count != 2 or len(rejected) != 2:
        raise RuntimeError("unexpected lab result; review input or validation rules")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
