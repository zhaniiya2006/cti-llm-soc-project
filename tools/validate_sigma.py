"""Validate with the official pySigma parser; do not claim SIEM execution."""

import json
import platform
from importlib.metadata import version
from pathlib import Path

from sigma.collection import SigmaCollection

REPO = Path(__file__).resolve().parents[1]


def main():
    path = REPO / "week3/sigma/example_domain_connection.yml"
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    if collection.errors or len(collection.rules) != 1:
        raise RuntimeError(f"Sigma parse failed: {collection.errors}")
    rule = collection.rules[0]
    result = {
        "rule": path.relative_to(REPO).as_posix(),
        "parser": "official SigmaHQ pySigma",
        "pysigma_version": version("pysigma"),
        "python_version": platform.python_version(),
        "parsed_rules": len(collection.rules),
        "rule_id": str(rule.id),
        "syntax_validation": "passed",
        "siem_execution": "not performed",
        "detection_effectiveness": "not measured",
    }
    out = REPO / "week3/data/sigma-validation.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
