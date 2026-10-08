# CTI and LLM-assisted SOC project

**Group:** CS-2423

**Course:** Introduction to Threat Hunting, 2026-2027

**Scope:** Weeks 1-4

The project studies how validated threat intelligence can support a SOC analyst and provide structured input for an LLM. The exercises use documentation examples and public research. The repository does not claim to contain a deployed LLM SOC application.

## Reports and evidence

| Week | Assignment | Report | Evidence |
|---|---|---|---|
| 1 | CTI glossary and classification of threats and sources | [Week 1 report](Week1/week1-report.md) | Glossary, classification table and linked primary references |
| 2 | OSINT collection and data source mapping | [Week 2 report](week2/week2-report.md) | [Images](week2/images/), [structured observations](week2/data/osint-observations.csv), [source mapping](week2/data/source-mapping.csv) |
| 3 | MISP import, filtering and normalization | [Week 3 report](week3/week3-report.md) | [Data](week3/data/), [live MISP screenshot](week3/images/03-misp-event-live.jpg), [lab reproduction](week3/lab-reproduction.md) |
| 4 | WannaCry case study using the Kill Chain and ATT&CK | [Week 4 report](week4/week4-report.md) | Cited stage mapping and detection opportunities; a literature study, not a malware execution lab |

## Reproduce the processing

Requires Python 3.10 or newer; the core processor uses only the standard library. Run from the repository root:

```powershell
python week3/process_iocs.py
python week3/enrich_correlate.py
python -m unittest discover -s tests -v
python tools/verify_repo.py
```

The included sample produces 8 input records, 4 valid unique indicators, 2 duplicates and 2 rejected records. All exported MISP IDS flags remain false. The generated context and relationships are a local training demonstration, not proof of malicious activity.

Optional Sigma syntax validation uses the official pySigma parser and requires Python 3.11 or newer:

```powershell
python -m pip install -r requirements-validation.txt
python tools/validate_sigma.py
```

Illustrations can be regenerated on Windows with Segoe UI fonts using `python week3/render_evidence.py` after installing `requirements-figures.txt`. They are clearly labelled illustrations; the JPG in `week3/images` is an actual MISP interface capture.

## Verification and limitations

The local MISP instance was running and Event 1 was imported with four attributes. Deploying that lab from scratch is a separate reproduction step documented in the lab guide. Elastic was not run; Sigma parser validation does not establish detection effectiveness in a SIEM. The original Maltego screenshot shows manually entered entities and zero links, so automated transforms and verified relationships are not claimed.

See [the audit](docs/audit-weeks1-4.md) for requirement coverage, remaining evidence limitations and the comparison with GitHub. [The master audit prompt](docs/master-audit-prompt.txt) defines how to repeat the review. [Upload instructions](docs/upload-instructions.md) explain how to preserve the folder structure on GitHub.

## Repository structure

```text
Week1/     CTI fundamentals report
week2/     OSINT report, observations and images
week3/     Processor, inputs, outputs, Sigma rule and MISP evidence
week4/     WannaCry case study
docs/      Audit, master prompt and upload guide
tests/     Normalization and provenance checks
tools/     Repository and Sigma validators
```
