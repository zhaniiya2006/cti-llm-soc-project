# CTI and LLM-assisted SOC project

**Group:** CS-2423

**Course:** Introduction to Threat Hunting, 2026-2027

**Scope:** Weeks 1-10

The project studies how validated threat intelligence can support a SOC analyst and provide structured input for an LLM. The exercises use documentation examples and public research. The repository does not claim to contain a deployed LLM SOC application.

## Reports and evidence

| Week | Assignment | Report | Evidence |
|---|---|---|---|
| 1 | CTI glossary and classification of threats and sources | [Week 1 report](Week1/week1-report.md) | Glossary, classification table and linked primary references |
| 2 | OSINT collection and data source mapping | [Week 2 report](week2/week2-report.md) | [Images](week2/images/), [structured observations](week2/data/osint-observations.csv), [source mapping](week2/data/source-mapping.csv) |
| 3 | MISP import, filtering and normalization | [Week 3 report](week3/week3-report.md) | [Data](week3/data/), [live MISP screenshot](week3/images/03-misp-event-live.jpg), [lab reproduction](week3/lab-reproduction.md) |
| 4 | WannaCry case study using the Kill Chain and ATT&CK | [Week 4 report](week4/week4-report.md) | Cited stage mapping and detection opportunities; a literature study, not a malware execution lab |
| 5 | Hypothesis-driven PowerShell hunt in Elastic | [Week 5 report](week5/week5-report.md) | [Genuine native events](week5/data/), [actual query results](week5/evidence/live-run/hunt-results.json), [3 live Kibana screenshots](week5/images/) |
| 6 | ATT&CK technique analysis (Assignment 4) | [Week 6 report](week6/week6-report.md) | [Navigator layer](week6/navigator/powershell-layer.json), archived Week 5 observation mapping |
| 7 | CAR implementation (Assignment 4) | [Week 7 report](week7/week7-report.md) | [Native process observations](week7/data/live-run/), [actual Elastic results](week7/evidence/live-run/results.json) |
| 8 | Adversary emulation plan (Assignment 5) | [Week 8 report](week8/week8-report.md) | Planned initial access, persistence, dummy-data transfer, telemetry and cleanup |
| 9 | Atomic Red Team (Assignment 6) | [Week 9 report](week9/week9-report.md) | [Executed parameterized atomic tests](week9/data/live-run/), [actual Elastic results](week9/evidence/live-run/results.json) |
| 10 | APT29 source analysis (Assignment 6) | [Week 10 report](week10/week10-report.md) | [Source-to-technique CSV](week10/data/apt29-mapping.csv), [literature Navigator layer](week10/navigator/apt29-study-layer.json) |

Start with [the Assignments 4-6 evidence index](docs/assignments4-6-status.md), [Assignment 4 coverage review](docs/assignment4-audit.md) and [7:30 defense outlines](docs/assignments4-6-defense.md). New lab execution was completed on 12 November 2026; existing commits and Week 5 evidence retain their original dates. The current portable lab and collection limits are described in [lab reproduction](docs/lab-reproduction.md).

Week 2 now includes [live DNS collection with six evidence-backed relationships](week2/dns-supplement.md). Maltego client transform execution still requires completion of its activation/login; the existing manual graph is preserved with its limitations.

## Reproduce the processing

Requires Python 3.10 or newer; the core processor uses only the standard library. Run from the repository root:

```powershell
python week3/process_iocs.py
python week3/enrich_correlate.py
python -m unittest discover -s tests -v
python tools/verify_repo.py
python tools/verify_week5.py
python tools/verify_assignments.py
```

The included sample produces 8 input records, 4 valid unique indicators, 2 duplicates and 2 rejected records. All exported MISP IDS flags remain false. The generated context and relationships are a local training demonstration, not proof of malicious activity.

Week 5 replay requires the existing local Elasticsearch/Kibana training lab:

```powershell
python week5/run_hunt.py --output-dir week5/evidence/my-replay
```

The archived four benign PowerShell launches produced four genuine Event 400 records. Actual Elastic searches returned 4 baseline records, 2 encoded-command candidates and 1 combined encoded/hidden candidate. All cases are benign; the results do not establish malware detection effectiveness. See the report for runtime prerequisites and collection commands.

Optional Sigma syntax validation uses the official pySigma parser and requires Python 3.11 or newer:

```powershell
python -m pip install -r requirements-validation.txt
python tools/validate_sigma.py
```

Illustrations can be regenerated on Windows with Segoe UI fonts using `python week3/render_evidence.py` after installing `requirements-figures.txt`. They are clearly labelled illustrations; the JPG in `week3/images` is an actual MISP interface capture.

## Verification and limitations

The local MISP instance was running and Event 1 was imported with four attributes. Deploying that lab from scratch is a separate reproduction step documented in the lab guide. Elastic was run and queried for Week 5; the Week 3 Sigma rule was not executed in that SIEM. Sigma parser validation does not establish detection effectiveness. The original Maltego screenshot shows manually entered entities and zero links. The new DNS relationships were collected independently, so they do not prove a Maltego transform execution.

See [the audit](docs/audit-weeks1-4.md) for requirement coverage, remaining evidence limitations and the comparison with GitHub. [The master audit prompt](docs/master-audit-prompt.txt) defines how to repeat the review. [Upload instructions](docs/upload-instructions.md) explain how to preserve the folder structure on GitHub.

[The updated progress record](docs/progress-weeks1-5.md) distinguishes the original audit from the new Week 2 collection and completed Week 5 practice.

## Repository structure

```text
Week1/     CTI fundamentals report
week2/     OSINT report, observations and images
week3/     Processor, inputs, outputs, Sigma rule and MISP evidence
week4/     WannaCry case study
week5/     Native PowerShell events, Elastic queries, results and live screenshots
week6/     ATT&CK study, Navigator layer and live import screenshot
week7/     CAR process observations, actual Elastic queries and results
week8/     ATT&CK-mapped emulation plan
week9/     Executed parameterized Atomic tests, native observations and Elastic results
week10/    Historical APT29 case analysis, source mapping and Navigator layer
docs/      Audit, master prompt and upload guide
tests/     Normalization and provenance checks
tools/     Collectors, Elastic query runners and artifact validators
```
