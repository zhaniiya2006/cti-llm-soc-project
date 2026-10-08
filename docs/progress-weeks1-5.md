# Progress update — Weeks 1–5

**Date:** 9 October 2026, Asia/Qyzylorda. New evidence timestamps are recorded in UTC; the collection crossed the local midnight boundary.

The [original Weeks 1–4 audit](audit-weeks1-4.md) is a historical review with its original GitHub snapshot. This update records the subsequent work.

| Week | Current coverage | Remaining limitation |
|---|---|---|
| 1 | Glossary and threat/source classification complete | Full student reading not evidenced |
| 2 | Original OSINT evidence, mapping, and new live DNS responses with six verified relationships | New Maltego transforms and graph capture pending client activation/login |
| 3 | MISP import and normalization evidenced; processor reproducible | Sigma parsed, not executed on SIEM telemetry |
| 4 | WannaCry analysis and evidence-qualified Kill Chain/ATT&CK mapping complete | Unknown attack stages remain explicitly unknown |
| 5 | Hypothesis, genuine native telemetry, actual Elastic query execution and three live Kibana screenshots complete | Four benign controls only; no malware effectiveness evaluation or production baseline |

## Week 2 work

[The DNS supplement](../week2/dns-supplement.md) contains raw A, AAAA, NS and null-MX responses, per-response SHA-256, timestamps and six relationship rows. Maltego Graph 4.13.0 was installed from its official vendor installer; the SHA-256 matched the download page and the Authenticode signature was valid. The client reached its Maltego ID activation screen. Installation and independent DNS collection do not establish completed transforms.

The user must complete activation/login before client execution can be documented. No fabricated Maltego graph screenshot has been added to replace the historical manual graph.

## Week 5 work

[The report](../week5/week5-report.md) contains the hypothesis, control cases, actual execution, analyst decision, limitations and reproduction commands.

- Four harmless marker-printing Windows PowerShell launches were performed during the final collection.
- Four genuine Event 400 records were selected by PID and exact time interval and exported with disclosed host/SID redactions.
- A new exercise-specific index was created in an existing isolated local Elastic 9.5.5 lab; other projects' events were not copied into it.
- Three Elasticsearch queries returned **4 → 2 → 1** records and were also executed in the live Kibana Console.
- Three screenshots are real interface captures. All four payloads were benign, including the final candidate.
- The runner resumed an interrupted metadata/data-view step by verifying the acknowledged ingestion, without reindexing that run. Preliminary diagnostic artifacts remain outside the project.

[verify_week5.py](../tools/verify_week5.py) checks manifest hashes, native XML/JSON agreement, PID/time correspondence, payload decoding, report record IDs and exact query/API response agreement. CI runs this check together with the existing repository and Sigma checks. This validates archived evidence consistency; it does not impersonate a live SIEM run.

## Next action

Finish Maltego activation/login, execute the relevant DNS transforms for the reserved training domain, and preserve their output, exported graph and readable real screenshot. Student reading notes can then be added under the student's own name. Week 5 practice is complete within its stated scope.
