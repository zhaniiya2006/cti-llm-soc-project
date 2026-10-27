# Week 7 — Using MITRE CAR for SIEM Analytics

**Group:** CS-2423  
**Course:** Introduction to Threat Hunting, 2026–2027  
**Project:** CTI and LLM-assisted SOC  
**Previous exercises:** Week 5 — Hypothesis-driven Threat Hunting; Week 6 — MITRE ATT&CK Framework  
**SIEM:** Elasticsearch and Kibana  
**Selected repository:** MITRE Cyber Analytics Repository (CAR)

## 1. Introduction

Security Operations Centers need more than lists of known indicators of compromise. Analysts must also be able to identify suspicious behavior from system events, determine whether the available evidence supports an investigation, and evaluate whether an analytic produces useful results.

The MITRE Cyber Analytics Repository (CAR) provides documented behavioral analytics intended to help identify adversary activity. CAR connects analytical logic with data requirements, expected behavior, and relevant ATT&CK techniques.

This exercise extends the previous PowerShell investigation. In Week 5, four benign PowerShell launches generated genuine Windows PowerShell Event 400 records. These records were ingested into Elasticsearch and examined using three searches. Week 6 mapped the observed behavior to MITRE ATT&CK technique T1059.001 — PowerShell.

Week 7 focuses on the next stage: translating a documented behavioral analytic into a SIEM implementation and evaluating whether the available telemetry is sufficient.

The selected analytic is CAR-2014-04-003 — PowerShell Execution. The implementation must preserve the analytic's data requirements and distinguish between an executable query, a successful technical test, and a validated security detection.

No malware execution is required for this exercise.

## 2. Objectives

The objectives are to:

1. Explain the purpose of MITRE CAR and its relationship with MITRE ATT&CK.
2. Distinguish analytics, detections, alerts, and investigation findings.
3. Select a published CAR analytic related to PowerShell execution.
4. Identify the telemetry and field requirements of the selected analytic.
5. Assess the suitability of the existing Week 5 dataset.
6. Develop a SIEM implementation plan for Elasticsearch and Kibana.
7. Define benign test cases and evaluation criteria.
8. Map the analytic to relevant ATT&CK techniques.
9. Document limitations and propose improvements to the SOC data pipeline.

## 3. Understanding MITRE CAR

### 3.1. What is CAR?

MITRE CAR is a repository of behavioral analytics for cybersecurity investigations and detection engineering.

An analytic describes a method for identifying behavior of interest from observable data. Depending on the analytic, it may specify data sources, fields, filtering conditions, expected behavior, and relationships between events.

The repository helps analysts move from a general security concern to a more precise analytical question.

For example, a general concern might be that PowerShell is being used to execute suspicious commands. A behavioral analytic can make that concern more concrete by defining which process attributes should be examined and what relationships between processes warrant review.

Official repository: https://car.mitre.org/

### 3.2. What an analytic contains

A documented analytic may include:

- An identifier and descriptive name.
- A security behavior or hypothesis.
- Required event sources and observable fields.
- Analytical logic or a reference implementation.
- Expected results or conditions for investigation.
- Links to relevant ATT&CK techniques.

These elements make it easier for analysts to understand why a query exists, what evidence it requires, and which conclusions can reasonably be drawn from its output.

An analytic must still be adapted to the data model, field names, and capabilities of the selected SIEM.

### 3.3. CAR and ATT&CK

CAR and ATT&CK serve related but different purposes.

ATT&CK provides a structured description of adversary tactics and techniques. CAR provides analytical methods that can help identify behaviors associated with those techniques.

For this project:

- ATT&CK identifies PowerShell execution as T1059.001.
- CAR supplies a documented PowerShell-related analytical approach.
- Elasticsearch stores and searches the collected telemetry.
- Kibana provides an interface for executing queries and inspecting results.
- The analyst evaluates whether the results support an investigation.

This relationship connects threat intelligence, detection engineering, and threat hunting within the SOC workflow.

## 4. Analytics, detections, and alerts

### 4.1. Analytics

An analytic is a method for examining data to identify a behavior of interest.

It can be expressed as a query, rule, statistical method, correlation procedure, or other analytical logic.

An analytic may be documented and implemented without having been tested successfully against real data.

### 4.2. Detections

A detection is an implemented mechanism intended to identify relevant security behavior in a monitoring environment.

A detection implementation requires suitable data, correct field mappings, appropriate logic, and testing. Its usefulness depends on whether it identifies the intended behavior without generating an unacceptable number of irrelevant results.

A query that runs successfully is not necessarily an effective detection.

### 4.3. Alerts

An alert is a notification or record produced when a rule or monitoring system's configured conditions are satisfied.

An alert indicates that the configured condition was met. It does not automatically prove that a compromise occurred.

For example, an alert about a PowerShell process launched by an unusual parent process may be worth investigating. The process might still belong to a legitimate administrative tool.

### 4.4. Investigation findings

An investigation finding is an analyst's conclusion based on the available evidence.

The analyst may classify an event as benign, suspicious, malicious, or inconclusive. The classification should be supported by contextual evidence and known ground truth where available.

In this exercise, the four Week 5 cases have known benign outcomes. A matching query result must therefore not be labelled as a confirmed malicious event.

## 5. Selected analytic: CAR-2014-04-003 — PowerShell Execution

### 5.1. Selection

The selected analytic is CAR-2014-04-003 — PowerShell Execution.

Official reference: https://car.mitre.org/analytics/CAR-2014-04-003/

The analytic is relevant because the previous exercises focused on PowerShell execution and the use of command-line characteristics to prioritize events for review.

The selected analytic examines PowerShell process execution using process information and parent-process context. Its original logic must be consulted before implementation so that the purpose, conditions, and data requirements are preserved.

### 5.2. Why parent-process context matters

A process rarely exists in isolation. Understanding which process started another process can help analysts distinguish expected activity from unusual execution chains.

For example, a PowerShell process launched by an approved management tool may be consistent with normal administrative activity. A PowerShell process launched by an unexpected application may warrant additional investigation.

However, parent-process relationships are not definitive proof of maliciousness. Legitimate software can use unusual process chains, and adversaries can abuse common parent processes.

The analytic should therefore be treated as a method for prioritizing investigation rather than an automatic verdict.

### 5.3. Original analytic versus adaptation

A faithful implementation should preserve the original analytic's required fields and conditions.

If the original analytic requires process-creation information and a parent executable, the implementation must obtain those values from suitable telemetry.

A query that searches only the command line for encoded or hidden PowerShell arguments is a different analytic. It may be useful, but it should be labelled as a CAR-inspired adaptation rather than the original CAR-2014-04-003.

This distinction is essential for reproducibility and academic accuracy.

## 6. Telemetry requirements and the Week 5 dataset

### 6.1. Available evidence

Week 5 collected four genuine Event 400 engine-start records from the Windows PowerShell log.

The dataset contains recorded PowerShell host information and command-line-related observations. It was exported from the controlled test run and ingested into a dedicated Elasticsearch index.

The original experiment produced these results:

| Search | Records returned |
|---|---:|
| Baseline PowerShell search | 4 |
| EncodedCommand search | 2 |
| EncodedCommand and WindowStyle Hidden search | 1 |

All four cases were benign. The archived data and query results are available in the Week 5 repository.

### 6.2. Why Event 400 is insufficient for the original CAR logic

Event 400 records PowerShell engine startup information. It does not, by itself, establish all process-creation attributes or parent-process relationships required by the selected CAR analytic.

The existence of a command line does not mean that the parent executable can be reliably reconstructed from that record.

The existing four records therefore cannot be assumed to contain all the information required by CAR-2014-04-003.

### 6.3. Additional telemetry

A suitable follow-up experiment should collect process-creation events from a controlled Windows environment.

Possible sources include:

- **Windows Security Event 4688:** process creation auditing, when the relevant audit policy is configured.
- **Sysmon Event ID 1:** process creation, when Sysmon is installed and configured.
- **PowerShell Event 400:** engine startup information.
- **PowerShell Event 4104:** script-block logging, when appropriately enabled and supported.

These sources serve different purposes. Process-creation telemetry can provide executable and parent-process attributes, while PowerShell-specific events can provide additional information about the engine or script content.

The availability of each field must be verified against the actual collected events. This project does not claim that Event 4688, Sysmon Event ID 1, or Event 4104 was collected in Week 5.

## 7. Proposed SIEM implementation

### 7.1. Implementation approach

The preferred implementation is to collect process-creation telemetry from a controlled Windows system, ingest the events into Elasticsearch, inspect the resulting field mappings, and execute a query based on the original CAR logic.

The process should follow these steps:

1. Review the original CAR analytic and document its conditions.
2. Confirm the available Windows event source.
3. Collect process-creation records for a small set of controlled, benign test cases.
4. Verify that executable and parent-process fields are present.
5. Ingest the events into a dedicated Elasticsearch index.
6. Inspect the actual field names and mappings.
7. Adapt the CAR logic to the verified schema.
8. Execute the query in Kibana or another supported Elasticsearch query interface.
9. Record the query, response, matching records, and errors.
10. Compare the results with the known test outcomes.

Each step must be documented accurately. If a prerequisite is unavailable, the report should identify the limitation rather than claim a completed test.

### 7.2. Field mapping

A SIEM implementation must translate the original analytic's data requirements into the fields available in the selected data model.

For example, an ECS-aligned dataset may expose fields such as:

| Field | Purpose |
|---|---|
| `process.name` | Name of the process being investigated |
| `process.executable` | Path to the executable, when available |
| `process.command_line` | Recorded command line |
| `process.parent.name` | Parent-process name |
| `process.parent.executable` | Parent-process path |
| `@timestamp` | Event time |
| `host.name` | Host that generated the event |

These are examples of possible ECS field names, not a statement that the existing Week 5 index contains all of them.

Before implementing the analytic, the analyst must inspect the index mapping and sample documents. If a required field is missing, the query must not silently substitute an unrelated field.

### 7.3. Example query logic

For an ECS-aligned process-creation dataset, a preliminary query might identify PowerShell processes whose parent executable is recorded and is not `explorer.exe`.

This illustrates the general analytical condition; it is not a claim that the original CAR query has already been executed in this project.

The query should only be run after confirming that the relevant fields exist and that the selected index contains appropriate process-creation events.

The output should include enough context to investigate the match, including the process name, command line, parent process, host, and timestamp where available.

### 7.4. Dedicated index and evidence preservation

The Week 5 implementation created a dedicated index and preserved the actual query requests and results.

The same principle should be followed in Week 7. A new test should use a separate index or a clearly isolated dataset so that the original evidence is not overwritten.

The implementation should preserve:

- The data source and collection time.
- The index name and relevant mappings.
- The exact query.
- The response and matching records.
- Any errors or missing fields.
- The known outcome of each test case.

This approach supports reproducibility and makes it easier to distinguish archived results from new experiments.

## 8. Test plan and expected interpretation

### 8.1. Test cases

The four known Week 5 cases can be retained as regression cases for a compatible command-line investigation.

| Case | Ground truth | Evaluation objective |
|---|---|---|
| plain | Benign | Establish baseline behavior |
| encoded | Benign | Evaluate encoded-command context |
| hidden | Benign | Evaluate hidden-window context |
| encoded_hidden | Benign | Evaluate the combined command-line characteristics |

These cases can help verify that a compatible query behaves consistently with the existing dataset. They do not automatically test the parent-process conditions of the original CAR analytic.

For the original analytic, the test dataset must also contain valid process-creation and parent-process information.

### 8.2. Technical validation

Technical validation should establish that:

- The query is syntactically valid.
- The intended index is selected.
- Required fields exist.
- Searches complete without errors or timeouts.
- The returned records satisfy the query conditions.
- The result count agrees with the saved response.

A query that returns zero records is not automatically incorrect. The dataset may not contain matching activity, or a field mapping may be unsuitable. The cause must be investigated.

### 8.3. Behavioral validation

Behavioral validation asks whether the analytic identifies the behavior it was designed to examine.

This requires suitable test cases with known outcomes and sufficient telemetry. A small benign-only dataset can demonstrate that the query runs and can help reveal unexpected matches, but it cannot establish the analytic's ability to detect real malicious activity.

### 8.4. Security effectiveness

A stronger evaluation would require a broader dataset containing both legitimate and representative suspicious behavior, appropriate ground truth, and enough observations to estimate detection performance.

The four benign Week 5 records are insufficient to establish production accuracy, sensitivity, or false-positive rates.

The exercise therefore separates successful query execution from demonstrated detection effectiveness.

## 9. ATT&CK mapping

The PowerShell execution behavior examined in this exercise maps to:

- **Technique:** T1059.001 — PowerShell.
- **Parent technique:** T1059 — Command and Scripting Interpreter.
- **Primary tactic:** Execution.

Reference: https://attack.mitre.org/techniques/T1059/001/

This mapping explains the behavior that the analytic is intended to investigate. It does not imply that every matching PowerShell process is malicious.

The mapping should be retained in the analytic documentation so that analysts can understand the relationship between the query and the ATT&CK behavior.

Additional techniques should only be included if the collected evidence supports them.

## 10. Analytics in the CTI and LLM-assisted SOC workflow

This exercise also relates to the broader project objective of supporting SOC analysts with structured and validated threat intelligence.

A possible workflow is:

1. **Collection:** gather events from a documented source.
2. **Normalization:** represent relevant fields consistently.
3. **Analysis:** apply a documented analytic to the available telemetry.
4. **Correlation:** compare the results with contextual information and known test outcomes.
5. **ATT&CK mapping:** describe the behavior using a shared framework.
6. **Analyst review:** decide whether the event is benign, suspicious, malicious, or inconclusive.
7. **LLM-assisted explanation:** provide a structured summary of the observed evidence, query conditions, uncertainties, and next investigative steps.

An LLM should not replace the underlying event data or independently turn a matching query into a confirmed incident.

For example, a structured investigation record could contain the observed process, its parent, the query that matched, the relevant ATT&CK technique, the known test outcome, and unresolved questions.

An LLM could then help summarize that record, provided the source information is preserved and unsupported claims are avoided.

No deployed LLM-based SOC application is claimed in this exercise.

## 11. Limitations

Several limitations affect the current implementation.

First, the archived Week 5 dataset contains only four controlled PowerShell Event 400 records. It is not a representative enterprise dataset.

Second, the collected records do not establish the parent-process information required for a full evaluation of the selected CAR analytic.

Third, an ECS-style query cannot be assumed to work against an index with different field names or data types. Actual mappings must be checked.

Fourth, the test cases are benign. They can support limited regression checks but cannot establish detection effectiveness against malware or real intrusions.

Fifth, a successful query execution does not prove that an alerting mechanism, production detection rule, or incident-response workflow has been deployed.

Finally, additional Windows logging, data ingestion, and SIEM configuration may be required before the original CAR logic can be evaluated.

These limitations should remain visible in the final report.

## 12. Conclusion

This exercise examined how MITRE CAR can support behavioral analytics and SIEM implementation.

CAR provides a documented analytical starting point, while Elasticsearch and Kibana can be used to query collected telemetry and inspect matching events. ATT&CK provides a common language for describing the behavior associated with the analytic.

The Week 5 dataset is useful for understanding the existing PowerShell hunt, but its Event 400 records do not establish all the process-creation and parent-process attributes required by the selected CAR analytic.

A faithful implementation therefore requires suitable additional telemetry or an explicitly documented adaptation. Query execution, behavioral validation, and detection effectiveness must be assessed separately.

This approach supports the project's overall objective: helping SOC analysts use structured threat intelligence and transparent analytical methods without overstating what the available evidence proves.

## 13. References

1. MITRE Cyber Analytics Repository: https://car.mitre.org/
2. MITRE CAR, PowerShell Execution (CAR-2014-04-003): https://car.mitre.org/analytics/CAR-2014-04-003/
3. MITRE ATT&CK, PowerShell (T1059.001): https://attack.mitre.org/techniques/T1059/001/
4. Microsoft, about_Logging: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging
5. Microsoft, Audit Process Creation: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation
6. Elastic, Query DSL: https://www.elastic.co/docs/reference/query-languages/query-dsl
7. Elastic, ES|QL: https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
8. Week 5 report, query files, collection manifest, and archived Elastic evidence in this repository.
