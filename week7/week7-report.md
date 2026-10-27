# Week 7 — Using MITRE CAR for SIEM Analytics

**Group:** CS-2423  
**Course:** Introduction to Threat Hunting, 2026–2027  
**Project:** CTI and LLM-assisted SOC

## 1. Objective

The objective of this exercise is to study the MITRE Cyber Analytics Repository (CAR), distinguish analytics from detections, select a published analytic, and assess how it can be implemented in a SIEM.

This work extends the controlled PowerShell threat hunt completed in Week 5 and the ATT&CK mapping prepared in Week 6.

## 2. Analytics and detections

An analytic describes a method for identifying a behavior of interest from available data. It specifies the logic, required telemetry, and conditions that may warrant investigation.

A detection is an implemented and evaluated mechanism that identifies relevant events in a monitoring environment. Its effectiveness depends on data quality, query correctness, coverage, and testing.

A query returning results does not automatically establish that an attack occurred. Results must be compared with known ground truth and investigated in context.

## 3. Selected MITRE CAR analytic

**Selected analytic:** CAR-2014-04-003 — PowerShell Execution.

Official reference: https://car.mitre.org/analytics/CAR-2014-04-003/

The analytic examines PowerShell process execution and uses process information, including the parent executable, to identify launches that may warrant investigation.

## 4. Required telemetry

The original analytic requires process-creation information sufficient to identify the PowerShell executable and its parent process.

The Week 5 dataset contains four genuine Windows PowerShell Event 400 engine-start records. It includes recorded command-line information but does not establish the parent process executable for these cases.

Consequently, the archived Week 5 records alone are insufficient to fully evaluate the original parent-process analytic.

## 5. Proposed SIEM implementation

The preferred implementation is to collect genuine process-creation events from a controlled Windows test environment, ingest them into Elasticsearch, and evaluate a query based on the original CAR logic.

The implementation must document:

- The source and event type of the collected telemetry.
- The field mapping for the executable and parent executable.
- The exact query submitted to Elasticsearch.
- The returned event count and relevant records.
- Whether the test results agree with the known benign or suspicious test cases.

If process-creation telemetry cannot be collected, a clearly labelled CAR-inspired query can be evaluated against the available command-line records. Such a query must not be presented as a complete implementation of the original CAR analytic.

## 6. ATT&CK mapping

The PowerShell behavior is associated with MITRE ATT&CK technique T1059.001 — PowerShell, under the Execution tactic.

Reference: https://attack.mitre.org/techniques/T1059/001/

This mapping describes the behavior under investigation. It does not prove that a matching event is malicious.

## 7. Evaluation criteria

The analytic should be evaluated against known test cases.

A successful technical test requires evidence that the query executes correctly against the intended data and returns the expected records. A separate assessment is required to determine whether the results distinguish malicious behavior from legitimate administrative activity.

The four benign Week 5 cases can provide a limited regression test for a compatible command-line query. They cannot establish the effectiveness of a parent-process analytic when parent-process data are absent.

## 8. Limitations

The current archived dataset contains only four controlled PowerShell engine-start records. It does not establish process ancestry, comprehensive script-block logging, or network activity.

No malware execution is necessary for this exercise. Any additional test data should be generated in a controlled environment and documented accurately.

Until the required telemetry is available and the query has been executed, the proposed implementation remains unvalidated.

## 9. Conclusion

MITRE CAR provides a structured starting point for translating a documented behavioral analytic into SIEM query logic. The implementation must preserve the original analytic's telemetry requirements and document any deviations.

The relationship between CAR and ATT&CK helps connect detection engineering with a common description of adversary behavior. Reliable evaluation requires executable query logic, suitable event data, and known test outcomes.

## 10. References

1. MITRE CAR, PowerShell Execution: https://car.mitre.org/analytics/CAR-2014-04-003/
2. MITRE ATT&CK, PowerShell T1059.001: https://attack.mitre.org/techniques/T1059/001/
3. Elastic, Query DSL: https://www.elastic.co/docs/reference/query-languages/query-dsl
4. Microsoft, Windows PowerShell logging: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging
5. Week 5 report and evidence in this repository.
