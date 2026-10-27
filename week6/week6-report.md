# Week 6 — MITRE ATT&CK Framework: PowerShell Technique Analysis

**Group:** CS-2423  
**Course:** Introduction to Threat Hunting, 2026–2027  
**Project:** CTI and LLM-assisted SOC  
**Previous work:** Week 5 — Hypothesis-driven Threat Hunting in Elastic  
**Primary framework:** MITRE ATT&CK Enterprise

## 1. Introduction

Cybersecurity analysts need a consistent way to describe adversary behavior, connect observed events to known attack techniques, and communicate investigation results across a Security Operations Center (SOC).

MITRE ATT&CK is a knowledge base that organizes adversary tactics and techniques based on observed real-world behavior. It provides a common vocabulary for threat intelligence, detection engineering, incident response, and threat hunting.

This exercise extends the previous stages of the CTI and LLM-assisted SOC project. Week 5 focused on a hypothesis-driven PowerShell hunt in Elasticsearch and Kibana. Four benign PowerShell launches were collected as controlled test cases, indexed, and examined using three searches.

Week 6 uses these existing observations to demonstrate how a SOC analyst can map behavior to ATT&CK, distinguish suspicious indicators from confirmed malicious activity, and document the results using ATT&CK Navigator.

The exercise does not execute malware or claim that an actual intrusion was detected.

## 2. Objectives

The objectives of this exercise are to:

1. Explain the ATT&CK concepts of tactics, techniques, sub-techniques, and procedures.
2. Select and investigate one specific technique relevant to the previous PowerShell hunt.
3. Describe a controlled simulation of command-line characteristics that may warrant investigation.
4. Map observed behavior to appropriate ATT&CK techniques and tactics.
5. Reuse the existing Week 5 Elasticsearch results to evaluate the investigation hypothesis.
6. Prepare an ATT&CK Navigator layer that documents the technique examined.
7. Identify the limitations of the available telemetry and explain why ATT&CK mapping does not establish malicious intent.

## 3. The MITRE ATT&CK framework

### 3.1. Tactics

A tactic represents the adversary's objective: the reason for performing an action during an intrusion.

For example, Execution describes attempts to run malicious code or commands on a system. An adversary may use a scripting environment to execute commands, but the same environment is also routinely used by administrators and legitimate software.

A tactic provides context for the objective being pursued. It does not, by itself, identify the exact command, program, or procedure used.

### 3.2. Techniques and sub-techniques

A technique describes a method an adversary uses to achieve an objective. A sub-technique provides a more specific description of that method.

For this exercise, the selected technique is T1059 — Command and Scripting Interpreter. Its sub-technique T1059.001 identifies PowerShell.

The distinction is important because an analyst should use the most specific supported mapping rather than assigning a broad technique when the available evidence supports a narrower description.

### 3.3. Procedures

A procedure is the specific way a threat actor, tool, or intrusion implements a technique.

For example, an investigation may establish that PowerShell was started with a particular command-line argument. That observation describes an execution detail. However, the argument alone does not establish that a known threat actor performed the action or that the action was malicious.

A procedure-level claim requires evidence about the actual behavior, its context, and, when relevant, its relationship to a documented threat campaign or tool.

### 3.4. Why ATT&CK is useful in a SOC

ATT&CK can support several SOC activities:

- Threat intelligence analysts can describe how an adversary operates.
- Threat hunters can formulate hypotheses about observable behavior.
- Detection engineers can map detection logic to relevant techniques.
- Incident responders can organize findings and identify missing evidence.
- SOC managers can identify areas where telemetry or detection coverage is incomplete.

An ATT&CK mapping is a structured description, not a verdict. Analysts must still examine the underlying events and compare them with known benign and malicious behavior.

**Primary reference:** https://attack.mitre.org/

## 4. Selected technique: T1059.001 — PowerShell

### 4.1. Technique overview

PowerShell is a command-line shell and scripting environment commonly used for Windows administration, configuration management, automation, and troubleshooting.

Because it is a legitimate and widely available tool, PowerShell can also be abused by adversaries to execute commands and scripts.

The technique selected for this exercise is:

- **Technique ID:** T1059
- **Sub-technique ID:** T1059.001
- **Technique name:** PowerShell
- **Primary tactic:** Execution
- **Technology:** Windows PowerShell command and scripting environment

Official reference: https://attack.mitre.org/techniques/T1059/001/

### 4.2. Why this technique was selected

The selection follows directly from the Week 5 experiment. The previous exercise collected genuine Windows PowerShell Event 400 records and searched their recorded command-line information for selected argument patterns.

The test cases included:

- A baseline PowerShell launch.
- A launch containing an EncodedCommand argument.
- A launch containing a WindowStyle Hidden argument.
- A launch containing both arguments.

These cases allowed the analyst to examine how command-line characteristics affect the number of events selected for review.

The technique is therefore relevant to the existing evidence and allows the project to continue from hypothesis-driven hunting to structured behavior mapping.

### 4.3. Encoded and hidden arguments

An EncodedCommand argument may indicate that a command was supplied in encoded form. Encoding is not equivalent to encryption and does not inherently establish malicious intent.

Encoded commands may be used in legitimate automation, deployment scripts, administrative tools, and testing environments.

A WindowStyle Hidden argument requests a hidden window for the relevant process launch. Legitimate applications can also use hidden windows to perform background tasks.

When these characteristics appear together, an analyst may prioritize the event for review. The correct decision depends on additional evidence, such as the parent process, user context, script contents, file activity, network connections, and whether the activity matches an approved administrative task.

Neither argument independently proves that an attack occurred.

## 5. Controlled simulation methodology

### 5.1. Purpose of the simulation

The Week 5 experiment used benign PowerShell commands to generate known test cases. Each command printed a predefined training marker.

The purpose was to examine the effect of selected command-line characteristics on the hunt results without executing malware or interacting with external systems.

The original collector and evidence are documented in the repository:

- Collector: https://github.com/zhaniiya2006/cti-llm-soc-project/blob/main/week5/collect_lab_events.ps1
- Native event records: https://github.com/zhaniiya2006/cti-llm-soc-project/blob/main/week5/data/windows-events.xml
- Indexed JSON Lines: https://github.com/zhaniiya2006/cti-llm-soc-project/blob/main/week5/data/powershell-events.jsonl
- Collection manifest: https://github.com/zhaniiya2006/cti-llm-soc-project/blob/main/week5/data/collection-manifest.json

### 5.2. Test cases

| Case | EncodedCommand argument | WindowStyle Hidden argument | Ground truth |
|---|---|---|---|
| plain | No | No | Benign |
| encoded | Yes | No | Benign |
| hidden | No | Yes | Benign |
| encoded_hidden | Yes | Yes | Benign |

All four test cases are known benign controls. The collector suppressed the child windows using its Start-Process launch option. This is distinct from the arguments recorded in the PowerShell command line.

### 5.3. Telemetry collected

The previous experiment collected four genuine Event 400 records from the Windows PowerShell log.

Event 400 is associated with the start of a PowerShell engine instance. It can provide useful information about PowerShell startup and the recorded host application.

However, Event 400 should not be treated as a substitute for every other type of process or script telemetry.

The existing records do not independently establish:

- The full parent-process chain.
- Every statement executed by the script.
- Network destinations contacted by the process.
- File or registry modifications.
- Credential access or lateral movement.

The experiment therefore provides a narrow but documented view of PowerShell execution rather than a complete reconstruction of an intrusion.

## 6. Mapping the observed behavior to ATT&CK

### 6.1. Primary mapping

The primary mapping is T1059.001 — PowerShell, associated with the Execution tactic.

This mapping describes the execution behavior examined in the experiment. It does not classify the four known benign events as attacks.

### 6.2. Observation-to-technique mapping

| Observation | Mapping | Reasoning |
|---|---|---|
| PowerShell engine startup | T1059.001 — PowerShell | The observed activity involves the PowerShell execution environment. |
| EncodedCommand argument | T1059.001 — PowerShell | The command uses a PowerShell execution feature; the argument alone does not prove obfuscation intended to evade detection. |
| WindowStyle Hidden argument | T1059.001 — PowerShell | The activity involves a PowerShell launch with a hidden-window argument. |
| Encoded and hidden arguments together | T1059.001 — PowerShell | The combination is a useful triage signal but remains insufficient to establish malicious intent. |

The same technique may be relevant to both benign and malicious activity. ATT&CK mapping describes the behavior, while the analyst's assessment establishes whether that behavior is suspicious or malicious in a particular context.

### 6.3. Avoiding unsupported mappings

An analyst should not automatically map an encoded command to Defense Evasion merely because its contents are encoded.

Similarly, the presence of a hidden-window argument is not enough to establish a complete defense-evasion procedure.

A stronger mapping would require additional evidence that the behavior was used to avoid security controls or conceal malicious activity. The current test cases do not establish that conclusion.

There is also no evidence in this experiment of persistence, privilege escalation, lateral movement, or command-and-control activity. These techniques should not be added to the mapping without supporting observations.

## 7. Reuse of the Week 5 Elastic results

The previous exercise executed three searches against a dedicated Elasticsearch index.

| Search | Actual result count | Cases returned |
|---|---:|---|
| Baseline PowerShell search | 4 | All four controls |
| EncodedCommand search | 2 | encoded, encoded_hidden |
| Combined encoded and hidden search | 1 | encoded_hidden |

These counts come from the archived Week 5 execution. They are reused here as existing evidence; they are not presented as a new Week 6 SIEM run.

### 7.1. Baseline search

The baseline search returned all four controlled PowerShell engine-start records. It provided the reference population for evaluating the more specific searches.

### 7.2. EncodedCommand search

The EncodedCommand search returned two records: encoded and encoded_hidden.

This result shows that the query narrowed the dataset based on the recorded command-line characteristic. It does not demonstrate that the two commands were malicious.

### 7.3. Combined search

The combined search returned one record, encoded_hidden.

The review set decreased from four records to one. However, inspection and Base64 decoding confirmed that the encoded payloads printed the predefined training markers.

The remaining candidate was also benign. Consequently, the result demonstrates candidate filtering rather than confirmed attack detection.

### 7.4. Evaluation of the hypothesis

The original hypothesis proposed that encoded PowerShell launches merit review and that combining the encoded and hidden arguments narrows the review set.

The observed results support the limited claim that these query conditions reduce the number of matching records in this four-case dataset.

They do not establish production detection effectiveness, sensitivity to malware, false-positive rates across a real enterprise, or resistance to command-line variations.

## 8. ATT&CK Navigator

ATT&CK Navigator is a tool for creating and viewing layers over ATT&CK matrices. Layers can help analysts record techniques of interest, document assessments, and communicate the scope of an investigation.

For this project, a Navigator layer is prepared to highlight T1059.001 — PowerShell.

The layer is intended to document the technique studied and the existing Week 5 evidence. It should not be interpreted as a validated detection-coverage assessment.

The layer file is stored at:

`week6/navigator/powershell-layer.json`

Official tool: https://mitre-attack.github.io/attack-navigator/

### 8.1. Interpretation of the layer

The highlighted technique represents the focus of the investigation.

A score or visual highlight is meaningful only when its interpretation is documented. In this exercise, the layer identifies the technique examined rather than assigning a measured percentage of detection coverage.

To validate the artifact, it must be loaded into ATT&CK Navigator and checked for schema compatibility and correct rendering. A successful JSON upload should be documented with a genuine screenshot of the interface.

## 9. Detection and telemetry improvements

The experiment identifies several opportunities for improving the visibility available to a SOC analyst.

### 9.1. Process-creation telemetry

Process-creation records can provide information about the executable, command line, process identifier, and parent process. This information helps reconstruct how a process was started.

Windows Security Event 4688 or Sysmon Event ID 1 can provide process-creation information when appropriately configured and collected.

### 9.2. PowerShell script-block logging

PowerShell script-block logging can record script content under the relevant configuration and logging conditions. Event 4104 may therefore provide additional context for script analysis.

The availability of such events depends on configuration, version, policy, and collection settings. They were not collected in the existing Week 5 experiment.

### 9.3. Network and file context

Network connection records, file events, user identity, host role, and approved administrative activity can help distinguish legitimate automation from suspicious behavior.

No network or file activity is claimed for the four test cases.

## 10. Reproducibility and evidence

The existing Week 5 results can be reviewed using the archived evidence:

- Hunt queries: https://github.com/zhaniiya2006/cti-llm-soc-project/blob/main/week5/hunt-queries.json
- Hunt results: https://github.com/zhaniiya2006/cti-llm-soc-project/blob/main/week5/evidence/live-run/hunt-results.json
- API transcript: https://github.com/zhaniiya2006/cti-llm-soc-project/blob/main/week5/evidence/live-run/api-transcript.json
- Live Kibana screenshots: https://github.com/zhaniiya2006/cti-llm-soc-project/tree/main/week5/images

The Navigator layer should be imported and checked separately. Any new screenshot must represent an actual interface capture.

The CSV mapping and JSON layer should be checked for valid formatting before being used as final project artifacts.

## 11. Limitations

This exercise is based on four controlled, benign test cases. The sample is too small to establish broad detection performance.

The available Event 400 records do not provide a complete process tree, full script execution history, or comprehensive network telemetry.

The command-line searches identify selected arguments and do not establish maliciousness. Alternative argument forms, unusual whitespace, different hosts, and other execution methods may require more advanced parsing and additional data sources.

The exercise does not claim that malware was executed or detected.

## 12. Conclusion

This exercise applied the MITRE ATT&CK framework to a controlled PowerShell threat-hunting scenario.

T1059.001 provided a consistent description of the execution behavior under investigation. The existing Elastic results demonstrated how progressively narrower query conditions can prioritize a smaller set of events for manual review.

The known benign outcomes were essential to the evaluation: the final candidate was not a confirmed attack. The exercise therefore demonstrates the distinction between identifying an observable behavior, mapping it to ATT&CK, and determining whether it is malicious.

The results also show that better process, script, and network telemetry would support more complete investigations.

## 13. References

1. MITRE ATT&CK, PowerShell (T1059.001): https://attack.mitre.org/techniques/T1059/001/
2. MITRE ATT&CK, Command and Scripting Interpreter (T1059): https://attack.mitre.org/techniques/T1059/
3. MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
4. Microsoft, about_Logging: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging
5. Microsoft, Audit Process Creation: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation
6. Week 5 report and archived evidence in the project repository.
