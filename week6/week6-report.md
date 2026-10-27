# Week 6 — MITRE ATT&CK Framework

**Group:** CS-2423  
**Course:** Introduction to Threat Hunting, 2026–2027  
**Project:** CTI and LLM-assisted SOC

## 1. Objective

The objective of this exercise is to study the MITRE ATT&CK framework, examine one specific technique, simulate suspicious command-line characteristics in a controlled environment, and map the observed behavior to ATT&CK tactics and techniques.

The selected technique is **T1059.001 — PowerShell**, a sub-technique of Command and Scripting Interpreter.

This exercise extends the hypothesis-driven PowerShell hunt documented in Week 5. The test cases use benign commands and do not execute malware.

## 2. ATT&CK terminology

- **Tactics** describe the adversary's objective or why an action is performed.
- **Techniques** describe how an adversary attempts to achieve an objective.
- **Procedures** describe how a specific threat actor or tool implements a technique in practice.

ATT&CK is a knowledge base of adversary behavior based on real-world observations. It provides a common language for documenting threats and organizing detection coverage.

## 3. Selected technique: T1059.001 — PowerShell

PowerShell is a command-line shell and scripting environment available on Windows and other platforms. It is used for legitimate administration, automation, and software management, but adversaries may also abuse it to execute commands or scripts.

The primary tactic associated with T1059.001 is **Execution**.

Reference: https://attack.mitre.org/techniques/T1059/001/

## 4. Controlled simulation

The project previously collected four genuine Windows PowerShell Event 400 records from controlled, benign launches.

| Test case | EncodedCommand argument | WindowStyle Hidden argument | Known behavior |
|---|---|---|---|
| plain | No | No | Benign output |
| encoded | Yes | No | Benign output |
| hidden | No | Yes | Benign output |
| encoded_hidden | Yes | Yes | Benign output |

The commands printed predefined training markers. No malware, credential theft, downloads, or external command-and-control connections were used.

The simulation represents selected command-line characteristics that may warrant investigation. It does not reproduce a complete malicious attack.

## 5. Mapping observations to ATT&CK

| Observation | ATT&CK mapping | Interpretation |
|---|---|---|
| PowerShell engine started | T1059.001 — PowerShell | Consistent with PowerShell execution |
| EncodedCommand argument present | T1059.001 — PowerShell | An investigation indicator, not proof of malicious activity |
| WindowStyle Hidden argument present | T1059.001 — PowerShell | May warrant additional context and investigation |
| Encoded and hidden arguments appear together | T1059.001 — PowerShell | A higher-priority triage candidate in this exercise |

The primary mapping is the Execution tactic. The presence of an encoded or hidden argument alone does not establish Defense Evasion. Additional evidence is necessary to determine whether a separate tactic or technique is applicable.

The observed events do not establish persistence, privilege escalation, lateral movement, or command-and-control activity.

## 6. SIEM hunting results

The Week 5 Elastic searches returned the following results:

| Search | Records returned |
|---|---:|
| Baseline PowerShell search | 4 |
| EncodedCommand search | 2 |
| EncodedCommand and WindowStyle Hidden search | 1 |

These results are reused as the existing project evidence; they are not presented as a new Week 6 execution.

All four events were benign. The combined search reduced the review set to one event, but that event was also benign. The result demonstrates candidate filtering rather than confirmed attack detection.

## 7. ATT&CK Navigator

An ATT&CK Navigator layer can visualize the technique examined in this report.

The layer identifies T1059.001 as the primary technique studied. Highlighting a technique in Navigator documents analytical focus; it does not prove that a technique was detected in a real attack.

The corresponding layer file is intended to be stored in `week6/navigator/powershell-layer.json`.

## 8. Limitations

The experiment contains only four controlled events. Its results cannot establish production detection accuracy, false-positive rates, or resistance to evasion.

The collected Event 400 records do not provide all the process lineage, network activity, or script-block details needed for a comprehensive investigation. Additional telemetry, including process-creation events and PowerShell script-block logging, would improve visibility.

The exercise does not claim to have detected malware.

## 9. Conclusion

This exercise applied MITRE ATT&CK to a controlled PowerShell threat-hunting scenario. T1059.001 provided a consistent way to describe the observed execution behavior, while Elastic searches helped prioritize events for review.

The results demonstrate why ATT&CK mappings must be interpreted together with event context and verified ground truth. Suspicious command-line characteristics are useful investigation signals, but they do not independently establish malicious intent.

## 10. References

1. MITRE ATT&CK, PowerShell (T1059.001): https://attack.mitre.org/techniques/T1059/001/
2. MITRE ATT&CK Navigator: https://attack.mitre.org/tools/attack-navigator/
3. MITRE ATT&CK, Command and Scripting Interpreter (T1059): https://attack.mitre.org/techniques/T1059/
4. Microsoft, about_Logging: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging
5. Week 5 report and associated evidence in this repository.
