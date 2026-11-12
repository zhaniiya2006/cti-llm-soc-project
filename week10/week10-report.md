# Week 10 - APT29 techniques and implications for our SOC

**Group:** CS-2423 | **Assignment 6, part 2** | **Method:** source-based case analysis, no APT malware execution

## 1. Scope and sources

The syllabus asks us to analyze APT29 or APT41 and map observed TTPs to ATT&CK. We chose APT29 because it offers a published delivery-chain case to compare with our endpoint-only lab.

Our campaign source is Mandiant's [Backchannel Diplomacy](https://cloud.google.com/blog/topics/threat-intelligence/apt29-evolving-diplomatic-phishing), published **21 September 2023**, about diplomatic phishing operations during 2023. [MITRE's G0016 profile](https://attack.mitre.org/groups/G0016/) supplies the group identity and broader context. These describe reported historical activity; this is not a claim about a new incident in November 2026.

We keep separate campaign variants separate. The table below combines analyst mappings from different sections of the report for comparison; it is not one proven intrusion timeline.

## 2. Evidence-to-technique mapping

| Source locator | Reported observation, paraphrased | ATT&CK mapping | Mapping status and SOC evidence to seek |
|---|---|---|---|
| March 2023 Türkiye campaign | Phishing messages supplied links to hosted payloads | [T1566.002 - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) | Our direct mapping; preserve email URL and redirect chain |
| Evolving Approach to Malware Delivery | ROOTSAW used HTML to assemble/deliver follow-on content | [T1027.006 - HTML Smuggling](https://attack.mitre.org/techniques/T1027/006/) | Our direct mapping for the HTML variant; collect browser-created file provenance |
| Evolving Approach to Malware Delivery | Opening a shortcut or binary caused the next execution stage | [T1204.002 - Malicious File](https://attack.mitre.org/techniques/T1204/002/) | Our direct mapping of the user-opened file step; inspect download and process lineage |
| March/European campaigns | Delivery depended on user-agent or IP filtering | [T1480 - Execution Guardrails](https://attack.mitre.org/techniques/T1480/) | Our cautious mapping of conditional delivery; server-side gating is not proof of local sandbox discovery |
| Second-stage downloader discussion | SPICYBEAT obtained further payloads from cloud storage | [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | Our direct mapping of inbound payload retrieval; inspect endpoint and proxy observations |
| July ICEBEAT campaign | A legitimate messaging platform carried control traffic | [T1102 - Web Service](https://attack.mitre.org/techniques/T1102/) | Broad mapping only; the cited narrative does not alone establish all bidirectional semantics |

The linked live ATT&CK matrix uses **Stealth** for T1027.006 and T1480. The CSV records the current tactic label rather than carrying forward the older Defense Evasion label.

Mappings are our interpretation of the named source passages, checked against the linked technique definitions. We avoid T1497.001 solely from a user-agent check because that does not necessarily establish virtualization discovery. Likewise, a reference to cloud C2 is insufficient to infer actual exfiltration bytes.

## 3. Detection priorities derived from the case

Our existing CAR analytic covers only a small endpoint question: whether powershell.exe has a non-explorer parent. That cannot by itself identify a phishing link, HTML smuggling, a DLL launched without PowerShell, server-side filtering or cloud-service C2.

| Priority | Practical SOC action | Required evidence | Main limitation |
|---|---|---|---|
| 1 | Join message URL -> browser download -> child process in a time-bounded investigation | Mail/proxy/browser and endpoint process telemetry | User and host linkage may be incomplete |
| 2 | Track downloaded archive/shortcut execution and unexpected process lineage | File provenance, process creation and signature data | Legitimate installers can look similar |
| 3 | Investigate unusual process access to cloud services with follow-on payload creation | DNS/proxy, process-attributed network and file events | Common services have a large benign baseline |
| 4 | Preserve blocked/decoy delivery outcomes alongside successful ones | Gateway responses and controlled analyst observations | A decoy or 404 does not prove absence of earlier compromise |

These are proposed investigation improvements, not tested detections. A useful deployment decision would first establish which data sources exist and what joins are reliable, then validate rules on representative benign activity and approved emulation. Broadly blocking all cloud services would disrupt legitimate work without proving actor-specific coverage.

## 4. Relationship to Weeks 8 and 9

The Week 8 chain is a generic lab plan. The Week 9 interpreter tests validate selected benign endpoint observations. Neither reproduces ROOTSAW, ICEBEAT or the reported APT29 campaigns. Sharing an ATT&CK technique with an actor is not evidence that the actor is present.

For the CTI/LLM SOC project, a sourced record should preserve publication date, passage locator, paraphrased observation, technique ID, whether the mapping is explicit or analyst-inferred, and confidence limits. These fields help an LLM explain the evidence without merging campaign variants or promoting a benign query match into actor attribution.

## 5. Deliverables and conclusion

[The mapping CSV](data/apt29-mapping.csv) is a structured version of the source-to-technique table. [The Navigator layer](navigator/apt29-study-layer.json) marks **literature-mapped techniques**, not tested detections. No percentage score is assigned.

The case broadens our project beyond command-line flags: useful threat intelligence must change collection priorities and analytical questions. Our next measurable improvement would be correlating a controlled local download with an observed process chain, while keeping provenance and benign alternatives visible.
