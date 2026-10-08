# Week 4 - The Cyber Kill Chain

**Group:** CS-2423

**Case:** WannaCry ransomware outbreak, May 2017

**Method:** Literature-based analysis; no malware was executed

## 1. Objective and source method

The assignment is to analyze a real attack using the seven Kill Chain stages and map the stages to ATT&CK TTPs. This report uses the [Lockheed Martin model](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html), [MITRE's WannaCry entry S0366](https://attack.mitre.org/software/S0366/) and the original [Secureworks CTU analysis, now hosted by Sophos](https://www.sophos.com/en-us/research/wcry-ransomware-analysis).

The outbreak combines exploitation of vulnerable Windows SMB services, automated propagation and encryption. Evidence of malware behavior does not reconstruct the attackers' complete preparation process or identify the first infection path in every affected organization.

## 2. Stage mapping

Kill Chain stages and ATT&CK tactics are different taxonomies. The following mappings are analytical associations, not one-to-one equivalences. Repeated spread also creates a cycle rather than a single linear sequence.

| Kill Chain stage | Case evidence and interpretation | ATT&CK association | Evidence status |
|---|---|---|---|
| Reconnaissance | The original attacker reconnaissance before the outbreak is not established in these sources. On an already infected machine, WannaCry discovers other systems to spread to; this is a later discovery step. | [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018/) describes the observed post-compromise discovery. [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595/) is a conceptual pre-compromise analogue, not a verified WannaCry procedure here. | Original reconnaissance unknown; later discovery documented |
| Weaponization | The deployed tool combines a propagation component with ransomware. The exact development and packaging sequence is not reconstructed. | [T1587.001 Develop Capabilities: Malware](https://attack.mitre.org/techniques/T1587/001/) and [T1588.005 Obtain Capabilities: Exploits](https://attack.mitre.org/techniques/T1588/005/) are conceptual preparation associations, not confirmed WannaCry procedures here. T1210 describes exploit use, not tool construction. | Capabilities documented; preparation associations inferred |
| Delivery | During propagation to another host, malware reaches that host via the remote-service exploitation and transfer process. This does not establish how every initial victim was infected. | [T1210 Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/) and [T1570 Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/) | Network propagation documented; initial entry not generalized |
| Exploitation | The worm uses the EternalBlue SMBv1 exploit to spread to vulnerable remote Windows systems. | [T1210](https://attack.mitre.org/techniques/T1210/) | Documented in S0366 |
| Installation | WannaCry creates the `mssecsvc2.0` service. | [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003/) | Documented in S0366 |
| Command and Control | Reported WannaCry components use Tor-related communication. This is not evidence that a successful C2 connection is necessary for every local encryption step. | [T1090.003 Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/) and [T1573.002 Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002/) | Documented communication behavior; runtime necessity not asserted |
| Actions on Objectives | Files are encrypted and a ransom is demanded. Interference with recovery increases impact. | [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) and [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) | Documented in S0366 |

No preparation technique is labelled confirmed to fill an unknown stage. Conceptual associations are explicitly distinguished from observed procedures. Identifying an evidence gap is part of correct analysis.

## 3. Observable behavior and defensive opportunities

The following detection suggestions are analyst proposals. They were not executed against production telemetry.

| Observed behavior | Potential evidence | Defensive opportunity | Limitation |
|---|---|---|---|
| Remote-system discovery and repeated SMB attempts | Network connections to many hosts; SMB traffic | Correlate unusual fan-out on TCP 445 with endpoint process context | Legitimate administration can create similar patterns |
| Remote exploitation and transfer | Network IDS signals, host execution and file creation | Apply vendor patches, restrict SMB reachability, correlate network and host events | An IDS signature alone is not proof of successful compromise |
| `mssecsvc2.0` service creation | Windows service-installation audit and process telemetry | Investigate unexpected service installation and binary location | Name-based detection is narrow and can be evaded |
| Tor-related communication | Proxy, DNS and egress records with process context | Review unusual egress associated with suspicious binaries | Tor use by itself is not proof of WannaCry |
| Encryption and recovery interference | High-volume file changes, process activity, backup-tool audit | Combine impact symptoms with earlier propagation/service events | A ransomware verdict requires contextual evidence |

The Kill Chain is useful for organizing opportunities to interrupt an attack. ATT&CK adds behavior-level detail. Neither framework proves that every incident followed every listed stage.

## 4. Implications for the LLM-assisted SOC

An LLM could summarize the cited behaviors and propose investigative questions. It should preserve distinctions between observation, inference and unknown information. For example, it must not rewrite post-infection discovery as proven original reconnaissance or turn a conceptual mapping into an observed event.

Analysts should verify technique IDs, evidence and chronology before using the output to prioritize a response. This case study demonstrates analysis rather than a working LLM detection system.

## 5. Results and limits

All seven stages are considered, with explicit gaps for original reconnaissance and weaponization. The original report's unsupported equivalence between weaponization and T1210 was removed. Repeated propagation and later discovery are distinguished from pre-compromise activity. The report provides direct links for the case and the mapped techniques.

There are no malware execution screenshots, packet captures or host logs in this week. The syllabus asks for a case analysis and TTP mapping; it does not require executing ransomware. Images of a malware run would not be appropriate evidence for a literature study that did not run it.

## References

1. Lockheed Martin. [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html).
2. Hutchins, Cloppert and Amin. [Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf). Recommended reading; the vendor server returned HTTP 403 to the audit tool, so full-text access was not confirmed during this run.
3. MITRE. [WannaCry S0366](https://attack.mitre.org/software/S0366/), with linked procedure evidence. Accessed during the audit on 8 October 2026.
4. Secureworks Counter Threat Unit. (2017). [WCry Ransomware Analysis](https://www.sophos.com/en-us/research/wcry-ransomware-analysis), original technical research now hosted by Sophos.
5. MITRE. Technique pages linked directly in the stage table. Pre-compromise [Active Scanning T1595](https://attack.mitre.org/techniques/T1595/) and post-compromise [Remote System Discovery T1018](https://attack.mitre.org/techniques/T1018/) are intentionally distinguished.
