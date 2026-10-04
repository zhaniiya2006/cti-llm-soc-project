# Week 4 – The Cyber Kill Chain

**Group:** CS-2423

## Case Study: WannaCry Ransomware Attack

### Objective

The objective of this exercise is to analyze the WannaCry ransomware attack using the seven stages of the Cyber Kill Chain developed by Lockheed Martin. The attack is also mapped to corresponding MITRE ATT&CK techniques and tactics. This analysis demonstrates how a real-world cyberattack can be examined from the initial discovery of vulnerable systems to the final impact on the victim.

## 1. Introduction

WannaCry is a ransomware attack that became widespread in May 2017. It affected Windows computers in organizations around the world. WannaCry was particularly dangerous because it had worm-like capabilities that allowed it to automatically spread from one vulnerable computer to another.

The malware used a vulnerability in the Server Message Block (SMBv1) protocol. The vulnerability was exploited using the EternalBlue exploit. After gaining access to a vulnerable system, WannaCry installed its malicious components and encrypted files, preventing users from accessing their data.

The WannaCry attack is a useful example for studying the Cyber Kill Chain because its activities can be analyzed as a sequence of stages. MITRE ATT&CK techniques can also be used to describe the specific behaviors associated with the attack.

## 2. Cyber Kill Chain Analysis

| Cyber Kill Chain Stage | WannaCry Activity | MITRE ATT&CK TTP |
|---|---|---|
| 1. Reconnaissance | WannaCry searched for remote systems that could be reached and potentially infected through vulnerable network services. It focused on systems that exposed vulnerable SMB services. | T1018 – Remote System Discovery |
| 2. Weaponization | The malware combined ransomware functionality with worm-like spreading capabilities. It included the ability to exploit a vulnerability in SMBv1 using the EternalBlue exploit. | T1210 – Exploitation of Remote Services |
| 3. Delivery | WannaCry spread between vulnerable Windows systems through the SMBv1 protocol. This allowed the malicious software to reach additional systems without requiring a traditional email attachment or manual installation. | T1210 – Exploitation of Remote Services |
| 4. Exploitation | WannaCry exploited the SMBv1 vulnerability using the EternalBlue exploit. Successful exploitation allowed the malware to execute code on vulnerable remote systems and continue spreading. | T1210 – Exploitation of Remote Services |
| 5. Installation | After compromising a system, WannaCry created the `mssecsvc2.0` Windows service. This service was used to execute malicious components and support the infection process. | T1543.003 – Create or Modify System Process: Windows Service |
| 6. Command and Control | WannaCry used Tor-related communication mechanisms for command-and-control activity in versions of the malware. Proxying communication can make it more difficult to identify the actual destination of network traffic. | T1090.003 – Proxy: Multi-hop Proxy |
| 7. Actions on Objectives | The main objective of WannaCry was to impact the availability of data by encrypting files on infected computers. Victims were shown a ransom demand requesting payment in Bitcoin in exchange for the possibility of recovering access to their files. | T1486 – Data Encrypted for Impact |

## 3. Detailed Attack Analysis

### Reconnaissance

The first stage of the Cyber Kill Chain is reconnaissance. During this stage, an attacker identifies potential targets and systems that may be vulnerable to attack.

In the case of WannaCry, the malware had the ability to discover remote systems and attempt to connect to vulnerable SMB services. This behavior helped the malware identify additional computers that could potentially be infected.

The corresponding MITRE ATT&CK technique is T1018 – Remote System Discovery.

### Weaponization

The weaponization stage involves preparing the malicious capability that will be used against a target.

WannaCry combined ransomware functionality with worm-like spreading capabilities. A key part of its spreading mechanism was the EternalBlue exploit, which targeted a vulnerability in the SMBv1 protocol.

The combination of exploitation and ransomware functionality made WannaCry capable of both spreading across networks and causing significant damage to infected systems.

### Delivery

During the delivery stage, the malicious capability reaches the target system.

Unlike traditional ransomware that may depend on phishing emails or malicious attachments, WannaCry was able to spread directly between vulnerable Windows systems through SMB. This allowed the malware to move rapidly between connected systems.

The activity is associated with T1210 – Exploitation of Remote Services in MITRE ATT&CK.

### Exploitation

The exploitation stage occurs when the attacker takes advantage of a vulnerability to gain access or execute malicious activity.

WannaCry exploited a vulnerability in SMBv1 using the EternalBlue exploit. Vulnerable Windows systems could therefore be compromised remotely. This exploitation mechanism was one of the main reasons why WannaCry was able to spread so quickly.

MITRE ATT&CK maps this behavior to T1210 – Exploitation of Remote Services.

### Installation

After exploitation, WannaCry installed and executed its malicious components on the compromised system.

One of the observed behaviors was the creation of the `mssecsvc2.0` Windows service. Creating a Windows service provides a mechanism for executing malicious software on the infected computer.

This behavior corresponds to T1543.003 – Create or Modify System Process: Windows Service.

### Command and Control

Command and Control (C2) is the stage in which malicious software communicates with infrastructure controlled by the attacker.

WannaCry used Tor-related communication mechanisms for command-and-control activity in some versions. The use of proxy or anonymization mechanisms can make malicious network communication more difficult to trace.

This behavior can be mapped to T1090.003 – Proxy: Multi-hop Proxy.

### Actions on Objectives

The final stage of the Cyber Kill Chain represents the attacker's intended result.

WannaCry was designed to encrypt files on infected systems. After encryption, victims were presented with a ransom demand requesting payment in Bitcoin. The encryption of files prevented users from normally accessing their data and created the main impact of the ransomware attack.

This behavior corresponds to T1486 – Data Encrypted for Impact.

## 4. MITRE ATT&CK Techniques

The main MITRE ATT&CK techniques used to describe the WannaCry attack are:

- **T1018 – Remote System Discovery**
- **T1210 – Exploitation of Remote Services**
- **T1543.003 – Create or Modify System Process: Windows Service**
- **T1090.003 – Proxy: Multi-hop Proxy**
- **T1486 – Data Encrypted for Impact**

These techniques provide a more detailed description of the technical behaviors observed during the attack. While the Cyber Kill Chain describes the overall progression of an attack, MITRE ATT&CK focuses on specific adversary behaviors and techniques.

## 5. Attack Impact

The WannaCry outbreak demonstrated how quickly ransomware can spread when vulnerable systems are connected to a network.

The attack affected organizations in many countries and disrupted important services. One of the most well-known examples was the impact on healthcare organizations, including the UK's National Health Service.

The combination of automated network propagation and file encryption made WannaCry significantly more disruptive than ransomware that requires each victim to be infected individually.

## 6. Cyber Kill Chain and MITRE ATT&CK Comparison

The Cyber Kill Chain and MITRE ATT&CK provide two different but complementary approaches to analyzing cyberattacks.

The Cyber Kill Chain provides a high-level view of the attack progression. It divides an attack into seven stages, starting with reconnaissance and ending with actions on objectives.

MITRE ATT&CK provides a more detailed technical description of adversary behavior. Instead of only describing the general stage of an attack, ATT&CK identifies specific techniques such as Remote System Discovery, Exploitation of Remote Services, Windows Service creation, Proxy usage, and Data Encrypted for Impact.

Using both frameworks makes the analysis more detailed and helps security professionals understand how an attack develops and which behaviors can be detected.

## 7. Conclusion

The WannaCry ransomware attack is a clear example of how a real-world cyberattack can be analyzed using the Cyber Kill Chain.

The attack progressed through activities that can be associated with reconnaissance, weaponization, delivery, exploitation, installation, command and control, and actions on objectives. The attack also demonstrates how MITRE ATT&CK techniques can provide additional technical details about the behavior of the malware.

The most important techniques identified in this analysis include T1018, T1210, T1543.003, T1090.003, and T1486.

Analyzing WannaCry using both the Cyber Kill Chain and MITRE ATT&CK provides a structured method for understanding the attack, identifying malicious behaviors, and improving cybersecurity detection and defense.

## 8. References

1. Lockheed Martin. *The Cyber Kill Chain*.
2. Lockheed Martin. *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains*.
3. MITRE ATT&CK. *WannaCry (S0366)*.
4. MITRE ATT&CK. *T1018 – Remote System Discovery*.
5. MITRE ATT&CK. *T1210 – Exploitation of Remote Services*.
6. MITRE ATT&CK. *T1543.003 – Create or Modify System Process: Windows Service*.
7. MITRE ATT&CK. *T1090.003 – Proxy: Multi-hop Proxy*.
8. MITRE ATT&CK. *T1486 – Data Encrypted for Impact*.
