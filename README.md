# Threat-Hunting-Scenario-Assistance

## Executive Summary

On October 9, 2025, threat hunters identified a sophisticated intrusion on `gab-intern-vm`, an intern workstation. What was presented as a routine remote support session was in reality a structured, multi-phase attack: the threat actor executed a rapid discovery sweep, collected sensitive system data, staged artifacts for exfiltration, transferred data to an external IP, and established dual persistence mechanisms to ensure continued access after the session ended.

A deliberately crafted misdirection artifact (`SupportChat_log.lnk`) was planted to justify the session activity as legitimate troubleshooting. The attack followed a clear kill-chain progression: initial execution bypass, rapid environment discovery, data collection and staging, exfiltration, and layered persistence. The use of living-off-the-land binaries (wmic, tasklist, PowerShell, RuntimeBroker.exe) was deliberate — minimizing the forensic footprint while maximizing information gain.

---

## 1. Findings

### Key Indicators of Compromise

**Hostname:** `gab-intern-vm`  
**Category:** `Intern Workstation`  
**Attack Date:** `October 9, 2025`  
**Primary Window:** 12:51:44 – 12:52:14 UTC (approx. 30-second discovery sweep)  
**Exfil Destination:** `100.29.147.161` (external, actor-controlled)  
**Staging Path:** `C:\Users\Public\ReconArtifacts.zip`

---

***FLAG 0 - STARTING POINT***

**Objective :** The objective was to identify which machine showed the earliest and most consistent signs of suspicious activity—based on shared file traits, download-folder executions, and intern-related hosts—and determine the correct starting point for the hunt.

**Flag Value :** `gab-intern-vm`

```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName has_any ("intern")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```
<img width="875" height="121" alt="image" src="https://github.com/user-attachments/assets/8c2e7c95-931f-4416-9a2e-539c6a31b200" />

---

***FLAG 1 – INITIAL EXECUTION DETECTION***

**Objective :** Detect the earliest anomalous execution that could represent an entry point.

**Flag Value :** `-ExecutionPolicy`

```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "powershell", "powershell_ise.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FolderPath
| order by TimeGenerated asc
```
<img width="1272" height="107" alt="image" src="https://github.com/user-attachments/assets/38c4a06d-1776-4ddf-9667-246f03e071a2" />

---

***FLAG 2 – DEFENSE DISABLING***

**Objective :** Identify indicators that suggest attempts to imply or simulate changing security posture.

**Flag Value :** `DefenderTamperArtifact.lnk`

```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ActionType in~ ("FileCreated","FileModified","FileWrite","FileAccessed")
| where InitiatingProcessFileName in~ ("notepad.exe","explorer.exe","regedit.exe","cmd.exe","powershell.exe","mmc.exe")
| where FileName !startswith "__PSScriptPolicyTest"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="891" height="72" alt="image" src="https://github.com/user-attachments/assets/fdc2f498-6bd6-4b6d-9716-4bded9db6097" />

---

***FLAG 3 – QUICK DATA PROBE***

**Objective :** Spot brief, opportunistic checks for readily available sensitive content.

**Flag Value :** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`

```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("Get-Clipboard", "GetClipboard", "clip.exe", " clip ", "Get-Content | clip", "Set-Clipboard", "Get-ClipboardValue")
| project TimeGenerated, FileName, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```
<img width="900" height="72" alt="image" src="https://github.com/user-attachments/assets/445525b0-25f3-45c5-8664-6b025db3940c" />

---

***FLAG 4 – HOST CONTEXT RECON***

**Objective :** Spot brief, opportunistic checks for readily available sensitive content.

**Flag Value :** `2025-10-09T12:51:44.3425653Z`

```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("qwinsta","quser","query session","query user","whoami","systeminfo","hostname","ipconfig","net user","net localgroup","wmic useraccount","wmic computersystem","Get-WmiObject","Get-CimInstance","Get-LocalUser")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, ProcessId
| order by TimeGenerated desc
```
<img width="757" height="71" alt="image" src="https://github.com/user-attachments/assets/4cbc26aa-88de-4267-9137-76a81c46de15" />

---

***FLAG 5 – STORAGE SURFACE MAPPING***

**Objective :** Detect discovery of local or network storage locations that might hold interesting data.

**Flag Value :** `"cmd.exe" /c wmic logicaldisk get name,freespace,size`

```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any (
    "dir ", "tree ", "net view", "net share", "net use","wmic logicaldisk",
    "fsutil", "mountvol", "robocopy"
)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, ProcessId
| order by TimeGenerated asc
| extend rn = row_number()
```
<img width="917" height="95" alt="image" src="https://github.com/user-attachments/assets/f4ac042d-1984-48c2-93ba-ae3a929049c7" />

---

***FLAG 6 – CONNECTIVITY AND NAME RESOLUTION CHECK***

**Objective :** Identify checks that validate network reachability and name resolution.

**Flag Value :** `RuntimeBroker.exe`

```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("ping","nslookup","Resolve-DnsName","Test-NetConnection","tracert","curl","Invoke-WebRequest","Invoke-RestMethod","wget","GetHostEntry","netstat","query session","qwinsta")
| project TimeGenerated, ChildFileName = FileName, ChildCommandLine = ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated asc
```
<img width="948" height="78" alt="image" src="https://github.com/user-attachments/assets/c7f29448-0691-4920-a99a-8b8d05373780" />

---

***FLAG 7 – INTERACTIVE SESSION DISCOVERY***

**Objective :** Reveal attempts to detect interactive or active user sessions on the host.

**Flag Value :** `2533274790397065`

```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("query session","qwinsta","quser","query user","whoami /all","whoami /groups")
| project TimeGenerated, FileName, InitiatingProcessParentId, InitiatingProcessCommandLine, InitiatingProcessUniqueId
| order by TimeGenerated asc
```
<img width="830" height="279" alt="image" src="https://github.com/user-attachments/assets/24475dd4-f6b2-4c8a-ab70-cb7c90edde1b" />

---

***FLAG 8 – RUNTIME APPLICATION INVENTORY***

**Objective :** Detect enumeration of running applications and services to inform risk and opportunity.

**Flag Value :** `tasklist.exe`

```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any (
    "tasklist","tasklist /v","Get-Process","wmic process list",
    "powershell -Command Get-Process","powershell -Command Get-Service"
)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```
<img width="650" height="93" alt="image" src="https://github.com/user-attachments/assets/a5e645bb-8702-4570-9e6d-ff7774d03eb8" />

---

***FLAG 9 – PRIVILEGE SURFACE CHECK***

**Objective :** Detect attempts to understand privileges available to the current actor.

**Flag Value :** `2025-10-09T12:52:14.3135459Z`

```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("whoami /all","whoami /groups")
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName
| order by TimeGenerated asc
```
<img width="647" height="75" alt="image" src="https://github.com/user-attachments/assets/bb1f77ff-fc66-4767-a36d-39fae5cb4586" />

---

***FLAG 10 – PROOF-OF-ACCESS & EGRESS VAIDATION***

**Objective :** Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.

**Flag Value :** `www.msftconnecttest.com`

```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "curl.exe", "wget.exe", "bitsadmin.exe")
| where RemoteUrl != ""
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, Protocol, RemotePort
| order by TimeGenerated asc
```
<img width="1293" height="91" alt="image" src="https://github.com/user-attachments/assets/b1b2f75a-8b91-48d5-90bc-e5f2819ff60c" />

---

***FLAG 11 – BUNDLING / STAGING ATRIFACTS***

**Objective :** Detect consolidation of artifacts into a single location or package for transfer.

**Flag Value :** `C:\Users\Public\ReconArtifacts.zip`

```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ActionType in ("FileCreated", "FileCopied", "FileModified")
| where FileName has_any (".zip", ".txt", ".log", ".csv")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="891" height="76" alt="image" src="https://github.com/user-attachments/assets/7a7774d7-c65b-4707-b673-4e76c684298c" />

---

***FLAG 12 – OUTBOUND TRANSFER ATTEMPT (SIMULATED)***

**Objective :** Identify attempts to move data off-host or test upload capability.

**Flag Value :** `100.29.147.161`

```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "curl.exe", "wget.exe", "bitsadmin.exe")
| where RemoteUrl != ""
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, Protocol, RemotePort
| order by TimeGenerated asc
```
<img width="916" height="72" alt="image" src="https://github.com/user-attachments/assets/575e3ab1-1eb2-4f8c-ba66-65440ccd04ba" />

---

***FLAG 13 – SCHEDULED RE-EXECUTION PERSISTANCE***

**Objective :** Detect creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in.

**Flag Value :** `SupportToolUpdater`

```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FileName =~ "schtasks.exe" or InitiatingProcessFileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("create", " /create ", "/sc", "/tn")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="915" height="93" alt="image" src="https://github.com/user-attachments/assets/bb4229c1-29db-4f81-b748-bbfa10dbcea4" />

---

***FLAG 14 – AUTORUN FALLBACK PERSISTENCE***

**Objective :** Spot lightweight autorun entries placed as backup persistence in user scope.

**Flag Value :** `RemoteAssistUpdater`

```
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where RegistryKey has_any (
    @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
| where ActionType == "RegistryValueSet"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
*Note: the above flag could not be shown because the autorun registry events were not available due to log retention limts. But if it was available then we would have used the above query.*

---

***FLAG 15 – PLANTED NARATIVE / COVER ARTIFACT***

**Objective :** Identify a narrative or explanatory artifact intended to justify the activity.

**Flag Value :** `SupportChat_log.lnk`

```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FolderPath has @"\Windows\Recent\"
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType
| order by TimeGenerated desc
```
<img width="1028" height="77" alt="image" src="https://github.com/user-attachments/assets/34474264-3aeb-432b-923d-dc0e09edb0aa" />

---

## 2. Investigation Summary

On October 9, 2025, threat hunting on `gab-intern-vm` uncovered a malicious actor operating under the guise of a remote support session. The actor began by bypassing PowerShell execution policy controls before staging a fake Defender tampering artifact to mislead investigators. Within a compressed 30-second window (12:51–12:52 UTC), they conducted a swift but thorough discovery sweep — harvesting clipboard contents, enumerating drives via `wmic`, cataloguing running processes with `tasklist.exe`, validating active user sessions, confirming privileges, and testing outbound connectivity through `msftconnecttest.com` to blend with legitimate traffic. All collected data was archived into `C:\Users\Public\ReconArtifacts.zip` and exfiltrated to the external IP `100.29.147.161`. To ensure continued access, two persistence entries were planted — `SupportToolUpdater` as the primary and `RemoteAssistUpdater` in the HKCU Run key as a low-privilege backup. Finally, the actor created and reviewed `SupportChat_log.lnk`, a planted narrative designed to frame the entire session as legitimate troubleshooting.

---

## 3. Attack Narrative

**Phase 1 — Entry Point: Execution Policy Bypass**  
The earliest anomalous activity was a PowerShell invocation using the `-ExecutionPolicy` flag, overriding the default policy to allow unsigned or restricted script execution. This served as the foundation for all subsequent activity and is a classic indicator of an actor circumventing endpoint security controls on a non-admin workstation.

**Phase 2 — Defense Evasion Simulation**  
The creation of `DefenderTamperArtifact.lnk` suggests the actor either simulated or staged the appearance of Windows Defender tampering. This artifact functions as deliberate misdirection — designed to imply a security posture change and potentially confuse incident responders investigating Defender-related alerts.

**Phase 3 — Rapid Discovery Sweep (12:51:44 – 12:52:14 UTC)**  
Within an approximately 30-second window, the actor conducted a comprehensive but lightweight environment survey using native Windows tooling. Each check was brief and targeted:
**Clipboard** — PowerShell `-NoProfile -Sta` silently queried clipboard contents at `12:51:44` UTC. This opportunistic check targets credentials, tokens, or sensitive text recently copied by the user.
**Disk** — `wmic logicaldisk get name,freespace,size` enumerated local drives to identify data repositories and assess available staging space.
**Network** — `RuntimeBroker.exe` was used for DNS and network connectivity checks, abusing a trusted Windows process to blend in with normal system behavior.
**Sessions** — The actor checked for active interactive user sessions (ID: `2533274790397065`) to determine whether a real user was monitoring the machine.
**Processes** — `tasklist.exe` catalogued all running processes, identifying security tools, monitoring software, and exploitation opportunities.
**Privileges** — The actor confirmed available privileges at `12:52:14` UTC to determine the scope of actions possible without escalation.
**Connectivity** — A request to `www.msftconnecttest.com` validated the exfiltration path using a legitimate Microsoft domain to blend with normal traffic.

**Phase 4 — Collection & Staging**  
All reconnaissance output was consolidated into `C:\Users\Public\ReconArtifacts.zip`. The Public folder was chosen intentionally — it is world-readable, requires no special privileges to write to, and is a well-known staging location for lateral movement and exfiltration preparation.

**Phase 5 — Exfiltration**  
Data was transferred to the external IP address `100.29.147.161`. This IP has no affiliation with Microsoft or any legitimate organisational service, indicating actor-controlled infrastructure. The prior connectivity test to `msftconnecttest.com` confirms the actor validated this path before transferring data.

**Phase 6 — Dual Persistence Establishment**  
Two separate persistence mechanisms were deployed, providing primary and fallback re-entry:
**Primary** — `SupportToolUpdater`: Named to mimic legitimate support tooling and evade casual inspection of startup entries.
**Backup (HKCU)** — `RemoteAssistUpdater`: Written to the HKCU (user scope) Run key, requiring no administrative privileges. This fallback ensures re-entry even if the primary mechanism is discovered and removed.

**Phase 7 — Misdirection Artifact Planted**  
`SupportChat_log.lnk` was created and subsequently opened by the actor (evidenced by a Windows Recent `.lnk` artifact). This file was designed to present a plausible cover story — a support chat log justifying all preceding activity as legitimate troubleshooting. The actor reviewed it to confirm the narrative was convincing before concluding the session.

---

## 4. MITRE ATT&CK Mapping

| Tactic                      | Technique                                              | Evidence                                                      |
| --------------------------- | ------------------------------------------------------ | ------------------------------------------------------------- |
| Execution / Defense Evasion | T1059.001 — PowerShell                                 | PowerShell -ExecutionPolicy bypass                            |
| Defense Evasion             | T1562.001 — Impair Defenses: Disable or Modify Tools   | DefenderTamperArtifact.lnk                                    |
| Collection                  | T1115 — Clipboard Data                                 | Get-Clipboard (silent, no-profile)                            |
| Discovery                   | T1082 — System Information Discovery                   | wmic logicaldisk get name,freespace,size                      |
| Discovery                   | T1016 — System Network Configuration Discovery         | RuntimeBroker.exe network/DNS check                           |
| Discovery                   | T1033 — System Owner / User Discovery                  | Active session enumeration                                    | 
| Discovery                   | T1057 — Process Discovery                              | tasklist.exe                                                  | 
| Discovery                   | T1069 — Permission Groups Discovery                    | Privilege validation                                          | 
| Discovery                   | T1016.001 — Internet Connection Discovery              | msftconnecttest.com connectivity test                         | 
| Collection                  | T1560.001 — Archive Collected Data                     | ReconArtifacts.zip staged in Public                           |
| Exfiltration                | T1041 — Exfiltration Over C2 Channel                   | Transfer to 100.29.147.161                                    |
| Persistence                 | T1547.001 — Boot or Logon Autostart: Registry Run Keys | SupportToolUpdater Run key , RemoteAssistUpdater HKCU Run key |
| Defense Evasion             | T1036 — Masquerading                                   | SupportChat_log.lnk misdirection                              |

---

## 5. Recommendations

### Immediate Actions  

- Isolate gab-intern-vm immediately and preserve a forensic image before any remediation.
- Block external IP 100.29.147.161 at the firewall and proxy level, and investigate any other hosts that communicated with this IP.
- Remove both persistence entries: SupportToolUpdater and RemoteAssistUpdater from HKCU and HKLM Run keys.
- Delete the staged archive C:\Users\Public\ReconArtifacts.zip and investigate its contents for data sensitivity
- Reset credentials for all accounts active on gab-intern-vm during the attack window. Any clipboard contents (passwords, tokens) must be treated as compromised.
- Review and revoke any remote access sessions or support tool credentials used during the October 9 session.

### Short-Term Remediation  

- Enable and validate DeviceRegistryEvents logging across all endpoints. This hunt identified a critical gap: Run key persistence was entirely invisible due to missing registry audit logs.
- Create alerts for HKCU Run key modifications specifically. User-scope persistence is commonly deprioritised versus HKLM and is a known attacker preference for low-privilege footholds.
- Alert on Get-Clipboard usage within PowerShell scripts running in non-interactive or -NoProfile contexts, particularly on non-developer workstations.
- Flag creation of archive files in C:\Users\Public\ and other world-readable staging locations as a high-fidelity exfiltration-preparation indicator.
- Implement behavioral detection for rapid sequential discovery commands (wmic + tasklist + privilege checks) within short time windows from the same process tree.
- Alert on PowerShell -ExecutionPolicy bypass used from non-administrative, non-IT accounts on standard workstations.

### Longer-Term Hardening  

- Enforce remote support sessions through dedicated, monitored jump hosts with session recording. Direct remote access to intern or standard workstations should require explicit approval and logging.
- Implement PowerShell Constrained Language Mode on all non-admin endpoints to restrict the scope of scripts that can execute without elevated privileges.
- Deploy application control (AppLocker or Windows Defender Application Control) to block unsigned script execution and limit living-off-the-land binary abuse.
- Apply egress filtering with a whitelist-based approach for outbound connections. Unknown external IPs such as 100.29.147.161 should be blocked by default.
- Apply heightened monitoring sensitivity to intern and shared workstations, which are common initial access targets due to lower security baselines and less scrutiny.
- Review and enforce log retention policies to ensure all Device* tables (especially DeviceRegistryEvents) are actively collecting across all onboarded endpoints.
- Develop an incident response playbook specifically for the malicious remote support session scenario, covering detection, isolation, evidence preservation, and credential revocation steps.

---

**Report Status:** Complete  

**Next Review:** 15 November 2025 

**Distribution:** Cyber Range
