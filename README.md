# Threat-Hunting-Scenario-Assistance

This threat hunt explores a suspicious “support session” that turned out to be anything but routine. What appeared to be troubleshooting actually revealed staged actions, planted explanations, and a sequence of behaviors aimed at gaining system insight rather than offering help. The investigation focuses on rebuilding the timeline, identifying the planted narrative, and distinguishing genuine activity from intentional misdirection.

## Environment & Data Sources
- **Host:** `gab-intern-vm` (Windows endpoint)
- **Telemetry:** Azure Log Analytics Workspaces:
  - `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`
- **Timeframe:** 2025-10-06 → 2025-10-10 (UTC)

---

### Flag 0 - Starting Point

**Objective :**  
The objective was to identify which machine showed the earliest and most consistent signs of suspicious activity—based on shared file traits, download-folder executions, and intern-related hosts—and determine the correct starting point for the hunt.

**Flag Value :**  
`gab-intern-vm`

**KQL Query :**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName has_any ("intern")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by TimeGenerated asc
```

<img width="1363" height="222" alt="Flag 0" src="https://github.com/user-attachments/assets/09b08e44-3416-4978-9253-b5346d01bb8c" />

---

### Flag 1 – Initial Execution Detection

**Objective :**  
Detect the earliest anomalous execution that could represent an entry point.

**Flag Value :**  
`-ExecutionPolicy`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "powershell", "powershell_ise.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, FolderPath
| order by TimeGenerated asc
```

<img width="1347" height="142" alt="image" src="https://github.com/user-attachments/assets/a9ab556f-275e-4c34-b218-ccb8e17b4b9d" />

---

### Flag 2 – Defense Disabling

**Objective :**  
Identify indicators that suggest attempts to imply or simulate changing security posture.

**Flag Value :**  
`DefenderTamperArtifact.lnk`

**KQL Query :**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ActionType in~ ("FileCreated","FileModified","FileWrite","FileAccessed")
| where InitiatingProcessFileName in~ ("notepad.exe","explorer.exe","regedit.exe","cmd.exe","powershell.exe","mmc.exe")
| where FileName !startswith "__PSScriptPolicyTest"
| project TimeGenerated, InitiatingProcessFileName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="800" height="200" alt="Flag 2" src="https://github.com/user-attachments/assets/44945fbf-f515-4f1c-9916-886e94cbccc6" />

---

### Flag 3 – Quick Data Probe

**Objective :**  
Spot brief, opportunistic checks for readily available sensitive content.

**Flag Value :**  
`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("Get-Clipboard", "GetClipboard", "clip.exe", " clip ", "pbpaste", "Get-Content | clip", "Set-Clipboard", "Get-ClipboardValue")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId, ReportId
| order by TimeGenerated asc
```

<img width="800" height="150" alt="Flag 3" src="https://github.com/user-attachments/assets/3eee55f4-96bd-4d81-99cb-8aeb3277641a" />

---

### Flag 4 – Host Context Recon

**Objective :**  
Spot brief, opportunistic checks for readily available sensitive content.

**Flag Value :**  
`2025-10-09T12:51:44.3425653Z`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("qwinsta","quser","query session","query user","whoami","systeminfo","hostname","ipconfig","net user","net localgroup","wmic useraccount","wmic computersystem","Get-WmiObject","Get-CimInstance","Get-LocalUser")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, ProcessId
| order by TimeGenerated desc
```

<img width="720" height="158" alt="Flag 4" src="https://github.com/user-attachments/assets/2d423cf8-dc73-4398-9030-8522ffd127a3" />

---

### Flag 5 – Storage Surface Mapping

**Objective :**  
Detect discovery of local or network storage locations that might hold interesting data.

**Flag Value :**  
`"cmd.exe" /c wmic logicaldisk get name,freespace,size`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any (
    "Get-ChildItem", "Get-PSDrive", "Get-SmbShare", "Get-SmbShareAccess",
    "Get-PSProvider", "dir ", "tree ", "net view", "net share", "net use",
    "wmic logicaldisk", "fsutil", "mountvol", "robocopy", "dir /s", "Get-ChildItem -Recurse",
    "Get-Volume","Get-Partition","Get-PSProvider -PSProvider FileSystem"
)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine, ProcessId
| order by TimeGenerated asc
| extend rn = row_number()
```

<img width="1195" height="118" alt="Flag 5" src="https://github.com/user-attachments/assets/dac081ef-170f-4a46-b9b0-9034836e478b" />

---

### Flag 6 – Connectivity & Name Resolution Check

**Objective :**  
Identify checks that validate network reachability and name resolution.

**Flag Value :**  
`RuntimeBroker.exe`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("ping","nslookup","Resolve-DnsName","Test-NetConnection","tracert","curl","Invoke-WebRequest","Invoke-RestMethod","wget","GetHostEntry","netstat","query session","qwinsta")
| project TimeGenerated, ChildFileName = FileName, ChildCommandLine = ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<img width="862" height="242" alt="image" src="https://github.com/user-attachments/assets/d1dc41d5-3aba-4ec8-8a45-cd6ece94fcc4" />

---

### Flag 7 – Interactive Session Discovery

**Objective :**  
Reveal attempts to detect interactive or active user sessions on the host.

**Flag Value :**  
`2533274790397065`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("query session","qwinsta","quser","query user","whoami /all","whoami /groups")
| project TimeGenerated, FileName, InitiatingProcessParentId, InitiatingProcessCommandLine, InitiatingProcessUniqueId
| order by TimeGenerated asc
```

<img width="1142" height="208" alt="image" src="https://github.com/user-attachments/assets/151d61af-934c-4f0e-b6b1-874f7ce92381" />

---

### Flag 8 – Runtime Application Inventory

**Objective :**  
Detect enumeration of running applications and services to inform risk and opportunity.

**Flag Value :**  
`tasklist.exe`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any (
    "tasklist","tasklist /v","Get-Process","Get-Service","sc query","wmic process list",
    "Get-WmiObject -Class Win32_Process","Get-CimInstance -ClassName Win32_Process",
    "Get-CimInstance -ClassName Win32_Service","powershell -Command Get-Process","powershell -Command Get-Service"
)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

<img width="760" height="210" alt="Flag 8" src="https://github.com/user-attachments/assets/3d23011a-7617-4f2e-a58a-68d6926469b5" />

---

### Flag 9 – Privilege Surface Check

**Objective :**  
Detect attempts to understand privileges available to the current actor.

**Flag Value :**  
`2025-10-09T12:52:14.3135459Z`

**KQL Query :**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("whoami /all","whoami /groups")
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName
| order by TimeGenerated asc
```

<img width="756" height="950" alt="image" src="https://github.com/user-attachments/assets/a97a03e8-39b3-499f-bd1f-276c461dcff9" />

---

### Flag 10 – Proof-of-Access & Egress Validation

**Objective :**  
Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.

**Flag Value :**  
`www.msftconnecttest.com`

**KQL Query :**
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "curl.exe", "wget.exe", "bitsadmin.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, Protocol, RemotePort
| order by TimeGenerated asc
```

<img width="756" height="180" alt="image" src="https://github.com/user-attachments/assets/593ed620-869c-43a1-b9c9-70d2cb663d2d" />

---

### Flag 11 – Bundling / Staging Artifacts

**Objective :**  
Detect consolidation of artifacts into a single location or package for transfer.

**Flag Value :**  
`C:\Users\Public\ReconArtifacts.zip`

**KQL Query :**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ActionType in ("FileCreated", "FileCopied", "FileModified")
| where FileName has_any (".zip", ".txt", ".log", ".csv")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="636" height="200" alt="Flag 11" src="https://github.com/user-attachments/assets/c47488d8-8551-4a4e-bccc-f13e703ef2d8" />


