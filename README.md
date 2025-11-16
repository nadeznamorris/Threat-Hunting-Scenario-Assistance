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

