# Azure Threat Detection Lab
![Lab Architecture](images/lab_architecture.png)

## Overview

This project demonstrates a cloud **`threat detection engineering workflow`** using Microsoft Sentinel and Azure Log Analytics.

The goal of the lab was to simulate attacker behaviors on a Windows virtual machine and build detection queries capable of identifying suspicious activity.

Telemetry is collected using **Windows Security Events** and ingested into Azure through the **`Azure Monitor Agent (AMA)`**. The logs are analyzed using **Kusto Query Language (KQL)** to detect attacker techniques.

The project demonstrates how detection engineers convert raw telemetry into actionable detections mapped to **MITRE ATT&CK techniques**.

---

# Lab Architecture

Internet Traffic  
↓  
Azure Windows Virtual Machine  
↓  
Windows Security Events  
↓  
Azure Monitor Agent (AMA)  
↓  
Log Analytics Workspace  
↓  
Microsoft Sentinel  
↓  
Threat Detection Queries


---

# Detection Engineering

The following detections were developed using **KQL** and validated against telemetry generated in the lab environment.

---

# 1️) Brute Force Login Detection

**MITRE ATT&CK:** T1110 – Brute Force

This detection identifies excessive failed login attempts that may indicate password spraying or brute force authentication attacks.

## Detection Query

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by Account, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts > 5
| sort by FailedAttempts desc
```
![Brute Force Login Detection](images/brute_force_login_detection.png)

# 2) Encoded PowerShell Execution Detection

**MITRE ATT&CK:**  T1059 – Command and Scripting Interpreter (PowerShell)

Attackers frequently execute PowerShell using encoded commands to hide malicious payloads.

## Detection Query

```kql
SecurityEvent
| where EventID == 4688
| where Process has "powershell"
| where CommandLine contains "-EncodedCommand"
| project TimeGenerated, Computer, Account, Process, CommandLine
```
![Encoded PowerShell Execution Detection](images/encoded_powerShell_execution_detection.png)

# 3) Suspicious Parent Process Detection

**MITRE ATT&CK:** T1059 – Command Execution

This detection identifies PowerShell processes launched from unusual parent processes.

## Detection Query

```kql
SecurityEvent
| where EventID == 4688
| where Process has "powershell"
| where ParentProcessName !contains "explorer.exe"
| project TimeGenerated, Computer, Process, ParentProcessName, Account
```

![Suspicious Parent Process Detection](images/suspicious_parent_process_detection.png)

Unusual parent processes launching PowerShell may indicate attacker activity such as command execution or malware activity.

# 4) Network Beaconing Detection

**MITRE ATT&CK:** T1071 – Application Layer Protocol

Command-and-control malware often communicates with external infrastructure at regular intervals.

## Detection Query

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| summarize Connections=count() by Computer, bin(TimeGenerated, 1m)
| where Connections > 20
| sort by Connections desc
```
![Network Beaconing Detection](images/network_beaconing_detection.png)

This detection identifies hosts generating unusually frequent outbound network connections.

# 5️) Privileged Logon Detection

**MITRE ATT&CK:** T1078 – Valid Accounts

Event ID 4672 indicates that special administrative privileges were assigned to a user account.

## Detection Query

```kql
SecurityEvent
| where EventID == 4672
| project TimeGenerated, Account, Computer
| sort by TimeGenerated desc
```

![Privileged Logon Detection](images/privileged_logon_detection.png)

Example accounts observed in the lab:

NT AUTHORITY\SYSTEM

VIRTUAL USERS\sshd_4024

![Privileged Logon Detection](images/privileged_logon_detection.png)

# 6️) Scheduled Task Persistence Detection

**MITRE ATT&CK:** T1053 – Scheduled Task / Job

Attackers often create scheduled tasks to maintain persistence.

## Detection Query

```kql
SecurityEvent
| where EventID == 4698
| project TimeGenerated, Computer, Activity
| sort by TimeGenerated desc
```
![Scheduled Task Persistence Detection](images/scheduled_task_persistence_detection.png)

Example event detected:

4698 – A scheduled task was created

# 7️) Admin Group Membership Change Detection

**MITRE ATT&CK:** T1098 – Account Manipulation

This detection identifies accounts added to privileged security groups.

## Detection Query

```kql
SecurityEvent
| where EventID == 4732
| project TimeGenerated, Account, Computer, Activity
| sort by TimeGenerated desc
```
![Admin Group Membership Change Detection](images/admin_Group_membership_change_detection.png)

No events were detected during the testing window in the lab environment.

# 8️) Suspicious Service Creation Detection

**MITRE ATT&CK:** T1543 – Create or Modify System Process

Attackers often create Windows services to execute malware or maintain persistence.

## Detection Query

```kql
SecurityEvent
| where EventID == 4697
| project TimeGenerated, Account, Computer, Activity
| sort by TimeGenerated desc
```
![Suspicious Service Creation Detection](images/suspicious_service_creation_detection.png)

Example event observed:

4697 – A service was installed in the system

Account observed:

WORKGROUP\vm-chido-lab-ca$


# 9️) Remote Desktop Logon Detection

**MITRE ATT&CK:** T1021 – Remote Services

This detection identifies successful Remote Desktop Protocol (RDP) logons.

## Detection Query

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project TimeGenerated, Account, Computer, IpAddress
| sort by TimeGenerated desc
```
![Remote Desktop Logon Detection](images/remote_desktop_logon_detection.png)

Example event observed:

Account:

vm-chido-lab-ca\chidoazurelab

Source IP:

206.x.x.x

# Microsoft Sentinel Detection Rule

An analytics rule was created in Microsoft Sentinel to convert detection queries into automated alerts.

# Microsoft Sentinel Incident Example

When detection rules trigger, Microsoft Sentinel generates security incidents for investigation.

# Skills Demonstrated

- Cloud security monitoring

- Threat detection engineering

- Microsoft Sentinel analytics rule creation

- KQL threat hunting

- MITRE ATT&CK mapping

- Windows security log analysis

- Attack simulation and detection validation

# Conclusion

This lab demonstrates the process of building practical threat detections in Microsoft Sentinel using real Windows telemetry.

The project simulates attacker behaviors and develops KQL detections mapped to MITRE ATT&CK techniques commonly used by adversaries.

It highlights how detection engineers transform raw telemetry into actionable security monitoring capabilities.
