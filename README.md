<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/mfrancis415/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user "monica" downloaded a tor installer, did something that results in many tor-related files being copied to desktop and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-11-03T19:53:03.0933701Z`. These events began at: `2025-11-03T19:27:53.8153868Z`.


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "monica-hunting"
| where InitiatingProcessAccountName  == "monica"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-03T19:27:53.8153868Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/74faf187-65b0-489d-886a-cbebf11784a2">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for and `ProcessCommandLine` that contained the string “tor-browser-windows-x86_64-portable-15.0.exe”. Based on the logs returned at `2025-11-03T19:30:47.4419515Z`, an employee on the “monica-hunting” device ran the file `tor-browser-windows-x86_64-portable-15.0.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents 
| where DeviceName == "monica-hunting"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/5f5b67c0-3bae-49cc-9ca0-04b1f79bdbbd">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “monica” actually opened the tor browser. There was an evidence that they did open it at `2025-11-03T19:31:20.5319351Z`. There were several other instances of `firefox.exe` as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "monica-hunting"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-broswer.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc  
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/4f228c5f-f367-4cfa-9ada-ba3a49defda9">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the know tor ports. At `2025-11-03T19:32:02.8247093Z`, Monica's device successfully connected to the remote IP address `164.215.103.126` on port `9001`, using the program `tor.exe` located in the folder `c:\users\monica\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a few other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "monica-hunting"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/8c4e4bed-31b8-46d5-9721-018f30212175">

---

# 🔍 Chronological Event Timeline

## 1. File Download – TOR Installer
- **Timestamp:** 2025-11-03T19:27:53.8153868Z  
- **Event:** The user "monica" renamed the file `tor-browser-windows-x86_64-portable-15.0.exe` in the Downloads folder, indicating it was downloaded.  
- **Action:** FileRenamed  
- **File Path:** `C:\Users\Monica\Downloads\tor-browser-windows-x86_64-portable-15.0.exe`  

---

## 2. Process Execution – Silent Install
- **Timestamp:** 2025-11-03T19:30:47.4419515Z  
- **Event:** The user "monica" executed the TOR installer with a silent install flag (`/S`).  
- **Action:** ProcessCreated  
- **File Path:** `C:\Users\Monica\Downloads\tor-browser-windows-x86_64-portable-15.0.exe`  

---

## 3. File Creation – TOR Executables and Artifacts
- **Timestamp:** 2025-11-03T19:31:05–19:31:06Z  
- **Event:** TOR-related files were created post-installation, including the main executable and license documents.  
- **Action:** FileCreated  
- **File Paths:**  
  - `C:\Users\Monica\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`  
  - `C:\Users\Monica\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\tor.txt`  
  - `C:\Users\Monica\Desktop\Tor Browser\Tor Browser.lnk`  

---

## 4. File Creation – Firefox Profile and Storage
- **Timestamp:** 2025-11-03T19:31:25–19:31:39Z  
- **Event:** Firefox browser profile files were created, indicating setup of TOR browser environment.  
- **Action:** FileCreated  
- **File Paths:**  
  - `C:\Users\Monica\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\storage.sqlite`  
  - `C:\Users\Monica\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\storage-sync-v2.sqlite`  

---

## 5. Process Execution – TOR Browser Launch
- **Timestamp:** 2025-11-03T19:31:20.5319351Z  
- **Event:** First launch of `firefox.exe` from the TOR Browser directory.  
- **Action:** ProcessCreated  
- **File Path:** `C:\Users\Monica\Desktop\Tor Browser\Browser\firefox.exe`  

---

## 6. Process Execution – TOR Daemon Start
- **Timestamp:** 2025-11-03T19:31:34.697Z  
- **Event:** `tor.exe` launched with full configuration parameters including SOCKS and control ports.  
- **Action:** ProcessCreated  
- **File Path:** `C:\Users\Monica\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`  

---

## 7. Network Connections – TOR Entry Nodes
- **Timestamp:** 2025-11-03T19:32:02.8247093Z  
- **Event:** TOR successfully connected to IP `164.215.103.126` on port `9001`, a known TOR entry node.  
- **Action:** ConnectionSuccess  
- **Process:** `tor.exe`  
- **File Path:** `C:\Users\Monica\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`  

---

## 8. Network Connections – Encrypted Traffic via TOR
- **Timestamp:** 2025-11-03T19:31:50–19:45:06Z  
- **Event:** Multiple outbound connections made via TOR to various IPs and URLs over ports `443` and `9001`.  
- **Action:** ConnectionSuccess  
- **Processes:** `tor.exe`, `firefox.exe`  
- **File Paths:**  
  - `C:\Users\Monica\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`  
  - `C:\Users\Monica\Desktop\Tor Browser\Browser\firefox.exe`  

---

## 9. File Creation – TOR Shopping List
- **Timestamp:** 2025-11-03T19:53:03.0933701Z  
- **Event:** A file named `tor-shopping-list.txt` was created in the Documents folder and later moved to Desktop.  
- **Action:** FileCreated and FileRenamed  
- **File Paths:**  
  - `C:\Users\Monica\Documents\tor-shopping-list.txt`  
  - `C:\Users\Monica\Desktop\tor-shopping-list.txt`  

---

# 🔒 Summary of Findings: Unauthorized TOR Browser Usage

An investigation was conducted on workstation **monica-hunting** following suspicions of unauthorized encrypted traffic and potential TOR browser activity. The threat hunt confirmed that the user **monica** downloaded, installed, and actively used the TOR browser to establish outbound connections to known TOR entry nodes and encrypted endpoints.

## Key Findings
- **TOR Installation:** The user downloaded and silently installed `tor-browser-windows-x86_64-portable-15.0.exe` on November 3, 2025.
- **Executable Creation:** Installation resulted in the creation of TOR-related executables (`tor.exe`, `firefox.exe`) and browser artifacts on the desktop.
- **Process Execution:** Multiple instances of `tor.exe` and `firefox.exe` were launched, indicating active use of the TOR browser.
- **Network Activity:** The device established outbound connections to IP addresses over TOR-specific ports (9001, 443), including known TOR entry nodes.
- **User Artifacts:** A file named `tor-shopping-list.txt` was created and accessed, suggesting user engagement with TOR-related content.

## Risk Implications
- **Bypassing Security Controls:** Use of TOR may allow circumvention of network monitoring and access to restricted or anonymous resources.
- **Data Exfiltration Potential:** Encrypted outbound traffic via TOR poses a risk of unauthorized data transmission.
- **Policy Violation:** Installation and use of unapproved software violates acceptable use policies and introduces operational risk.

---

## Response Taken

TOR usage was confirmed on the endpoint `monica-hunting` by the user `monica`. The device was isolated, and the user's direct manager was notified.

---
