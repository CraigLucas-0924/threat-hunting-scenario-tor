# threat-hunting-scenario-tor
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
[Scenario Creation](https://github.com/CraigLucas-0924/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)


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

Queried the DeviceFileEvents table for any file names containing the string "tor" and identified evidence suggesting the user downloaded a Tor installer. This action led to multiple Tor-related files being copied to the desktop, along with the creation of a file named "tor-shopping-list.txt". These events began at 2025-05-10T18:32:36Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
|where DeviceName == "craigir"
|where FileName contains "tor"
|order by Timestamp desc
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,InitiatingProcessAccountName

```
![image](https://github.com/user-attachments/assets/91621ef9-d602-41e3-a272-df1517ee1380)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the ProcessEvents table for any ProcessCommandLine entries containing the string "tor-browser-windows-x86_64-portable-14.5.1.exe". At 2025-05-10T20:14:42Z, a user on the device "CraigIR" executed the file from their Downloads folder using the /s switch, initiating a silent installation of the Tor browser.
**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.1.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, SHA256, ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/f6582e91-89c0-4e14-8afa-0b4c374e9a91)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Queried the DeviceProcessEvents table for evidence that the user account "craigir" launched the Tor browser. At 2025-05-10T20:18:36Z, a process associated with Tor was executed, confirming the browser was opened. Multiple instances of firefox.exe (Tor) and Tor.exe were also observed spawning shortly thereafter, indicating active use of the application.
**Query used to locate events:**

```kql
DeviceProcessEvents  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/e43ae003-a936-4339-8543-81a533d6c9f6)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-05-10T18:40:53.1089685Z`, an employee on the "craigir" device successfully established a connection to the remote IP address `195.90.200.83` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\craigir\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/97f900e5-615d-40c1-ac30-0f896e5e4137)

---

## Chronological Event Timeline 

## 📅 Timeline of Events

- **2025-05-10T13:32:36Z – Initial Tor Installer Activity Detected**  
  The file `tor-browser-windows-x86_64-portable-14.5.1.exe` was renamed within the `Downloads` folder by user `craigir`, indicating the beginning of the installation process.  
  **(Event Source: DeviceFileEvents)**

- **2025-05-10T18:32:36Z – Tor Files Appear on Desktop**  
  A search for filenames containing `"tor"` revealed multiple Tor-related files were copied to the desktop, including the creation of `tor-shopping-list.txt`, suggesting engagement with Tor setup.  
  **(Event Source: DeviceFileEvents)**

- **2025-05-10T20:14:42Z – Silent Tor Installation Executed**  
  User `craigir` executed the Tor installer using the `/s` switch from the `Downloads` folder, triggering a **silent installation** without user prompts.  
  **(Event Source: ProcessEvents)**

- **2025-05-10T20:18:36Z – Tor Browser Execution Confirmed**  
  Logs confirmed the launch of the Tor browser. Multiple associated processes such as `firefox.exe` (Tor) and `Tor.exe` were spawned, indicating active use.  
  **(Event Source: DeviceProcessEvents)**

## 🧾 Executive Summary: Suspicious Tor Browser Activity on Endpoint `craigir`

On **May 10, 2025**, the endpoint identified as **`craigir`** exhibited a series of events strongly indicating the **deliberate download, installation, and use** of the Tor browser—an anonymizing tool often associated with privacy-focused or evasive behavior.

The activity began at approximately **1:08 PM**, when the device initiated multiple successful outbound internet connections. Shortly thereafter, between **1:32 PM and 1:36 PM**, the system was observed downloading files clearly related to the Tor browser, including the portable installation package. These actions coincided with a noticeable spike in **process initiations**, likely tied to the silent execution and unpacking of the installer.

At **3:14 PM**, telemetry confirmed that the Tor browser was fully installed. This was followed by additional download events and **further process launches** spanning **3:15 PM to 3:57 PM**, suggesting either automated configuration or direct user interaction with the application.

Collectively, this timeline reflects **intentional and sustained engagement** with the Tor browser. The use of silent installation methods, combined with multiple executions of `Tor.exe` and `firefox.exe (Tor)`, suggests an attempt to **anonymize activity or circumvent standard endpoint monitoring controls**.

> ⚠️ *This behavior warrants further investigation and may constitute a violation of acceptable use policies depending on the organization's security guidelines.*

---

## ✅ Response Actions

- The device `CraigIR` was **isolated from the network** to prevent further anonymous activity.
- The user’s **direct manager was notified** and incident handling was escalated to IT Security.

---
