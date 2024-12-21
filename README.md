# Zeus Banking Trojan Detection Project

## Overview

This project demonstrates the detection and analysis of the Zeus Banking Trojan using various cybersecurity tools and methodologies. By simulating malware execution in a controlled environment, this project aims to provide insights into detecting and mitigating such threats.

---

## Objectives

- Simulate the execution of the Zeus Banking Trojan in a secure environment.
- Analyze network and system activities to identify malicious patterns.
- Utilize tools like Suricata, Splunk, Volatility, and YARA for comprehensive detection.
- Provide actionable insights and a replicable process for Zeus Trojan analysis.

---

## Implementation Steps

### 1. Environment Setup

- **Kali Linux Machine:**
  - Install Suricata and Wireshark.
  - Configure for network monitoring and log forwarding.
- **Windows 10 Machine:**
  - Install the Zeus malware's zip file from [theZoo repository](https://github.com/ytisf/theZoo/tree/master/malware/Binaries/ZeusBankingVersion_26Nov2013).
  - Disable Windows Defender and firewall to prevent interference.
- **Network Configuration:**
  - Set up both machines on the same NAT network (e.g., 192.168.111.0).

### 2. Traffic Analysis Using Wireshark

- **Capture Traffic:**
  - Start live traffic capture on the infected VM.
  - Apply filters using the Windows machine's IP to isolate relevant traffic.
- **Analyze Traffic:**
  - Identify malicious IPs, protocols, and IOCs (Indicators of Compromise) like domain resolutions and URI patterns.

### 3. Malware Detection Using Suricata

- **Install and Configure Suricata:**
  - Define the home network in `suricata.yaml` as the Windows VM's IP.
  - Set the monitored interface to `eth0`.
- **Custom Rule Creation:**
  - Create rules to detect Zeus-specific HTTP requests and DNS queries.
  - Save rules in `/etc/suricata/rules/zeus.rules`.
- **Run Suricata:**
  - Execute the malware and observe Suricata's real-time alerts.

### 4. Log Forwarding to Splunk

- **Configure Log Forwarding:**
  - Modify `suricata.yaml` to enable log output to both `eve.json` and `fast.log`.
- **Set Up Splunk Universal Forwarder:**
  - Configure `outputs.conf` and `inputs.conf` to forward logs to Splunk.
  - Collect Windows Event Logs for Application, Security, and System events.

### 5. Monitoring and Dashboards in Splunk

- **Analyze Logs:**
  - Use Splunk to search for anomalies in network traffic and system events.
  - Query logs for Zeus-specific IOCs and alerts.
- **Create Dashboards:**
  - Panel 1: Frequency of detected alerts by signature.
  - Panel 2: IPs generating or receiving traffic.
  - Panel 3: Zeus-specific alerts over time.
  - Panel 4: Newly created processes (EventCode 4688).

### 6. Memory Analysis with Volatility

- **Memory Acquisition:**
  - Capture a memory image from the infected system.
- **Analyze with Volatility:**
  - List running processes (`pslist`) to identify suspicious activities.
  - Dump executables from memory for further analysis.
  - Use plugins like `malfind` to detect injected code or anomalous memory regions.

### 7. YARA Rule-Based Detection

- **Create YARA Rules:**
  - Develop rules to detect Zeus-related artifacts in binaries, configuration files, and memory dumps.
- **Run Scans:**
  - Apply YARA rules on the infected system and memory dumps to identify Zeus artifacts.

---

## Installation Steps

### Prerequisites

1. **Virtual Machine Software:** Install VirtualBox or VMware.
2. **Operating Systems:** Download and configure Kali Linux and Windows 10 ISO images.
3. **Tools Installation:**
   - Kali Linux: Install Suricata, Wireshark, Splunk, Volatility3, and YARA.
   - Windows: Install Splunk Universal Forwarder.

### Step-by-Step Guide

1. **Setup Virtual Machines:**

   - Configure the network to NAT mode.
   - Allocate sufficient memory and CPU resources.

2. **Install Suricata on Kali:**

   ```bash
   sudo apt update && sudo apt install suricata
   ```

3. **Install Wireshark on Kali:**

   ```bash
   sudo apt install wireshark
   ```

4. **Configure Splunk on Kali:**

   - Download and install Splunk from the official site.
   - Use the `dpkg` command to install the package:

     ```bash
     sudo dpkg -i splunk_package.deb
     ```
   - Set up a Splunk instance and configure data inputs.

5. **Install Zeus Malware on Windows:**

   - Download the Zeus binary from theZoo repository.
   - Disable antivirus and extract the malware.

6. **Run Suricata:**

   ```bash
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0
   ```

7. **Run Volatility:**

   Clone the Volatility repository:

   ```bash
   git clone https://github.com/volatilityfoundation/volatility3.git
   ```

   Analyze the memory dump:

   ```bash
   python3 vol.py -f memory_dump.vmem --profile=WinXPSP2x86 pslist
   ```

8. **Apply YARA Rules:**

   Update and install YARA:

   ```bash
   sudo apt update
   sudo apt install yara
   ```

   Run YARA scan:

   ```bash
   yara -r zeus_rules.yar memory_dump.vmem
   ```

---

## Tutorial

For a detailed walkthrough of the implementation, watch our [YouTube tutorial](#).

---

## Disclaimer

This project involves working with live malware. **Extreme caution** must be exercised. Ensure all testing is performed in a secure, isolated environment to prevent accidental harm. Follow ethical guidelines and cybersecurity best practices strictly.

