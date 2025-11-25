**Threat Detection Network Security Monitoring Using Security Onion**

This project demonstrates practical experience with Security Onion, a full-stack Network Security Monitoring (NSM) and Intrusion Detection platform. It’s built to catch intrusions while giving real-time visibility into traffic behavior through integrated analysis tools.
It covers two major threat-detection scenarios:

Scenario 1 — Live Attack Simulation Using Kali Linux
  * Nmap aggressive scans
  * Hydra brute-force attempts
  * Real-time alerting from Suricata + Zeek
  * Log and PCAP analysis
  * Response actions (IP blocking)
  
Scenario 2 — Malware PCAP Investigation (SpoonWatch)
  * Using open-source malware-traffic PCAPs
  * Importing and analyzing PCAP in Security Onion
  * Investigating IOCs via the Cases tool
  * Identifying C2 behavior, malware download patterns, and suspicious HTTP logs

The outcome shows full-range cyber defense abilities usually needed for SOC, threat hunting, or digital forensics jobs - using real scenarios. It’s built to reflect hands-on experience instead of theory, linking tasks through practical flow rather than isolated steps. Each phase connects with the next, showing how detection leads into response when handled under pressure.

What is Security Onion?
Security Onion is an open-source Network Security Monitoring (NSM) and Intrusion Detection Platform used by SOC teams for:
  * Packet capture
  * IDS/IPS alerts (Suricata)
  * Protocol logging (Zeek/Bro)
  * SIEM capabilities (Elastic stack)
  * Case management & investigation workflows
It combines tools such as Zeek, Suricata, Elastic Stack, Stenographer, and Hunt in one environment.


**Scenario 1 — Live Attack Simulation From Kali Linux**

1️⃣ Deployment & Installation
Security Onion VM Setup
  * 4 CPU, 8 GB RAM, 200 GB disk
  * Second NIC set to Host-Only
  * Standard standalone installation
  * SSH access enabled

Post-install validation: _sudo so-status_

<img width="1915" height="1078" alt="SecOnion Services running" src="https://github.com/user-attachments/assets/02de24de-30bc-4bdc-b434-d35bf1df59d8" />

When services failed to start, they were rebuilt using: _sudo so-salt state.highstate_

Network connectivity was validated by pinging the sensor: _ping 192.168.**.***_

<img width="1908" height="1078" alt="ping SecOnion" src="https://github.com/user-attachments/assets/8d29cc1b-6c67-4bd3-a599-d138ec294c0c" />


2️⃣ Sensor Verification & Attack Traffic Generation

From Kali Linux, the following attacks were executed against the Security Onion sensor:

🔹 Nmap Aggressive Scan
nmap -A 192.168.**.***

🔹 SSH Brute Force with Hydra
hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://192.168.**.***

Result:
Suricata and Zeek immediately generated alert activity, including:
  * GPL ICMP PING *NIX
  * ET Scan activity
  * SSH brute-force detection patterns
  * UPnP Subscribe CallStranger scanning traffic (ET signature)

3️⃣ Log Investigation & Timeline Reconstruction
Logs were reviewed using Alerts, Hunt, and Dashboards.

🔹 Suricata Alerts
The earliest detection showing attack activity was:
  * GPL ICMP PING NIX, confirming host probing
  * Followed by ET SCAN UPnP SUBSCRIBE Inbound, Possible CallStranger Scan (CVE-2020-12695)
  
<img width="1713" height="877" alt="Sensor Verification_01" src="https://github.com/user-attachments/assets/7a633c03-cf97-4229-90a1-82ba3eb68eb5" />

This signature indicates scanning for vulnerable UPnP devices (network-enabled devices designed to automatically discover each other and communicate on a local network without manual configuration).
Key risks of CallStranger:
  * Information disclosure
  * Data exfiltration
  * DDoS amplification
  * Potential Remote Code Execution depending on the device

🔹 Zeek Connection Logs
Zeek revealed:
  * High-volume UDP broadcast activity
  * DNS/DHCP patterns
  * Possible host-only adapter NAT masking traffic (Kali’s traffic appeared as 192.168.196.1, not its true 192.168.70.133)

🔹 HTTP Logs
  * No C2 traffic detected
  * No unusual User-Agents
  * No /php or exploit-based requests

4️⃣ Response Action — Blocking the Attacker

The malicious IP (192.168.196.1) was blocked using iptables:
sudo iptables -A INPUT -s 192.168.196.1 -j DROP

Verification:
sudo iptables -L -n --line-numbers

<img width="1662" height="950" alt="Blocked IPs" src="https://github.com/user-attachments/assets/c1125ef0-8147-4ef8-9ef4-91e10f505624" />


**Scenario 2 — Malware PCAP Investigation (SpoonWatch)**

A malware traffic PCAP was downloaded from malware-traffic-analysis.net and ingested into Security Onion.

1️⃣ Tools Used — Security Onion “Cases” App

Cases allows analysts to:

🔹 Escalate alerts from Hunts, Dashboards, or Suricata

🔹 Add observables (IPs, hashes, domains)

🔹 Attach logs, screenshots, and notes

🔹 Track investigation history

🔹 Use TLP (Traffic Light Protocol) and PAP (Permissible Actions Protocol)

2️⃣ Importing the PCAP Into Security Onion
Steps executed:
sudo so-import-pcap 2022-01-07-traffic-analysis-exercise.pcap

<img width="1916" height="1072" alt="PCAP Importation" src="https://github.com/user-attachments/assets/f2059ac2-31fc-4bb8-b192-ee4ec137c930" />

After import, logs appeared in:

 🔹 Alerts
 
 🔹 Hunt
 
 🔹 Dashboards
 
 🔹 Kibana/Elastic Discover

3️⃣ Threat Findings

🔹 Malware Download Attempt
Suricata detected:

ET MALWARE Vidar/Arkei/Megumin/Oski Stealer HTTP POST Pattern

→ Indicates credential-stealing malware families attempting beaconing or data exfiltration.

<img width="1915" height="1078" alt="SpoonWatch Dashboard" src="https://github.com/user-attachments/assets/ab76ee46-6507-4c38-a754-75e97011e80f" />
  
  
🔹 Suspicious Server Response

ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response

→ The server returned a file beginning with “MZ”, the signature of a Windows PE executable.

<img width="1911" height="1072" alt="Scenario 2- Observables" src="https://github.com/user-attachments/assets/3718379f-85ca-4c8f-81d5-6747ef91acdc" />

🔹 File Offered for Download

ET INFO PE EXE or DLL Windows file download HTTP

→ Confirms compilation of a Windows executable being delivered to the victim.

<img width="1917" height="1066" alt="Malicious download " src="https://github.com/user-attachments/assets/59e79262-fe4a-44c8-9151-93bd38cb9b4a" />

🔹Data Exfiltration Attempt via ZIP Archive (Critical)

Suricata also triggered a high-fidelity alert indicating attempted exfiltration of user data:

ET HUNTING SUSPICIOUS Zipped Filename in Outbound POST Request (Chrome_Default.txt)

<img width="1918" height="1078" alt="data exfiltration" src="https://github.com/user-attachments/assets/7aa5d9ee-a249-435d-91a7-758dbd441185" />

What this indicates:

The infected host attempted to send a ZIP archive via an outbound HTTP POST request.
Inside the archive was a filename matching known credential-theft patterns, in this case, Chrome_Default.txt
This is strongly associated with malware exfiltrating:

  * Browser passwords
  * Cookies
  * Autofill data
  * Local session tokens
  * Browser profile artifacts

This behavior is consistent with Vidar/Arkei stealer malware, which:

  * Collects browser and system information
  * Packs it into a ZIP archive
  * Exfiltrates the data to a Command-and-Control (C2) server

🔹 IOC Analysis

  * IPs checked against OSINT / AbuseIPDB
    <img width="1917" height="1076" alt="Abuse-IP " src="https://github.com/user-attachments/assets/d890281f-bed9-491c-9227-104a79f7a003" />
  * URLs reviewed
  * Hostnames extracted from Zeek HTTP logs

This produced a full chain of malicious behavior:
Victim → C2 server → Malware Download → PE EXE Response

**Tools, Frameworks & Skills Demonstrated**

🔹 Blue-Team Tools

  * Security Onion (NSM platform)
  
  * Suricata IDS
  
  * Zeek / Bro
  
  * Elastic Stack (Dashboards, Discover)
  
  * Hunt
  
  * Cases (case management)
  
  * PCAP ingestion and analysis

🔹 Attack Tools

  * Nmap
  
  * Hydra
  
  * ICMP scanning
  
  * SSH brute forcing

🔹 Investigative Skills
  * Alert triage
  
  * Log correlation
  
  * Connection analysis
  
  * HTTP header inspection
  
  * DNS analysis
  
  * IOC extraction
  
  * Threat intelligence lookups
  
  * Timeline reconstruction
  
  * Network-level response (iptables)

In conclusion, this project demonstrates complete, hands-on experience with:

✔️ Deploying and managing Security Onion

✔️ Generating real attack traffic

✔️ Investigating Suricata, Zeek, and Elastic logs

✔️ Importing malware PCAPs

✔️ Performing SOC-style triage and escalation

✔️ Taking real containment actions (IP blocking)
