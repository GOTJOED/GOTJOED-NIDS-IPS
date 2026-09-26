# GOTJOED-NIDS-IPS
Network-based Intrusion Detection System with IPS

A lightweight, locally-hosted security tool built for Linux environments. It leverages native `tshark` packet capturing in the background to monitor network traffic in real-time, matching activity against active threat intelligence feeds (Abuse.ch, CISA KEV, and Emerging Threats).

## Deployment Modes
This tool is flexible and can operate in two distinct modes depending on your network needs:

* **Pure NIDS Mode (Detection Only):** Passively monitors local network traffic. It logs malicious activity and streams alerts to the web dashboard without interfering with or altering the network flow. 
* **Active IPS Mode (Prevention):** When deployed behind a network, it actively defends your system by dynamically injecting kernel-level firewall rules (`ipset` and `iptables`) to instantly ban and drop packets from identified threat IPs.

## Key Features
* **TShark Backend:** Low-overhead packet inspection running silently in the background.
* **Dynamic Threat Intel:** Automatically syncs with Abuse.ch, CISA KEV, and ET Open rule sets.
* **Local Web Dashboard:** A live, interactive UI to monitor threat logs, view active engine storage, and manage banned hosts.
* **Manual & Auto Banning:** Manually ban suspicious IPs straight from the dashboard, or let the IPS auto-ban based on severe CVE/CWE matches.

* ## Preview
* **Live Threat Overview & Stream**
<img width="1906" height="941" alt="image" src="https://github.com/user-attachments/assets/f69877b2-46af-4db1-9529-a96b25a36fdd" />
<img width="1284" height="861" alt="image" src="https://github.com/user-attachments/assets/e0465ccc-64d0-46a4-9029-529f5a1d26ff" />

**Active Threat Feeds (Abuse.ch, CISA, ET)**
<img width="1916" height="592" alt="image" src="https://github.com/user-attachments/assets/587f2bda-0739-4b25-bc6f-962263056db0" />

**IPS Banned Hosts**
<img width="1912" height="574" alt="image" src="https://github.com/user-attachments/assets/e41f9b45-d665-4fa4-be25-c09f7bdb2e40" />

**Settings**
<img width="1922" height="663" alt="image" src="https://github.com/user-attachments/assets/51b33da8-2905-4fc7-b7e8-0743bdf20988" />

## Getting Started
1. Run `sudo ./setup.sh` to configure the environment.
2. Run `sudo ./run.sh` to start the detection engine and local web server.
