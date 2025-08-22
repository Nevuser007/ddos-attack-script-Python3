# ddos-attack-script-Python3
This project is an educational penetration testing and DDoS simulation tool built with Python. It features multiple attack vectors (SYN, UDP, ICMP, DNS Amplification, HTTP Flood, Slowloris, WordPress XML-RPC), automatic reconnaissance using Nmap, GeoIP-based IP mapping, Tor/VPN integration for anonymity, and PDF reporting
# Advanced Pentest & DDoS Simulator (Educational Use Only)

🚨 **Disclaimer:** This tool is intended **for educational purposes and authorized penetration testing only**. Do **NOT** use it for illegal activities or attacks against systems without explicit permission. The author is **not responsible** for any misuse.

---

## 📌 About the Project
This project is a **cybersecurity and penetration testing toolkit** that simulates multiple attack vectors such as SYN Flood, UDP Flood, ICMP, DNS Amplification, Slowloris, and WordPress XML-RPC exploits.  

It provides a **graphical user interface (GUI)**, real-time monitoring, and reporting features to help security researchers and students learn about attack patterns and defense mechanisms.

---

## ⚡ Features
- ✅ Multiple attack vectors (SYN, UDP, ICMP, HTTP Flood, DNS Amplification, Slowloris, Slow POST, WordPress XML-RPC)  
- 📊 Real-time monitoring with live graphs and statistics  
- 🔎 Automatic reconnaissance (Nmap-based port and OS detection)  
- 🌍 GeoIP integration with IP mapping (Folium)  
- 🛡️ VPN and Tor integration for anonymity  
- 📄 PDF report generation after tests  
- 🎨 User-friendly GUI (Tkinter) with Dark Mode support  

---

## 🛠 Installation
Requires **Python 3.10+**.  

Clone the repository and install dependencies:  
```bash
git clone https://github.com/username/pentest-ddos-simulator.git
cd pentest-ddos-simulator
pip install -r requirements.txt
