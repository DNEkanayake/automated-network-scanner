# Automated Network Scanner

A robust, lightweight Python network utility designed to scan a local subnet for active hosts and analyze open ports on discovered devices. Built using **Scapy** for packet crafting and **Socket** for port verification, this tool automatically logs its findings into structured JSON and CSV formats for documentation.

## Features
- **Host Discovery:** Leverages ARP broadcast packets to identify all online devices within a specified CIDR block.
- **Port Scanning:** Conducts basic TCP handshake connections across common network service ports.
- **Banner Grabbing:** Attempts basic service version detection from open sockets.
- **Reporting:** Automatically exports structured scan data to spreadsheet-ready `.csv` and `.json` formats.

## Skills Demonstrated
- Network Architecture & Layer 2/Layer 4 Protocols (ARP, TCP, Subnetting)
- Automation with Python 
- Data Serialization (JSON/CSV)
- System Troubleshooting

## Getting Started

### Prerequisites
- Python 3.x
- Npcap (Ensure "WinPcap API-compatible Mode" is enabled during installation)

### Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/DNEkanayake/automated-network-scanner.git](https://github.com/YOUR_USERNAME/automated-network-scanner.git)
   cd automated-network-scanner

  
  
Install the required dependencies:   

Bash
pip install scapy


Usage
Run the script with administrator privileges and specify the target IP network range:

Bash
python Scanner.py -t 192.168.8.0/24