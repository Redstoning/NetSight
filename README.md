# NetSight

NetSight is a Python-based PCAP inspection tool that analyzes packet captures, summarizes protocol activity, identifies top network talkers, and flags suspicious behaviors such as port scanning, ICMP spikes, SYN-heavy activity, and abnormal DNS usage.

## Features
- PCAP parsing with Scapy
- Protocol distribution analysis
- Top source and destination host tracking
- Detection of basic suspicious traffic patterns
- Terminal-based styled output with animated boot sequence

Installation
1. Clone the repository
git clone https://github.com/redstoning/netsight.git
cd netsight
2. Create a virtual environment
python3 -m venv venv
3. Activate the virtual environment

Mac / Linux:

source venv/bin/activate

Windows:

venv\Scripts\activate
4. Install dependencies
pip install -r requirements.txt
Adding PCAP Files

Place packet capture files inside the pcap/ folder.

Example:

netsight/pcap/test.pcap
Running NetSight

From the project root folder:

python netsight.py pcap/test.pcap

Example:

python netsight.py pcap/mytraffic.pcap
