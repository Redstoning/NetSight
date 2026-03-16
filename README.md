# NetSight

NetSight is a Python-based PCAP inspection tool that analyzes packet captures, summarizes protocol activity, identifies top network talkers, and flags suspicious behaviors such as port scanning, ICMP spikes, SYN-heavy activity, and abnormal DNS usage.

---

## Features

- PCAP parsing with Scapy
- Protocol distribution analysis
- Top source and destination host tracking
- Detection of basic suspicious traffic patterns
- Terminal styled output with animated boot sequence

---

## Installation

Clone the repository:

git clone https://github.com/redstoning/netsight.git  
cd netsight

Create a virtual environment:

python3 -m venv venv

Activate the environment

Mac / Linux:

source venv/bin/activate

Windows:

venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

---

## Requirements

NetSight requires:

- Python 3.9+
- scapy
- rich

Install manually if needed:

pip install scapy rich

---

## Adding PCAP Files

Place packet capture files inside the `pcap/` folder.

Example:

netsight/pcap/test.pcap

---

## Running NetSight

From the project root directory:

python netsight.py pcap/test.pcap

Example:

python netsight.py pcap/mytraffic.pcap

---

## Example Output

NetSight will display:

- protocol distribution
- top talkers
- destination hosts
- suspicious traffic indicators

---

## License

Apache 2.0 License
