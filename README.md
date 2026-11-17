# 🛡 Digital Forensics Artifacts Collector and Analyzer

A unified, multi-OS live forensics acquisition and automated analysis tool built in Python for **Windows, Linux, and macOS**. It streamlines evidence collection, log parsing, threat hunting, and reporting into a single interactive workflow.

## 🚀 Key Features
- **Live Artifacts Acquisition:** Collects OS-native forensic artifacts (EVTX logs, Registry hives, shell history, auth/audit logs, running processes, and persistence mechanisms).
- **Automated Parsing & Threat Hunting:** Built-in analysis for system logs, suspicious processes, and persistence indicators.
- **Interactive Reporting:** Generates clean HTML dashboards with timeline views and supports JSON/CSV/PDF exports.
- **Cross-Platform Support:** Works seamlessly across Windows, Linux (Ubuntu/Kali/CentOS), and macOS environments.

## 📋 Prerequisites
- **Python 3.8+**
- Required Python libraries:
  ```bash
  pip install python-evtx volatility3 python-registry requests tqdm
