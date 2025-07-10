# The Scanner

The Scanner is Völva’s core component for mapping Iceland’s internet-facing systems. It performs continuous host discovery and port scanning to reveal exposed services, track changes, and support proactive cybersecurity. Built for reliability and minimal network impact, it helps visualize national digital exposure—transparently and ethically. For further details, see the [thesis](https://hdl.handle.net/1946/50479).

## Völva: Scan Iceland 

The core component responsible for conducting the network scans, is named Völva. It spans in three phases in the scanning pipeline (prepare, host discovery and port scanning). 

![Coverage](.github/img/coverage.svg)
![Version](https://img.shields.io/github/v/tag/volvan/scanner?label=version)
![License](https://img.shields.io/badge/license-Custom--Academic--Use-blue)
![Tests](https://img.shields.io/github/actions/workflow/status/volvan/scanner/tests.yml?branch=main&label=tests)
![Code Style](https://img.shields.io/github/actions/workflow/status/volvan/scanner/formatting.yml?branch=main&label=pep8)
![Python](https://img.shields.io/badge/python-3.11-blue)

---


## Hierarchy Overview  

```t
~/scanner/
├── LICENSE.md
├── README.md
├── requirements.txt
│
├── _tests/
│   ├── ...
│   
└── src/
    ├── __init__.py             # Includes version release number
    ├── config/
    │   ├── __init__.py
    │   ├── crypto_config.py
    │   ├── database_config.py
    │   ├── logging_config.json
    │   ├── logging_config.py
    │   ├── rmq_config.py
    │   └── scan_config.py      # The configurations for the scanner
    │
    ├── database/
    │   ├── __init__.py
    │   └── db_manager.py
    │
    ├── rmq/
    │   ├── __init__.py
    │   └── rmq_manager.py
    │
    ├── scanners/
    │   ├── __init__.py
    │   ├── discovery_scan/
    │   │   ├── __init__.py
    │   │   ├── ip_manager.py
    │   │   └── ip_scanner.py
    │   └── port_scan/
    │       ├── __init__.py
    │       ├── port_manager.py
    │       └── port_scanner.py
    │
    ├── utils/
    │   ├── __init__.py
    │   ├── batch_handler.py
    │   ├── block_handler.py
    │   ├── crypto.py
    │   ├── ping_handler.py
    │   ├── ports_handler.py
    │   ├── probe_handler.py
    │   ├── queue_initializer.py
    │   ├── randomize_handler.py
    │   ├── timestamp.py
    │   └── worker_handler.py
    │
    ├── report_generator/
    │   ├── __init__.py
    │   ├── db_handler.py
    │   ├── email_handler.py
    │   ├── generate_report.py
    │   ├── latex_utils.py
    │   ├── main.py
    │   ├── queries.py
    │   ├── README.md
    │   ├── report_config.py
    │   └── templates/
    │       ├── admin.tex
    │       └── supervisor.tex
    │
    ├── initialize_fail_queue.py
    ├── initialize_ip_scan.py
    ├── initialize_port_scan.py
    └── README.md

```
## Getting Started

This project uses Python3 and runs in a virtual environment. 

## Prerequisites

- Python 3.11 installed on the working machine
- RabbitMQ setup and accessible from the machine.
- PostgreSQL database setup and accessible from the machine.
- Network connectivity for scanning targets (ICMP, TCP).

### 1. Clone the Repository

```bash
sudo apt install -y git
git clone https://github.com/volvan/scanner.git
cd scanner/
```

### 2. Set Up The Environment

```bash
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Environment Variables

Create a `.env` file in the root of the project and set required values:

```bash
# RabbitMQ
export RMQ_HOST=<host>
export RMQ_PORT=<port>
export RMQ_USER=<username>
export RMQ_PASS=<password>

# PostgreSQL
export DB_NAME=<database>
export DB_HOST=<host>
export DB_PORT=<port>
export DB_USER=<username>
export DB_PASS=<password>


# Format-Preserving Encryption
export FPE_KEY=<byte key>
export FPE_ALPHABET=<alphabet string>
export FPE_LENGTH=<integer>

# Email + Report Generator
export SMTP_SERVER=...
export SMTP_PORT=...
export SMTP_USER=...
export SMTP_PASS=...
export EMAIL_FROM=...
export EMAIL_TO=...
```

Then load them:

```bash
source .env
```

### Full Usage Documentation

For full instructions on running scans, generating reports, sending emails, and handling retries, refer to the component-specific guides:

- **Scanner**: `src/README.md`
    
- **Report Generator & Email Handler**: `src/report_generator/README.md`
    
