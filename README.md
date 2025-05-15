# The Scanner

The Scanner is Völva’s core component for mapping Iceland’s internet-facing systems. It performs continuous host discovery and port scanning to reveal exposed services, track changes, and support proactive cybersecurity. Built for reliability and minimal network impact, it helps visualize national digital exposure—transparently and ethically.

## Völva: Scan Iceland 

The core component responsible for conducting the network scans. It spans in three phases in the scanning pipeline (prepare, host discovery and port scanning)

![Coverage](.github/img/coverage.svg)
![Version](https://img.shields.io/github/v/tag/volvan/scanner?label=version)
![License](https://img.shields.io/badge/license-Custom--Academic--Use-blue)
![Tests](https://img.shields.io/github/actions/workflow/status/volvan/scanner/tests.yml?branch=main&label=tests)
![Code Style](https://img.shields.io/github/actions/workflow/status/volvan/scanner/formatting.yml?branch=main&label=pep8)
![Python](https://img.shields.io/badge/python-3.11-blue)

---

## Quick links

- **[Website](https://volva.frostbyte.is)**

- **[GitLab Mirror](https://gitlab.frostbyte.is/academic-projects/scan_ice)**

- **[Original Repository](https://github.com/marteinnlundi/ScanICE)**

- **[Presentation Slides for Völva](https://blank.page/)**




## Hierarcy overview 

```t
~/scanner/
├── CODE_OF_CONDUCT.md
├── LICENSE.md
├── README.md
├── requirements.txt
│
├── _tests/
│   ├── config/
│   │   └── test_logging_config.py
│   ├── conftest.py
│   ├── database/
│   │   └── test_db_manager.py
│   ├── rmq/
│   │   └── test_rmq_manager.py
│   ├── scanner/
│   │   ├── discovery_scan/
│   │   │   ├── test_ip_manager.py
│   │   │   └── test_ip_scanner.py
│   │   └── port_scan/
│   │       ├── test_port_manager.py
│   │       └── test_port_scanner.py
│   ├── test_initialize_ip_scan.py
│   ├── test_initialize_port_scan.py
│   └── utils/
│       ├── test_batch_handler.py
│       ├── test_block_handler.py
│       ├── test_crypto_handler.py
│       ├── test_ping_handler.py
│       ├── test_ports_handler.py
│       ├── test_probe_handler.py
│       ├── test_queue_initializer.py
│       ├── test_randomize_handler.py
│       ├── test_timestamp.py
│       └── test_worker_handler.py
│
└── src/
    ├── __init__.py
    ├── config/
    │   ├── __init__.py
    │   ├── crypto_config.py
    │   ├── database_config.py
    │   ├── logging_config.json
    │   ├── logging_config.py
    │   ├── rmq_config.py
    │   └── scan_config.py
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
## How to Run

This project uses Python 3 and a virtual environment. Below are the minimal steps to get started.

### 1. Clone the Repository

```bash
sudo apt install -y git
git clone https://github.com/marteinnlundi/ScanICE.git
cd scanner/
```

### 2. Set Up Python Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

To deactivate:

```bash
deactivate
```

### 3. Environment Variables

Create a `.env` file in the root of the project and set required values:

```bash
# RabbitMQ
export RMQ_HOST=...
export RMQ_PORT=...
export RMQ_USER=...
export RMQ_PASS=...

# PostgreSQL
export DB_HOST=...
export DB_PORT=...
export DB_USER=...
export DB_PASS=...
export DB_NAME=...

# Format-Preserving Encryption
export FPE_KEY=...
export FPE_ALPHABET=...
export FPE_LENGTH=...

# Email + Report Generator
export SMTP_SERVER=...
export SMTP_PORT=...
export SMTP_USER=...
export SMTP_PASS=...
export EMAIL_FROM=...
export EMAIL_TO=...
export NATION=...
```

Then load them:

```bash
source .env
```

### Full Usage Documentation

For full instructions on running scans, generating reports, sending emails, and handling retries, refer to the component-specific guides:

- **Scanner**: `src/README.md`
    
- **Report Generator & Email Handler**: `src/report_generator/README.md`
    
