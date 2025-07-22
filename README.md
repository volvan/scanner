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
    
