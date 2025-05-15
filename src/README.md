# Scanner 

This document describes how to set up and run the ScanICE-service, the main scanner engine. It covers environment setup, configuration, and all supported execution modes.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Setup](#setup)
    1. [Python Virtual Environment](#python-virtual-environment)
    2. [Install Dependencies](#install-dependencies)
    3. [Environment Variables](#environment-variables)
3. [Configuration](#configuration)
    1. [Environment Files](#environment-files)
    2. [Configuration Directories](#configuration-directories)
4. [Running the System](#running-the-system)
    1. [Terminal](#terminal)
    2. [tmux](#tmux)
    3. [Long Scans and tmux Recommendation](#long-scans-and-tmux-recommendation)
5. [Individual Script Reference](#individual-script-reference)
    1. [IP Discovery Scan](#ip-discovery-scan)
    2. [Port Scan](#port-scan)
    3. [Retry Fail Queue](#retry-fail-queue)
6. [Concurrent and Back-to-Back Execution](#concurrent-and-back-to-back-execution)
    1. [Back-to-Back](#back-to-back)
    2. [Parallel / Multi-Country](#parallel--multi-country)
7. [Logs and Monitoring](#logs-and-monitoring)
8. [Troubleshooting](#troubleshooting)

## 1. Prerequisites

- Access to VM with SSH access.
- Python 3.9+ installed on the VM.
- RabbitMQ server accessible from the VM.
- PostgreSQL database accessible from the VM.
- Network connectivity for scanning targets (ICMP, TCP).

## 2. Setup

### 2.1 Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2.2 Install Dependencies

```bash
pip install --upgrade pip
pip install -r src/requirements.txt
```

### 2.3 Environment Variables

Create a `.env` file in `project-root/src/` with the following entries:

```dotenv
# RabbitMQ
RMQ_HOST=<host>
RMQ_PORT=<port>
RMQ_USER=<username>
RMQ_PASS=<password>

# PostgreSQL
DB_HOST=<host>
DB_PORT=<port>
DB_USER=<username>
DB_PASS=<password>
DB_NAME=<database>

# Format-Preserving Encryption (FPE)
FPE_KEY=<32-byte key>
FPE_ALPHABET=<alphabet string>
FPE_LENGTH=<integer>

# Scan Configuration (optional overrides)
ADDR_FILE=targets/blocks.txt
PORTS_FILE=targets/ports.txt
SCAN_NATION=IS
USE_PRIORITY_PORTS=true
FETCH_RIX=false

# Queue names (optional namespacing)
ALL_ADDR_QUEUE=all_addr
ALIVE_ADDR_QUEUE=alive_addr
DEAD_ADDR_QUEUE=dead_addr
FAIL_QUEUE=fail_queue
ALL_PORTS_QUEUE=all_ports
PRIORITY_PORTS_QUEUE=priority_ports
OUTPUT_FAIL_QUEUE=retry_failed_ports
```

All variables without defaults in code must be set here.

## 3. Configuration

### 3.1 Environment Files

The Python code loads `.env` via `dotenv.load_dotenv()`. Ensure `.env` is present at runtime or export the same variables in your shell.

### 3.2 Configuration Directories
- `src/config/crypto_config.py`: FPE parameters.
- `src/config/database_config.py`: Database credentials.
- `src/config/rmq_config.py`: RabbitMQ credentials.
- `src/config/scan_config.py`: Scan parameters and queue names.
- `src/config/logging_config.json`: Logging settings.

## 4. Running the System

### 4.1 Terminal

In an activated virtual environment, from `project-root/src/`:

```bash
# Discovery scan
python initialize_ip_scan.py

# Port scan
python initialize_port_scan.py

# Retry fail queue
python initialize_fail_queue.py
```

You can redirect logs:

```bash
python initialize_ip_scan.py >> scan_ip.log 2>&1
```


### 4.2 tmux

For long-running scans, use tmux:

```bash
tmux new -s scanice
# inside pane
source venv/bin/activate
cd src
python initialize_ip_scan.py
```

Detach with `Ctrl+b d`, reattach with `tmux attach -t scanice`.

### 4.3 Long Scans and tmux Recommendation

If total tasks exceed `THRESHOLD` (default 30), the system switches to batch mode. In this case, a tmux session is recommended to maintain the process when detached.

## 5. Individual Script Reference

### 5.1 IP Discovery Scan

**Script:** `initialize_ip_scan.py`

**Flow:**

1. Start DBWriter for hosts.
2. Enqueue targets from `ADDR_FILE` or RIX if `FETCH_RIX=true`.
3. Record `discovery_start_ts`.
4. Launch `IPScanner` (direct or batch mode).
5. Record `discovery_done_ts`.
6. Insert summary row into `summary` table.

Run:

```bash
python initialize_ip_scan.py
```

### 5.2 Port Scan

**Script:** `initialize_port_scan.py`

**Flow:**

1. Start DBWriter for ports.
2. Seed ports from `PORTS_FILE` into `PRIORITY_PORTS_QUEUE` or `ALL_PORTS_QUEUE`.
3. Record `port_start_ts`.
4. Launch `PortScanner` (persistent workers).
5. Record `port_done_ts`.
6. Update or insert summary row with port metadata.

Run:

```bash
python initialize_port_scan.py
```

### 5.3 Retry Fail Queue

**Script:** `initialize_fail_queue.py`

**Flow:**

1. Start DBWriter for ports.
2. Consume `FAIL_QUEUE` tasks.
3. Retry each IP:port scan once.
4. Route still-unknown to `OUTPUT_FAIL_QUEUE`.

Run:

```bash
python initialize_fail_queue.py
```

## 6. Concurrent and Back-to-Back Execution

### 6.1 Back-to-Back

To run discovery then port scan sequentially in one terminal:

```bash
python initialize_ip_scan.py && python initialize_port_scan.py
```

### 6.2 Parallel / Multi-Country

For concurrent scans per country:

1. Create separate env files, e.g. `.env.IS`, `.env.SE`.
2. Override `SCAN_NATION` and queue names in each:
    
    ```dotenv
    SCAN_NATION=SE
    ALL_ADDR_QUEUE=SE.all_addr
    ALIVE_ADDR_QUEUE=SE.alive_addr
    # … etc.
    ```
    
3. In separate tmux windows or terminals, load each env and start:
    
    ```bash
    source venv/bin/activate
    set -a && source src/.env.SE && set +a
    python initialize_ip_scan.py
    ```
    

Ensure queue names do not collide by prefixing with country code.

## 7. Logs and Monitoring

- Logs are written to `logs/ip_scan.log` and `logs/port_scan.log` (as per `logging_config.json`).
- Adjust `debug`, `log_to_file`, and `service_tag` in `src/config/logging_config.json`.
- Monitor in real time:
    
    ```bash
    tail -f logs/ip_scan.log
    ```
    

## 8. Troubleshooting

- **Missing env variables:** Ensure `.env` is loaded or variables are exported.
- **RabbitMQ errors:** Check connection settings, `rabbitmqctl list_queues`.
- **PostgreSQL errors:** Verify credentials and network access.
- **High memory/CPU:** Tune `SCAN_MEM_LIMIT` and `CPU_LIMIT` in `scan_config.py` or via env overrides.
