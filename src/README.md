# Scanner 

This document describes how to set up and run the scanner, the main scanner engine.


## Prerequisites

Make sure you have setup the enviroment by following the _Getting Started_ chapter in the head `/README` file. 

The Python code loads `.env` via `dotenv.load_dotenv()`. Ensure `.env` is present at runtime or export the same variables in your shell.

## Configurations 

The only files needed to modify the scanner should be the ones listed in the `src/config/*` directory. 


## How to Run 

In an activated virtual environment, from `scanner/src/`:

```bash
# Run the Discovery scan
python initialize_ip_scan.py
# With redirected logs:
python initialize_ip_scan.py >> scan_ip.log 2>&1

# Run the Port scan
python initialize_port_scan.py
```

For continuously running scans, use tmux:

```bash
tmux new -s scanice
# inside pane
source venv/bin/activate
cd src
python initialize_ip_scan.py
```

Detach with `Ctrl+b d`, reattach with `tmux attach -t scanice`.


### Run with code formatter

Pep8 and flake8 are used, to run them, follow these steps:

```bash 
pre-commit install
cd .github
# Run the formatter on all files
pre-commit run --all-files
```

## Detailed Pipelines Flow

### IP Discovery Scan

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

### Port Scan

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


### Parallel / Multi-Country

For concurrent scans per country:

1. Create separate env files, for example: `.env.IS` and `.env.SE`.
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

## Logs and Monitoring

- Logs are written to `logs/ip_scan.log` and `logs/port_scan.log` (as per `logging_config.json`).
- Adjust `debug`, `log_to_file`, and `service_tag` in `src/config/logging_config.json`.
- Monitor in real time:
    
    ```bash
    tail -f logs/ip_scan.log
    ```
    
