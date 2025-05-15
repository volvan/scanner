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
├── CODE_OF_CONDUCT.md             # Contributor guidelines and community expectations
├── LICENSE.md                     # Project license (e.g., MIT, GPL)
├── README.md                      # Main documentation file
├── requirements.txt               # Python dependencies
│
├── _tests/                        # Unit and integration tests
│   ├── config/
│   │   └── test_logging_config.py        # Tests logging configuration logic
│   ├── database/
│   │   └── test_db_manager.py            # Tests for database interactions
│   ├── rmq/
│   │   └── test_rmq_manager.py           # Tests for RabbitMQ functionality
│   ├── scanner/
│   │   ├── discovery_scan/
│   │   │   ├── test_ip_manager.py        # Tests for IP batching and handling
│   │   │   └── test_ip_scanner.py        # Tests for the discovery scanning logic
│   │   └── port_scan/
│   │       ├── test_port_manager.py      # Tests for port batching and grouping
│   │       └── test_port_scanner.py      # Tests for Nmap-based port scanning
│   ├── test_initialize_ip_scan.py        # Tests for the IP scan entrypoint
│   ├── test_initialize_port_scan.py      # Tests for the port scan entrypoint
│   └── utils/
│       ├── test_batch_handler.py         # Tests for task batching logic
│       ├── test_block_handler.py         # Tests for block/target list parsing
│       ├── test_crypto_handler.py        # Tests for encryption utilities
│       ├── test_ping_handler.py          # Tests ICMP ping logic
│       ├── test_ports_handler.py         # Tests for port range/selection handling
│       ├── test_probe_handler.py         # Tests for probe (Nmap) execution/response
│       ├── test_queue_initializer.py     # Tests queue initialization
│       ├── test_randomize_handler.py     # Tests for input shuffling/randomization
│       ├── test_timestamp.py             # Tests for time-based logic
│       └── test_worker_handler.py        # Tests for task processing logic
│
└── src/
    ├── config/                            # Central configuration files
    │   ├── crypto_config.py               # Config for encryption/decryption (e.g. keys)
    │   ├── database_config.py             # PostgreSQL connection setup
    │   ├── logging_config.json            # Logging settings in JSON format
    │   ├── logging_config.py              # Python logger initializer
    │   ├── rmq_config.py                  # RabbitMQ settings (queue names, host, etc.)
    │   └── scan_config.py                 # Parameters for scan behavior (timeouts, retries)
    │
    ├── database/
    │   └── db_manager.py                  # PostgreSQL abstraction layer for inserts/queries
    │
    ├── rmq/
    │   └── rmq_manager.py                 # Handles RabbitMQ connections, queue publish/consume
    │
    ├── scanners/
    │   ├── discovery_scan/
    │   │   ├── ip_manager.py              # Prepares and batches IPs for scanning
    │   │   └── ip_scanner.py              # Executes ping-based host discovery
    │   └── port_scan/
    │       ├── port_manager.py            # Prepares port scan jobs and manages groupings
    │       └── port_scanner.py            # Executes port scans using Nmap
    │
    ├── utils/                             # Reusable helper functions and shared logic
    │   ├── batch_handler.py               # Batches IPs/ports/tasks into scanable units
    │   ├── block_handler.py               # Loads and parses target IP blocks
    │   ├── crypto.py                      # Handles encryption/decryption routines
    │   ├── ping_handler.py                # Performs ICMP pings (host alive check)
    │   ├── ports_handler.py               # Reads and parses ports file
    │   ├── probe_handler.py               # Probes hosts using Nmap and extracts results
    │   ├── queue_initializer.py           # Sets up RabbitMQ queues and seeds jobs
    │   ├── randomize_handler.py           # Randomizes input order (IPs, ports)
    │   ├── timestamp.py                   # Adds timestamps and formatting utilities
    │   └── worker_handler.py              # Core scanning loop for handling tasks from queue
    │
    ├── initialize_fail_queue.py           # Requeues failed tasks for retry
    ├── initialize_ip_scan.py              # Entrypoint script to start discovery scans
    ├── initialize_port_scan.py            # Entrypoint script to start port scans
```




## How to Run

1. Clone the repository 

1.1 Install git: 

```bash
sudo apt install -y git
```


2. Create the ENV

(?)

```bash
export RMQ_USER="user"
export RMQ_PASS="<password>" 
```


3. Install Requirements 


```bash
cd scanner/
requirements.txt
```

4. Now you should be able to run 

    4.1 Manually with venv : 

    ```bash
    # Activate venv
    source venv/bin/activate
    ...

    # Deact venv
    deactivate
    ```

    4.2 With Visual Studio Code 

    1. Select interpreter as the Python Venv installed already in src 
    2. Run any file within VSCode

