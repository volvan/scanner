# The Scanner

The Scanner is Völva’s core component for mapping Iceland’s internet-facing systems. It performs continuous host discovery and port scanning to reveal exposed services, track changes, and support proactive cybersecurity. Built for reliability and minimal network impact, it helps visualize national digital exposure—transparently and ethically.

## Völva: Scan Iceland 

The core component responsible for conducting the network scans. It spans in three phases in the scanning pipeline (prepare, host discovery and port scanning)

![Coverage](.github/img/coverage.svg)
![Version](https://img.shields.io/github/v/tag/volvan/scanner?label=version)
![License](https://img.shields.io/github/license/volvan/scanner)
![Tests](https://img.shields.io/github/actions/workflow/status/volvan/scanner/tests.yml?branch=dev&label=tests)
![Code Style](https://img.shields.io/github/actions/workflow/status/volvan/scanner/formatting.yml?branch=dev&label=pep8)
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
├── .github/
│   ├── CONTRIBUTE
│
├── docs/                       # Additional setups (optional)
│   ├── vm_setup.md/            # Specs and setup instructions
│   └── prometheus.md/
│
├── _tests/                     # py tests
│   ├── database/
│   │   └── ...
│   ├── rmq/ 
│   │   └── ...
│   ├── scanner/ 
│   │   └── discovery_scan/
│   │   │   ...
│   │   │   ...
│   │   └── port_scan/
│   │   │   ...
│   │   │  ....
│   └── utils/ 
│
└── README.md
│ 
│ 
└── src/                        # Source Code
    ├── venv/                   # Virtual environment
    │
    ├── config/                 # Global configuration files
    │   └── database_config.py  # PostgreSQL connection details
    │   └── rmq_config.py       # RabbitMQ-specific settings
    │   └── scan_config.py      # Scanner settings
    │   └── database_config.py  # PostgreSQL connection details
    │   └── targets_config.py   # Targets configurations, target = who to scan
    │
    │
    ├── database/               # Database-specific modules 
    │   └── database_manager.py
    │   └── initialize_tables.py
    │
    │
    ├── rmq/                    # RabbitMQ-specific modules
    │   └── initialize_queues.py
    │   └── rmq_manager.py 
    │
    │
    ├── scanners/               # Host discovery module     
    │   ├── ip_scan/            # IP address scanning module
    │   │   ├── ip_scanner.py
    │   │   └── ip_manager.py
    │   └── port_scan/          # Port scanning module
    │       ├── port_scanner.py
    │       └── port_manager.py
    │
    ├── targets/                # Targets to scan
    │   ├── blocks.txt 
    │   └── ports.txt 
    │
    ├── utils/                  # Utility functions used across modules
    │   ├── logger.py           # logger for debugging
    │   ├── block_handler.py
    │   ├── ping_handler.py     # handles pings with only alive or dead responses
    │   ├── ports_handler.py
    │   └── probe_handler.py    # handles probes (nmap) with data responses
    │
    ├── initialize_port_scan.py # "main" for port scanning
    ├── initialize_ip_scan.py   # "main" for ip scanning
    │
    │
    └── report_generator/       # Report Generator
        └── main.py
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

