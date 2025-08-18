import os
# TODO[P_High][Emilia]: fix fetch from RIX everywhere.. and verify it works afterwards
# TODO: what happens if USE_PRIORITY_PORTS is true /or false AND we have both ports.txt and priorityports.txt or can we only use ports.txt?

# ------------------------------------------------------------------------------
# --------- GLOBAL SETTINGS AND CONFIGURATIONS TO FINE TUNE THE SCANNER --------
# ------------------------------------------------------------------------------

SCAN_TYPE:str         = "ip"                                         # (DEF: ip_port)  - Run discovery scan or port scan (values: ip, port and ip_port)
SCAN_MODE_LIGHT:bool  = True                                         # (DEF: False)  - If False, runs intense scan that adds -sV to port probes (for better version detection)


# ----- MONITORING and LOGS ------------------------------------------------------
DEBUG_MODE:bool       = True                                         # Debug mode will prompt user in start of run
SERVICE_TAG           = SCAN_TYPE + "_scan"                          # The logger file / tag, such as "ip_scan" or "port_scan"
LOG_TO_FILE:bool      = True                                         # If True, logs debug levels in log file, else warnings
LOG_TO_TERMINAL:bool  = False                                        # If True, logs debug levels to terminal, else warnings
# -------------------------------------------------------------------------------


# ----- PATHS ------------------------------------------------------------------
BASE_DIR              = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR              = os.path.dirname(os.path.dirname(BASE_DIR))
TARGETS_FILE_PATH     = os.path.join(BASE_DIR, "..", "targets")      # Stored under src/targets/ and stores 'blocks.txt', 'ports.txt'

TARGETS_FILE:str      = os.path.join(TARGETS_FILE_PATH, "blocks.txt")# File containing IP/CIDR blocks to scan (used when FETCH_RIX is False)
PORTS_FILE:str        = os.path.join(TARGETS_FILE_PATH, "ports.txt") # The file containing the ports to scan

CONFIG_PATH           = os.path.join(os.path.dirname(__file__), "../config/logging_config.json") # Logs json config path
LOG_DIR               = os.path.join(ROOT_DIR, "logs")               # Where to store the logs
LOG_FILE_PATH         = os.path.join(LOG_DIR, f"{SERVICE_TAG}.log")  # Name of the log file
# --------------------------------------------------------------------------------


# ----- RESOURCE LIMITS ---------------------------------------------------------
MEM_LIMIT = 1_000 * 1024**2                                          # Memory (in bytes)
CPU_LIMIT = 70                                                       # CPU (percent)
# -------------------------------------------------------------------------------


# ----- SCAN PARAMS USED IN BOTH HOST DISCOVERY AND PORT SCAN -------------------
SCAN_NATION:str       = "IS"                                          # The Nation-code that is being scanned
FETCH_RIX:bool        = False                                         # (DEF: True)  - If True, fetch IPs from RIX.is
FAIL_QUEUE:str        = f"{SCAN_NATION}.fail_queue"                   # The RabbitMQ queue name that contains ip or (ip,port) pairs that encountered an error or failed while the scan was processing

TOTAL_MAX_WORKERS     = 10                                            # (DEF: 250)  - Number of workers/processes to spawn 
SCAN_DELAY:float      = 0.5                                           # Delay (sec) between scan attempts       # TODO: should it be used so often? (10 times in the code currently)

# Batches
BATCH_WORKERS_PER_QUEUE_MAX = 1                                       # (DEF: 100)  - Workers concurrently working on tasks per queue 
BATCH_QUEUES_ACTIVE_MAX = 5                                           #             - Max batches that exist concurrently
BATCH_CREATED_QUEUES_MAX = 10                                         # Extra prebuilt batches waiting for workers to work on them (buffer)

BATCH_QUEUE_TIMEOUT_SEC = 300                                         # Max time allowed per batch queue        # TODO: IF this is what i think it is, its the max time a process can live when its working on a batch.. if so it should be implemented in port scan also right? or that all processes (in batch or not) should have a timeout? the name of this const is atleast not descriptive.. it seems to me at first glance that port x on all ips is = batch - meaning that a process can scan all those targets only in this timeframe
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# --------------------------- DISCOVERY SCAN PARAMS ----------------------------
ALL_ADDR_QUEUE = f"{SCAN_NATION}.all_addr"                            # The RabbitMQ queue name that contains of all ips to scan
ALIVE_ADDR_QUEUE = f"{SCAN_NATION}.alive_addr"                        # The RabbitMQ queue name that contains all IPs discovered as 'alive' 
DEAD_ADDR_QUEUE = f"{SCAN_NATION}.dead_addr"                          # The RabbitMQ queue name that contains all IPs discovered as 'dead'

THRESHOLD = 20                                                        # Direct vs batch mode threshold
WHO_IS_SCAN_DELAY = 2                                                 # (DEF: 2)    - Delay between whois lookups       # TODO: verify correct use
BATCH_QUEUE_SIZE_MAX = 8                                              # (DEF: 500)  - Tasks (IPs) per batch

# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# --------------------------- PORT SCAN PARAMS ---------------------------------
USE_PRIORITY_PORTS = False                                            # Set this to True if ports file consists of priority ports

ALL_PORTS_QUEUE = f"{SCAN_NATION}.all_ports"                          # The RabbitMQ queue name that contains all ports to scan 
PRIORITY_PORTS_QUEUE = f"{SCAN_NATION}.priority_ports"                # The RabbitMQ queue name that contains all ports to scan when USE_PRIORITY_PORTS is True

PROBE_JITTER_MAX = float(0.1)                                         # jitter to add on top of SCAN_DELAY (in seconds) # TODO:[emilia] verify

NMAP_RETRY_DELAY = 200                                                # (DEF: 200ms)  - Minimum delay between two probes to the same port
NMAP_RETRY_ATTEMPTS = 1                                               # How many extra probes may be sent if there's no reply (excluding the initial probe)
_T1_TIMEOUT = 15                                                      # (helper)    - T1 probes wait up to 15s for a response by design
NMAP_PROBE_TIMEOUT = (                                                # (DEF: 60) The scan will have this max seconds to scan its target port on any ip before going for timeout
    (NMAP_RETRY_DELAY / 1000) * (1 + NMAP_RETRY_ATTEMPTS)                   # delay * retry attempts
  + (_T1_TIMEOUT * (1 + NMAP_RETRY_ATTEMPTS))                               # RTT waits * retry attempts
  + 30                                                                      # the added slack
) 
# ------------------------------------------------------------------------------


# ----- DATABASE WRITER  -------------------------------------------------------    # TODO: not all in use atm, should implement 
DB_MIN_CONN = 1                                                       # Min number of PSQL connections in the thread pool
DB_MAX_CONN = 20                                                      # Max number of PSQL connections in the thread pool

DB_HOST_WRITERS = 4                                                   # Amount of database writer threads (pulling from db_hosts)
DB_PORT_WRITERS = 5                                                   # Amount of database writer threads (pulling from db_ports)

DB_MAX_BATCH_SIZE = 500                                               # Max db rows to flush in each iteration from the db_* queues to the database
DB_TASK_TIMEOUT = 15_000                                              # (ms) The task the worker is executing has a timeout of this 
DB_BATCH_TIMEOUT = float(0.7)                                         # Flush at least this often from the db_* queues to the database or until DB_BATCH_SIZE is reached
# ------------------------------------------------------------------------------



