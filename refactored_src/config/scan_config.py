import os  
# TODO[Emilia]: fix fetch from RIX everywhere.. and verify it works afterwards
# TODO: Check if any dead-code and where (if anywhere) these are used 
# TODO: what happens if USE_PRIORITY_PORTS is true /or false AND we have both ports.txt and priorityports.txt or can we only use ports.txt?

# ------------------------------------------------------------------------------
# --------- GLOBAL SETTINGS AND CONFIGURATIONS TO FINE TUNE THE SCANNER --------
# ------------------------------------------------------------------------------


# ----- PATHS ------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(BASE_DIR))
TARGETS_FILE_PATH = os.path.join(BASE_DIR, "..", "targets")           # Stored under src/targets/ and stores 'blocks.txt', 'ports.txt'
# ------------------------------------------------------------------------------
# ----- MONITORING and LOGS ------------------------------------------------------
DEBUG_MODE = True                                                     # Debug mode will prompt user in start of run
LOG_TO_FILE = True                                                    # If True, logs debug levels in log file, else warnings
LOG_TO_TERMINAL = False                                               # If True, logs debug levels to terminal, else warnings

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/logging_config.json") # Logs json config path
LOG_DIR = os.path.join(ROOT_DIR, "logs")                              # Where to store the logs
# ------------------------------------------------------------------------------
# ----- RESOURCE LIMITS --------------------------------------------------------
MEM_LIMIT = 1_000 * 1024**2                                           # Memory (in bytes)
CPU_LIMIT = 70                                                        # CPU (percent)
# ------------------------------------------------------------------------------


# --------- SCAN PARAMS USED IN BOTH HOST DISCOVERY AND PORT SCAN --------------
SCAN_TYPE:str           = "port"
SCAN_NATION:str         = "IS"                                                    # The Nation-code that is being scanned
FETCH_RIX:bool          = False                                                     # (DEF: True)  - If True, fetch IPs from RIX.is
TARGETS_FILE:str        = "blocks.txt"                                           # File containing IP/CIDR blocks to scan (used when FETCH_RIX is False)
PORTS_FILE:str          = os.path.join(TARGETS_FILE_PATH, "ports.txt")             # The file containing the ports to scan
FAIL_QUEUE:str          = f"{SCAN_NATION}.fail_queue"                              # The RabbitMQ queue name that contains ip or (ip,port) pairs that encountered an error or failed while the scan was processing

SCAN_DELAY:float        = 0.5                                               # Delay (sec) between scan attempts       # TODO: should it be used so often? (10 times in the code currently)
MAX_BATCH_PROCESSES:int = 100                                             # Spawn new batch processes in "start_consuming", up to max limit reached
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# --------------------------- DISCOVERY SCAN PARAMS ----------------------------
ALL_ADDR_QUEUE = f"{SCAN_NATION}.all_addr"                            # The RabbitMQ queue name that contains of all ips to scan
ALIVE_ADDR_QUEUE = f"{SCAN_NATION}.alive_addr"                        # The RabbitMQ queue name that contains all IPs discovered as 'alive' 
DEAD_ADDR_QUEUE = f"{SCAN_NATION}.dead_addr"                          # The RabbitMQ queue name that contains all IPs discovered as 'dead'

THRESHOLD = 2                                                         # Direct vs batch mode threshold
BATCH_SIZE = 10                                                       # (DEF: 500)  - Tasks per batch
IP_MAX_BATCH_AMOUNT = 5                                                  #             - Max batches that exist concurrently
WHO_IS_SCAN_DELAY = 2                                                 # (DEF: 2)    - Delay between whois lookups       # TODO: verify correct use
WORKERS = 3                                                           # (DEF: 250)  - Number of workers to spawn
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# --------------------------- PORT SCAN PARAMS ---------------------------------
ALL_PORTS_QUEUE = f"{SCAN_NATION}.all_ports"                          # The RabbitMQ queue name that contains all ports to scan 
PRIORITY_PORTS_QUEUE = f"{SCAN_NATION}.priority_ports"                # The RabbitMQ queue name that contains all ports to scan when USE_PRIORITY_PORTS is True

USE_PRIORITY_PORTS = False                                            # Set this to True if ports file consists of priority ports
BATCH_AMOUNT = 100                                                    # Concurrent port batches     # TODO: rename PORT_MAX_BATCH_AMOUNT and verify correctly used
BATCH_TIMEOUT_SEC = 300                                               # Max time allowed per batch queue        # TODO: IF this is what i think it is, its the max time a process can live when its working on a batch.. if so it should be implemented in port scan also right? or that all processes (in batch or not) should have a timeout? the name of this const is atleast not descriptive.. it seems to me at first glance that port x on all ips is = batch - meaning that a process can scan all those targets only in this timeframe
PROBE_TIMEOUT = int(os.getenv("PROBE_TIMEOUT", "60"))                 # Allow override of the subprocess timeout via environment variable       # TODO: What is this? dont tell me its processes that are host scanning and they have 60 seconds to live? or? and why in the world is it casting a str to int? is there a reason for it?
# ------------------------------------------------------------------------------



# ----- DATABASE WRITER  -------------------------------------------------------    # TODO: not all in use atm, should implement 
DB_MIN_CONN = 1                                                       # Min number of PSQL connections in the thread pool
DB_MAX_CONN = 20                                                      # Max number of PSQL connections in the thread pool
DB_HOST_WRITERS = 4                                                   # Amount of database writer threads (pulling from db_hosts)
DB_PORT_WRITERS = 4                                                   # Amount of database writer threads (pulling from db_ports)
DB_MAX_BATCH_SIZE = 500                                               # Max db rows to flush in each iteration from the db_* queues to the database
DB_BATCH_TIMEOUT = float(0.7)                                         # Flush at least this often from the db_* queues to the database or until DB_BATCH_SIZE is reached
# ------------------------------------------------------------------------------







# ------------------------------------------------------------------------------
# TODO[emilia]: look into this and how this is being used
SCAN_MAX_RETRIES = int(os.getenv("SCAN_MAX_RETRIES", 2))              # how many times Nmap will retry
PROBE_JITTER_MAX = float(os.getenv("PROBE_JITTER_MAX", 0.1))          # jitter to add on top of SCAN_DELAY (in seconds)
# Unprivileged “stealth” connect-scan settings 
SCAN_DELAY_MS = int(os.getenv("SCAN_DELAY_MS", 200))                  # how long to wait between Nmap probes (in ms)
SCAN_DELAY_STR = f"{SCAN_DELAY_MS}ms"
# base flags for an unprivileged, slower connect-scan
UNPRIV_SCAN_FLAGS = [
    "-sT",
    "-T1",                                                            # very slow timing template
    f"--scan-delay={SCAN_DELAY_STR}",
    f"--max-retries={SCAN_MAX_RETRIES}",
    "--data-length", "20",
    "-Pn"                                                             # skip host-discovery ping
]

# ─── Nmap port-scan flags (externalized for easy tweaking) ────────────────
NMAP_FLAGS = {
    "service_detection": "-sV",
    "ports": "-p",
}
# ------------------------------------------------------------------------------





# ----- RabbitMQ QUEUE NAMES  --------------------------------------------------
#ALL_ADDR_QUEUE = f"{SCAN_NATION}.all_addr"                            # The queue used for Host discovery, consists of all ips to scan
# ALIVE_ADDR_QUEUE = f"{SCAN_NATION}.alive_addr"                        # The queue contains all IPs discovered as 'alive' in HostDiscovery scan
# DEAD_ADDR_QUEUE = f"{SCAN_NATION}.dead_addr"                          # The queue contains all IPs discovered as 'dead' in HostDiscovery scan
# FAIL_QUEUE = f"{SCAN_NATION}.fail_queue"                              # The queue contains ip or (ip,port) pairs that encountered an error or failed while the scan was processing
# ALL_PORTS_QUEUE = f"{SCAN_NATION}.all_ports"                          # The queue contains all ports to scan in PortScan 
# PRIORITY_PORTS_QUEUE = f"{SCAN_NATION}.priority_ports"                # The queue contains all ports to scan in PortScan when USE_PRIORITY_PORTS is True
# ------------------------------------------------------------------------------
