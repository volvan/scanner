import os  # TODO[Emilia]: fix fetch from RIX everywhere..


# --- Global settings and configurations ---------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(BASE_DIR))


# --- Monitoring (logs) configurations ---------------------
DEBUG_MODE = True                                                     # Debug mode T/F
LOG_TO_FILE = True                                                    # Log the output to a file or simply in terminal

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/logging_config.json")
LOG_DIR = os.path.join(ROOT_DIR, "logs")


# ---  Resource limits ---------------------
MEM_LIMIT = 1_000 * 1024**2                                           # Memory in bytes
CPU_LIMIT = 70                                                        # CPU percent


# ─── General scan parameters ──────────────────────────────────────────────
WORKERS = 3                                                           # Number of workers to spawn (DEFAULT: 250)
SCAN_DELAY = float(0.5)                                               # Delay (sec) between scan attempts
THRESHOLD = int(3)                                                   # Direct vs batch mode threshold
BATCH_SIZE = int(3)                                                 # Tasks per batch & DB insert size ( DEFAULT: 500)
MAX_BATCH_PROCESSES = int(100)                                        # Max concurrent batch-forked processes
WHO_IS_SCAN_DELAY = int(2)


# ─── Discovery scan phase specific ─────────────────────────────────────────
SCAN_NATION = "IS"                                                    # Scan Nation to scan

# Targets - Who to scan
FETCH_RIX = False                                                     # If True, fetch IPs from RIX.is
TARGETS_FILE_PATH = os.path.join(BASE_DIR, "..", "targets")           # Stored under src/targets/ and used when FETCH_RIX is False
ADDR_FILE = "blocks.txt"                                              # File containing IP/CIDR blocks to scan
# TODO[Franz]: rename ADDR_FILE to TARGETS_FILE

# ─── RabbitMQ queue names (centralized for easy updates) ─────────────────────
ALL_ADDR_QUEUE = f"{SCAN_NATION}.all_addr"                       # The queue used for IP discovery
ALIVE_ADDR_QUEUE = f"{SCAN_NATION}.alive_addr"
DEAD_ADDR_QUEUE = f"{SCAN_NATION}.dead_addr"
FAIL_QUEUE = f"{SCAN_NATION}.fail_queue"
ALL_PORTS_QUEUE = f"{SCAN_NATION}.all_ports"
PRIORITY_PORTS_QUEUE = f"{SCAN_NATION}.priority_ports"


# ─── Port scan phase specific ──────────────────────────────────────────────

# Ports - What ports to scan
PORTS_FILE = os.getenv("PORTS_FILE", os.path.join(TARGETS_FILE_PATH, "ports.txt"))

BATCH_AMOUNT = int(os.getenv("BATCH_AMOUNT", 100))                    # Concurrent port batches
PORT_SCAN_RETRY_LIMIT = int(os.getenv("PORT_SCAN_RETRY_LIMIT", 2))    # Retry unknown/failed ports this many times
BATCH_TIMEOUT_SEC = int(os.getenv("BATCH_TIMEOUT_SEC", 300))          # Max time allowed per batch queue
WORKER_RESTART_LIMIT = int(os.getenv("WORKER_RESTART_LIMIT", 3))      # Times to restart worker before marking failed
USE_PRIORITY_PORTS = os.getenv("USE_PRIORITY_PORTS", "true").lower() == "true"  # Use priority ports
PROBE_TIMEOUT = int(os.getenv("PROBE_TIMEOUT", "60"))                 # Allow override of the subprocess timeout via environment variable

# ─── Unprivileged “stealth” connect-scan settings ──────────────────────────
SCAN_DELAY_MS = int(os.getenv("SCAN_DELAY_MS", 200))                  # how long to wait between Nmap probes (in ms)
SCAN_DELAY_STR = f"{SCAN_DELAY_MS}ms"
SCAN_MAX_RETRIES = int(os.getenv("SCAN_MAX_RETRIES", 2))              # how many times Nmap will retry
PROBE_JITTER_MAX = float(os.getenv("PROBE_JITTER_MAX", 0.1))          # jitter to add on top of SCAN_DELAY (in seconds)


# ─── Retry scan specific ──────────────────────────────────────────────
OUTPUT_FAIL_QUEUE = os.getenv("OUTPUT_FAIL_QUEUE", "retry_failed_ports")   # A new queue for “second-stage” failures

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
