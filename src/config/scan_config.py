import os

# Path configs
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGETS_FILE_PATH = os.path.join(BASE_DIR, "..", "targets")
PORTS_FILE = os.getenv("PORTS_FILE", os.path.join(TARGETS_FILE_PATH, "ports.txt"))
WHO_IS_SCAN_DELAY = int(os.getenv("WHO_IS_SCAN_DELAY", 2))

# Resource limits (memory in bytes, CPU percent)
MEM_LIMIT = int(os.getenv("SCAN_MEM_LIMIT", 1_000)) * 1024**2
CPU_LIMIT = int(os.getenv("SCAN_CPU_LIMIT", 70))

# ─── RabbitMQ queue names (centralized for easy updates) ─────────────────────

# Manual override using environment variables for flexibility during testing/multi-country runs
ALIVE_ADDR_QUEUE = os.getenv("ALIVE_ADDR_QUEUE", "alive_addr")
DEAD_ADDR_QUEUE = os.getenv("DEAD_ADDR_QUEUE", "dead_addr")
FAIL_QUEUE = os.getenv("FAIL_QUEUE", "fail_queue")
ALL_PORTS_QUEUE = os.getenv("ALL_PORTS_QUEUE", "all_ports")
PRIORITY_PORTS_QUEUE = os.getenv("PRIORITY_PORTS_QUEUE", "priority_ports")

# # Optional: Uncomment for namespacing queues per country (future usage)
# NAMESPACE = os.getenv("SCAN_NATION", "IS")  # e.g. "IS", "SE", "GL"

# ALL_ADDR_QUEUE        = f"{NAMESPACE}.all_addr"
# ALIVE_ADDR_QUEUE      = f"{NAMESPACE}.alive_addr"
# DEAD_ADDR_QUEUE       = f"{NAMESPACE}.dead_addr"
# FAIL_QUEUE            = f"{NAMESPACE}.fail_queue"
# ALL_PORTS_QUEUE       = f"{NAMESPACE}.all_ports"
# PRIORITY_PORTS_QUEUE  = f"{NAMESPACE}.priority_ports"

# ─── Discovery scan phase specific ─────────────────────────────────────────
FETCH_RIX = False                                                     # If True, fetch IPs from RIX.is
QUEUE_NAME = "all_addr"                                               # The queue used for IP discovery
ADDR_FILE = os.getenv("ADDR_FILE", "blocks.txt")                      # File containing IP/CIDR blocks
SCAN_METHOD = os.getenv("SCAN_METHOD", "default")                     # Discovery method (e.g., tcp_syn_ping)
SINGLE_CIDR = os.getenv("SINGLE_CIDR", "8.8.8.0/28")                  # Single CIDR example
SINGLE_ADDR = os.getenv("SINGLE_ADDR", "8.8.8.0")                     # Single IP example

# ─── General scan parameters ──────────────────────────────────────────────
WORKERS = int(os.getenv("WORKERS", 250))                              # Number of workers to spawn
SCAN_DELAY = float(os.getenv("SCAN_DELAY", 0.5))                      # Delay (sec) between scan attempts
THRESHOLD = int(os.getenv("THRESHOLD", 30))                           # Direct vs batch mode threshold
BATCH_SIZE = int(os.getenv("BATCH_SIZE", 500))                        # Tasks per batch & DB insert size
MAX_BATCH_PROCESSES = int(os.getenv("MAX_BATCH_PROCESSES", 100))      # Max concurrent batch-forked processes

# ─── Port scan phase specific ──────────────────────────────────────────────
PORTS_FILE = os.getenv("PORTS_FILE", "ports.txt")
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

# ─── Per-session country tag (set manually here) ────────────────────────────
# SCAN_NATION = NAMESPACE  # unified tag for this scanning instance

# ─── Per-session country tag (used in summary DB records, reports, etc.) ────
SCAN_NATION = os.getenv("SCAN_NATION", "IS")
