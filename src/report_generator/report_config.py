import os
from dotenv import load_dotenv  # type:ignore

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load the env
load_dotenv()

NATION = 'GL'                                       # Nation that is currently being scanned and report created for
RUNNING = False                                     # If the scan is running, make it True

# Paths for reporting
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR_PATH = os.path.join(BASE_DIR, "templates")
REPORTS_BASE_DIR = os.path.join(BASE_DIR, "reports")
DIR_REPORT_PATH = os.path.join(REPORTS_BASE_DIR, NATION)

# Report creation configurations
TOP_ITEMS = 6                                       # Number of top items to display in summary tables
COMPILE_PDF = False                                 # compile or no

# backups configurations
BACKUP_SCRIPT = "./backup_handler.sh"               # MinIO script
BACKUP_LOG_DIR = f"./logs/backup_{NATION}.pdf"      # Logs to monitor te backup process

STATIC_OPTIONS = "--full-if-older-than 7D"            # Static for duplicity
ENCRYPTION = 'yes'                                    # duplicity

# mail hander configurations
EMAIL_SCRIPT = "./email_handler.sh"                 # Email handler script


# CREDENTIALS CONFIGURATIONS (move me)

# Backups
MINIO_URL = os.getenv("MINIO_URL")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
REPORT_BUCKET = os.getenv("REPORT_BUCKET")

# ACCESS_KEY # not sure
# SECRET_ACCESS_KEY # not sure

ENC_PASSPHRASE = os.getenv("ENC_PASSPHRASE")
SIGN_PASSPHRASE = os.getenv("SIGN_PASSPHRASE")
GPG_ENC_KEY = os.getenv("GPG_ENC_KEY")
GPG_SIGN_KEY = os.getenv("GPG_SIGN_KEY")

# Email
EMAIL_SCRIPT = os.path.join(BASE_DIR, "email_handler.py")