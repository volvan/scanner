import os
from dotenv import load_dotenv  # type:ignore

# Credentials (environment variables for security), imported from the `.env` file.

# Load the env
load_dotenv()

# For encrypting the IPs in the database.
FPE_KEY = os.getenv("FPE_KEY")
FPE_ALPHABET = os.getenv("FPE_ALPHABET")
FPE_LENGTH = int(os.getenv("FPE_LENGTH"))

# Database related credentials
DB_HOST = os.getenv("DB_HOST")      # The virtual-machine host, if ran on the same machine, use localhost
DB_PORT = os.getenv("DB_PORT")
DB_USER = os.getenv("DB_USER")      # export DB_USER="<username>"
DB_PASS = os.getenv("DB_PASS")      # export DB_PASS="<password>"
DB_NAME = os.getenv("DB_NAME")      # export DB_NAME="<database>"

# RabbitMQ related credentials
RMQ_HOST = os.getenv("RMQ_HOST")    # The virtual-machine host, if ran on the same machine, use localhost
RMQ_PORT = os.getenv("RMQ_PORT")
RMQ_USER = os.getenv("RMQ_USER")    # export RMQ_USER="<username>"
RMQ_PASS = os.getenv("RMQ_PASS")    # export RMQ_PASS="<password>"
