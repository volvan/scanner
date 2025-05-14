import os
from dotenv import load_dotenv  # type:ignore

# Load the env
load_dotenv()

# Credentials (environment variables for security)
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_USER = os.getenv("DB_USER")    # export DB_USER="<username>"
DB_PASS = os.getenv("DB_PASS")    # export DB_PASS="<password>"
DB_NAME = os.getenv("DB_NAME")    # export DB_NAME="<database>"