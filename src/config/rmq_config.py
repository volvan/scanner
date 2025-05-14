import os
from dotenv import load_dotenv  # type:ignore

# Load the env
load_dotenv()

# Credentials (environment variables for security)
RMQ_HOST = os.getenv("RMQ_HOST")
RMQ_PORT = os.getenv("RMQ_PORT")
RMQ_USER = os.getenv("RMQ_USER")    # export RMQ_USER="<username>"
RMQ_PASS = os.getenv("RMQ_PASS")    # export RMQ_PASS="<password>"