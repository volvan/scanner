import os
from dotenv import load_dotenv  # type:ignore

# Load the env
load_dotenv()

# Credentials (environment variables for security)
FPE_KEY = os.getenv("FPE_KEY")
FPE_ALPHABET = os.getenv("FPE_ALPHABET")
FPE_LENGTH = int(os.getenv("FPE_LENGTH"))