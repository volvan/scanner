
# ----- Manager imports ----- #
from utils.debug_tools import run_debug_maintenance
from services.ServiceManager import ServiceManager

# ----- Built-in Python Modules ----- #
from sys import exit as sys_exit
import os

# ----- Logger import ----- #
from config.logging_config import logger, configure_logging, WorkerPIDFilter, CONFIG_PATH

# ----- Scan Config Constants ----- #
from config.scan_config import DEBUG_MODE, SCAN_TYPE

# ----- Logger Config ----- #
configure_logging(CONFIG_PATH)
logger.addFilter(WorkerPIDFilter())

# ----- Restoring terminal to normal ----- #
# -- This is only needed when running locally.
# ---- Its purpose is to reset terminal to it's initial settings after running the application.
import atexit
import sys

def restore_terminal_echo():
    import termios
    try:
        attrs = termios.tcgetattr(sys.stdin)
        attrs[3] |= termios.ECHO  # turn echo back on
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, attrs)
    except Exception:
        pass

# Run the function when the application ends
if DEBUG_MODE: atexit.register(restore_terminal_echo)
# ---------------------------------------- #



# Instance of ServiceManager that stores all starter methods for all possible ScanType values
serviceManager = ServiceManager()

# Helps direct current process to the correct method based on the SCAN_TYPE value from scan_config
scan_type_to_method:dict = {
    'ip': serviceManager.start_ip_scan,
    'port': serviceManager.start_port_scan,
    'ip_port': serviceManager.start_ip_port_scan
}

def main():
    # Call corresponding method based on the SCAN_TYPE value
    try:
        # Verify that the ScanType value is valid
        if type(SCAN_TYPE) != str or SCAN_TYPE not in scan_type_to_method:
            available_scan_types = tuple(scan_type_to_method.keys())
            logger.error(f'Invalid SCAN_TYPE value provided. Value `{str(SCAN_TYPE)}` is not in the available SCAN_TYPE values: {available_scan_types}. Exiting application...')
            sys_exit(1)

        logger.info(f'Initializing scan of type {SCAN_TYPE}')

        # Used as a bdebug mode helper, to clean up queues and the log file
        if DEBUG_MODE:
            run_debug_maintenance()

        # Run method based on SCAN_TYPE value
        scan_type_to_method[SCAN_TYPE]()
    
    #----- Unexpected Exception -----#
    except Exception as e:
        # When an unexpected exception is raised, then print the type of the exception and it's error message
        template = "An unexpected exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(e).__name__, e.args)
        logger.error(message)

    


if __name__ == '__main__':
    main()
    