
# ----- Manager imports ----- #
from utils.debug_tools import run_debug_maintenance
from services.ServiceManager import ServiceManager

# ----- Built-in Python Modules ----- #
from sys import exit as sys_exit

# ----- Logger import ----- #
from config.logging_config import logger, configure_logging, WorkerPIDFilter, CONFIG_PATH

# ----- Scan Config Constants ----- #
from config.scan_config import DEBUG_MODE, SCAN_TYPE

# ----- Logger Config ----- #
configure_logging(CONFIG_PATH)
logger.addFilter(WorkerPIDFilter())


# Instance of ServiceManager that stores all starter methods for all possible ScanType values
serviceManager = ServiceManager()

# Helps direct the application to the correct method based on the SCAN_TYPE from scan_config.py
scan_type_to_method:dict = {
    'ip': serviceManager.start_ip_scan,
    'port': serviceManager.start_port_scan,
    'ip_port': serviceManager.start_ip_port_scan
}

if __name__ == '__main__':
    # Call corresponding method based on the SCAN_TYPE value
    try:
        # Verify that the ScanType value is valid
        if SCAN_TYPE not in scan_type_to_method:
            available_scan_types = tuple(scan_type_to_method.keys())
            logger.error(f'Invalid SCAN_TYPE value provided. Value `{str(SCAN_TYPE)}` is not in the available SCAN_TYPE values: {available_scan_types}. Exiting application...')
            sys_exit(1)

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
