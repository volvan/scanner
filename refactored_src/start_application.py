import termios
import atexit
import sys

from utils.debug_tools import run_debug_maintenance
from services.ServiceManager import ServiceManager
from utils.config_validator import ConfigValidator

from config.logging_config import logger, configure_logging, WorkerPIDFilter
from config.scan_config import DEBUG_MODE, SCAN_TYPE


# TODO:[P_Low][] - Set /targets as example on git

def restore_terminal_echo():
    """Restore terminal echo settings when the app exits.
    
    This is only needed when running locally. 
    Its purpose is to reset terminal to it's initial settings after running the application.
    """
    
    try:
        attrs = termios.tcgetattr(sys.stdin)
        attrs[3] |= termios.ECHO  # turn echo back on
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, attrs)
    except Exception:
        pass



def main():
    """Main entry point for the scanner.
    
    Configures logging, validates the config and kicks off the scan.
    """

    # Configure logging
    configure_logging()
    logger.addFilter(WorkerPIDFilter())

    # Register terminal restoration in debug mode
    if DEBUG_MODE:
        atexit.register(restore_terminal_echo)
        logger.info("Application will run in debug mode.")
    else: 
        logger.info("Application will NOT run in debug mode.")

    # Used as a debug mode helper, to clean up queues and the log file
    run_debug_maintenance()

    # Direct the scan to the correct method based on the SCAN_TYPE value from scan_config
    serviceManager = ServiceManager()
    scan_methods:dict = { 
        'ip': serviceManager.start_ip_scan,
        'port': serviceManager.start_port_scan,
        'ip_port': serviceManager.start_ip_port_scan,
    }
    # Verify that the ScanType value is valid
    if not isinstance(SCAN_TYPE, str) or SCAN_TYPE not in scan_methods:
        logger.error(f"Invalid SCAN_TYPE '{SCAN_TYPE}'. Available types: {tuple(scan_methods)}. Exiting.")
        sys.exit(1)


    # Run the config validator to validate all in scan_config
    try:
        ConfigValidator.validate_on_startup()
    except Exception as e:
        logger.critical(f"[Startup] Configuration validation failed: \n {e}")
        exit(1)

    # Run method based on SCAN_TYPE value
    try:
        logger.info(f"Initializing '{SCAN_TYPE}' scan.")
        scan_methods[SCAN_TYPE]()
    except KeyboardInterrupt:
        sys.exit(130) # Ctrl-C exit
    except Exception as e:
        logger.error(f"An unexpected exception of type {type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
    