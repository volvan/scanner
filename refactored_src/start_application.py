
# ----- Manager imports -----#
from utils.debug_tools import run_debug_maintenance
from services.ServiceManager import ServiceManager

# ----- Standard libraries -----#
import sys

# ----- Logger import -----#
from config.logging_config import logger, configure_logging, WorkerPIDFilter, CONFIG_PATH
from config.scan_config import DEBUG_MODE

# TODO:[Franz]
#   option 1  - Run "Host Discovery Scan"
#   oprtion 2 - run "Port Scan"
#   option 3  - run scan (ip and then port scan)

# Franz: Remove?
# E: No.. When running the program it will do so automatically (by script) so one should not need to run it themselfs.
#      .. Becouse of that, it needs to have some global constant, like "SCAN = ip, port, ip_port"
#      .. -> meaning either run only host discovery, only port or ip and then right after the port scan.


# Should only run this file to start Völva

configure_logging(CONFIG_PATH)

# logger.addFilter(LogicFilter(logicWrapper))
logger.addFilter(WorkerPIDFilter())

acceptable_args = ['ip', 'port']

if __name__ == '__main__':
    # Validate command line arguments passed in
    args = sys.argv
    if sys.gettrace() is not None:
        args.append(input('[ip/port/fail]: '))

    command = args[-1]

    if len(args) != 2 or command not in acceptable_args:
        print('\nInvalid argument(s).\n\n\tpython3 start_application [ip]scan|[port]scan\n\n\nPlease try again\n')
        sys.exit(1)

    serviceManager = ServiceManager()

    args_direct = {
        'ip': serviceManager.start_ip_scan,
        'port': serviceManager.start_port_scan,
    }

    # Call corresponding method based on the comand given
    try:
        # USed as a bdebug mode helper, to clean up queues and the log file
        if DEBUG_MODE:
            run_debug_maintenance()
        args_direct[command]()
    except AssertionError as e:
        print(f'Something went wrong\nErr: {e}')
