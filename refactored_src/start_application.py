
#----- Manager imports -----#
from services.ServiceManager import ServiceManager

#----- Standard libraries -----#
import sys

#----- Logger import -----#
from config.logging_config import logger, configure_logging, WorkerPIDFilter, CONFIG_PATH



configure_logging(CONFIG_PATH)

# logger.addFilter(LogicFilter(logicWrapper))
logger.addFilter(WorkerPIDFilter())

acceptable_args = ['ip', 'port']

if __name__ == '__main__':
    # Validate command line arguments passed in
    args = sys.argv
    if sys.gettrace() is not None: args.append(input('[ip/port/fail]: '))

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
        args_direct[command]()
    except AssertionError as e:
        print(f'Something went wrong\nErr: {e}')
