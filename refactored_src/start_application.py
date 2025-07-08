
#----- Wrapper imports -----#
from .services.ServiceManager import ServiceManager

#----- Standard libraries -----#
import sys



serviceManager = ServiceManager()

args_direct = {
    'ip': serviceManager.start_ip_scan,
    'port': serviceManager.start_port_scan,
    'fail': serviceManager.start_fail_queue,
}



if __name__ == '__main__':
    

    # Validate command line arguments passed in
    args = sys.argv
    command = args[-1]
    if len(args) != 2 or command not in args_direct: 
        print('\nInvalid argument(s).\n\n\tpython3 start_application [ip]scan|[port]scan|[fail]queue\n\n\nPlease try again\n')
        sys.exit(1)

    # Call corresponding method based on the comand given
    args_direct[command]()
