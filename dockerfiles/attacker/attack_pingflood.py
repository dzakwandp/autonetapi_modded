import os
import sys
import signal
import time

ip_address = "10.50.10.11"
add_args = " -f"
try:
    os.system("ping" + ip_address + add_args)
except KeyboardInterrupt:
    #os.system("pkill hping3")
    sys.exit(0)
