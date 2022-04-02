import os
import sys
import signal
import time
from datetime import datetime

ip_address = "10.50.10.11"
add_args = ""
try:
    datetime_start = datetime.now()
    print("[log] Connection started at ", datetime_start)
    print("")
    time_start = time.time()
    os.system("ping " + ip_address + add_args)
    time.sleep(5)
    os.system("pkill ping")
except KeyboardInterrupt:
    #os.system("pkill hping3")
    time_stop = time.time()
    time_elapsed = time_stop - time_start
    print("Time elapsed: ", time_elapsed)
    #sys.exit(0)
