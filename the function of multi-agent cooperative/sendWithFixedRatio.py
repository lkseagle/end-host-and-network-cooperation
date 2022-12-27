import os
import re
import subprocess 
import time
import sched
import re
from time import sleep
import random
import datetime
import numpy as np
from numpy import array as matrix, arange
from probe_hdrs import *
class sender:
	def __init__(self):
		pass

	def sendpak(self):
        ########use learn={2,3,4,5} to respect aware-path. 0 is initination. 1 is to multi-threshold.
		probe_pkt2 = Ether(dst='08:00:00:00:04:44', src='08:00:00:00:01:11') / \
                Probe(hop_cnt=0,learn=1) / \
                ProbeFwd(egress_spec=5,percent1=3,percent2=3) / \
                ProbeFwd(egress_spec=2) / \
                ProbeFwd(egress_spec=1,percent1=3,percent2=3)

		try:
			sendp(probe_pkt2, iface='eno2') #topogy 1ms
			time.sleep(1)
		except KeyboardInterrupt:
			sys.exit()   

if __name__ == '__main__':
	senders=sender()
	senders.sendpak()
