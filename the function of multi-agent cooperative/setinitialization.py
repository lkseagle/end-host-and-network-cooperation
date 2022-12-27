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

	def setinitialization(self) :
		probe_pkt6 = Ether(dst='34:48:ed:f8:f1:37', src='34:48:ed:f8:f3:41') / \
                Probe(hop_cnt=0,learn=0) / \
                ProbeFwd(egress_spec=3) / \
                ProbeFwd(egress_spec=2) / \
                ProbeFwd(egress_spec=1)
		probe_pkt7 = Ether(dst='34:48:ed:f8:f1:37', src='34:48:ed:f8:f3:41') / \
                Probe(hop_cnt=0,learn=0) / \
                ProbeFwd(egress_spec=5) / \
                ProbeFwd(egress_spec=1)
		probe_pkt8 = Ether(dst='34:48:ed:f8:f1:37', src='34:48:ed:f8:f3:41') / \
                Probe(hop_cnt=0,learn=0) / \
                ProbeFwd(egress_spec=4) / \
                ProbeFwd(egress_spec=2) / \
                ProbeFwd(egress_spec=1)
		try:
			sendp(probe_pkt6, iface='eno2')
			time.sleep(1)
			sendp(probe_pkt7, iface='eno2')
			time.sleep(1)
			sendp(probe_pkt8, iface='eno2')
		except KeyboardInterrupt:
			sys.exit()        

if __name__ == '__main__':
	senders=sender()
	senders.setinitialization()
	time.sleep(1)
