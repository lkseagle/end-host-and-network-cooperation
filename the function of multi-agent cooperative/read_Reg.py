# -*- coding: utf-8 -*-
#!/usr/bin/env python

import os
import re
import subprocess 
import time
import sched

p = subprocess.Popen('simple_switch_CLI --thrift-port 9091',shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True) 
p.stdin.write('register_read qlength_reg') 
out,err = p.communicate()
fl = "./s2_qlength.txt"
if os.path.exists(fl):
	os.remove(fl) 
with open(fl,"a") as file:
	file.write(out)
