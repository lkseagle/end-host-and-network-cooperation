#!/usr/bin/env python

from probe_hdrs import *

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def handle_pkt(pkt):
    if ProbeData in pkt:
        data_layers = [l for l in expand(pkt) if l.name=='ProbeData']
        f1 = "./log_data.txt"
        with open(f1,"a") as file:
            print("-------------------------------------\n")
            #file.write("-------------------------------------\n")
            for sw in data_layers:
                # utilization = 0 if sw.cur_time == sw.last_time else 8.0*sw.byte_cnt/(sw.cur_time - sw.last_time)
                length=sw.qdepth
                result = "Switch {} - Port {}: threshold1: {} threshold1: {} q-Length: {} \n".format(sw.swid, sw.port, sw.last_time, sw.cur_time, length)
                print(result)
                file.write(result)

'''
            bedelay=data_layers[0].cur_time
        
            for i in range(1,len(data_layers)):
                utilization = 0 if data_layers[i].cur_time == data_layers[i].last_time else 8.0*data_layers[i].byte_cnt/(data_layers[i].cur_time - data_layers[i].last_time)
                length=data_layers[i].qdepth
                droppkt=data_layers[i].enpckcont-data_layers[i-1].pckcont     
                delay= bedelay-data_layers[i].cur_time
                bedelay= data_layers[i].cur_time
                result = "Switch {}: delay:{}us bw:{} Mbps  droppkt:{} q-Length:{} \n".format(data_layers[i].swid, delay, utilization, droppkt, length)    
                print(result)
                file.write(result)
'''

def main():
    iface = 'eth0'
    fl = "./log_data.txt"
    if os.path.exists(fl):
        os.remove(fl) 
    print "sniffing on {}".format(iface)
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
