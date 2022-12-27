#!/usr/bin/env python

from probe_hdrs import *
import os
import time

result=""
result2=""
count=0
switchMap = [0, 104, 106, 108, 112, 114, 110]

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def handle_pkt(pkt, timestr):
    global result
    global result2
    global count
    if ProbeData in pkt:
        data_layers = [l for l in expand(pkt) if l.name=='ProbeData']
        switchMap = [0, 104, 106, 108, 112, 114, 110]
        bedelay=data_layers[0].cur_time
        thput=data_layers[0].pckcont
        result=result+str(thput)+" "
        result2=result2+"data_layers[0].pckcont: "+str(thput)+"\n"
        for i in range(1,len(data_layers)):
            utilization = 0 if data_layers[i].cur_time == data_layers[i].last_time else 8.0*data_layers[i].byte_cnt/(data_layers[i].cur_time - data_layers[i].last_time)
            length=data_layers[i].qdepth
            droppkt=data_layers[i].enpckcont-data_layers[i-1].pckcont     
            delay= bedelay-data_layers[i].cur_time
            bedelay= data_layers[i].cur_time     
            result=result+"{} {} {} {} ".format(delay, utilization, droppkt, length)
            result2=result2+"Switch {} -port {}:\ndelay: {}\nbandwidth: {}\ndroppkt: {}\nqdepth: {} \n\n".format(switchMap[data_layers[i].swid],data_layers[i].port, delay, utilization, droppkt, length)             
            print "Switch {} -port {}: delay:{}us bw:{} Mbps  droppkt:{} q-Length:{} \n".format(switchMap[data_layers[i].swid],data_layers[i].port, delay, utilization, droppkt, length)    
        count=count+1
        if count==3:
            print result
            print result2
            print "*************************"
            f1 = "/home/sinet51/sanlu-INT/logs/singledata" + timestr +".txt"
            f2 = "/home/sinet51/sanlu-INT/logs/logWithChinese" + timestr +".txt"
            with open(f1,"a+") as file:   
                  #file.write(str(state)+" "+str(action)+" "+str(reward)+" "+str(r)+'\n')
                  file.write(result+'\n')
            with open(f2,"a+") as file:   
                  file.write(result2+'\n')                  
            result="\n\n\nnew round!!!!!:\n"
            result2="\n\n\nnew round!!!!!:\n" 
            count=0  
               
           
def main():
    timestr = time.strftime("%Y%m%d-%H%M%S")
    iface = 'eno4'
    #fl = "logs/singledata.txt"
    #if os.path.exists(fl):
    #    os.remove(fl) 
    print "sniffing on {}".format(iface)
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x,timestr))


if __name__ == '__main__':
    main()
