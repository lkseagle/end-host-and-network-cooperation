# -*- coding: utf-8 -*-
#############################################################

####################################################################################
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
from send import sender
from probe_hdrs import *

linkMap = {"up":2, "mid":1, "down":3}  # 交换机在系统中的id
portOfSwitch104 = {"up":3, "mid":5, "down":4}
schedule = sched.scheduler(time.time,time.sleep)

class linkState:
    def __init__(self, name,pckcount,delay,utilization,dropRate,length):
        self.name = name
        self.pckcount = pckcount   # 此链路总包数
        self.delay = delay    # 时延 us  ，两条链路时取和
        self.utilization = utilization   # 带宽 Mbps，两条链路时取平均
        self.dropRate = dropRate   # 丢包率，两条链路时取和
        self.length = length    # 队列深度，两条链路时取大值

def learnSet(learnData):
    # learnData[104的出端口，up 路分配的比例，mid 路分配的比例]
    probe_pkt = Ether(dst='b0:26:28:9c:e3:8d', src='34:48:ed:f8:f3:41')/Probe(hop_cnt=0,learn=1)
    probe_pkt = probe_pkt / ProbeFwd(egress_spec=learnData[0],percent1=learnData[1],percent2=learnData[2])  # 在104的逻辑
    if learnData[0] != 5:     # 如果104的出端口不是5，就表示走的上下两路，上下两路要多一个交换机，
        probe_pkt = probe_pkt / ProbeFwd(egress_spec=2)   # 106 108的出端口都是2
    try:
        sendp(probe_pkt/ProbeFwd(egress_spec=1,swid=4,percent1=learnData[1],percent2=learnData[2]), iface='eno2')
        print("发送learnSet")
    except KeyboardInterrupt:
        sys.exit()
    
def run():
    f1 = "/home/p4/tutorials/exercises/xlink3path/message/ranmes.txt"
    #read states
    links = []
    with open("./singledata.txt", "r") as fo:
        for line in fo.readlines():
            line = line.strip()
            if line =='':
                continue
            content = line.split(" ")
            if content[0] == "mid":
                links.append(linkState(content[0],
                                       int(content[1]), 
                                       int(content[2]),
                                       float(content[3]), 
                                       int(content[4])/int(content[1]), 
                                       int(content[5])))
            else:   # 106和108都是从2口出
                links.append(linkState(content[0],
                                       int(content[1]), 
                                       int(content[2])+int(content[6]),    # 时延
                                       (float(content[3])+float(content[7]))/2,    # 带宽
                                       (int(content[4])+int(content[8]))/int(content[1]),     # 丢包率
                                       max(int(content[5]),int(content[9]))))   # 队列深度
    linkSelect = ""
    dropRateMin = 100
    for link in links: # 计算丢包率，选出丢包率最小的路
        if link.dropRate  < dropRateMin:  
            dropRateMin = link.dropRate
            linkSelect = link.name
    learnData = [portOfSwitch104[linkSelect],0,0]    # 第一个参数是104的出端口，0 用来占位而已
    if sys.argv[1] == "1":    # 时延，依据时延分配交换机逻辑， less is better
        delaySum = 0
        for link in links:
            delaySum += 1/(abs(link.delay) + 1)    # 防止分母为0  ，时延对1不敏感
        for link in links:
            if link.name == "up":
                learnData[1]=max(round((1 / (abs(link.delay)  + 1)) * 10 / delaySum),0)
            if link.name == "mid":
                learnData[2]=max(round((1 / (abs(link.delay) + 1)) * 10 / delaySum),0)
    elif sys.argv[1] == "2":    # 带宽 more is better
        bwSum = 0
        for link in links:
            bwSum += link.utilization
        for link in links:
            if link.name == "up":
                learnData[1]=round(link.utilization * 10 / bwSum)
            if link.name == "mid":
                learnData[2]=round(link.utilization * 10 / bwSum)
    elif sys.argv[1] == "3":    # 丢包率  此文件发送的INT包选择丢包率最低的路 less is better
        dropRateSum = 0
        for link in links:
            dropRateSum += 1/(abs(link.dropRate) + 0.01)    # 防止分母为0 ， 
        for link in links:
            if link.name == "up":
                learnData[1]=max(round((1 / (link.dropRate + 0.01)) * 10 / dropRateSum),0)
            if link.name == "mid":
                learnData[2]=max(round((1 / (link.dropRate + 0.01)) * 10 / dropRateSum),0)
    elif sys.argv[1] == "4":    # 队列深度 less is better
        lengthSum = 0
        for link in links:
            lengthSum += 1/(link.length + 1)    # 防止分母为0 ，队列深度对1不敏感
        for link in links:
            if link.name == "up":
                learnData[1]= round((1 / (link.length + 1)) * 10 / lengthSum)
            if link.name == "mid":
                learnData[2]= round((1 / (link.length + 1)) * 10 / lengthSum)

    elif sys.argv[1] == "5":
        maxLinkBwName = ""
        maxLinkBw = -1
        for link in links:
            if (link.utilization > maxLinkBw):
                maxLinkBwName = link.name
                maxLinkBw = link.utilization
        if (maxLinkBwName == "up"):
            learnData[1] = 10
            learnData[2] = 0
        elif (maxLinkBwName == "mid"):
            learnData[1] = 0
            learnData[2] = 10
        else:
            learnData[1] = 0
            learnData[2] = 0


    # 由于learnData中有0的话会导致没有效果（原因后叙），所以此处改一下
    # if learnData[1] == 0:
    #     learnData[1] = 1
    #     if learnData[2] >= 8:
    #         learnData[2] -= 1
    # if learnData[2] == 0:
    #     learnData[2] = 1
    #     if learnData[1] >= 8:
    #         learnData[1] -= 1
    print("up:%d, mid:%d, down:%d"%(learnData[1],learnData[2],10-learnData[1]-learnData[2]))
    learnSet(learnData)
    
if __name__ == "__main__":
  run()
  for i in range(100):
      ###make the tuple<action,states>
       senders=sender()
       senders.sendpak() ####collect next states.
       time.sleep(1)

'''
def learnset(learnn):
    original=np.array([[2,1],[2,2]])######gai
    learnss=np.array(learnn).reshape(2,2)
    learnlist=np.hstack((original,learnss))
    print(learnlist)
    i = 0
    probe_pkt = Ether(dst='b0:26:28:9c:e3:8d', src='34:48:ed:f8:f3:41')/Probe(hop_cnt=0,learn=1)
    for i in range(2):
        try:
            probe_pkt = probe_pkt / ProbeFwd(egress_spec=int(learnlist[i][0]),percent1=int(learnlist[i][2]),percent2=int(learnlist[i][3]))
        except ValueError:
            pass
    while True:
        try:
            sendp(probe_pkt/ProbeFwd(egress_spec=2,swid=1,percent1=int(learnlist[0][2]),percent2=int(learnlist[0][3])), iface='eth0')
            break
        except KeyboardInterrupt:
            sys.exit()
            
          
    mes = line.split(' ')
    #print mes
    #b = random.sample(range(8,10),1)
    #b =[np.random.randint(1,10) for js in range(4)]
    b=[3,2,1,3]
    b =[np.random.randint(1,5) for js in range(4)]
    if(len(mes)==15):
        learnset(b)
        actions=' '.join(str(i) for i in b)
    #####record action t and state t
        with open(f1,"a") as file:   
           file.write(str(actions)+" "+str(line)+'\n')
        fo.close()
    '''