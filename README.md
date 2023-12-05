# end-host and network cooperation congestion control protocol
We design a new congestion control protocol that realize the cooperation of end-host and network. We modified the linx kernel (linux-5.4.224) and implement our protocol. Our protocol contains two part: the function of ack-rate control and the function of multi-agent cooperative congestion control. In addition, we design two engineering experiments by p4 language and mininet to verify the performance of our protocol. 
# Experimental environment configuration
Our experimental based P4. Firstly, the follower should install a P4 executive module on your virtual machine by the introduction (https://github.com/p4lang/tutorials）. 
Then, the follower should recompile the Linux kernel by our linux code (linux-5.4.224).
The follower should change the current congestion control protocol as Reno for you own virtual machine, because our code is modified based on the Reno original code.
# working steps
After completing the above environment configuration, we begin our experiment process. For a clear understanding, we design two demos to shou the function of ack-rate control and the function of multi-agent cooperative congestion control.
Firstly, put two engineering experiments into the /p4-tutorials/exercise. for each experiments doing the following steps:
The function of ack-rate control: 
1. ~/$: sudo make
2. ~/$: xterm h1 h2 h4 h5

for different performance analysis:
firstly, for throughput, rtt, drop, and queue analysis
3. ~/$: h1->h4 :send a flow for perfromance analysis by iperf. s1: tcpdumo -i s1-eth1 -w s1-eth1.pcap (for performance analysis by wireshark)
4. ~/$: h2 ->h5 : using INT framework to detect queue length.  h2: python send.py  h5: python receive.py

secondly, for scheduling faireness analysis
3. ~/$: h1->h4 send three flows for perfromance analysis by iperf. using tcpdump and wireshark to monitor the data in switch 1 eth1 prot.
finally, according to the wireshark file to make performance analysis.

The function multi-agent cooperative congestion control: 
1. ~/$: sudo make
2. ~/$: xterm h1 h2 h4 h5
3. ~/$: h1-> h4: sending a flow. s1: tcpdumo -i s1-eth1 -w s1-eth1.pcap (for performance analysis by wireshark)
4. ~/$: h2-> h5: doing INT framework for queue analysis. h2: python send.py  h5: python receive.py

Our experiment make a combination of mininet, INT frameowrk, iperf and wireshark. the main logic expression are shown in ##.P4 file of each directory. 
