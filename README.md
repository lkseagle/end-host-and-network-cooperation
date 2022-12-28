# end-host and network cooperation congestion control protocol
We design a new congestion control protocol that realize the cooperation of end-host and network. We modified the linx kernel (linux-5.4.224) and implement our protocol. Our protocol contains two part: the function of ack-rate control and the function of multi-agent cooperative congestion control. In addition, we design two engineering experiments by p4 language and mininet to verify the performance of our protocol. 
# Experimental environment configuration
Our experimental based P4. Firstly, the follower should install a P4 executive module on your virtual machine by the introduction (https://github.com/p4lang/tutorials）. 
Then, the follower should recompile the Linux kernel by our linux code (linux-5.4.224).
The follower should change the current congestion control protocol as Reno for you own virtual machine, because our code is modified based on the Reno original code.
# working steps
After completing the above environment configuration， we begin our experiment process. The function of ack-rate control and the function of multi-agent cooperative congestion control are two engineering experiments for different congestion status.

