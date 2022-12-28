# end-host and network cooperation congestion control protocol
We design a new congestion control protocol that realize the cooperation of end-host and network. We modified the linx kernel (linux-5.4.224) and implement our protocol. Our protocol contains two part: the function of ack-rate control and the function of multi-agent cooperative congestion control. In addition, we design two engineering experiments by p4 language and mininet to verify the performance of our protocol. 
# Experimental environment configuration
###Our experimental based P4. Firstly, the follower should install a P4 executive module on your virtual machine by the introduction (https://github.com/p4lang/tutorials）. 
