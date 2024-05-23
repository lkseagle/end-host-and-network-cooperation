/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x800;
const bit<16> TYPE_PROBE = 0x812;
const bit<32> MAX_NUMS = 1 << 16;  
const bit<8> TCP_PROTOCOL = 0x06;

#define MAX_HOPS 10
#define MAX_PORTS 8
#define LEN_CUR_REG 500000

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;
register<bit<48>>(1) congestion_time_reg;   // 最近一次发生拥塞的时间，此时间的后一秒内收到的ACK都要被增加my_wnd字段
register<bit<32>>(1) byte_dropped_cnt_reg;   // 最近一次发生拥塞时，丢弃的字节数
register<bit<32>>(1) max_cwnd_reg;
register<bit<32>>(1) cur_cwnd_reg;
register<bit<48>>(1) modify_time_reg;
register<bit<32>>(LEN_CUR_REG) all_cur_cwnd_reg;
register<bit<32>>(1) cur_pkt_num_reg;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;			// IP首部长度，单位为4bit
    bit<8>    diffserv;
    bit<16>   totalLen;		// IP包总长度，单位为1字节
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {      // 固定长度 20 字节 
    bit<16>     srcPort;
    bit<16>     dstPort;
    bit<32>     seqNum;
    bit<32>     ackNum; // 普通数据包ackNum=1，ACK包ackNum=期望发送方继续发的包序号（单位字节）
    bit<4>      offset;
    bit<6>      reserved;
    bit<1>      URG;
    bit<1>      ACK;  // ACK=1: ackNum有效；否则其无效。一般来说，建立连接后，ACK一直为1。
    bit<1>      PSH;
    bit<1>      RST;
    bit<1>      SYN;
    bit<1>      FIN;
    bit<16>     cwnd;
    bit<16>     checkSum;
    bit<16>     urgentPointer;
}

// 自定的tcp选项字段，4字节，直接放在TCP固定头部之后作为第一个TCP可选项即可 ，
// 然后将TCP的首部长度加1，IP包总长加4，重新计算TCP校验和
header my_wnd_t{
	bit<8>		type;		//0xfe	类型值固定254
	bit<8>		length;		//长度为0x04
	bit<16>		value;		// 自己设的窗口值
}

header options_t{		// 只解析12个字节就行，每个TCP都至少会有如下12byte的选项字段
	bit<96>		nop_nop_timeStamps;
}

// Top-level probe header, indicates how many hops this probe
// packet has traversed so far.
header probe_t {    
    bit<8> hop_cnt;
}

// The data added to the probe by each switch at each hop.
header probe_data_t { // 176
    bit<1>    bos;      // bottom of stack
    bit<7>    swid;
    bit<8>    port;
    bit<32>   byte_cnt;
    time_t    last_time; // bit<48>
    time_t    cur_time;  // bit<48>
    bit<32>   qdepth;
}

// Indicates the egress port the switch should send this probe
// packet out of. There is one of these headers for each hop.
header probe_fwd_t {
    bit<8>   egress_spec;
}

struct parser_metadata_t {
    bit<8>  remaining;
}

struct metadata {
    bit<8> egress_spec;
    parser_metadata_t parser_metadata;
	bit<16> TCP_length;		// 计算得到TCP包的长度，用于区分TCP数据包与IP包，同时用于计算TCP校验和。
    bit<7>  swid;
    bit<32>  pktcont2;
}


struct headers {
    ethernet_t              ethernet;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
	my_wnd_t				my_wnd;
	options_t				options;
    probe_t                 probe;
    probe_data_t[MAX_HOPS]  probe_data;
    probe_fwd_t[MAX_HOPS]   probe_fwd;
    // 包头堆栈有 next 和 last 两个属性，.next引用游标下一个元素， .last 引用游标上一个元素；同时 .next 成功引用后会将游标向后移一位。
    // 游标起初在第0个位置。.next 超出堆栈长度或在第0个位置.last会直接报错，所以不要指望.next自动把内容读完，需要用变量来约束遍历过程。
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_PROBE: parse_probe;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_tcp;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition parse_options;
    }

 	state parse_options {
        packet.extract(hdr.options);
        transition accept;
    }
 
    state parse_probe {
        packet.extract(hdr.probe);
        meta.parser_metadata.remaining = hdr.probe.hop_cnt + 1;
        transition select(hdr.probe.hop_cnt) {
            0: parse_probe_fwd;
            default: parse_probe_data;
        }
    }

    state parse_probe_data {
        packet.extract(hdr.probe_data.next);
        transition select(hdr.probe_data.last.bos) {  // 游标在最新读取的probe_data之后，所以必须用.last来读取
            1: parse_probe_fwd; // bos 为1表示这是第一个被添加的probe_data，也就是栈底的元素
            default: parse_probe_data;
        }
    }

    state parse_probe_fwd {
        packet.extract(hdr.probe_fwd.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        // extract the forwarding data
        meta.egress_spec = hdr.probe_fwd.last.egress_spec;
        transition select(meta.parser_metadata.remaining) {
            0: accept;
            default: parse_probe_fwd;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<bit<32>>(MAX_PORTS) my_reg;   // 使用寄存器保存交换机收到的包数量，寄存器只可以保存 10 个32位的数据，
    // 寄存器是顺序存储的类似数组用下标读写的形式

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    action set_swid(bit<7> swid) {
        meta.swid = swid;
    }

    table swid {
        actions = {
            set_swid;
        }
    }
    
    register<bit<32>>(MAX_PORTS) contpkts;
    bit<32> pkg_cnt_ingress;
    bit<32> new_count;
    apply {
        swid.apply();

        if (hdr.ipv4.isValid() || hdr.probe.isValid()) {
            contpkts.read(pkg_cnt_ingress, (bit<32>)standard_metadata.ingress_port);
            pkg_cnt_ingress = pkg_cnt_ingress + 1;
            meta.pktcont2 = pkg_cnt_ingress;  //trans to egress packetdata传输到出口数据包
            // reset the byte count when a probe packet passes through 当探测数据包通过时重置字节计数
            new_count = (hdr.probe.isValid()) ? 0 : pkg_cnt_ingress;
            contpkts.write((bit<32>)standard_metadata.ingress_port, new_count);     
        }
        
        if (hdr.probe.isValid()) {
            // fill out probe fields 
            if (hdr.probe_data[0].byte_cnt > pkg_cnt_ingress){
                bit<32> byte_dropped_cnt = hdr.probe_data[0].byte_cnt - pkg_cnt_ingress;
                byte_dropped_cnt_reg.write(0, byte_dropped_cnt);    // 把丢弃的字节数写入寄存器
                congestion_time_reg.write(0,(bit<48>)3);    // 把拥塞修改次数写入
            }
        }

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();

		   
            meta.TCP_length = hdr.ipv4.totalLen - ((bit<16>)hdr.ipv4.ihl << 2);	// standard_metadata.packet_length <= 66,
            
            time_t cur_time = standard_metadata.ingress_global_timestamp;
            bit<48> modify_time;
            modify_time_reg.read(modify_time,0);
            time_t time_difference = cur_time - modify_time;     // 当前时间与上次修改时间的时间差
            if(time_difference > 1000000){
                modify_time_reg.write(0, cur_time);
                // ACK包没有data部分，只有32个字节的首部（20固定+12可选项[每个2字节的填充和10字节的时间戳]）
                if (hdr.ipv4.protocol == TCP_PROTOCOL && meta.TCP_length <= 32 && meta.swid == (bit<7>)2){ 	// 只在2号交换机修改ACK，免得不同的交换机同时修改造成结果混乱
                    //
                    time_t congestion_time;
                    congestion_time_reg.read(congestion_time, 0);    // 读出拥塞，
                    
                    bit<32> max_cwnd;
                    bit<32> cur_cwnd;
                    if(congestion_time == 0){ // 如果没有发生过拥塞，或者拥塞处理完了，窗口就慢慢增加
                        max_cwnd_reg.read(max_cwnd, 0);    // 读出max_cwnd
                        cur_cwnd_reg.read(cur_cwnd, 0);    // 读出cur_cwnd
                        if (max_cwnd == 0 && cur_cwnd == 0){
                            max_cwnd = 1;
                            cur_cwnd = max_cwnd;
                        }else{
                            // bit<32> tmp ;
                            // tmp = cur_cwnd / 5;
                            // cur_cwnd = cur_cwnd + (bit<32>)tmp;
                            cur_cwnd = cur_cwnd + 1;

                            if (cur_cwnd >= max_cwnd){
                                max_cwnd = cur_cwnd;
                            }
                          if(hdr.tcp.cwnd<cur_cwnd){
                           cur_cwnd=hdr.tcp.cwnd;	// 与Rwnd进行交互
                           }
                        }
                        max_cwnd_reg.write(0, max_cwnd);
                        cur_cwnd_reg.write(0, cur_cwnd);

                    }else{  
                        max_cwnd_reg.read(max_cwnd, 0);    // 读出max_cwnd
                        cur_cwnd_reg.read(cur_cwnd, 0);    // 读出cur_cwnd
                        max_cwnd = cur_cwnd;
                        max_cwnd_reg.write(0, max_cwnd);

                        bit<32> byte_dropped_cnt;
                        byte_dropped_cnt_reg.read(byte_dropped_cnt, 0);    // 读出上一次发生拥塞时被丢弃的字节数
                
                        cur_cwnd = cur_cwnd - byte_dropped_cnt >> 1;
                        if(hdr.tcp.cwnd<cur_cwnd){
                           cur_cwnd=hdr.tcp.cwnd;	// 与Rwnd进行交互
                           }
                        cur_cwnd_reg.write(0, cur_cwnd);

                        congestion_time = congestion_time - 1;
                        congestion_time_reg.write(0,congestion_time);
                    }
                    hdr.my_wnd.setValid();
                    hdr.my_wnd.type = 0xfe;		// type固定254
                    hdr.my_wnd.length = 0x04;	// 该字段(TLV)的总长度为4
                    hdr.my_wnd.value = (bit<16>)cur_cwnd;	// 算法交互字段； 写入的值在内核里会被wscale放大的
                    hdr.tcp.offset = hdr.tcp.offset + 1; // tcp的offset字段就是tcp包的首部总长度	（它的单位是4个字节）
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4; // IP首部记录的报文总长度字段			
                    meta.TCP_length = meta.TCP_length + 4;	// 重新计算TCP长度
                    hdr.options.setValid(); 
                }
            }
            // bit<32> cur_cwnd;
			// cur_cwnd_reg.read(cur_cwnd,0);

        }
        else if (hdr.probe.isValid()) {
            standard_metadata.egress_spec = (bit<9>)meta.egress_spec; // INT 包的每个交换机的出口地址是提前指定的
            hdr.probe.hop_cnt = hdr.probe.hop_cnt + 1;
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    // count the number of bytes seen since the last probe
    register<bit<32>>(MAX_PORTS) byte_cnt_reg;
    // remember the time of the last probe
    register<time_t>(MAX_PORTS) last_time_reg;
    apply {
        bit<32> byte_cnt;
        bit<32> new_byte_cnt;
        time_t last_time;
        // time_t cur_time = standard_metadata.egress_global_timestamp;    
        time_t cur_time = standard_metadata.ingress_global_timestamp;
        
        byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
        // byte_cnt = byte_cnt + standard_metadata.packet_length;
        byte_cnt = byte_cnt + 1;
        // reset the byte count when a probe packet passes through
        new_byte_cnt = (hdr.probe.isValid()) ? 0 : byte_cnt;
        byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);

        if (hdr.probe.isValid()) {
            // fill out probe fields 
            if (hdr.probe_data[0].byte_cnt > meta.pktcont2){
                bit<32> byte_dropped_cnt = hdr.probe_data[0].byte_cnt - meta.pktcont2;
                byte_dropped_cnt_reg.write(0, byte_dropped_cnt);    // 把丢弃的字节数写入寄存器  

                bit<32> cur_pkt_num;
                cur_pkt_num_reg.read(cur_pkt_num ,0);
                if (cur_pkt_num < LEN_CUR_REG){
                    all_cur_cwnd_reg.write(cur_pkt_num, byte_dropped_cnt);  
                    cur_pkt_num = cur_pkt_num + 1;
                    cur_pkt_num_reg.write(0,cur_pkt_num);
                }
            }
        
            hdr.probe_data.push_front(1);
            hdr.probe_data[0].setValid();
            if (hdr.probe.hop_cnt == 1) {
                hdr.probe_data[0].bos = 1;
            }
            else {
                hdr.probe_data[0].bos = 0;
            }
            // set switch ID field
            hdr.probe_data[0].port = (bit<8>)standard_metadata.egress_port;
            hdr.probe_data[0].byte_cnt = byte_cnt;
            // read / update the last_time_reg
            last_time_reg.read(last_time, (bit<32>)standard_metadata.egress_port);
            last_time_reg.write((bit<32>)standard_metadata.egress_port, cur_time);
            hdr.probe_data[0].last_time = last_time;
            hdr.probe_data[0].cur_time = cur_time;
            hdr.probe_data[0].qdepth = (bit<32>)standard_metadata.deq_qdepth;  // 记录入口
        
            hdr.probe_data[0].swid = (bit<7>)meta.swid;
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ***************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
	update_checksum(	// IP 和 TCP 的校验和计算使用相同的计算方法。
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      	  hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

	update_checksum(	// 更新TCP校验和
	    	hdr.my_wnd.isValid(),
            { hdr.ipv4.srcAddr,
	      	  hdr.ipv4.dstAddr,
			  (bit<8>)0x00,		// 8bit 全0填充
              hdr.ipv4.protocol,
              // (bit<16>)hdr.tcp.offset << 2,	// 会报错
			  meta.TCP_length,		// TCP包的总长度，得计算得到
			// 以上是伪首部
			// TCP的校验和计算需要伪首部+TCP所有字段，但这里我们需要重新计算TCP校验和的情况只有增加ACK内容时，所以只使用了如下这些TCP字段值。
              hdr.tcp.srcPort,
	      	  hdr.tcp.dstPort,
              hdr.tcp.seqNum,
              hdr.tcp.ackNum,
              hdr.tcp.offset,
              hdr.tcp.reserved,
              hdr.tcp.URG,
              hdr.tcp.ACK,
              hdr.tcp.PSH,
              hdr.tcp.RST,
              hdr.tcp.SYN,
              hdr.tcp.FIN,
              hdr.tcp.cwnd,
              hdr.tcp.urgentPointer,
			  hdr.my_wnd.type,
			  hdr.my_wnd.length,
			  hdr.my_wnd.value,
			  hdr.options.nop_nop_timeStamps
			},
            hdr.tcp.checkSum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
		packet.emit(hdr.my_wnd);
		packet.emit(hdr.options);
        packet.emit(hdr.probe);
        packet.emit(hdr.probe_data);
        packet.emit(hdr.probe_fwd);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
