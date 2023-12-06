/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x800;
const bit<16> TYPE_PROBE = 0x812; 
const bit<16> TYPE_ECN = 0x1111;


#define MAX_HOPS 10
#define MAX_PORTS 8
#define PORT_TO_S2 1
#define PORT_TO_S3 2
#define PORT_TO_S4 3
#define CNT_PKT_UP 2
#define CNT_PKT_MID 3
#define CNT_PKT_DOWN 4
#define ECN_TIMEOUT 100000 
#define LEN_QLENGTH_REG 500000

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

//INT time
typedef bit<48> time_t;

register<bit<48>>(10) ecn_timer;   // 使用寄存器保存交换机收到的包数量，寄存器只可以保存 10 个32位的数据，
register<bit<32>>(LEN_QLENGTH_REG) qlength_reg;
register<bit<32>>(1) pkt_cnt;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ecn_t{
    bit<16> identification;  // ecn包头放这儿，因为ecn报文是不需要后面那些东西的。
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// 顶级探测标头，指示此探测的跳数
// 到目前为止，数据包已遍历
header probe_t {
    bit<8> hop_cnt;
    bit<8> learn; //0 - INT, 1-learning set 
	
}

// The data added to the probe by each switch at each hop.(每个交换机在每个跃点添加到探测器的数据)
header probe_data_t {
    bit<1>    bos;
    bit<7>    swid;
    bit<8>    port;
    bit<32>   byte_cnt;
    bit<32>   pckcont;
    bit<32>   enpckcont;
    time_t    last_time;
    time_t    cur_time;
    bit<32>   qdepth;
}

// Indicates the egress port the switch should send this probe(指示交换机应发送此探测数据包的出口端口。每个跳都有一个标题。)
// packet out of. There is one of these headers for each hop.
header probe_fwd_t {
    bit<8>    egress_spec;
    bit<8>    swid;
    bit<8>    percent_up;
    bit<8>    percent_mid;
}

struct parser_metadata_t {
    bit<8>  remaining;
}

struct metadata {
    bit<8> egress_spec;
    parser_metadata_t parser_metadata;
    bit<9>  port_send_to;
    bit<32> temp_count;
    bit<32> threshold1;
    bit<32> threshold2;
    bit<7> swid;
    bit<8> percent_up;
    bit<8> percent_mid;
    bit<32> pktcont2;
    bit<48> ethernet_srcAddr;   // 用于ecn
}


struct headers {
    ethernet_t              ethernet;
    ecn_t                   ecn; 
    ipv4_t                  ipv4;
    probe_t                 probe;
    probe_data_t[MAX_HOPS]  probe_data;
    probe_fwd_t[MAX_HOPS]   probe_fwd;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata){
    state start{
        transition parse_ethernet;
    }

    state parse_ethernet{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_ECN:       parse_ecn;
            TYPE_IPV4:      parse_ipv4;
            TYPE_PROBE:     parse_probe;
            default:        accept;
        }
    }
    
    state parse_ecn{
        packet.extract(hdr.ecn);
        transition accept;
    }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition accept;
    }

    // 顶级探测标头
    state parse_probe{
        packet.extract(hdr.probe);
	// 又经过了一次交换机，所以跳数加一
        meta.parser_metadata.remaining = hdr.probe.hop_cnt + 1;
        transition select(hdr.probe.hop_cnt){
	    0:
            parse_probe_fwd;
        default:
            parse_probe_data;
        }
    }

    state parse_probe_data{
        packet.extract(hdr.probe_data.next);
        transition select(hdr.probe_data.last.bos)
        {
	    1:
            parse_probe_fwd;
        default:
            parse_probe_data;
        }
    }

    state parse_probe_fwd {
        packet.extract(hdr.probe_fwd.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        // extract the forwarding data
        meta.egress_spec = hdr.probe_fwd.last.egress_spec;
        meta.percent_up= hdr.probe_fwd.last.percent_up;
        meta.percent_mid= hdr.probe_fwd.last.percent_mid;
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
    // 一共256位，每位32bit
    register< bit<32> >(256) count;
    //设置轮询阈值
    register< bit<32> >(10) threshold;
    //set ingress port count packet, because before forward aggrestion(设置入口端口计数数据包，因为在转发聚合之前)
    register<bit<32>>(MAX_PORTS) contpkts;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port)
    {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action ipv4_forward_up(macAddr_t dstAddr, egressSpec_t port)
    {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        // ipv4_forward(dstAddr, port);
    }
    action ipv4_forward_down(macAddr_t dstAddr, egressSpec_t port)
    {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action ipv4_forward_mid(macAddr_t dstAddr, egressSpec_t port)
    {
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
	
    table ipv4_lpm_up {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward_up;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table ipv4_lpm_mid {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward_mid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table ipv4_lpm_down {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward_down;
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
            NoAction;
        }
        default_action = NoAction();
    }
	// 更改并交换路径阈值
    bit<32> cg=0;
	bit<32> cnt_pkt_up=0;
	bit<32> cnt_pkt_mid=0;
	bit<32> cnt_pkt_down=0;

	// register< bit<32> >(256) count;
    action read_reg_count() {
        count.read(cg,(bit<32>)0);
        count.read(meta.temp_count,(bit<32>)1); 
        count.read(cnt_pkt_up,(bit<32>)2); 
        count.read(cnt_pkt_mid,(bit<32>)3); 
        count.read(cnt_pkt_down,(bit<32>)4); 
    }
   bit<32>threshold3=0;
   action read_reg_threshold(){
        threshold.read(meta.threshold1,(bit<32>)0);
        threshold.read(meta.threshold2,(bit<32>)1);
    }
    bit<32> pkg_cnt_ingress;
    bit<32> new_count;
 
    apply {
        read_reg_threshold(); 
	    swid.apply();   // 读取交换机ID
        if(meta.threshold1 == 0){
                meta.threshold1=(bit<32>)60;
		        meta.threshold2=(bit<32>)30;
		        threshold.write(0,meta.threshold1);
		        threshold.write(1,meta.threshold2);
        }
        threshold3=100 - meta.threshold2 - meta.threshold1;
        if (hdr.ecn.isValid()){
            // 根据标识进行一些策略
            bit<48> cur_ecn_time = standard_metadata.ingress_global_timestamp;  // 数据包在入口出现时的时间
            bit<48> last_ecn_time;
            ecn_timer.read(last_ecn_time, 9);    // 把时间暂时放在第9个位置
            if (cur_ecn_time - last_ecn_time > ECN_TIMEOUT ) {  // 当前这个ECN包来到的时间比上一个处理的ECN包的时间超过1秒了
                if (standard_metadata.ingress_port == 5 ){ // 上路
                    if (meta.threshold1 > 4){
                        meta.threshold1 = meta.threshold1 - 4;
                        meta.threshold2 = meta.threshold2 + 2;
                        threshold3 = threshold3 + 2;
                        threshold.write(0, meta.threshold1);
                        threshold.write(1, meta.threshold2);
                    }
                }else if (standard_metadata.ingress_port == 4){// 中路
                    if (meta.threshold2 > 4){
                        meta.threshold2 = meta.threshold2 - 4;
                        meta.threshold1 = meta.threshold1 + 2;
                        threshold3 = threshold3 + 2;
                        threshold.write(0, meta.threshold1);
                        threshold.write(1, meta.threshold2);
                    }
                }else {                                 // 下路
                    if (threshold3 > 4){
                        threshold3 = threshold3 - 4;
                        meta.threshold1 = meta.threshold1 + 2;
                        meta.threshold2 = meta.threshold2 + 2;
                        threshold.write(0, meta.threshold1);
                        threshold.write(1, meta.threshold2);
                    }
                }
                ecn_timer.write(9, cur_ecn_time);   // 写入当前处理的ECN包的来到时间。
            }
            drop();
        }   // if 里面的drop之后不会再运行下面的代码了 。 
        meta.ethernet_srcAddr = hdr.ethernet.srcAddr;   // 将源地址保存到自定义的元数据中
        // 入口数据包conut--   increment byte cnt for this packet's port此数据包端口的增量字节数量
        // register<bit<32>>(8) contpkts; 把寄存器contpkts的第ingress_port位上的数据给pkg_cnt_ingress
        contpkts.read(pkg_cnt_ingress, (bit<32>)standard_metadata.ingress_port);
        pkg_cnt_ingress = pkg_cnt_ingress + 1;
        meta.pktcont2 = pkg_cnt_ingress;  //trans to egress packetdata传输到出口数据包
        // reset the byte count when a probe packet passes through 当探测数据包通过时重置字节计数
        new_count = (hdr.probe.isValid()) ? 0 : pkg_cnt_ingress;
        contpkts.write((bit<32>)standard_metadata.ingress_port, new_count); 
        //register< bit<32> >(256) count   
        //把count第0,1,2,3,4的值赋给cg，meta.temp_count，cnt_pkt_up，cnt_pkt_mid，cnt_pkt_down
        read_reg_count();
        read_reg_threshold();
        // 顶级探测标头
        if (hdr.probe.isValid()) {
            standard_metadata.egress_spec = (bit<9>)meta.egress_spec;
            hdr.probe.hop_cnt = hdr.probe.hop_cnt + 1;
            if(hdr.probe.learn == 0) {
                threshold.write(0, (bit<32>)50);
                threshold.write(1, (bit<32>)33);
            }
            else if(hdr.probe.learn == 1) {
                threshold.write(0,(bit<32>)meta.percent_up);
                threshold.write(1,(bit<32>)meta.percent_mid);
            }
        }else if(hdr.ipv4.isValid()){ 
            if(meta.swid == 1){ 
                if(hdr.ipv4.dstAddr <= 0x0a000303 ){    // 去h1,h2,h3的逻辑
                    ipv4_lpm.apply();
                }else{
                    read_reg_count();
                    read_reg_threshold();
                    if(meta.temp_count < 100){
                        if(cg==0){  // cg：change
                            // 应该是判断该从哪个端口发出去
                            meta.port_send_to = 1;  // 这些都是魔法数字
                            count.write((bit<32>)1,meta.temp_count+1);
                            //把count第0,1,2,3,4的值赋给cg，meta.temp_count，cnt_pkt_up，cnt_pkt_mid，cnt_pkt_down
                            count.write((bit<32>)2,cnt_pkt_up + 1);
                            if(cnt_pkt_up + 1 == meta.threshold1){
                                count.write((bit<32>)2,101);
                            }
                            if(cnt_pkt_mid<101){
                                cg=1;
                            }else if(cnt_pkt_down<101){
                                cg=2;
                            }else{
                                cg=0;
                            }
                            count.write((bit<32>)0,cg);	
                        }else if(cg==1){
                            meta.port_send_to = 2;
                            count.write((bit<32>)1,meta.temp_count+1);
                            count.write((bit<32>)3,cnt_pkt_mid+1);
                            if(cnt_pkt_mid +1 ==meta.threshold2){
                                count.write((bit<32>)3,101);
                            }
                            if(cnt_pkt_down<101){
                                cg=2;
                            }else if(cnt_pkt_up<101){
                                cg=0;
                            }else{
                                cg=1;
                            }
                            count.write((bit<32>)0,cg); 
                        }else if(cg==2){
                            meta.port_send_to = 3;
                            count.write((bit<32>)1,meta.temp_count+1);
                            count.write((bit<32>)4,cnt_pkt_down+1);
                            if(cnt_pkt_down==threshold3-1){
                                count.write((bit<32>)4,101);
                            }
                            if(cnt_pkt_up<101){
                                cg=0;
                            }else if(cnt_pkt_mid<101){
                                cg=1;
                            }else{
                                cg=2;
                            }
                            count.write((bit<32>)0,cg);
                        }
                    }else{
                        // 这时发了一轮包了（100个）
                        //reset form begin
                        meta.port_send_to = 1;
                        //cg=1;
                        // cg，meta.temp_count，cnt_pkt_up，cnt_pkt_mid，cnt_pkt_down的值给1/1/1/0/0
                        count.write((bit<32>)0,(bit<32>)1);
                        count.write((bit<32>)1,(bit<32>)1);
                        count.write((bit<32>)2,(bit<32>)1);
                        count.write((bit<32>)3,(bit<32>)0);
                        count.write((bit<32>)4,(bit<32>)0);
                        // 特殊情况处理
                        if (meta.threshold1 == 1){
                            count.write((bit<32>)2,(bit<32>)101);
                        }
                        if (meta.threshold2 == 0){
                            count.write((bit<32>)3,(bit<32>)101);
                        }
                        if (threshold3 == 0){
                            count.write((bit<32>)4,(bit<32>)101);
                        }
                        // 1口 若门限值为0时 特殊处理
                        if (meta.threshold1 == 0) {
                            count.write((bit<32>)2,(bit<32>)101);
                            // 2口 门限值不为0 第一个包从2口发
                            if (meta.threshold2 != 0){
                                meta.port_send_to = 2;
                                if (threshold3 != 0){
                                    count.write((bit<32>)0,(bit<32>)2);
                                } else {
                                    count.write((bit<32>)0,(bit<32>)1);
                                }
                                count.write((bit<32>)1,(bit<32>)1);
                                count.write((bit<32>)3,(bit<32>)1);
                            } else {
                                // 仅3口门限值不为0 第一个包从3口发
                                meta.port_send_to = 3;
                                count.write((bit<32>)0,(bit<32>)2);
                                count.write((bit<32>)1,(bit<32>)1);
                                count.write((bit<32>)4,(bit<32>)1);
                            }
                        }
                    }
                    if(meta.port_send_to == PORT_TO_S2){
                        ipv4_lpm_up.apply();
                    }else if(meta.port_send_to == PORT_TO_S3){
                        ipv4_lpm_mid.apply();
                    }else if(meta.port_send_to == PORT_TO_S4){
                        ipv4_lpm_down.apply();
                    }
                }
            } else {// swid == 2,3,4,5 都是直接简单转发
                ipv4_lpm.apply(); 
            }
        } else {    // 不是INT也不是IPv4包
            ipv4_lpm.apply();
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    // count the number of bytes seen since the last probe(统计自上次探测以来看到的字节数,推测是每个端口的)
    register<bit<32>>(MAX_PORTS) byte_cnt_reg;
    // remember the time of the last probe (记住上次探测的时间,推测是每个端口的)
    register<time_t>(MAX_PORTS) last_time_reg;
    // 统计各个端口一共发出去几个数据包啦
    register<bit<32>>(MAX_PORTS) encontpkts;

    apply {
        if (standard_metadata.instance_type != 0){      // 克隆出来的包走这里的逻辑
            // 经测试，这里的meta一定是传入的meta，不是本文件之前写的meta
            hdr.ethernet.dstAddr = meta.ethernet_srcAddr; // mac目的地址改为上一跳MAC，mac源地址已经在上面改成本机mac了。
            hdr.ethernet.etherType = TYPE_ECN;
            hdr.ecn.setValid();
            hdr.ecn.identification = 0x0001;   // 标记位
            truncate((bit<32>)16);
            // 截断剩16 个字节(6个源mac，6个目的mac，2个是etherType，2个是identification)
        } else{   // 普通的包走这里的逻辑
            /*   */

			bit<32> cur_pkt_num;
			pkt_cnt.read(cur_pkt_num,0);
			if (cur_pkt_num < LEN_QLENGTH_REG){
				qlength_reg.write(cur_pkt_num, (bit<32>)standard_metadata.deq_qdepth);    // 记录所有的qlength
		     	cur_pkt_num = cur_pkt_num + 1;
				pkt_cnt.write(0,cur_pkt_num);
			}
            
            // 判断何种包需要克隆成ECN包：队列深度大于50 发ecn, 只对IPv4的数据包进行克隆变成ECN包，还要对交换机进行限制
            // 还可以加上判断剔除ACK包，使用standard_metadata.packet_length > 100 &&      但因为ACK直接从7口传输，所以这个判断在这里不需要
            if ( standard_metadata.enq_qdepth > 8 && hdr.ethernet.etherType == TYPE_IPV4 && meta.swid >= 2 && meta.swid < 5){
                clone3(CloneType.E2E, (bit<32>)standard_metadata.ingress_port, {meta}); 
                // 克隆包的出端口通过第二个参数sessionID决定
            }

            // 下面普通的包的逻辑
            bit<32> enpkg_cnt_ingress;
            bit<32> new_encont;
            // ingress packet conut--   increment byte cnt for this packet's port此数据包端口的增量字节数量
            encontpkts.read(enpkg_cnt_ingress, (bit<32>)standard_metadata.egress_port);
            enpkg_cnt_ingress = enpkg_cnt_ingress + 1;
            // reset the byte count when a probe packet passes through
            new_encont = (hdr.probe.isValid()) ? 0 : enpkg_cnt_ingress;
            encontpkts.write((bit<32>)standard_metadata.egress_port, new_encont); 

            // 该端口的字节数量
            bit<32> byte_cnt;
            bit<32> new_byte_cnt;
            time_t last_time;
            time_t cur_time = standard_metadata.egress_global_timestamp;
            // increment byte cnt for this packet's port 此数据包端口的增量字节数量
            byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
            byte_cnt = byte_cnt + standard_metadata.packet_length;
            // reset the byte count when a probe packet passes through
            new_byte_cnt = (hdr.probe.isValid()) ? 0 : byte_cnt;
            byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, new_byte_cnt);

            if (hdr.probe.isValid()) {
                // fill out probe fields
                hdr.probe_data.push_front(1);
                hdr.probe_data[0].setValid();
                if (hdr.probe.hop_cnt == 1) {
                    hdr.probe_data[0].bos = 1;
                }
                else {
                    hdr.probe_data[0].bos = 0;
                }
                // set switch ID field
                hdr.probe_data[0].swid=(bit<7>)meta.swid;
                hdr.probe_data[0].port = (bit<8>)standard_metadata.egress_port;
                hdr.probe_data[0].byte_cnt = byte_cnt;
                hdr.probe_data[0].pckcont =meta.pktcont2;
                hdr.probe_data[0].enpckcont =enpkg_cnt_ingress;
                // read / update the last_time_reg
                last_time_reg.read(last_time, (bit<32>)standard_metadata.egress_port);
                last_time_reg.write((bit<32>)standard_metadata.egress_port, cur_time);
                hdr.probe_data[0].last_time = (bit<48>)meta.threshold1;
                hdr.probe_data[0].cur_time = (bit<48>)meta.threshold2;
                hdr.probe_data[0].qdepth = (bit<32>)standard_metadata.deq_qdepth;
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ***************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
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
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ecn);
        packet.emit(hdr.ipv4);
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
