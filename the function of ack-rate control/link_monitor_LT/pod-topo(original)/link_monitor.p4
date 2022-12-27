/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x800;
const bit<16> TYPE_ECN = 0x1111;
const bit<16> TYPE_PROBE = 0x812;
const bit<32> MAX_NUMS = 1 << 16;  
const bit<8> TCP_PROTOCOL = 0x06;

#define MAX_HOPS 10
#define MAX_PORTS 8

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ecn_hdr_t{
    bit<16> identification;  // ecn包头放着，因为ecn报文是不需要后面那些东西的。
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

header tcp_t {
    bit<107>     before_ACK;
    bit<1>      ACK;
    bit<4>      others;
    bit<16>     cwnd;
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
     bit<32>   endepth;
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
    bit<9>  ingress_port;   // 用于ecn
    bit<48> ethernet_srcAddr;   // 用于ecn
}

struct headers {
    ethernet_t              ethernet;
    ecn_hdr_t               ecn_hdr;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
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
            TYPE_ECN: parse_ecn;
            TYPE_IPV4: parse_ipv4;
            TYPE_PROBE: parse_probe;
            default: accept;
        }
    }
    
    state parse_ecn{
        packet.extract(hdr.ecn_hdr);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_tcp;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
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
    // 队列深度大于50 发ecn
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
/*
        if (hdr.ipv4.protocol == TCP_PROTOCOL && hdr.tcp.ACK == 1){
            hdr.tcp.cwnd = 0x9999;
        }
*/

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
    
    apply {
        if (hdr.ecn_hdr.isValid()){
            // 根据标识进行一些策略
            my_reg.write(0, 11);    // 在第0个位置写上 11 
            drop();
        }   // if 里面的drop之后应该不会再运行下面的代码了吧。
        meta.ingress_port = standard_metadata.ingress_port;
        // meta.ethernet_srcAddr = hdr.ethernet.srcAddr;
        meta.ethernet_srcAddr = 0x3333333;
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
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

    action set_swid(bit<7> swid) {
        hdr.probe_data[0].swid = swid;
		
    }

    table swid {
        actions = {
            set_swid;
            NoAction;
        }
        default_action = NoAction();
    }

/*
设置s2 交换机队列处理速率
simple_switch_CLI --thrift-port 9091
set_queue_rate 7600

*/
    apply {
        // 队列深度大于50 发ecn, 只对IPv4包进行克隆变成ECN包
        if ( standard_metadata.enq_qdepth > 50 && hdr.ethernet.etherType == TYPE_IPV4){
            if (standard_metadata.instance_type == 0){
                clone3(CloneType.E2E, (bit<32>)standard_metadata.ingress_port, {meta}); 
            }else{
                // 经测试，这里的meta一定是传入的meta，不是本文件之前写的meta
                hdr.ethernet.dstAddr = meta.ethernet_srcAddr; // mac地址改为上一跳MAC，
                hdr.ethernet.etherType = TYPE_ECN;
                hdr.ecn_hdr.setValid();
                hdr.ecn_hdr.identification = 0x2;   // TODO：之后再改成其他有意义的值
                truncate((bit<32>)16);    
                // 截断剩16 个字节(6个源mac，6个目的mac，2个是etherType，2个是identification)
            }
        }

        if (standard_metadata.instance_type == 0){  // 非克隆包才能进入，
        // 这里面包含了INT包和普通包的逻辑
            bit<32> byte_cnt;
            bit<32> new_byte_cnt;
            time_t last_time;
            time_t cur_time = standard_metadata.egress_global_timestamp;
            // increment byte cnt for this packet's port
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
                swid.apply();
                hdr.probe_data[0].port = (bit<8>)standard_metadata.egress_port;
                hdr.probe_data[0].byte_cnt = byte_cnt;
                // read / update the last_time_reg
                last_time_reg.read(last_time, (bit<32>)standard_metadata.egress_port);
                last_time_reg.write((bit<32>)standard_metadata.egress_port, cur_time);
                hdr.probe_data[0].last_time = last_time;
                hdr.probe_data[0].cur_time = cur_time;
                hdr.probe_data[0].qdepth = (bit<32>)standard_metadata.enq_qdepth;   // 记录入口
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
        packet.emit(hdr.ecn_hdr);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
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
