
#define  MAXBUF  1024*4
#define  PCAP_TOUT 5
#define  PROMISC 0
#define  TRUE  1
#define  FALSE  0

/* Ethernet protocol ID's */    
#define ETHERTYPE_PUP           0x0200          /* Xerox PUP */
#define ETHERTYPE_IP            0x0800          /* IP */
#define ETHERTYPE_ARP           0x0806          /* Address resolution */
#define ETHERTYPE_REVARP        0x8035          /* Reverse ARP */

/* This structure defines an ethernet arp header.  */

/* ARP protocol opcodes. */
#define ARPOP_REQUEST   1               /* ARP request.  */
#define ARPOP_REPLY     2               /* ARP reply.  */
#define ARPOP_RREQUEST  3               /* RARP request.  */
#define ARPOP_RREPLY    4               /* RARP reply.  */
#define ARPOP_InREQUEST 8               /* InARP request.  */
#define ARPOP_InREPLY   9               /* InARP reply.  */
#define ARPOP_NAK       10              /* (ATM)ARP NAK.  */

/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_NETROM   0               /* From KA9Q: NET/ROM pseudo. */
#define ARPHRD_ETHER    1               /* Ethernet 10/100Mbps.  */
#define ARPHRD_EETHER   2               /* Experimental Ethernet.  */
#define ARPHRD_AX25     3               /* AX.25 Level 2.  */
#define ARPHRD_PRONET   4               /* PROnet token ring.  */
#define ARPHRD_CHAOS    5               /* Chaosnet.  */
#define ARPHRD_IEEE802  6               /* IEEE 802.2 Ethernet/TR/TB.  */
#define ARPHRD_ARCNET   7               /* ARCnet.  */
#define ARPHRD_APPLETLK 8               /* APPLEtalk.  */
#define ARPHRD_DLCI     15              /* Frame Relay DLCI.  */
#define ARPHRD_ATM      19              /* ATM.  */
#define ARPHRD_METRICOM 23              /* Metricom STRIP (new IANA id).  */

/* Dummy types for non ARP hardware */
#define ARPHRD_SLIP       0x256
#define ARPHRD_CSLIP      0x257
#define ARPHRD_SLIP6      0x258
#define ARPHRD_CSLIP6     0x259
#define ARPHRD_RSRVD      0x260             /* Notional KISS type.  */
#define ARPHRD_ADAPT      0x264
#define ARPHRD_ROSE       0x270 
#define ARPHRD_X25        0x271             /* CCITT X.25.  */
#define ARPHDR_HWX25      0x272             /* Boards with X.25 in firmware.  */
#define ARPHRD_PPP        0x512
#define ARPHRD_CISCO      0x513             /* Cisco HDLC.  */
#define ARPHRD_HDLC       ARPHRD_CISCO
#define ARPHRD_LAPB       0x516             /* LAPB.  */
#define ARPHRD_DDCMP      0x517             /* Digital's DDCMP.  */
#define ARPHRD_RAWHDLC    0x518             /* Raw HDLC.  */
    
#define ARPHRD_TUNNEL     0x768             /* IPIP tunnel.  */
#define ARPHRD_TUNNEL6    0x769             /* IPIP6 tunnel.  */
#define ARPHRD_FRAD       0x770             /* Frame Relay Access Device.  */
#define ARPHRD_SKIP       0x771             /* SKIP vif.  */
#define ARPHRD_LOOPBACK   0x772             /* Loopback device.  */
#define ARPHRD_LOCALTLK   0x773             /* Localtalk device.  */
#define ARPHRD_FDDI       0x774             /* Fiber Distributed Data Interface. */
#define ARPHRD_BIF        0x775             /* AP1000 BIF.  */ 
#define ARPHRD_SIT        0x776             /* sit0 device - IPv6-in-IPv4.  */
#define ARPHRD_IPDDP      0x777             /* IP-in-DDP tunnel.  */
#define ARPHRD_IPGRE      0x778             /* GRE over IP.  */
#define ARPHRD_PIMREG     0x779             /* PIMSM register interface.  */
#define ARPHRD_HIPPI      0x780             /* High Performance Parallel I'face. */
#define ARPHRD_ASH        0x781             /* (Nexus Electronics) Ash.  */
#define ARPHRD_ECONET     0x782             /* Acorn Econet.  */
#define ARPHRD_IRDA       0x783             /* Linux-IrDA.  */
#define ARPHRD_FCPP       0x784             /* Point to point fibrechanel.  */
#define ARPHRD_FCAL       0x785             /* Fibrechanel arbitrated loop.  */
#define ARPHRD_FCPL       0x786             /* Fibrechanel public loop.  */
#define ARPHRD_FCPFABRIC  0x787             /* Fibrechanel fabric.  */
#define ARPHRD_IEEE802_TR 0x800             /* Magic type ident for TR.  */
#define ARPHRD_IEEE80211  0x801             /* IEEE 802.11.  */



 

/* IP version number */
#define IPVERSION       4

struct ether_header
{
	u_int8_t  ether_dhost[6];      /* destination eth addr */
	u_int8_t  ether_shost[6];      /* source ether addr    */
	u_int16_t ether_type;          /* packet type ID field */
};

struct arphead
{
	u_int16_t arp_hardware_type;				 /* Format of hardware address.  */
	u_int16_t arp_protocol_type;				 /* Format of protocol address.  */
	u_int8_t arp_hardware_length;			 /* Length of hardware address.  */
	u_int8_t arp_protocol_length;			 /* Length of protocol address.  */
	u_int16_t arp_operation_code;			 /* ARP opcode (command).  */ //1为请求 2为回复
	u_int8_t arp_source_ethernet_address[6];		 /* Sender hardware address.  */
	u_int8_t arp_source_ip_address[4];			 /* Sender IP address.  */
	u_int8_t arp_destination_ethernet_address[6];   /* Target hardware address.  */
	u_int8_t arp_destination_ip_address[4];		 /* Target IP address.  */
};

struct iphead
{
	u_int8_t ip_header_length:4,ip_version:4;
	u_int8_t ip_tos;
	u_int16_t ip_length;
	u_int16_t ip_id;
	u_int16_t ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_protocol;
	u_int16_t ip_checksum;
	struct in_addr ip_souce_address;
	struct in_addr ip_destination_address;
};


struct tcphead
  {
    u_int16_t th_sport;         /* source port */
    u_int16_t th_dport;         /* destination port */
    u_int32_t th_seq;             /* sequence number */
    u_int32_t th_ack;             /* acknowledgement number */
    u_int8_t th_off:4;          /* data offset */
    u_int8_t th_x2:4;           /* (unused) */
    u_int8_t th_flags;
#define TH_FIN        0x01
#define TH_SYN        0x02
#define TH_RST        0x04
#define TH_PUSH       0x08
#define TH_ACK        0x10
#define TH_URG        0x20
    u_int16_t th_win;           /* window */
    u_int16_t th_sum;           /* checksum */
    u_int16_t th_urp;           /* urgent pointer */
};

struct udphead
{
	u_int16_t udp_source_port;
	u_int16_t udp_destinanion_port;
	u_int16_t udp_length;
	u_int16_t udp_checksum;
};

struct icmphead
{
	u_int8_t icmp_type;
	u_int8_t icmp_code;
	u_int16_t icmp_checksum;
	u_int16_t icmp_id;
	u_int16_t icmp_sequence;
};


/*
icmp
类型	代码	描述	查	询	差		错
0 	0 	回显应答(P i n g应答）		
3 		目的不可达：					
	0 
	1
	2 	网络不可达主机不可达协议不可达				
	3 
	4 
	5 
	6 	端口不可达需要进行分片但设置了不分片比特源站选路失败目的网络不认识					
	7 	目的主机不认识				
	8
	9 	源主机被隔离（作废不用）目的网络被强制禁止				
	1 0 	目的主机被强制禁止				
	11 
	12 
	13 	由于服务类型TO S ，网络不可达由于服务类型TO S ，主机不可达由于过滤，通信被强制禁止				
	14 	主机越权			
	15 	优先权中止生效			
4 	0 	源端被关闭（基本流控制）			
5 	0 	重定向： 对网络重定向				
	1 	对主机重定向				
	2 	对服务类型和网络重定向			
	3 	对服务类型和主机重定向		
8 	0 	请求回显（P i n g请求）			
9 	0 	路由器通告				
1 0 	0 	路由器请求				
11 		超时：					
	0 	传输期间生存时间为0（Traceroute）					
	1 	在数据报组装期间生存时间为0					
1 2 		参数问题：					
	0 	坏的I P首部（包括各种差错）				
	1 	缺少必需的选项				
1 3 	0 	时间戳请求		
1 4 	0 	时间戳应答	
1 5 	0 	信息请求（作废不用）			
1 6 	0 	信息应答（作废不用）			
1 7 	0 	地址掩码请求				
1 8 	0 	地址掩码应答	
*/

