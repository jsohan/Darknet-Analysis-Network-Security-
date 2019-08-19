#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
//"Simple" struct for TCP
struct tcp_header {
	u_short sport; // Source port
	u_short dport; // Destination port
	u_int seqnum; // Sequence Number
	u_int acknum; // Acknowledgement number
	u_char th_off; // Header length
	u_char flags; // packet flags
	u_short win; // Window size
	u_short crc; // Header Checksum
	u_short urgptr; // Urgent pointer...still don't know what this is...
};


/* 4 bytes IP address */
struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	bool operator==(const ip_address& a) const
	{
		return (byte1 == a.byte1 && byte2 == a.byte2 && byte3 == a.byte3 && byte4 == a.byte4);
	}
	bool operator!=(const ip_address& a) const
	{
		return (byte1 != a.byte1 || byte2 != a.byte2 || byte3 != a.byte3 || byte4 != a.byte4);
	}
};


/* IPv4 header */
struct ip_header{
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
};

//Funt Prototype
//packet handler
void my_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void print_all();
void ip_query();
void probe_query();
int sub_string(char *a);
void printer(int k);


//global Var
int count = 0;
int arrayVal = 0;
ip_address sipArray[20];
struct ip_address ipstart;
struct ip_address ipend;
int flag = 0;
int max = 10000;
char ptype[10000][14];
//array of ip addresses from suspected probe packets 
ip_address *suspectip = (ip_address *)malloc(max * sizeof(ip_address));
//array of their destination ip addresses
ip_address *destip = (ip_address *)malloc(max * sizeof(ip_address));
//array of their destination ports
u_short *destport = (u_short *)malloc(max * sizeof(u_short));
//array of how many packets have that source ip
int *packets = (int *)malloc(max * sizeof(int));
//array of what type of prob it is
//0=horizontal
//1=vertical
//2=strobe
int *type = (int *)malloc(max * sizeof(int));
//array of probe start time
timeval *pkstart = (timeval*)malloc(max * sizeof(timeval));
//array of probe end time
timeval *pkend = (timeval*)malloc(max * sizeof(timeval));
//current size of dynamic array
int arraySize = 0;



//------------------------------------------
//array of ip addresses from suspected probe packets 
ip_address *tsuspectip = (ip_address *)malloc(max * sizeof(ip_address));
//array of their destination ip addresses
ip_address *tdestip = (ip_address *)malloc(max * sizeof(ip_address));
//array of their destination ports
u_short *tdestport = (u_short *)malloc(max * sizeof(u_short));
//array of how many packets have that source ip
int *tpackets = (int *)malloc(max * sizeof(int));
//array of what type of prob it is
//0=horizontal
//1=vertical
//2=strobe
int *ttype = (int *)malloc(max * sizeof(int));
//array of probe start time
//array of probe start time
timeval *tpkstart = (timeval*)malloc(max * sizeof(timeval));
//array of probe end time
timeval *tpkend = (timeval*)malloc(max * sizeof(timeval));