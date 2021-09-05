/*

  Network IDS Experiment Code by John Hyung-Jong KIM

 */

#ifdef _MSC_VER
 /*
  * we do not want the warnings about the old deprecated and unsecure CRT functions
  * since these examples can be compiled under *nix as well
  */
#define _CRT_SECURE_NO_WARNINGS
#endif

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <string>
#include <iostream>
#include <list>
#include <tuple>

#include "pcap.h"
#pragma comment(lib, "ws2_32")

#define ETH_ALEN 6
  /* 14 bytes ethernet header */
typedef struct ethhdr//typedef A B
{
	u_char   h_dest[ETH_ALEN];   /* destination eth addr */
	u_char   h_source[ETH_ALEN]; /* source ether addr    */
	u_short  h_proto;            /* packet type ID field */
}eth_hdr;


/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

typedef struct arphdr
{
	u_short hwtype; //hardware type
	u_short prototype;//protocol type
	u_char hlen;//h/w length
	u_char plen;//protocol length
	u_short opcode; //operation code
	u_char sender_mac[ETH_ALEN];
	ip_address	saddr;
	u_char target_mac[ETH_ALEN];
	ip_address	daddr;
}arphdr;



/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

time_t timer_for_renew = 0;
time_t renew_time_std = 120;

int abnormality_std = 10;

using namespace std;

list<tuple<string, string, int>> ip_pairs;

list<tuple<string, string>> mac_ip_map;


FILE* fp;


bool is_new_mac_ip(string macAddr, string IpAddr) {

	list<tuple<string, string>>::iterator iter = mac_ip_map.begin();

	for (; iter != mac_ip_map.end(); iter++)
	{
		if (get<0>(*iter) == macAddr && get<1>(*iter) == IpAddr) {
			return false;
		}

	}

	return true;
}

void add_mac_ip_map(string macAddr, string IpAddr) {

	if (is_new_mac_ip(macAddr, IpAddr)) {
		mac_ip_map.push_back(std::make_tuple((string)macAddr, (string)IpAddr));
	}

}

void renew_mac_ip_map() {

	mac_ip_map.clear();

}


void check_mac_ip_map_abnormality(string macAddr, string IpAddr) {

	list<tuple<string, string>>::iterator iter = mac_ip_map.begin();

	for (; iter != mac_ip_map.end(); iter++)
	{

		if (get<0>(*iter) == macAddr && get<1>(*iter) != IpAddr) {
			fprintf(fp, "Map is switched [%s and %s] to [%s and %s]\n",
				get<1>(*iter).c_str(), get<0>(*iter).c_str(), IpAddr.c_str(), macAddr.c_str());
			printf("Map is switched [%s and %s] to [%s and %s]\n",
				get<1>(*iter).c_str(), get<0>(*iter).c_str(), IpAddr.c_str(), macAddr.c_str());
		}
		else if (get<0>(*iter) != macAddr && get<1>(*iter) == IpAddr) {
			fprintf(fp, "Map is switched [%s and %s] to [%s and %s]\n",
				get<1>(*iter).c_str(), get<0>(*iter).c_str(), IpAddr.c_str(), macAddr.c_str());
			printf("Map is switched [%s and %s] to [%s and %s]\n",
				get<1>(*iter).c_str(), get<0>(*iter).c_str(), IpAddr.c_str(), macAddr.c_str());
		}
	}
}



bool is_new(string srcIP, string dstIP) {

	list<tuple<string, string, int>>::iterator iter = ip_pairs.begin();

	for (; iter != ip_pairs.end(); iter++)
	{
		if (get<0>(*iter) == srcIP && get<1>(*iter) == dstIP) {
			get<2>(*iter)++;
			return false;
		}

	}

	return true;
}


void add_ip_pair(string srcIP, string dstIP) {

	if (is_new(srcIP, dstIP)) {
		ip_pairs.push_back(std::make_tuple((string)srcIP, (string)dstIP, 1));
	}

}


void renew_ip_pair() {

	ip_pairs.clear();

}

void check_abnormality() {

	list<tuple<string, string, int>>::iterator iter = ip_pairs.begin();

	if (ip_pairs.size() > abnormality_std) {
		fprintf(fp, "Too many connection in this machine[%d]\n", ip_pairs.size());
		printf("\nToo many connection in this machine[%d]\n", ip_pairs.size());
	}

	for (; iter != ip_pairs.end(); iter++)
	{
		if (get<2>(*iter) > abnormality_std) {
			fprintf(fp, "Too many connection between %s and %s CNT[%d]\n",
				get<0>(*iter).c_str(), get<1>(*iter).c_str(), get<2>(*iter));
			printf("\nToo many connection between %s and %s CNT[%d]\n",
				get<0>(*iter).c_str(), get<1>(*iter).c_str(), get<2>(*iter));

		}

	}
}




int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "arp or udp or ip";
	struct bpf_program fcode;

	fp = fopen("log.txt", "a");

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
//	if ((adhandle = pcap_open_live(d->name,	// name of the device
//		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
//		1,				// promiscuous mode (nonzero means promiscuous)
//		1000,			// read timeout
//		errbuf			// error buffer
//	)) == NULL)

//	if ((adhandle = pcap_open_offline("tcp-ack-scan.pcap", errbuf)) == NULL)
//	if ((adhandle = pcap_open_offline("arp-poison.pcap", errbuf)) == NULL)
	if ((adhandle = pcap_open_offline("active-scan.pcap", errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL) {
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
		struct sockaddr_in* addr_in = (struct sockaddr_in*)(d->addresses->addr);
		char* s = inet_ntoa(addr_in->sin_addr);
		printf("IP address: %s\n", s);
	}
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);//p.c.d.

	return 0;
}

time_t prev_local_tv_sec = 0;//0으로 초기화

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
//header --> timestamp, length
//pkt_data --> "ethernet frame"
{
	struct tm* ltime;
	char timestr[16];
	eth_hdr* eh; //ethernet header pointer
	ip_header* ih;// ip header
	udp_header* uh; // udp header
	arphdr* arphd; // arp header

	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	if (prev_local_tv_sec != 0)
		timer_for_renew += (local_tv_sec - prev_local_tv_sec);

	if (timer_for_renew >= renew_time_std) {
		timer_for_renew = 0;
		renew_ip_pair();
	}


	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ethernet header */
	eh = (eth_hdr*)(pkt_data);//type casting

	switch (ntohs(eh->h_proto))
	{
	case 0x800:
		/* retireve the position of the ip header */
		ih = (ip_header*)(pkt_data +
			14); //length of ethernet header

		/* retireve the position of the udp header */
		ip_len = (ih->ver_ihl & 0xf) * 4;
		uh = (udp_header*)((u_char*)ih + ip_len);
		//type casting
		//1. 덧셈으로 위치 찾아 가기 , 14, 20...
		//2. header type으로 casting...
		/* convert from network byte order to host byte order */
		sport = ntohs(uh->sport);//network : Big-endian
		dport = ntohs(uh->dport);
		char src_ip[20], dest_ip[20];
		char src_mac[20], dest_mac[20];

		sprintf(src_ip, "%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		sprintf(dest_ip, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);

		sprintf(src_mac, "%02x-%02x-%02x-%02x-%02x-%02x", eh->h_source[0], eh->h_source[1], eh->h_source[2],
			eh->h_source[3], eh->h_source[4], eh->h_source[5]);
		sprintf(dest_mac, "%02x-%02x-%02x-%02x-%02x-%02x", eh->h_dest[0], eh->h_dest[1], eh->h_dest[2],
			eh->h_dest[3], eh->h_dest[4], eh->h_dest[5]);

		add_ip_pair((string)src_ip, (string)dest_ip);
		check_abnormality();

		/* print ip addresses and udp ports */
		printf("%s.%s.%d -> %s.%s.%d\n", src_mac, src_ip, sport, dest_mac, dest_ip, dport);
		//printf("the tuple size is %d\n", ip_pairs.size());

		/*IP 정보 출력 */ break;
	case 0x806:

		arphd = (arphdr*)(pkt_data + 14);
		printf("\n===========  ARP Header ==============\n");
		printf("h/w type: %u", ntohs(arphd->hwtype));
		if (ntohs(arphd->hwtype) == 1)
		{
			printf("  Ethernet");
		}
		printf("\nprotocol type:%#x", ntohs(arphd->prototype));
		if (ntohs(arphd->prototype) == 0x800)
		{
			IN_ADDR addr;
			printf("  IP\n");
			//printf("\n opcode: %d ", ntohs(arphd->opcode));
			printf("\n opcode: %d ", arphd->opcode);

			sprintf(src_ip, "%d.%d.%d.%d", arphd->saddr.byte1, arphd->saddr.byte2, arphd->saddr.byte3, arphd->saddr.byte4);
			sprintf(dest_ip, "%d.%d.%d.%d", arphd->daddr.byte1, arphd->daddr.byte2, arphd->daddr.byte3, arphd->daddr.byte4);

			printf("sender mac:0x");
			sprintf(src_mac, "%02x-%02x-%02x-%02x-%02x-%02x", arphd->sender_mac[0], arphd->sender_mac[1], arphd->sender_mac[2],
				arphd->sender_mac[3], arphd->sender_mac[4], arphd->sender_mac[5]);
			printf("%02x-%02x-%02x-%02x-%02x-%02x", arphd->sender_mac[0], arphd->sender_mac[1], arphd->sender_mac[2],
				arphd->sender_mac[3], arphd->sender_mac[4], arphd->sender_mac[5]);

			printf("\nsender ip: %s\n", src_ip);

			printf("target mac:0x");
			sprintf(dest_mac, "%02x-%02x-%02x-%02x-%02x-%02x", arphd->target_mac[0], arphd->target_mac[1], arphd->target_mac[2],
				arphd->target_mac[3], arphd->target_mac[4], arphd->target_mac[5]);
			printf("%02x-%02x-%02x-%02x-%02x-%02x", arphd->target_mac[0], arphd->target_mac[1], arphd->target_mac[2],
				arphd->target_mac[3], arphd->target_mac[4], arphd->target_mac[5]);
			printf("\ntarget ip: %s\n", dest_ip);
		}

		if (strcmp(src_mac, "ff-ff-ff-ff-ff-ff") != 0 &&
			strcmp(src_ip, "255.255.255.255") != 0 &&
			strcmp(src_ip, "0.0.0.0") != 0 &&
			strcmp(src_ip, "192.168.1.1") != 0 &&
			strcmp(src_ip, "192.168.1.0") != 0) {
			add_mac_ip_map((string)src_mac, (string)src_ip);
			check_mac_ip_map_abnormality((string)src_mac, (string)src_ip);
		}
		/*ARP 정보 출력*/ break;
	default:printf("Not support Protocol\n"); break;
	}

	prev_local_tv_sec = local_tv_sec;
}
