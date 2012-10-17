
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define IP_V4 4
#define IP_V6 6

		
int 
main(int argc, char ** argv)
{

	char errbuf[PCAP_ERRBUF_SIZE];

	assert(argc == 2);

	pcap_t *capture = pcap_open_offline(argv[1], errbuf);

	if (capture == NULL)
		fprintf(stderr, "Failed to open trace");

	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;

	const struct ether_header *eth; /* The Ethernet header */


	uint16_t ether_type;
	uint8_t ip_version;
	uint16_t payload_size;
	char src_ip[17];
	char dst_ip[17];
	uint8_t protocol;
	uint16_t src_port;
	uint16_t dst_port;

	struct ip *ip4_hdr;
	struct ip6_hdr *ip6_hdr;
	uint ip_hdr_size;
	struct tcphdr *tcp;
	struct udphdr *udp;

	uint64_t millis;

	printf("%s", "Timestamp,Ethernet Type,IP Version,Payload Bytes,Source IP,Destination IP,Transport Protocol,Source Port,Destination Port\n");
	
	while (pcap_next_ex(capture, &pkt_header, &pkt_data) > 0)
	{

		eth = (struct ether_header *)(pkt_data);

		ether_type = ntohs (eth->ether_type);

		millis = pkt_header->ts.tv_sec * 1000 + pkt_header->ts.tv_usec / 1000 ; 
		printf("%llu,", millis);
		printf("%x,", ether_type);

		switch (ether_type)
		{
			
			case ETHERTYPE_IP:
				ip4_hdr = (struct ip*)(eth + 1);
				ip6_hdr = (struct ip6_hdr *)(eth + 1);
				ip_version = ip4_hdr->ip_v;


				switch(ip_version)
				{
					case IP_V4:

						ip_hdr_size = ip4_hdr->ip_hl*4;
						payload_size = ntohs(ip4_hdr->ip_len) - ip_hdr_size;
						if (inet_ntop(AF_INET, &(ip4_hdr->ip_src), src_ip, sizeof(src_ip)) == NULL)
							fprintf(stderr, "%s\n", "Error converting IP address to string");
						if (inet_ntop(AF_INET, &(ip4_hdr->ip_dst), dst_ip, sizeof(dst_ip)) == NULL)
							fprintf(stderr, "%s\n", "Error converting IP address to string");
						protocol = ip4_hdr->ip_p;
						break;
					case IP_V6:
						ip_hdr_size = sizeof(*ip6_hdr);
						payload_size = ip6_hdr->ip6_plen;
						if (inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, sizeof(src_ip)) == NULL)
							fprintf(stderr, "%s\n", "Error converting IP address to string");
						if (inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, sizeof(dst_ip)) == NULL)
							fprintf(stderr, "%s\n", "Error converting IP address to string");
						protocol = ip6_hdr->ip6_nxt; 
						break;
					default:
						break;
				}
				if(ip_version == IP_V4 || ip_version == IP_V6)
				{
					printf("%d,%d,%s,%s,%d,", ip_version, payload_size, src_ip, dst_ip, protocol);

					switch(protocol)
					{
						case 6: //TCP
							tcp = (struct tcphdr *)((void *)ip4_hdr + ip_hdr_size);
							src_port = ntohs(tcp->th_sport);
							dst_port = ntohs(tcp->th_dport);
							break;
						case 17: //UDP
							udp = (struct udphdr *)((void *)ip4_hdr + ip_hdr_size);
							src_port = ntohs(udp->uh_sport);
							dst_port = ntohs(udp->uh_dport);
							break;
						default:
							break;
					}
					if (protocol == 6 || protocol == 17)
						printf("%d,%d", src_port, dst_port);
					else
						printf("%s", ",");
				}
				else
					printf("%s", ",,,,,,");

				break;

			default:
				printf("%s", ",,,,,,");
				break;
		}

		printf("%s", "\n");	
	}
	return 0;
}