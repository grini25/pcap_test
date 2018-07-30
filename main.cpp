#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#define ETHERTYPE_IP 0x0800
#define IPPROTO_TCP 0x06

struct ether_header {
	u_int8_t eth_dmac[6];
	u_int8_t eth_smac[6];
	u_int16_t ether_type;
};

struct ip_header {
	u_int8_t version:4;
	u_int8_t header_len:4;
	u_int8_t tos;
	u_int16_t total_len;
	u_int16_t id;
	u_int8_t frag_off:5; //flag(3 bits), fragment offset(13 bits)
	u_int8_t m_frag:1;
	u_int8_t d_frag:1;
	u_int8_t reserved_zero:1;
	u_int8_t frag_offset;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t checksum;
	struct in_addr sip;
	struct in_addr dip;
};

struct tcp_header {
	u_int16_t tcp_sport;
	u_int16_t tcp_dport;
	u_int32_t sequence;
	u_int32_t acknowledge;
	u_int8_t ns:1;
	u_int8_t reserved_part:3;
	u_int8_t data_offset:4;
	u_int8_t fin:1;
	u_int8_t syn:1;
	u_int8_t rst:1;
	u_int8_t psh:1;
	u_int8_t ack:1;
	u_int8_t urg:1;
	u_int8_t ecn:1;
	u_int8_t cwr:1;
	u_int16_t window;
	u_int16_t checksum;
	u_int16_t urgent_pointer;
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac_addr(const u_char *data);
void print_ip(const u_char *data);
void print_tcp(const u_char *data, int len);
void print_data(const u_char *data, int data_len);

int main(int argc, char* argv[]) {
  int offset = 0;
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet); //&packet ethernet start part
    if (res == 0) continue; //can't catch packet
    if (res == -1 || res == -2) break; //can't read packet
    printf("%u bytes captured\n", header->caplen); //modify for assingment
    print_mac_addr(packet);
  }

  pcap_close(handle);
  return 0;
}

void print_mac_addr(const u_char *data) {
	int i;
	struct ether_header *eth;
	eth = (struct ether_header *)data;
	
	printf("=========================================\n");
	printf("Dst MAC Address : [");
	for(i=0;i<5;i++) printf("%02x:", eth->eth_dmac[i]);
	printf("%02x]\n", eth->eth_dmac[5]);
	printf("Src MAC Address : [");
	for(i=0;i<5;i++) printf("%02x:", eth->eth_smac[i]);
	printf("%02x]\n", eth->eth_smac[5]);

	if (ntohs(eth->ether_type) == ETHERTYPE_IP) print_ip(data+14);
	
	return ;
}

void print_ip(const u_char *data) {
	struct ip_header *ihd;
	ihd = (struct ip_header *)data;
	int len=ihd->header_len*4;
	
	printf("Dst IP Address : %s\n", inet_ntoa(ihd->dip));
	printf("Src IP Address : %s\n", inet_ntoa(ihd->sip));
	if (ihd->protocol == IPPROTO_TCP) print_tcp(data+len, ihd->total_len-len);
	return ;
}

void print_tcp(const u_char *data, int len) {
	struct tcp_header *tcph;
	tcph = (struct tcp_header *)data;
	int offset=tcph->data_offset*4;

	printf("Dst Port Number : %d\n", ntohs(tcph->tcp_dport));
	printf("Src Prot Number : %d\n", ntohs(tcph->tcp_sport));
	
	print_data(data+offset, len-offset);
	printf("=========================================\n");
}

void print_data(const u_char *data, int data_len) {
	int i;

	printf("===================DATA==================\n");
	if (data_len > 16) for(i=0;i<16;i++) printf("%c ", data[i]);
	else for(i=0;i<data_len;i++) printf("%c ", data[i]);
	printf("\n");
}
