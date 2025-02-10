#ifndef SNIFFER_H
#define SNIFFER_H

#include <iostream>
#include <fstream>
#include <cstring>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <tuple>
#include <string>

#define SIZE_ETHERNET 14
#define IP_ADDRESS_SIZE 16
#define IP_HL(ip) ((ip) -> ip_vhl & 0x0f)

using namespace std;

// Структура для IP-заголовка
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
    #define IP_RF 0x8000		/* reserved fragment flag */
    #define IP_DF 0x4000		/* don't fragment flag */
    #define IP_MF 0x2000		/* more fragments flag */
    #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol PS: 6 for TCP, 17 for UDP*/
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

// Структура для TCP-заголовка
typedef u_int tcp_seq;
struct sniff_tcp {
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
    #define TH_OFF(th) (((th) -> th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

// Структура для UDP-заголовка
struct sniff_udp {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
};

class IpExtractor {
    private:
        const sniff_ip *ip;

    public:
        IpExtractor(const sniff_ip *ip);
        void PrintInfo(pcap_pkthdr* header);
        string GetSourceIp();
        string GetDestinationIp();
        bool isIpV4();
        bool isHeaderValid();
};

class TcpExtractor {
    private:
        const sniff_tcp* tcp;
    
    public:
        TcpExtractor(const sniff_tcp* tcp);
        void PrintInfo();
        bool isHeaderValid();
};

class UdpExtractor {
    private:
        const sniff_udp* udp;

    public:
    UdpExtractor(const sniff_udp* udp);
        void PrintInfo();
};   

void write_to_csv(const string& filename, const map<tuple<string, string, string, string>, vector<int>>& data);

#endif // SNIFFER_H