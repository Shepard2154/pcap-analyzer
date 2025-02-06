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

#define SIZE_ETHERNET 14
#define IP_ADDRESS_SIZE 16
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)

using namespace std;


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

typedef u_int tcp_seq;
struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
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
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

struct sniff_udp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    u_short th_sum;		/* checksum */
};

void print_ip_packet_info(const sniff_ip* packet, pcap_pkthdr* header) {
    cout << "packet IP version (class): " << packet -> ip_vhl << endl;
    cout << "packet IP protocol: " << int(packet -> ip_p) << endl;

    in_addr_t source_address = packet -> ip_src.s_addr;
    char source_string[IP_ADDRESS_SIZE];
    cout << "packet IP source address: " << inet_ntop(AF_INET, &source_address, source_string, sizeof(source_string)) << endl;

    in_addr_t destination_address = packet -> ip_dst.s_addr;
    char destination_string[IP_ADDRESS_SIZE];
    cout << "packet IP destination address: " << inet_ntop(AF_INET, &destination_address, destination_string, sizeof(destination_string)) << endl;

    cout << "Total length: " << ntohs(packet -> ip_len) << endl;
    cout << "Packet size: " << header -> len << endl;
    cout << "Number of bytes: " << header -> caplen << endl;
    cout << endl;
}

void write_to_csv(const string& filename, const map<tuple<string, string, string, string>, vector<int>>& data) {
    int packets_count = 0;
    int packets_bytes_size = 0;

    ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        return;
    }

    // Записываем заголовок CSV
    file << "IP_source,IP_destination,port_source,port_destination,packets_count,packets_bytes\n";

    // Записываем данные
    for (const auto& entry : data) {
        const auto& keys = entry.first; // Пара ключей
        const auto& values = entry.second; // Вектор значений

        // Записываем ключи
        file << get<0>(keys) << "," << get<1>(keys) << "," << get<2>(keys) << ',' << get<3>(keys);

        // Записываем значения
        for (int value : values) {
            packets_count++;
            packets_bytes_size += value;
        }

        // Переход на новую строку
        file << "," << packets_count << "," << packets_bytes_size << "\n";
    }

    // Закрываем файл
    file.close();
}


int main(int argc, char *argv[]) {
    string file_path = "../assets/example-01.pcap";
    char error_buffer[PCAP_ERRBUF_SIZE];
    int pcap_init(unsigned int opts, char *error_buffer);
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t **alldevsp;
    bpf_u_int32 mask,net;
    pcap_lookupnet(dev, &net, &mask, errbuf);
    
    // UNCOMMENT TO CATCH PACKETS FROM NET INTERFACE 
    // dev = pcap_lookupdev(errbuf);
    // if (dev == NULL) 
    // {
    //     fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    //     return(2);
    // }
    // printf("Device: %s\n", dev);
    // return(0);

    pcap_t *handle = pcap_open_offline(file_path.c_str(), error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open file %s: %s\n", file_path.c_str(), error_buffer);
        return -1;
    }
    cout << "File " << file_path.c_str() << " available for reading" << endl;

    const struct sniff_ip *ip;

    struct pcap_pkthdr* header;
    const u_char* packet;

    int result;
    int counter = 1;
    map<tuple<string, string, string, string>, vector<int>> data;

    u_int size_ip;
    const struct sniff_tcp *tcp;
    const u_char *payload;
    u_int size_tcp;
    u_short tcp_source_port;
    u_short tcp_destination_port;

    char source_string[IP_ADDRESS_SIZE];
    char destination_string[IP_ADDRESS_SIZE];
    in_addr_t source_address;
    in_addr_t destination_address;
    string source_ip;
    string source_port;
    string destination_ip;
    string destination_port;

    while ((pcap_next_ex(handle, &header, &packet)) == 1) {
        // Обработка пакета
        cout << "Обработка Пакета #" << counter++ << endl;

        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        

        if (ip -> ip_vhl != 0x45) {
            cout << "Пакет #" << counter++ << " не относится к IPv4" << endl;
            continue;
        }
        
        // for (int i = 0; i < header -> caplen; ++i) {
        //     cout << packet[i] << " ";
        // }
        print_ip_packet_info(ip, header);

        
        size_ip = IP_HL(ip) * 4;
        if (size_ip < 20 && size_ip > 60) {
            printf("Invalid IP header length: %u bytes\n", size_ip);
            return -1;
        }

        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;
        if (size_tcp < 20) {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return -1;
        }
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

        tcp_source_port = tcp -> th_sport;
        tcp_destination_port = tcp -> th_dport;

        cout << "TCP source port: " << ntohs(tcp_source_port) << endl;
        cout << "TCP destination port: " << ntohs(tcp_destination_port) << endl;
        cout << "TCP payload: " << sizeof(payload) << endl << endl;

        
        source_address = ip -> ip_src.s_addr;
        source_ip = inet_ntop(AF_INET, &source_address, source_string, sizeof(source_string));
        source_port = to_string(ntohs(tcp_source_port));
        
        destination_address = ip -> ip_dst.s_addr;
        destination_ip = inet_ntop(AF_INET, &destination_address, destination_string, sizeof(destination_string));
        destination_port = to_string(ntohs(tcp_destination_port));

        data[{source_ip, destination_ip, source_port, destination_port}].push_back(header -> caplen);
    }

    write_to_csv("output.csv", data);

    pcap_close(handle);
}
