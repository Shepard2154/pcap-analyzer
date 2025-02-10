#include "sniffer.h"

using namespace std;


int main(int argc, char *argv[]) {   
    char error_buffer[PCAP_ERRBUF_SIZE];
    int pcap_init(unsigned int opts, char *error_buffer);

    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t **alldevsp;
    bpf_u_int32 mask, net;
    pcap_lookupnet(dev, &net, &mask, errbuf);
    
    // TODO - begin: CAPTURING PACKETS FROM NET INTERFACE 
    // dev = pcap_lookupdev(errbuf);
    // if (dev == NULL) 
    // {
    //     fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    //     return(2);
    // }
    // printf("Device: %s\n", dev);
    // return(0);
    // TODO - end;

    string file_path = "../assets/example-02.pcap";
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
    u_int size_tcp;

    const struct sniff_udp *udp;
    u_int size_udp;
    u_short udp_source_port;
    u_short udp_destination_port;

    char source_string[IP_ADDRESS_SIZE];
    char destination_string[IP_ADDRESS_SIZE];
    in_addr_t source_address;
    in_addr_t destination_address;
    string source_ip;
    string source_port;
    string destination_ip;
    string destination_port;

    while ((pcap_next_ex(handle, &header, &packet)) == 1) {
        cout << "Обработка Пакета #" << counter++ << endl;

        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        if (ip -> ip_vhl != 0x45) {
            cout << "Пакет не относится к IPv4" << endl;
            continue;
        }
        
        IpExtractor ip_extractor(*ip);
        ip_extractor.PrintInfo(header);

        size_ip = IP_HL(ip) * 4;
        if (size_ip < 20 && size_ip > 60) {
            printf("Invalid IP header length: %u bytes\n", size_ip);
            return -1;
        }

        source_address = ip -> ip_src.s_addr;
        source_ip = inet_ntop(AF_INET, &source_address, source_string, sizeof(source_string));
        destination_address = ip -> ip_dst.s_addr;
        destination_ip = inet_ntop(AF_INET, &destination_address, destination_string, sizeof(destination_string));

        if (int(ip -> ip_p) == 6) {
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp) * 4;
            if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return -1;
            }

            TcpExtractor tcp_extractor(*tcp);
            tcp_extractor.PrintInfo();

            source_port = to_string(ntohs(tcp -> th_sport));
            destination_port = to_string(ntohs(tcp -> th_dport));
        } else if (int(ip -> ip_p) == 17) {
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
            
            UdpExtractor udp_extractor(*udp);
            udp_extractor.PrintInfo();

            source_port = to_string(ntohs(udp -> uh_sport));
            destination_port = to_string(ntohs(udp -> uh_dport));
        } else {
            cout << "Packet could not be resolved as TCP | UDP: " << int(ip -> ip_vhl) << endl;
            continue;
        }

        data[{source_ip, destination_ip, source_port, destination_port}].push_back(header -> caplen);
    }

    write_to_csv("output.csv", data);

    pcap_close(handle);
}
