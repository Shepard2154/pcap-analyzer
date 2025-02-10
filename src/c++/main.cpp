#include "sniffer.h"

using namespace std;


bool validate_ip_extractor(IpExtractor ip_extractor) {
    bool is_fourth_version = ip_extractor.isIpV4();
    if (!is_fourth_version) {
        cout << "Пакет не относится к IPv4" << endl;
        return false;
    }

    bool is_header_valid = ip_extractor.isHeaderValid();
    if (!is_header_valid) {
        cout << "Неверная длина заголовка";
        return false;
    }

    return true;
}

int main(int argc, char *argv[]) {   
    char error_buffer[PCAP_ERRBUF_SIZE];
    int pcap_init(unsigned int opts, char *error_buffer);

    char *dev, net_error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask, net;
    pcap_lookupnet(dev, &net, &mask, net_error_buffer);
    
    // TODO - begin: CAPTURING PACKETS FROM NET INTERFACE 
    // dev = pcap_lookupdev(net_error_buffer);
    // TODO - end;

    string file_path = "../assets/example-02.pcap";
    pcap_t *handle = pcap_open_offline(file_path.c_str(), error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open file %s: %s\n", file_path.c_str(), error_buffer);
        return -1;
    }
    cout << "File " << file_path.c_str() << " available for reading" << endl;

    // Processing variables
    int result;
    int counter = 1;
    map<tuple<string, string, string, string>, vector<int>> data;

    // PCAP variables
    struct pcap_pkthdr* header;
    const u_char* packet;

    // IP variables
    const struct sniff_ip *ip;
    u_int size_ip;
    bool is_valid;
    string source_ip;
    string destination_ip;

    // TCP | UDP variables
    string source_port;
    string destination_port;

    // TCP variables
    const struct sniff_tcp *tcp;
    u_int size_tcp;

    // UDP variables
    const struct sniff_udp *udp;
    u_int size_udp;
    
    while ((pcap_next_ex(handle, &header, &packet)) == 1) {
        cout << "Обработка пакета #" << counter++ << endl;
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(*ip) * 4;
        IpExtractor ip_extractor(*ip);
        is_valid = validate_ip_extractor(ip_extractor);
        if (is_valid) {
            ip_extractor.PrintInfo(header);
            source_ip = ip_extractor.GetSourceIp();
            destination_ip = ip_extractor.GetDestinationIp();
        } else { continue; }

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
