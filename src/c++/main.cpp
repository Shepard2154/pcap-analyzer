#include "sniffer.h"

using namespace std;


enum class Protocol {
    TCP = 6,
    UDP = 17,
};

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
    if (argc < 3) {
        std::cerr << "Пример вызова: " << argv[0] << " ../assets/example-01.pcap output" << endl;
        return -1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    int pcap_init(unsigned int opts, char *error_buffer);

    char *dev, net_error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask, net;
    pcap_lookupnet(dev, &net, &mask, net_error_buffer);
    
    // TODO - begin: CAPTURING PACKETS FROM NET INTERFACE 
    // dev = pcap_lookupdev(net_error_buffer);
    // TODO - end;

    string file_path = argv[1];
    pcap_t *handle = pcap_open_offline(file_path.c_str(), error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Ошибка при открытии файла %s: %s\n", file_path.c_str(), error_buffer);
        return -1;
    }
    cout << "Файл " << file_path.c_str() << " доступен для чтения" << endl;

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

    // UDP variables
    const struct sniff_udp *udp;
    
    while ((pcap_next_ex(handle, &header, &packet)) == 1) {
        cout << "Обработка пакета #" << counter++ << endl;
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;
        IpExtractor ip_extractor(ip);
        is_valid = validate_ip_extractor(ip_extractor);
        if (is_valid) {
            ip_extractor.PrintInfo(header);
            source_ip = ip_extractor.GetSourceIp();
            destination_ip = ip_extractor.GetDestinationIp();
        } else { continue; }

        if (Protocol(ip -> ip_p) == Protocol::TCP) {
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            TcpExtractor tcp_extractor(tcp);
            is_valid = tcp_extractor.isHeaderValid();
            if (is_valid) {
                tcp_extractor.PrintInfo();
                source_port = to_string(ntohs(tcp -> th_sport));
                destination_port = to_string(ntohs(tcp -> th_dport));
            } else { continue; }


        } else if (Protocol(ip -> ip_p) == Protocol::UDP) {
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
            UdpExtractor udp_extractor(udp);
            udp_extractor.PrintInfo();
            source_port = to_string(ntohs(udp -> uh_sport));
            destination_port = to_string(ntohs(udp -> uh_dport));
        } else {
            cout << "Пакет не распознан как TCP | UDP: " << int(ip -> ip_vhl) << endl;
            continue;
        }

        data[{source_ip, destination_ip, source_port, destination_port}].push_back(header -> caplen);
    }

    write_to_csv(argv[2] + string(".csv"), data);
    pcap_close(handle);
}
