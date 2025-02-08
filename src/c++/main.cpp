#include "sniffer.h"

using namespace std;


void print_ip_packet_info(const sniff_ip* packet, pcap_pkthdr* header) {
    cout << "packet IP version (class): " << packet -> ip_vhl << endl;
    cout << "packet IP protocol: " << int(packet -> ip_p) << endl;

    in_addr_t source_address = packet -> ip_src.s_addr;
    char source_string[IP_ADDRESS_SIZE];
    cout << "packet IP source address: " << inet_ntop(AF_INET, &source_address, source_string, sizeof(source_string)) << endl;

    in_addr_t destination_address = packet -> ip_dst.s_addr;
    char destination_string[16];
    cout << "packet IP destination address: " << inet_ntop(AF_INET, &destination_address, destination_string, sizeof(destination_string)) << endl;

    cout << "Total length: " << ntohs(packet -> ip_len) << endl;
    cout << "Packet size: " << header -> len << endl;
    cout << "Number of bytes: " << header -> caplen << endl;
    cout << endl;
}

void print_tcp_header(const struct sniff_tcp *tcp) {
    cout << "TCP source port: " << ntohs(tcp -> th_sport) << endl;
    cout << "TCP destination port: " << ntohs(tcp -> th_dport) << endl;
}

void print_udp_header(const struct sniff_udp *udp) {
    cout << "UDP source port: " << to_string(ntohs(udp -> uh_sport)) << endl;
    cout << "UDP destination port: " << to_string(ntohs(udp-> uh_dport)) << endl;
    cout << "UDP length: " << to_string(ntohs(udp -> uh_len)) << endl;
    cout << "UDP checksum: " << to_string(ntohs(udp -> uh_sum)) << endl << endl;
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
    string file_path = "../assets/example-02.pcap";
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
        
        print_ip_packet_info(ip, header);

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

            print_tcp_header(tcp);

            source_port = to_string(ntohs(tcp -> th_sport));
            destination_port = to_string(ntohs(tcp -> th_dport));
        } else if (int(ip -> ip_p) == 17) {
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
            print_udp_header(udp);
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
