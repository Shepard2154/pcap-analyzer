#include "sniffer.h"

using namespace std;


IpExtractor::IpExtractor(const sniff_ip* ip) : ip(ip)  {
    ip = ip;
}

TcpExtractor::TcpExtractor(const sniff_tcp* tcp) : tcp(tcp) {
    tcp = tcp;
}

UdpExtractor::UdpExtractor(const sniff_udp* udp) : udp(udp) {
    udp = udp;
}

void IpExtractor::PrintInfo(pcap_pkthdr* header) {
    cout << "packet IP version (class): " << this -> ip -> ip_vhl << endl;
    cout << "packet IP protocol: " << int(this -> ip -> ip_p) << endl;

    in_addr_t source_address = this -> ip -> ip_src.s_addr;
    char source_string[IP_ADDRESS_SIZE];
    cout << "packet IP source address: " << inet_ntop(AF_INET, &source_address, source_string, sizeof(source_string)) << endl;

    in_addr_t destination_address = this -> ip -> ip_dst.s_addr;
    char destination_string[16];
    cout << "packet IP destination address: " << inet_ntop(AF_INET, &destination_address, destination_string, sizeof(destination_string)) << endl;

    cout << "Total length: " << ntohs(this -> ip -> ip_len) << endl;
    cout << "Packet size: " << header -> len << endl;
    cout << "Number of bytes: " << header -> caplen << endl;
    cout << endl;
}

void TcpExtractor::PrintInfo() {
    cout << "TCP source port: " << ntohs(this -> tcp -> th_sport) << endl;
    cout << "TCP destination port: " << ntohs(this -> tcp -> th_dport) << endl;
}

void UdpExtractor::PrintInfo() {
    cout << "UDP source port: " << to_string(ntohs(this -> udp -> uh_sport)) << endl;
    cout << "UDP destination port: " << to_string(ntohs(this -> udp -> uh_dport)) << endl;
    cout << "UDP length: " << to_string(ntohs(this -> udp -> uh_len)) << endl;
    cout << "UDP checksum: " << to_string(ntohs(this -> udp -> uh_sum)) << endl << endl;
}


bool IpExtractor::isIpV4() {
    if (this -> ip -> ip_vhl != 0x45) {
        return -1;
    }
    return 1;
}

bool IpExtractor::isHeaderValid() {
    u_int size_ip;
    size_ip = IP_HL(this -> ip) * 4;
    if (size_ip < 20 && size_ip > 60) {
        return -1;
    }
    return 1;
}

string IpExtractor::GetSourceIp() {
    char source_string[IP_ADDRESS_SIZE];
    in_addr_t source_address;
    string source_ip;

    source_address = this -> ip -> ip_src.s_addr;
    source_ip = inet_ntop(AF_INET, &source_address, source_string, sizeof(source_string));
    return source_ip;
}

string IpExtractor::GetDestinationIp() {
    char destination_string[IP_ADDRESS_SIZE];
    in_addr_t destination_address;
    string destination_ip;

    destination_address = this -> ip -> ip_dst.s_addr;
    destination_ip = inet_ntop(AF_INET, &destination_address, destination_string, sizeof(destination_string));
    return destination_ip;
}

bool TcpExtractor::isHeaderValid() {
    u_int size_tcp;
    size_tcp = TH_OFF(this -> tcp) * 4;
    if (size_tcp < 20) {
        return -1;
    }
    return 1;
}

void write_to_csv(const string& filename, const map<tuple<string, string, string, string>, vector<int>>& data) {
    int packets_count = 0;
    int packets_bytes_size = 0;

    ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        return;
    }
    file << "IP_source,IP_destination,port_source,port_destination,packets_count,packets_bytes\n";

    for (const auto& entry : data) {
        const auto& keys = entry.first;
        const auto& values = entry.second;

        file << get<0>(keys) << "," << get<1>(keys) << "," << get<2>(keys) << ',' << get<3>(keys);
        for (int value : values) {
            packets_count++;
            packets_bytes_size += value;
        }
        file << "," << packets_count << "," << packets_bytes_size << "\n";
    }
    file.close();
}