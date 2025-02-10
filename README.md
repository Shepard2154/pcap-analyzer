# pcap-analyzer
A small application for analyzing IPv4 (TCP + UDP) packets in pcap files

# Compilation stage
1. Open terminal from directory with "main.cpp"
2. Compile the code from the directory containing "g++ -L ../../libs/libpcap-1.10.5 main.cpp sniffer.cpp -o main -lpcap"
3. Launch "./main ../src/assets/example-02.pcap output" in order to create "res1.csv"