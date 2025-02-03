# pcap-analyzer
a small application for analyzing pcap files

# Compilation stage
1. Check the file availability libpcap.so in the /usr/lib folder
2. Compile the code from the directory containing "main.cpp" with command "g++ -L /usr/lib main.cpp -o main -lpcap"