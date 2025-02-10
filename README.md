# pcap-analyzer
A small application for analyzing IPv4 (TCP + UDP) packets in pcap files

## Part #1 - collecting
### Compilation stage (option 1 - manually)
1. Open terminal from directory containing `main.cpp`;
2. Compile the code from this directory by command `g++ -L ../../libs/libpcap-1.10.5 main.cpp sniffer.cpp -o main -lpcap`;
3. Launch `./main ../assets/example-02.pcap output` in order to create `output.csv`.

### Compilation stage (option 2 - cmake)
1. Open terminal from directory `build`;
2. run `cmake .`;
2. run `make .`;
3. Launch `./main ../src/assets/example-02.pcap output` in order to create `output.csv`.

## Part #2 - analysis
1. Launch `python3 main.py input.csv output.csv`