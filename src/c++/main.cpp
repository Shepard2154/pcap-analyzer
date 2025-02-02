#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

using namespace std;

int main(int argc, char *argv[]) {
    string file_path = "../assets/example-01.pcap";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("file_path", error_buffer);
    // if (handle == NULL) {
    //   fprintf(stderr, "Couldn't open file %s: %s\n", "example.pcap", error_buffer);
    // return -1;
// }
}
