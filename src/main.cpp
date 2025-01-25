#include <iostream> 
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet){
    std::cout << "Packet length: " << header->len << std::endl;

    const ether_header* eth_header = (struct ether_header*) packet;
    const struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    std::cout << " srcip " << inet_ntoa(ip_header->ip_src);
    std::cout << " dstip " << inet_ntoa(ip_header->ip_dst);

    int payload_offset = sizeof(struct ether_header) + ip_header->ip_hl*4 + tcp_header->th_off*4;
    const u_char* payload = packet + payload_offset;
    int payload_length = header->len - payload_offset;

    std::cout << " ip payload: " << payload << std::endl;
}

int main(int argc, char const *argv[])
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        std::cerr << "error finding devices: " << errbuf << std::endl;
        return EXIT_FAILURE;
    }
    pcap_if_t one = *alldevs;

    pcap_t * handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        std::cerr << "failed to open device: " << errbuf << std::endl;
        return 1;
    }

    pcap_loop(handle, -1, packet_handler, nullptr);

    pcap_close(handle);
    return EXIT_SUCCESS;
}
