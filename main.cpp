#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

void printPacketInfo(const u_char* packet, struct pcap_pkthdr* header) {
    const struct ether_header *eth_header = (struct ether_header *) packet;
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    if (ip_header->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

        printf("Ethernet Header\n");
        printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_header->ether_shost[0],
               eth_header->ether_shost[1],
               eth_header->ether_shost[2],
               eth_header->ether_shost[3],
               eth_header->ether_shost[4],
               eth_header->ether_shost[5]);
        printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_header->ether_dhost[0],
               eth_header->ether_dhost[1],
               eth_header->ether_dhost[2],
               eth_header->ether_dhost[3],
               eth_header->ether_dhost[4],
               eth_header->ether_dhost[5]);

        printf("IP Header\n");
        printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

        printf("TCP Header\n");
        printf("Src Port: %d\n", ntohs(tcp_header->source));
        printf("Dst Port: %d\n", ntohs(tcp_header->dest));

        const u_char *payload = packet + sizeof(struct ether_header) + ip_header->ip_hl * 4 + tcp_header->doff * 4;
        int payload_len = header->caplen - (payload - packet);
        printf("Payload (first 20 bytes): ");
        for (int i = 0; i < payload_len && i < 20; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n\n");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printPacketInfo(packet, header);
    }

    pcap_close(pcap);
    return 0;
}
