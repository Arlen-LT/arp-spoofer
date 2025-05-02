
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <interface> <spoof_ip> <spoof_mac>\n", prog);
    exit(1);
}

int parse_mac(const char *str, uint8_t *mac) {
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2],
                  &mac[3], &mac[4], &mac[5]) == 6;
}

int main(int argc, char *argv[]) {
    if (argc != 4) usage(argv[0]);

    const char *iface = argv[1];
    const char *spoof_ip = argv[2];
    const char *spoof_mac_str = argv[3];
    uint8_t spoof_mac[6];

    if (!parse_mac(spoof_mac_str, spoof_mac)) {
        fprintf(stderr, "Invalid MAC address\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    uint8_t packet[42];
    struct ether_header *eth = (struct ether_header *)packet;
    struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));

    memset(packet, 0, sizeof(packet));

    // Ethernet Header
    memset(eth->ether_dhost, 0xFF, 6); // broadcast
    memcpy(eth->ether_shost, spoof_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);

    // ARP Header
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REPLY); // Gratuitous ARP reply

    memcpy(arp->arp_sha, spoof_mac, 6);
    inet_pton(AF_INET, spoof_ip, arp->arp_spa);
    memset(arp->arp_tha, 0xFF, 6);
    inet_pton(AF_INET, spoof_ip, arp->arp_tpa);

    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
    } else {
        printf("Sent Gratuitous ARP: %s is-at %s\n", spoof_ip, spoof_mac_str);
    }

    pcap_close(handle);
    return 0;
}
