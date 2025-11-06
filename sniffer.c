#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

// Basic constants 
#ifndef ETHER_HDR_LEN
#define ETHER_HDR_LEN 14
#endif
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

// Ethernet Header Structure
struct eth_header {
    u_char  ether_dhost[ETHER_ADDR_LEN];
    u_char  ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
} __attribute__((packed));

// IP Header Structure (IPv4)
struct ip_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int   ip_hl:4, ip_v:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    u_int   ip_v:4, ip_hl:4;
#endif
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct  in_addr ip_src, ip_dst;
} __attribute__((packed));

#define IP_HL(ip) (((ip)->ip_hl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_v) & 0x0f)

// TCP Header Structure
struct tcp_header {
    u_short th_sport;
    u_short th_dport;
    u_int   th_seq;
    u_int   th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int   th_x2:4, th_off:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    u_int   th_off:4, th_x2:4;
#endif
    u_char  th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
} __attribute__((packed));

// UDP Header Structure
struct udp_header {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
} __attribute__((packed));

// Struct to pass multiple arguments to packet_handler
typedef struct {
    pcap_dumper_t *pcap_dumper;
    FILE *text_output_file;
} sniffer_args_t;

// --- Global Statistics Counters ---
static int total_packets_captured = 0;
static int ethernet_broadcast_packets = 0;
static int ip_packets = 0;
static int tcp_packets = 0;
static int udp_packets = 0;
static int other_ether_packets = 0;
static int current_packet_number = 0;

// --- Function Prototypes ---
void print_mac(FILE *f, const char *label, const u_char *mac);
void parse_tcp_packet(FILE *f, const u_char *packet, int ip_offset, int ip_hdr_len, int total_ip_len, int packet_len);
void parse_udp_packet(FILE *f, const u_char *packet, int ip_offset, int ip_hdr_len, int total_ip_len, int packet_len);
void parse_ip_packet(FILE *f, const u_char *packet, int eth_hdr_len, int packet_len);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet);

void print_mac(FILE *f, const char *label, const u_char *mac) {
    fprintf(f, "%s: %02x:%02x:%02x:%02x:%02x:%02x\n",
            label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void parse_tcp_packet(FILE *f, const u_char *packet, int ip_offset, int ip_hdr_len, int total_ip_len, int packet_len) {
    tcp_packets++;
    int tcp_offset = ip_offset + ip_hdr_len;

    if (packet_len < tcp_offset + sizeof(struct tcp_header)) {
        fprintf(f, "  [!] Packet too short for TCP header.\n");
        return;
    }
    struct tcp_header *tcp = (struct tcp_header *)(packet + tcp_offset);
    u_int tcp_header_len = (tcp->th_off * 4);

    if (tcp_header_len < 20 || (tcp_offset + tcp_header_len) > packet_len) {
        fprintf(f, "  [!] Invalid TCP header length: %u bytes\n", tcp_header_len);
        return;
    }

    fprintf(f, "\t\tTCP Header:\n");
    fprintf(f, "\t\t\tSource Port: %d\n", ntohs(tcp->th_sport));
    fprintf(f, "\t\t\tDestination Port: %d\n", ntohs(tcp->th_dport));
    fprintf(f, "\t\t\tSequence Number: %u\n", ntohl(tcp->th_seq));
    fprintf(f, "\t\t\tAcknowledgement Number: %u\n", ntohl(tcp->th_ack));
    fprintf(f, "\t\t\tData Offset (Header Length): %u bytes\n", tcp_header_len);
    fprintf(f, "\t\t\tFlags: 0x%x [ ", tcp->th_flags);
    if (tcp->th_flags & 0x02) fprintf(f, "SYN ");
    if (tcp->th_flags & 0x10) fprintf(f, "ACK ");
    if (tcp->th_flags & 0x01) fprintf(f, "FIN ");
    if (tcp->th_flags & 0x04) fprintf(f, "RST ");
    if (tcp->th_flags & 0x08) fprintf(f, "PSH ");
    if (tcp->th_flags & 0x20) fprintf(f, "URG ");
    if (tcp->th_flags & 0x40) fprintf(f, "ECE ");
    if (tcp->th_flags & 0x80) fprintf(f, "CWR ");
    fprintf(f, "]\n");

    const u_char *payload = packet + tcp_offset + tcp_header_len;
    int payload_len = total_ip_len - (ip_hdr_len + tcp_header_len);

    if (payload_len > 0 && (payload + payload_len) <= (packet + packet_len)) {
        fprintf(f, "\t\t\tTCP Payload Length: %d bytes\n", payload_len);
    } else if (payload_len < 0) {
        fprintf(f, "\t\t\t[!] Malformed TCP packet: Negative payload length.\n");
    } else {
        fprintf(f, "\t\t\tTCP Payload Length: 0 bytes (No payload)\n");
    }
}

void parse_udp_packet(FILE *f, const u_char *packet, int ip_offset, int ip_hdr_len, int total_ip_len, int packet_len) {
    udp_packets++;
    int udp_offset = ip_offset + ip_hdr_len;

    if (packet_len < udp_offset + sizeof(struct udp_header)) {
        fprintf(f, "  [!] Packet too short for UDP header.\n");
        return;
    }
    struct udp_header *udp = (struct udp_header *)(packet + udp_offset);

    fprintf(f, "\t\tUDP Header:\n");
    fprintf(f, "\t\t\tSource Port: %d\n", ntohs(udp->uh_sport));
    fprintf(f, "\t\t\tDestination Port: %d\n", ntohs(udp->uh_dport));
    fprintf(f, "\t\t\tLength: %d bytes (header + data)\n", ntohs(udp->uh_len));

    int udp_payload_len = ntohs(udp->uh_len) - sizeof(struct udp_header);
    const u_char *payload = packet + udp_offset + sizeof(struct udp_header);

    if (udp_payload_len > 0 && (payload + udp_payload_len) <= (packet + packet_len)) {
        fprintf(f, "\t\t\tUDP Payload Length: %d bytes\n", udp_payload_len);
    } else if (udp_payload_len < 0) {
        fprintf(f, "\t\t\t[!] Malformed UDP packet: Negative payload length.\n");
    } else {
        fprintf(f, "\t\t\tUDP Payload Length: 0 bytes (No payload)\n");
    }
}

void parse_ip_packet(FILE *f, const u_char *packet, int eth_hdr_len, int packet_len) {
    ip_packets++;
    int ip_offset = eth_hdr_len;

    if (packet_len < ip_offset + sizeof(struct ip_header)) {
        fprintf(f, "  [!] Packet too short for IP header.\n");
        return;
    }
    struct ip_header *ip = (struct ip_header *)(packet + ip_offset);

    u_int ip_header_len = IP_HL(ip) * 4;
    u_int total_ip_len = ntohs(ip->ip_len);

    if (ip_header_len < 20 || (ip_offset + ip_header_len) > packet_len) {
        fprintf(f, "  [!] Invalid IP header length: %u bytes\n", ip_header_len);
        return;
    }

    fprintf(f, "\n\tIP Header:\n");
    fprintf(f, "\t\tVersion: %d\n", IP_V(ip));
    fprintf(f, "\t\tHeader Length: %u bytes\n", ip_header_len);
    fprintf(f, "\t\tTotal Length: %u bytes (including header and data)\n", total_ip_len);
    fprintf(f, "\t\tSource IP: %s\n", inet_ntoa(ip->ip_src));
    fprintf(f, "\t\tDestination IP: %s\n", inet_ntoa(ip->ip_dst));
    fprintf(f, "\t\tProtocol: %d ", ip->ip_p);

    if (ip->ip_p == IPPROTO_TCP) {
        fprintf(f, "(TCP)\n");
        parse_tcp_packet(f, packet, ip_offset, ip_header_len, total_ip_len, packet_len);
    } else if (ip->ip_p == IPPROTO_UDP) {
        fprintf(f, "(UDP)\n");
        parse_udp_packet(f, packet, ip_offset, ip_header_len, total_ip_len, packet_len);
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    total_packets_captured++;
    current_packet_number++;

    sniffer_args_t *args = (sniffer_args_t *)user_data;
    FILE *output_file = args->text_output_file;

    pcap_dump((u_char *)args->pcap_dumper, header, packet);

    fprintf(output_file, "\n--- Packet Captured! (Packet #%d) ---\n", current_packet_number);
    fprintf(output_file, "Length: %d bytes\n", header->len);

    if (header->len < ETHER_HDR_LEN) {
        fprintf(output_file, "  [!] Packet too short for Ethernet header.\n");
        fflush(output_file);
        return;
    }
    struct eth_header *ethernet = (struct eth_header *)(packet);

    fprintf(output_file, "Ethernet Header:\n");
    print_mac(output_file, "\tSource MAC", ethernet->ether_shost);
    print_mac(output_file, "\tDestination MAC", ethernet->ether_dhost);

    u_char broadcast_mac[ETHER_ADDR_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    if (memcmp(ethernet->ether_dhost, broadcast_mac, ETHER_ADDR_LEN) == 0) {
        fprintf(output_file, "\t[+] Packet is BROADCAST Packet (ff:ff:ff:ff:ff:ff)\n");
        ethernet_broadcast_packets++;
    }

    u_short ether_type = ntohs(ethernet->ether_type);
    fprintf(output_file, "\tEtherType: 0x%04x ", ether_type);

    if (ether_type == ETHERTYPE_IP) {
        parse_ip_packet(output_file, packet, ETHER_HDR_LEN, header->len);
    } else {
        other_ether_packets++;
        fprintf(output_file, "(Other Ethernet Type: 0x%04x)\n", ether_type);
    }

    fflush(output_file);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_t *handle;
    pcap_dumper_t *pcap_dumper;
    FILE *text_output_file;
    sniffer_args_t args;

    char *selected_device_name = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }
    if (alldevs == NULL) {
        fprintf(stderr, "No network devices found. Exiting.\n");
        return 1;
    }

    selected_device_name = alldevs->name;
    printf("Sniffing on device: %s\n", selected_device_name);

    handle = pcap_open_live(selected_device_name, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", selected_device_name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    struct bpf_program fp;

    char filter_exp[] = "tcp or udp";
    bpf_u_int32 net = 0;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        pcap_freecode(&fp);
        return 1;
    }
    printf("Applied BPF filter: \"%s\"\n", filter_exp);

    pcap_dumper = pcap_dump_open(handle, "sample.pcap");
    if (pcap_dumper == NULL) {
        fprintf(stderr, "Error opening pcap dump file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        pcap_freecode(&fp);
        return 1;
    }
    printf("Saving raw packet data to sample.pcap...\n");

    text_output_file = fopen("parsed_data.txt", "w");
    if (text_output_file == NULL) {
        perror("Error opening text output file");
        pcap_dump_close(pcap_dumper);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        pcap_freecode(&fp);
        return 1;
    }
    printf("Saving parsed data to parsed_data.txt...\n");

    args.pcap_dumper = pcap_dumper;
    args.text_output_file = text_output_file;

    printf("Capturing 100 packets...\n");
    pcap_loop(handle, 100, packet_handler, (u_char *)&args);

    // --- Print Statistics Summary ---
    fprintf(text_output_file, "\n--- Capture Statistics --- \n");
    printf("\n--- Capture Statistics --- \n");
    fprintf(text_output_file, "Total Packets Captured: %d\n", total_packets_captured);
    printf("Total Packets Captured: %d\n", total_packets_captured);
    fprintf(text_output_file, "  Ethernet Broadcasts: %d\n", ethernet_broadcast_packets);
    printf("  Ethernet Broadcasts: %d\n", ethernet_broadcast_packets);
    fprintf(text_output_file, "  IP Packets: %d\n", ip_packets);
    printf("  IP Packets: %d\n", ip_packets);
    fprintf(text_output_file, "    TCP Packets: %d\n", tcp_packets);
    printf("    TCP Packets: %d\n", tcp_packets);
    fprintf(text_output_file, "    UDP Packets: %d\n", udp_packets);
    printf("    UDP Packets: %d\n", udp_packets);
    fprintf(text_output_file, "  Other Ethernet Types: %d\n", other_ether_packets);
    printf("  Other Ethernet Types: %d\n", other_ether_packets);

    pcap_dump_close(args.pcap_dumper);
    printf("Raw packet data saved to sample.pcap\n");

    fclose(args.text_output_file);
    printf("Parsed data saved to parsed_data.txt\n");

    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    printf("\nCapture finished.\n");
    return 0;
}
