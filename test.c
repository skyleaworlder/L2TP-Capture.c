#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    const int ethernet_header_length = 14; // ethernet header length is always 14
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    // tcp
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

    /* Print payload in ASCII */
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }

    return;
}

int activate_error_process(int activate_result) {
    switch (activate_result)
    {
    case PCAP_ERROR:
        printf("generic error code");
        break;
    case PCAP_ERROR_BREAK:
        printf("loqp terminated by pcap_breakloop");
        break;
    case PCAP_ERROR_
    default:
        break;
    }
}

int main(int argc, char **argv) {

    // dev name
    char *device = "eth0";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_length = 1024;
    int total_packet_count = 200;
    int activate_result;
    u_char *my_arguments = NULL;

    struct bpf_program filter;
    char filter_exp[] = "udp and port 1401";
    bpf_u_int32 subnet_mask, ip;

    if (pcap_lookupnet(device, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", device);
        ip = 0;
        subnet_mask = 0;
    }

    // create handle
    handle = pcap_create(device, error_buffer);
    if (NULL == handle) {
        printf("pcap handler create error: %s\n", error_buffer);
        return 2;
    }

    // activate handle
    activate_result = pcap_activate(handle);
    

    // add filter of udp:1401
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);

    return 0;
}