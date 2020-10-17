#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>

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
        while (byte_count < payload_length) {
            if ( byte_count % 16 == 0 && byte_count) {
                putchar('\n');
            }
            printf("%02X ", *temp_pointer);
            ++temp_pointer;
            ++byte_count;
        }
        printf("\n");
    }

    return;
}

#define CREATE_HANDLE_ERROR 1
#define ACTIVATE_HANDLE_ERROR 2
#define PERROR_INET_NTOA 3
#define CONPILE_ERROR 4
#define SET_FILTER_ERROR 5
int ip_subnet_mask_print(bpf_u_int32 ip, bpf_u_int32 subnet_mask) {

    struct in_addr address;
    char ip_str[13];
    char subnet_mask_str[13];

    address.s_addr = ip;
    strcpy(ip_str, inet_ntoa(address));
    if (NULL == ip_str) {
        perror("inet_ntoa");
        return PERROR_INET_NTOA;
    }
    address.s_addr = subnet_mask;
    strcpy(subnet_mask_str, inet_ntoa(address));
    if (NULL == subnet_mask_str) {
        perror("inet_ntoa");
        return PERROR_INET_NTOA;
    }
    printf(
        "ip is %s, subnet mask is %s\n",
        ip_str, subnet_mask_str
    );
    return 0;
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
    case PCAP_ERROR_NOT_ACTIVATED:
        printf("the capture needs to be activated");
        break;
    case PCAP_ERROR_ACTIVATED:
        printf("the operation can't be performed on already activated captures");
        break;
    case PCAP_ERROR_NO_SUCH_DEVICE:
        printf("no such device exists");
        break;
    case PCAP_ERROR_RFMON_NOTSUP:
        printf("this device doesn't support rfmon (monitor) mode");
        break;
    case PCAP_ERROR_NOT_RFMON:
        printf("operation supported only in monitor mode");
        break;
    case PCAP_ERROR_PERM_DENIED:
        printf("no permission to open the device");
        break;
    case PCAP_ERROR_IFACE_NOT_UP:
        printf(" interface isn't up ");
        break;
    case PCAP_ERROR_CANTSET_TSTAMP_TYPE:
        printf("this device doesn't support setting the time stamp type");
        break;
    case PCAP_ERROR_PROMISC_PERM_DENIED:
        printf("you don't have permission to capture in promiscuous mode");
        break;
    case PCAP_ERROR_TSTAMP_PRECISION_NOTSUP:
        printf("the requested time stamp precision is not supported");
        break;
    case PCAP_WARNING:
        printf("generic warning");
        break;
    case PCAP_WARNING_PROMISC_NOTSUP:
        printf("this device doesn't support promiscuous mode");
        break;
    case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
        printf("the requested time stamp type is not supported");
        break;
    case 0:
        printf("handle activate success");
        break;
    default:
        break;
    }
    return activate_result;
}

int main(int argc, char **argv) {

    // dev name
    char *device = argv[1];
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_length = 1024;
    int total_packet_count = 20000;
    int inet_ntoa_result;
    int activate_result;
    u_char *my_arguments = NULL;

    struct bpf_program filter;
    char filter_exp[] = "tcp";

    bpf_u_int32 ip, subnet_mask; // bpf_u_int32 is integer type

    if (pcap_lookupnet(device, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", device);
        printf("error buffer is: %s\n", error_buffer);
        ip = 0;
        subnet_mask = 0;
    }
    inet_ntoa_result = ip_subnet_mask_print(ip, subnet_mask);
    if (PERROR_INET_NTOA == inet_ntoa_result) {
        printf("inet ntoa error\n");
        return PERROR_INET_NTOA;
    }

    // create handle
    handle = pcap_create(device, error_buffer);
    if (NULL == handle) {
        printf("pcap handler create error: %s\n", error_buffer);
        return CREATE_HANDLE_ERROR;
    }

    // activate handle
    activate_result = pcap_activate(handle);
    activate_error_process(activate_result);
    if (0 > activate_result) {
        printf("activate error occur\n");
        return ACTIVATE_HANDLE_ERROR;
    }

    // add filter of udp:1401
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == PCAP_ERROR) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return CONPILE_ERROR;
    }
    if (pcap_setfilter(handle, &filter) == PCAP_ERROR) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return SET_FILTER_ERROR;
    }

    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);

    return 0;
}
