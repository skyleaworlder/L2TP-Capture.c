#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>

/*
 *   |-------------------|
 *   |    Ethernet II    |   eth_header
 *   |-------------------|
 *   |       IPv4        |   ip_header
 *   |-------------------|
 *   |        UDP        |   udp_header
 *   |-------------------|
 *   |       L2TP        |
 *   |-------------------|
 *   |      Payload      |
 *   |-------------------|
 *
 *   in fact, payload still contain lots of protocol header,
 *   such as PPP, IPv4(toward other network), Layer 4 protocol: TCP/UDP,
 *   even Layer 8 protocol: HTTP.
 */
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
    const u_char *udp_header;
    const u_char *l2tp_header;
    const u_char *payload;

    const int ethernet_header_length = 14; // ethernet header length is always 14 bytes
    int ip_header_length;
    int udp_header_length;
    int l2tp_header_length;
    int payload_length;

    // ipv4
    ip_header = packet + ethernet_header_length;

    /*
     *   IPv4 4-7 bits are IHL(Internet Header Length)
     *   thus, (*ip_header) & 0x0F could store IHL.
     */
    ip_header_length = ((*ip_header) & 0x0F);
    /*
     *   The IPv4 header is variable in size due to the optional 14th field (options).
     *   The IHL field contains the size of the IPv4 header,
     *   it has 4 bits that specify the number of 32-bit words in the header.
     *   The minimum value for this field is 5,[28]
     *   which indicates a length of 5 × 32 bits = 160 bits = 20 bytes.
     *   As a 4-bit field, the maximum value is 15,
     *   this means that the maximum size of the IPv4 header is 15 × 32 bits,
     *   or 480 bits = 60 bytes.
     */
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    // udp
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_UDP) {
        printf("Not a UDP packet. Skipping...\n\n");
        return;
    }

    udp_header = packet + ethernet_header_length + ip_header_length;
    /*
     *   UDP header length is on the 4th and 5th bytes,
     *   so it needs to add two bytes result.
     *   There is udp_header_length(bytes)
     */
    udp_header_length = (((*(udp_header + 4)) & 0xFF) << 8) | (((*(udp_header + 5)) & 0xFF));
    printf("UDP header length in bytes: %d\n", udp_header_length);

    // l2tp
    l2tp_header = packet + ethernet_header_length + ip_header_length + udp_header_length;
    /*
     *    0                   1                   2                   3
     *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |           Tunnel ID           |           Session ID          |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |             Ns (opt)          |             Nr (opt)          |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |      Offset Size (opt)        |    Offset pad... (opt)        |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    int l2tp_type;
    int l2tp_len_field;
    int l2tp_sequence_field;
    int l2tp_offset_field;
    int l2tp_priority;
    int l2tp_version;

    // l2tp header 0 byte and 1 byte
    l2tp_type = ((*(l2tp_header)) & 0x80) >> 7;
    l2tp_len_field = ((*(l2tp_header)) & 0x40) >> 6;
    l2tp_sequence_field = ((*(l2tp_header)) & 0x08) >> 3;
    l2tp_offset_field = ((*(l2tp_header)) & 0x02) >> 1;
    l2tp_priority = (*(l2tp_header)) & 0x01;
    l2tp_version = (*(l2tp_header + 1)) & 0x0F;
    if (l2tp_version == 0x02)
        printf("Version: L2TP Ver.2\n");
    else {
        printf("L2TP Version error!\n");
        return;
    }
    if (l2tp_type)
        printf("Type: l2tp_type is: %d, L2TP carry control message.\n", l2tp_type);
    else
        printf("Type: l2tp_type is: %d, L2TP carry data message.\n", l2tp_type);
    if (l2tp_len_field)
        printf("Length: bit given %d.\n", l2tp_len_field);
    else
        printf("Length: not given, L is %d.\n", l2tp_len_field);
    if (l2tp_sequence_field)
        printf("Sequence: set to %d, Ns Nr present.\n", l2tp_sequence_field);
    else
        printf("Sequence: not given, S is %d.\n", l2tp_sequence_field);
    if (l2tp_offset_field)
        printf("Offset: set to %d, Offset size present.\n", l2tp_offset_field);
    else
        printf("Offset: not given, O is %d.\n", l2tp_offset_field);
    if (l2tp_priority)
        printf("Priority: set to %d.\n", l2tp_priority);
    else
        printf("Priority: not given, P is %d.\n", l2tp_priority);

    // l2tp header 2-3 byte
    int l2tp_total_length;
    int l2tp_total_length_bias;
    l2tp_total_length_bias = (l2tp_len_field) ? 2 : 0;
    if (l2tp_total_length_bias) {
        l2tp_total_length = (l2tp_len_field) ?
            (((*(l2tp_header + l2tp_total_length_bias)) & 0xFF) << 8) | ((*(l2tp_header + l2tp_total_length_bias + 1)) & 0xFF) : 0;
        printf("L2TP length: l2tp datagram total length is %d byte.\n", l2tp_total_length);
    }
    else
        printf("L2TP length: not set.\n");

    // l2tp header 4~7 byte
    int l2tp_tunnel_id, l2tp_session_id;
    int l2tp_tunnel_id_bias, l2tp_session_id_bias;
    l2tp_tunnel_id_bias = (l2tp_len_field) ? 4 : 2; // 4 or 2(without Length)
    l2tp_session_id_bias = l2tp_tunnel_id_bias + 2;
    l2tp_tunnel_id = (((*(l2tp_header + l2tp_tunnel_id_bias)) & 0xFF) << 8)
                    | ((*(l2tp_header + l2tp_tunnel_id_bias + 1)) & 0xFF);
    l2tp_session_id = (((*(l2tp_header + l2tp_session_id_bias)) & 0xFF) << 8)
                    | ((*(l2tp_header + l2tp_session_id_bias + 1)) & 0xFF);
    if (l2tp_tunnel_id == 0 || l2tp_session_id == 0) {
        printf("Tunnel id or Session id eq 0.");
        return;
    }
    else {
        printf("Tunnel Id: %d\n", l2tp_tunnel_id);
        printf("Session Id: %d\n", l2tp_session_id);
    }

    // l2tp header 8-9 & 10-11 byte
    int l2tp_Ns, l2tp_Nr;
    int l2tp_Ns_bias, l2tp_Nr_bias;
    l2tp_Ns_bias = (l2tp_sequence_field) ?
                    ((l2tp_len_field) ? 8 : 6) : 0;
    l2tp_Nr_bias = (l2tp_sequence_field) ? l2tp_Ns_bias + 2 : 0;
    if (l2tp_Ns_bias || l2tp_Nr_bias) {
        l2tp_Ns = (((*(l2tp_header + l2tp_Ns_bias)) & 0xFF) << 8)
                | ((*(l2tp_header + l2tp_Ns_bias + 1)) & 0xFF);
        l2tp_Nr = (((*(l2tp_header + l2tp_Nr_bias)) & 0xFF) << 8)
                | ((*(l2tp_header + l2tp_Nr_bias + 1)) &0xFF);
        printf("Ns(next sequence number): %d.\n", l2tp_Ns);
        printf("Nr(next control message received): %d.\n", l2tp_Nr);
    }
    else
        printf("Ns and Nr not present.\n");

    // l2tp header 12-13
    int l2tp_offset;
    int l2tp_offset_bias;
    l2tp_offset_bias = (l2tp_offset_field) ? (
        l2tp_len_field ? (l2tp_sequence_field ? 12 : 8) : (l2tp_sequence_field ? 10 : 6)
    ) : 0;
    l2tp_offset = (((*(l2tp_header + l2tp_offset_bias)) & 0xFF) << 8)
            | ((*(l2tp_header + l2tp_offset_bias + 1)) & 0xFF);
    if (l2tp_offset_bias)
        printf("Offset size(octets past L2TP header): %d.\n", l2tp_offset);
    else
        printf("Offset size not present.\n");

    l2tp_header_length = 1 + l2tp_len_field * 2 + 4 + l2tp_sequence_field * 4 + l2tp_offset_field * 2;
    printf("L2TP header length: %d\n", l2tp_header_length);

    int total_headers_size = ethernet_header_length + ip_header_length + udp_header_length + l2tp_header_length;
    printf("size of header caplen: %d bytes\n", header->caplen);
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + udp_header_length + l2tp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

    /* Print payload in ASCII */
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        u_char temp_array[16] = { 0 };
        int byte_count = 0;
        while (byte_count < payload_length) {
            if ( byte_count % 16 == 0 && byte_count) {
                printf(" |        ");
                unsigned int index;
                for (index = 0; index < 16; ++index) {
                    printf("%c", temp_array[index]);
                    temp_array[index] = 0;  // erase
                }
                putchar('\n');
            }
            printf("%02X ", *temp_pointer);
            temp_array[byte_count % 16] = *temp_pointer;
            ++temp_pointer;
            ++byte_count;
        }
        printf("\n");
    }

    printf("\n\n");
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
    // L2TP over udp port 1701
    char filter_exp[] = "udp port 1701";

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

    // add filter of udp:1701
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