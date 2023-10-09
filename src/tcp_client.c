#include "tcp_client.h"
#include "log.h"
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>

#define NUM_VALID_ACTIONS 5

extern int verbose_flag;  // External reference to the global verbose flag declared in main.c

static void printHelpOption(char *argv[]) {
    fprintf(stderr, "Usage: %s [--help] [-v] [-h HOST] [-p PORT] ACTION MESSAGE\n"
                    "\nArguments:\n"
                    "  ACTION   Must be uppercase, lowercase, reverse,\n"
                    "           shuffle, or random.\n"
                    "  MESSAGE  Message to send to the server\n"
                    "\nOptions:\n"
                    "\t--help\n"
                    "\t-v, --verbose\n"
                    "\t--host HOSTNAME, -h HOSTNAME\n"
                    "\t--port PORT, -p PORT\n", argv[0]);
}

// Parses the commandline arguments and options given to the program.
int tcp_client_parse_arguments(int argc, char *argv[], Config *config) {
    int opt;
    static struct option long_options[] = {
            {"help",    no_argument,       0, 0},
            {"host",    required_argument, 0, 'h'},
            {"port",    required_argument, 0, 'p'},
            {"verbose", no_argument,       0, 'v'},
            {0, 0,                         0, 0}
    };

    int long_index = 0;
    while ((opt = getopt_long(argc, argv, "h:p:v", long_options, &long_index)) != -1) {
        switch (opt) {
            case 0: // --help
                printHelpOption(argv);
                exit(EXIT_SUCCESS);
            case 'h':  // Host
                config->host = optarg;
                break;
            case 'p':  // Port
            {
                long port;
                char *endptr;
                port = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || port <= 0 || port > 65535) {
                    log_error("Invalid port number.");
                    return EXIT_FAILURE;
                }
                config->port = optarg;
                break;
                case 'v':  // Verbosity
                    verbose_flag = 1;
                break;
                default:
                    log_error("Invalid argument.");
                return EXIT_FAILURE;
            }
        }
    }

    if (optind < argc) config->file = argv[optind++];
    if (!config->file) {
        log_error("File argument missing.");
        return EXIT_FAILURE;
    }

    if (verbose_flag)
        log_info("Arguments parced");

    return EXIT_SUCCESS;
}


// Creates a TCP socket and connects it to the specified host and port.
int tcp_client_connect(Config config) {
    int sockfd;
    struct sockaddr_in server_address;
    struct hostent *server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error("Socket creation failed.");
        return TCP_CLIENT_BAD_SOCKET;
    }

    server = gethostbyname(config.host);
    if (!server) {
        log_error("Host not found.");
        return TCP_CLIENT_BAD_SOCKET;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    memcpy(&server_address.sin_addr.s_addr, server->h_addr, server->h_length);
    server_address.sin_port = htons((uint16_t) strtol(config.port, NULL, 10));

    if (connect(sockfd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        log_error("Connection failed.");
        return TCP_CLIENT_BAD_SOCKET;
    }

    if (verbose_flag)
        log_info("Socket connected");

    return sockfd;
}

// Helper function to convert action to its binary representation
static uint32_t action_to_binary(char *action) {
    if (strcmp(action, "uppercase") == 0) return 0x01;
    if (strcmp(action, "lowercase") == 0) return 0x02;
    if (strcmp(action, "reverse") == 0) return 0x04;
    if (strcmp(action, "shuffle") == 0) return 0x08;
    if (strcmp(action, "random") == 0) return 0x10;
    return 0;  // Default case (should not happen)
}

// Creates and sends a request to the server using the socket and configuration.
int tcp_client_send_request(int sockfd, char *action, char *message) {
    // Convert the action to its binary representation
    uint32_t binary_action = action_to_binary(action);

    // Calculate the message length
    uint32_t message_length = strlen(message);

    // Create the request header
    uint32_t header = (binary_action << 27) | message_length;

    // Convert the header to big-endian format
    uint32_t header_big_endian = htonl(header);

    // Send the header
    if (send(sockfd, &header_big_endian, sizeof(header_big_endian), 0) == -1) {
        log_error("Header send failed.");
        return EXIT_FAILURE;
    }

    // Send the message
    if (send(sockfd, message, message_length, 0) == -1) {
        log_error("Message send failed.");
        return EXIT_FAILURE;
    }

    if (verbose_flag)
        log_info("Request sent");

    return EXIT_SUCCESS;
}



// Receives the response from the server. The caller must provide a callback function to handle the response.
int tcp_client_receive_response(int sockfd, int (*handle_response)(char *)) {
    uint32_t header_big_endian;
    uint32_t message_length;

    // Receive the header
    if (recv(sockfd, &header_big_endian, sizeof(header_big_endian), 0) != sizeof(header_big_endian)) {
        log_error("Header receive failed.");
        return EXIT_FAILURE;
    }

    // Convert the header from big-endian format
    message_length = ntohl(header_big_endian);

    // Allocate buffer to store the message
    char *buffer = malloc(message_length + 1);  // +1 for null-terminator
    if (!buffer) {
        log_error("Memory allocation failed.");
        return EXIT_FAILURE;
    }

    // Receive the message
    size_t received = 0;
    while (received < message_length) {
        int bytes = recv(sockfd, buffer + received, message_length - received, 0);
        if (bytes <= 0) {
            free(buffer);
            log_error("Message receive failed.");
            return EXIT_FAILURE;
        }
        received += bytes;
    }
    buffer[message_length] = '\0';  // Null-terminate the received message

    // Handle the received message
    int result = handle_response(buffer);

    free(buffer);

    return result;
}


// Close the socket
int tcp_client_close(int sockfd) {
    if (close(sockfd) < 0) {
        log_error("Socket closure failed.");
        return EXIT_FAILURE;
    }

    if (verbose_flag)
        log_info("Socket closed");

    return EXIT_SUCCESS;
}

// Opens a file.
FILE *tcp_client_open_file(char *file_name) {
    FILE *fileData = fopen(file_name, "r");
    if (!fileData)
        log_error("File opening failed.");

    if (verbose_flag)
        log_info("File opened");

    return fileData;
}

// Check if the provided action is valid
static int is_valid_action(const char *action) {
    static const char *validActions[NUM_VALID_ACTIONS] = {
            "uppercase", "lowercase", "reverse", "shuffle", "random"
    };

    for (int i = 0; i < NUM_VALID_ACTIONS; i++)
        if (strcmp(action, validActions[i]) == 0)
            return EXIT_SUCCESS;

    return EXIT_FAILURE;
}

// Gets the next line of a file, filling in action and message.
int tcp_client_get_line(FILE *fd, char **action, char **message) {
    if (fd == NULL || action == NULL || message == NULL)
        return EXIT_FAILURE;

    char *stringLine = NULL;
    size_t readIn = 0;  // Set to 0 for getline to allocate memory as required.
    ssize_t charCount = getline(&stringLine, &readIn, fd);

    if (charCount == -1) {
        if (verbose_flag)
            log_warn("No line was read from file, program likely reached the end of the file.");
        free(stringLine); // Safe to call even if getline failed
        return EXIT_FAILURE;
    }

    // Remove newline character if present
    if (charCount > 0)
        stringLine[charCount - 1] = '\0';

    log_trace("String read from the file is: %s", stringLine);

    // Use a temporary buffer to parse the action and message
    char temp_action[100]; // Assuming an action name will not exceed 100 characters.
    char *temp_message = malloc(charCount * sizeof(char));
    if (!temp_message) {
        free(stringLine);
        return EXIT_FAILURE;
    }

    int read = sscanf(stringLine, "%99s %[^\n]", temp_action, temp_message);

    // Transfer pointers to caller
    *action = strdup(temp_action);
    *message = strdup(temp_message);

    free(temp_message);
    free(stringLine);

    if (read != 2 || is_valid_action(*action) == EXIT_FAILURE) {
        log_error("Invalid Action or message format provided.");
        free(*action);
        free(*message);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


// Close a file
int tcp_client_close_file(FILE *fd) {
    if (fclose(fd) == EOF) {
        log_error("File closure failed.");
        return EXIT_FAILURE;
    }

    if (verbose_flag)
        log_info("File Closed");

    return EXIT_SUCCESS;
}
