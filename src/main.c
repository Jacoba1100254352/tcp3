#include "tcp_client.h"
#include "log.h"
#include <ctype.h>

int verbose_flag = 0;  // Global flag for verbosity

// Global counters for tracking communication
static size_t messages_sent = 0;
static size_t messages_received = 0;

// Function to print usage instructions
static void printHelpOption(char *argv[]) {
    fprintf(stderr, "Usage: %s [--help] [-v] [-h HOST] [-p PORT] FILE\n"
                    "Arguments:\n  FILE: File with actions & messages for server (stdin with '-')\n"
                    "Options: --help, -v/--verbose, --host/-h HOSTNAME, --port/-p PORT\n", argv[0]);
}

// Handler for server responses
static int handle_response(char *response) {
    log_trace("%s", response);
    messages_received++;
    return EXIT_SUCCESS;  // Return success as receiving a response is the expected behavior
}

int main(int argc, char *argv[]) {
    Config config = {
            .host = TCP_CLIENT_DEFAULT_HOST,
            .port = TCP_CLIENT_DEFAULT_PORT
    };

    // Parse command-line arguments
    if (tcp_client_parse_arguments(argc, argv, &config)) {
        printHelpOption(argv);
        log_error("Error");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    int sockfd = tcp_client_connect(config);
    if (sockfd == TCP_CLIENT_BAD_SOCKET) {
        log_warn("Unable to connect to server.");
        exit(EXIT_FAILURE);
    }

    if (verbose_flag)
        log_info("Connected to %s:%s", config.host, config.port);

    // Open the input file or use stdin
    FILE *fp = (strcmp(config.file, "-") == 0) ? stdin : tcp_client_open_file(config.file);
    if (!fp) {
        log_error("Error opening file.");
        tcp_client_close(sockfd);
        return EXIT_FAILURE;
    }

    // Read lines from file and send to server
    char *action = NULL, *message = NULL;
    while (tcp_client_get_line(fp, &action, &message) == EXIT_SUCCESS) {
        if (tcp_client_send_request(sockfd, action, message) != EXIT_SUCCESS) {
            // Cleanup on error
            free(action);
            free(message);
            if (fp != stdin) tcp_client_close_file(fp);
            tcp_client_close(sockfd);
            log_error("Error");
            return EXIT_FAILURE;
        }
        messages_sent++;

        free(action);
        free(message);
    }

    if (verbose_flag)
        log_info("Messages sent: %zu.", messages_sent);

    if (fp != stdin)
        tcp_client_close_file(fp);

    // Only attempt to receive if we sent messages
    if (messages_sent > 0) {
        while (messages_received < messages_sent) {
            if (tcp_client_receive_response(sockfd, handle_response) != EXIT_SUCCESS) {
                tcp_client_close(sockfd);
                log_error("Error");
                exit(EXIT_FAILURE);
            }
            if (verbose_flag)
                log_debug("Messages received = %d, Messages sent = %d", messages_received, messages_sent);
        }
    }

    if (verbose_flag)
        log_info("Messages sent: %zu, messages received: %zu.", messages_sent, messages_received);

    int exitCode = (tcp_client_close(sockfd) != EXIT_SUCCESS) ? EXIT_FAILURE : EXIT_SUCCESS;
    if (verbose_flag)
        log_debug("Exit code = %d", exitCode);
    exit(exitCode);
}
