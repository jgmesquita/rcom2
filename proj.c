#include "proj.h"

/**
 * Parses the given FTP URL into its components.
 */
int parseURL(const char *input, URL *url) {
    regex_t regex;

    // Validate the URL starts with "ftp://"
    regcomp(&regex, BAR, 0);
    if (regexec(&regex, input, 0, NULL, 0)) return -1;

    // Parse authentication info
    regcomp(&regex, AT, 0);
    if (regexec(&regex, input, 0, NULL, 0) != 0) { // No user/password
        sscanf(input, HOST_REGEX, url->host, url->resource);
        strcpy(url->user, DEFAULT_USER);
        strcpy(url->password, DEFAULT_PASSWORD);
    } else { // With user/password
        sscanf(input, HOST_AT_REGEX, url->host, url->resource);
        sscanf(input, USER_REGEX, url->user);
        sscanf(input, PASS_REGEX, url->password);
    }

    // Extract the file name
    strcpy(url->file, strrchr(input, '/') + 1);

    // Resolve the host IP address
    struct hostent *h;
    if ((h = gethostbyname(url->host)) == NULL) return -1;
    strcpy(url->ip, inet_ntoa(*((struct in_addr *)h->h_addr)));

    return 0;
}

/**
 * Creates and connects a socket to the given IP and port.
 */
int createSocket(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in serverAddr = {0};

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(ip);
    serverAddr.sin_port = htons(port);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("connect()");
        return -1;
    }

    return sockfd;
}

/**
 * Authenticates the user using FTP USER and PASS commands.
 */
int authenticate(int controlSocket, const char *user, const char *password) {
    char command[MAX_LENGTH];
    char response[MAX_LENGTH];

    snprintf(command, sizeof(command), "USER %s\r\n", user);
    if (sendFTPCommand(controlSocket, command, response) != SV_READY4PASS) return -1;

    snprintf(command, sizeof(command), "PASS %s\r\n", password);
    return sendFTPCommand(controlSocket, command, response);
}

/**
 * Enters passive mode and retrieves the IP and port for the data connection.
 */
int enterPassiveMode(int controlSocket, char *ip, int *port, const char *controlIP) {
    char response[MAX_LENGTH];
    if (sendFTPCommand(controlSocket, "PASV\r\n", response) != SV_PASSIVE) {
        fprintf(stderr, "Failed to enter passive mode.\n");
        return -1;
    }

    // Print the PASV response
    printf("PASV response: %s\n", response);

    // Find the starting position of the numbers
    char *start = strchr(response, '(');
    char *end = strchr(response, ')');
    if (!start || !end || start > end) {
        fprintf(stderr, "Malformed PASV response.\n");
        return -1;
    }

    // Extract the string within parentheses
    char nums[100];
    strncpy(nums, start + 1, end - start - 1);
    nums[end - start - 1] = '\0';

    // Tokenize the numbers
    int h1, h2, h3, h4, p1, p2;
    if (sscanf(nums, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
        fprintf(stderr, "Could not parse PASV response numbers.\n");
        return -1;
    }

    // Build the IP address
    sprintf(ip, "%d.%d.%d.%d", h1, h2, h3, h4);

    // Calculate the port
    *port = (p1 << 8) | p2;

    // Debug output
    printf("Parsed IP: %s\n", ip);
    printf("Parsed port: %d\n", *port);

    // If IP is private, use control IP
    if (isPrivateIP(ip)) {
        printf("Using control connection IP instead of private PASV IP\n");
        strcpy(ip, controlIP);
    }

    return 0;
}

int isPrivateIP(const char *ip) {
    struct in_addr addr;
    if (inet_aton(ip, &addr) == 0) {
        return 0; // Invalid IP
    }

    uint32_t ip_addr = ntohl(addr.s_addr);

    // 10.0.0.0 - 10.255.255.255
    if ((ip_addr & 0xFF000000) == 0x0A000000) return 1;

    // 172.16.0.0 - 172.31.255.255
    if ((ip_addr & 0xFFF00000) == 0xAC100000) return 1;

    // 192.168.0.0 - 192.168.255.255
    if ((ip_addr & 0xFFFF0000) == 0xC0A80000) return 1;

    // 127.0.0.0 - 127.255.255.255 (Loopback)
    if ((ip_addr & 0xFF000000) == 0x7F000000) return 1;

    return 0;
}

/**
 * Sends an FTP command and reads the server's response.
 */
int sendFTPCommand(int socket, const char *command, char *response) {
    if (command != NULL) {
        if (write(socket, command, strlen(command)) < 0) {
            perror("write()");
            return -1;
        }
    }
    return readResponse(socket, response);
}

/**
 * Requests the specified resource (file) from the server.
 */
int requestFile(int controlSocket, const char *resource) {
    char command[MAX_LENGTH];
    snprintf(command, sizeof(command), "RETR %s\r\n", resource);
    return sendFTPCommand(controlSocket, command, NULL);
}

/**
 * Downloads the requested file from the data connection and saves it locally.
 */
int downloadFile(int controlSocket, int dataSocket, const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("fopen()");
        return -1;
    }

    char buffer[MAX_LENGTH];
    ssize_t bytes;
    while ((bytes = read(dataSocket, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, bytes, file);
    }

    fclose(file);
    return readResponse(controlSocket, buffer);
}

/**
 * Closes both control and data connections.
 */
int closeFTPConnections(int controlSocket, int dataSocket) {
    sendFTPCommand(controlSocket, "QUIT\r\n", NULL);
    return close(controlSocket) | close(dataSocket);
}

/**
 * Reads the server's response and extracts the response code.
 */
int readResponse(int sockfd, char *buffer) {
    char line[MAX_LENGTH];
    int code = 0;
    int multi_line = 0;

    if (buffer != NULL) {
        memset(buffer, 0, MAX_LENGTH);
    }

    while (1) {
        // Read a line
        int bytes = 0;
        char c;
        int index = 0;
        while (1) {
            if ((bytes = read(sockfd, &c, 1)) <= 0) {
                perror("read()");
                exit(EXIT_FAILURE);
            }
            if (c == '\r') continue;
            if (c == '\n') break;
            if (index < MAX_LENGTH - 1) {
                line[index++] = c;
            }
        }
        line[index] = '\0';

        // Append the line to buffer if buffer is not NULL
        if (buffer != NULL) {
            strncat(buffer, line, MAX_LENGTH - strlen(buffer) - 1);
            strncat(buffer, "\n", MAX_LENGTH - strlen(buffer) - 1);
        }

        // Parse the code
        int n;
        if (sscanf(line, "%d", &n) == 1) {
            if (code == 0) {
                code = n;
                // Check if it's a multi-line response
                if (strlen(line) >= 4 && line[3] == '-') {
                    multi_line = 1;
                } else {
                    break;
                }
            } else {
                // Check if multi-line response is ending
                if (multi_line && n == code && strlen(line) >= 4 && line[3] == ' ') {
                    break;
                }
            }
        }

        if (!multi_line) {
            // Single-line response; exit loop
            break;
        }
    }

    return code;
}

int main(int argc, char *argv[]) {
    // Validate the number of arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: ./download ftp://[<user>:<password>@]<host>/<url-path>\n");
        return EXIT_FAILURE;
    }

    // Parse the URL
    URL url = {0};
    if (parseURL(argv[1], &url) != 0) {
        fprintf(stderr, "Error parsing URL. Ensure it follows the correct format.\n");
        return EXIT_FAILURE;
    }

    // Display parsed information
    printf("Parsed URL Information:\n");
    printf("  Host: %s\n  Resource: %s\n  File: %s\n  User: %s\n  Password: %s\n  IP Address: %s\n\n",
           url.host, url.resource, url.file, url.user, url.password, url.ip);

    // Connect to the FTP server (control connection)
    int controlSocket = createSocket(url.ip, FTP_PORT);
    if (controlSocket < 0) {
        fprintf(stderr, "Failed to connect to FTP server at %s:%d\n", url.ip, FTP_PORT);
        return EXIT_FAILURE;
    }

    // Read and validate the server's initial response
    char response[MAX_LENGTH];
    if (readResponse(controlSocket, response) != SV_READY4AUTH) {
        fprintf(stderr, "Unexpected server response on connection: %s\n", response);
        close(controlSocket);
        return EXIT_FAILURE;
    }

    // Authenticate with the server
    if (authenticate(controlSocket, url.user, url.password) != SV_LOGINSUCCESS) {
        fprintf(stderr, "Authentication failed for user '%s'.\n", url.user);
        close(controlSocket);
        return EXIT_FAILURE;
    }
    printf("Authentication successful.\n");

    // Enter passive mode
    char dataIP[MAX_LENGTH];
    int dataPort;
    if (enterPassiveMode(controlSocket, dataIP, &dataPort, url.ip) != 0) {
        fprintf(stderr, "Failed to enter passive mode.\n");
        close(controlSocket);
        return EXIT_FAILURE;
    }
    printf("Entered passive mode. Data connection info - IP: %s, Port: %d\n", dataIP, dataPort);

    // Connect to the data connection
    int dataSocket = createSocket(dataIP, dataPort);
    printf("Data socket created: %d\n", dataSocket); // Debug statement
    if (dataSocket < 0) {
        fprintf(stderr, "Failed to establish data connection to %s:%d\n", dataIP, dataPort);
        close(controlSocket);
        return EXIT_FAILURE;
    }

    // Request the file from the server
    int requestResult = requestFile(controlSocket, url.resource);
    printf("File request result: %d\n", requestResult); // Debug statement
    if (requestResult != SV_READY4TRANSFER) {
        fprintf(stderr, "Failed to request file '%s'.\n", url.resource);
        close(controlSocket);
        close(dataSocket);
        return EXIT_FAILURE;
    }
    printf("File request successful. Beginning download...\n");

    // Download the file
    int downloadResult = downloadFile(controlSocket, dataSocket, url.file);
    printf("Download result: %d\n", downloadResult); // Debug statement
    if (downloadResult != SV_TRANSFER_COMPLETE) {
        fprintf(stderr, "Error downloading file '%s'.\n", url.file);
        close(controlSocket);
        close(dataSocket);
        return EXIT_FAILURE;
    }
    printf("File '%s' downloaded successfully.\n");
    // Close connections
    if (closeFTPConnections(controlSocket, dataSocket) != 0) {
        fprintf(stderr, "Error closing connections.\n");
        return EXIT_FAILURE;
    }
    printf("Connections closed successfully.\n");

    return EXIT_SUCCESS;
}
