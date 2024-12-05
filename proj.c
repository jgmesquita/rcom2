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
int enterPassiveMode(int controlSocket, char *ip, int *port) {
    char response[MAX_LENGTH];
    if (sendFTPCommand(controlSocket, "PASV\r\n", response) != SV_PASSIVE) return -1;

    int ip1, ip2, ip3, ip4, p1, p2;
    sscanf(response, PASSIVE_REGEX, &ip1, &ip2, &ip3, &ip4, &p1, &p2);
    sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
    *port = p1 * 256 + p2;

    return 0;
}

/**
 * Sends an FTP command and reads the server's response.
 */
int sendFTPCommand(int socket, const char *command, char *response) {
    if (command != NULL) {
        write(socket, command, strlen(command));
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
int readResponse(const int socket, char *buffer) {
    char byte;
    int index = 0, responseCode;
    enum { START, SINGLE, MULTIPLE, END } state = START;

    memset(buffer, 0, MAX_LENGTH);

    while (state != END) {
        if (read(socket, &byte, 1) <= 0) {
            perror("read()");
            exit(EXIT_FAILURE);
        }

        switch (state) {
            case START:
                if (byte == ' ') state = SINGLE;
                else if (byte == '-') state = MULTIPLE;
                else if (byte == '\n') state = END;
                else buffer[index++] = byte;
                break;
            case SINGLE:
                if (byte == '\n') state = END;
                else buffer[index++] = byte;
                break;
            case MULTIPLE:
                if (byte == '\n' && index >= 3 && 
                    strncmp(buffer, buffer + index - 3, 3) == 0) {
                    state = END;
                } else buffer[index++] = byte;
                break;
            case END:
                break;
        }
    }

    sscanf(buffer, "%d", &responseCode);
    return responseCode;
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
    if (enterPassiveMode(controlSocket, dataIP, &dataPort) != 0) {
        fprintf(stderr, "Failed to enter passive mode.\n");
        close(controlSocket);
        return EXIT_FAILURE;
    }
    printf("Entered passive mode. Data connection info - IP: %s, Port: %d\n", dataIP, dataPort);

    // Connect to the data connection
    int dataSocket = createSocket(dataIP, dataPort);
    if (dataSocket < 0) {
        fprintf(stderr, "Failed to establish data connection to %s:%d\n", dataIP, dataPort);
        close(controlSocket);
        return EXIT_FAILURE;
    }

    // Request the file from the server
    if (requestFile(controlSocket, url.resource) != SV_READY4TRANSFER) {
        fprintf(stderr, "Failed to request file '%s'.\n", url.resource);
        close(controlSocket);
        close(dataSocket);
        return EXIT_FAILURE;
    }
    printf("File request successful. Beginning download...\n");

    // Download the file
    if (downloadFile(controlSocket, dataSocket, url.file) != SV_TRANSFER_COMPLETE) {
        fprintf(stderr, "Error downloading file '%s'.\n", url.file);
        close(controlSocket);
        close(dataSocket);
        return EXIT_FAILURE;
    }
    printf("File '%s' downloaded successfully.\n", url.file);

    // Close connections
    if (closeFTPConnections(controlSocket, dataSocket) != 0) {
        fprintf(stderr, "Error closing connections.\n");
        return EXIT_FAILURE;
    }
    printf("Connections closed successfully.\n");

    return EXIT_SUCCESS;
}
