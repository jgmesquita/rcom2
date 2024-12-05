#include "proj.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: ./proj ftp://[<user>:<password>@]<host>/<url-path>\n");
        return EXIT_FAILURE;
    }

    URL url = {0};
    if (parseURL(argv[1], &url) != 0) {
        fprintf(stderr, "Error parsing URL. Please check the format.\n");
        return EXIT_FAILURE;
    }

    printf("Parsed URL:\n");
    printf("  Host: %s\n  Resource: %s\n  File: %s\n  User: %s\n  Password: %s\n  IP Address: %s\n",
           url.host, url.resource, url.file, url.user, url.password, url.ip);

    char response[MAX_LENGTH];
    int controlSocket = createSocket(url.ip, FTP_PORT);
    if (sendFTPCommand(controlSocket, NULL, response) != SV_READY_AUTH) {
        fprintf(stderr, "Failed to connect to FTP server at %s:%d\n", url.ip, FTP_PORT);
        return EXIT_FAILURE;
    }

    if (authenticate(controlSocket, url.user, url.password) != SV_LOGINSUCCESS) {
        fprintf(stderr, "Authentication failed for user '%s'.\n", url.user);
        return EXIT_FAILURE;
    }

    char dataIP[MAX_LENGTH];
    int dataPort;
    if (enterPassiveMode(controlSocket, dataIP, &dataPort) != SV_PASSIVE) {
        fprintf(stderr, "Failed to enter passive mode.\n");
        return EXIT_FAILURE;
    }

    int dataSocket = createSocket(dataIP, dataPort);
    if (requestFile(controlSocket, url.resource) != SV_READY_TRANSFER) {
        fprintf(stderr, "Failed to request file '%s'.\n", url.resource);
        return EXIT_FAILURE;
    }

    if (downloadFile(controlSocket, dataSocket, url.file) != SV_TRANSFER_COMPLETE) {
        fprintf(stderr, "Error downloading file '%s'.\n", url.file);
        return EXIT_FAILURE;
    }

    if (closeFTPConnections(controlSocket, dataSocket) != 0) {
        fprintf(stderr, "Error closing connections.\n");
        return EXIT_FAILURE;
    }

    printf("File '%s' downloaded successfully.\n", url.file);
    return EXIT_SUCCESS;
}


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

int createSocket(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in serverAddr = {0};

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(ip);
    serverAddr.sin_port = htons(port);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) return -1;

    return sockfd;
}

int authenticate(int controlSocket, const char *user, const char *password) {
    char command[MAX_LENGTH];
    char response[MAX_LENGTH];

    snprintf(command, sizeof(command), "USER %s\r\n", user);
    if (sendFTPCommand(controlSocket, command, response) != SV_READY_PASS) return -1;

    snprintf(command, sizeof(command), "PASS %s\r\n", password);
    return sendFTPCommand(controlSocket, command, response);
}

int enterPassiveMode(int controlSocket, char *ip, int *port) {
    char response[MAX_LENGTH];
    if (sendFTPCommand(controlSocket, "PASV\r\n", response) != SV_PASSIVE) return -1;

    int ip1, ip2, ip3, ip4, p1, p2;
    sscanf(response, PASSIVE_REGEX, &ip1, &ip2, &ip3, &ip4, &p1, &p2);
    sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
    *port = p1 * 256 + p2;

    return 0;
}

int sendFTPCommand(int socket, const char *command, char *response) {
    if (command != NULL) write(socket, command, strlen(command));
    return readResponse(socket, response);
}

int requestFile(int controlSocket, const char *resource) {
    char command[MAX_LENGTH];
    snprintf(command, sizeof(command), "RETR %s\r\n", resource);
    return sendFTPCommand(controlSocket, command, NULL);
}

int downloadFile(int controlSocket, int dataSocket, const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) return -1;

    char buffer[MAX_LENGTH];
    ssize_t bytes;
    while ((bytes = read(dataSocket, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, bytes, file);
    }

    fclose(file);
    return readResponse(controlSocket, buffer);
}

int closeFTPConnections(int controlSocket, int dataSocket) {
    sendFTPCommand(controlSocket, "QUIT\r\n", NULL);
    return close(controlSocket) | close(dataSocket);
}
