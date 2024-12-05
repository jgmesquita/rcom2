#ifndef PROJ_H
#define PROJ_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <regex.h>
#include <netdb.h>

// FTP and Network Constants
#define FTP_PORT 21
#define MAX_LENGTH 1024
#define DEFAULT_USER "anonymous"
#define DEFAULT_PASSWORD "anonymous@"

// Regular Expressions for Parsing
#define BAR "^ftp://"
#define AT "@"
#define HOST_REGEX "ftp://%[^/]/%s"
#define HOST_AT_REGEX "ftp://%*[^@]@%[^/]/%s"
#define USER_REGEX "ftp://%[^:]:%*[^@]@%*[^/]"
#define PASS_REGEX "ftp://%*[^:]:%[^@]@%*[^/]"
#define RESOURCE_REGEX "ftp://%*[^/]/%s"
#define RESPCODE_REGEX "^[0-9]+"
#define PASSIVE_REGEX ".*\\(([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)\\)"

// FTP Response Codes
enum FTPResponse {
    SV_READY4PASS = 331,
    SV_READY4AUTH = 220,
    SV_LOGINSUCCESS = 230,
    SV_PASSIVE = 227,
    SV_READY4TRANSFER = 150,
    SV_TRANSFER_COMPLETE = 226,
    SV_GOODBYE = 221
};

// URL Structure
typedef struct {
    char host[MAX_LENGTH];
    char user[MAX_LENGTH];
    char password[MAX_LENGTH];
    char resource[MAX_LENGTH];
    char file[MAX_LENGTH];
    char ip[MAX_LENGTH];
} URL;

// Function Declarations
int parseURL(const char *input, URL *url);
int createSocket(const char *ip, int port);
int authenticate(int controlSocket, const char *user, const char *password);
int enterPassiveMode(int controlSocket, char *ip, int *port, const char *controlIP);
int isPrivateIP(const char *ip);
int sendFTPCommand(int socket, const char *command, char *response);
int requestFile(int controlSocket, const char *resource);
int downloadFile(int controlSocket, int dataSocket, const char *filename);
int closeFTPConnections(int controlSocket, int dataSocket);
int readResponse(const int socket, char *buffer);

#endif 