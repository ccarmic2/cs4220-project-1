//takes server, and filename on server
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>

//#define SERVER_PORT 80                                                //client and server must agree on port number
#define SERVER_PORT 443                                                 //client and server must agree on port number
#define BUF_SIZE 4096                                                   //block transfer size (used for file transfer)

void fatal(const char *string);

int main(int argc, char **argv){
    int c, s, bytes;
    char buf[BUF_SIZE];                                                 //buffer for incoming file
    struct sockaddr_in channel;                                         //holds IP address
    char* request = "GET /\r\n\r\n";

    //create socket
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);                      //create socket
    if (s < 0) fatal("socket failed");                             
    printf("created socket\n");

    //set ip adress and port
    memset(&channel, 0, sizeof(channel));
    channel.sin_family = AF_INET;
    channel.sin_port = htons(SERVER_PORT);
    if (argc != 2) fatal("Usage: client server-ip");
    //convert ip address to machine readable bytes    
    if (inet_pton(AF_INET, argv[1], &channel.sin_addr.s_addr) <= 0) fatal("could not convert address");
    printf("got channel\n");

    c = connect(s, (struct sockaddr *) &channel, sizeof(channel));      //establish tcp connection with server
    if (c < 0) fatal("connect failed");
    printf("connected\n");

    //establish tls connection
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());                           //create ctx object that holds config data for TLS
    SSL* ssl = SSL_new(ctx);                                            //SSL structure needed for a connection
    SSL_set_fd(ssl, s);                                                 //Pass the socket(file descriptor) to SSL structure
    if (SSL_connect(ssl) <= 0) fatal("tls handshake not successful");   //initiates TLS handshake
    printf("Handshake was successful\n");

    //Connection is now established; Send request
    SSL_write(ssl, request, strlen(request));                           //write to the socket the file name
    printf("sending request \n");


    //Go get the file and write it to stdout
    printf("request reciving \n");
    memset(buf, 0, BUF_SIZE);                                           //zero out recive buffer each loop
    bytes = SSL_read(ssl, buf, (BUF_SIZE-1));                           //read from socket
    //if (bytes <= 0) exit(0);                                            //check for end of file
    printf("%s\n", buf);                                                //write to stdout
    printf("request recived\n");
}

void fatal(const char *string){
    printf("%s\n", string);
    exit(1);
}