/*
Connor Carmichael
CS 4220 Computer Networks
HTTPS client in C
*/

// takes server, and filename on server

// libraries
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
#include <openssl/hmac.h>
#include <openssl/evp.h>

// constants
// #define SERVER_PORT 80       // client and server must agree on port number
#define SERVER_PORT 8443        // client and server must agree on port number
#define BUF_SIZE 4096           // block transfer size (used for file transfer)
#define KEY "super secret key."

// function prototypes
void initialize_openssl();
SSL_CTX *create_ssl_context();
void fatal(const char *string);

int main(int argc, char **argv)
{
    // initialize variables
    int c, s, bytes;
    char buf[BUF_SIZE];                 // buffer for incoming file
    struct sockaddr_in channel;         // holds IP address
    char *request = "GET /\r\n\r\n";

    // create socket
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // create socket
    if (s < 0)
        fatal("Socket failed.");
    printf("Created socket.\n");

    // set ip address and port
    memset(&channel, 0, sizeof(channel));
    channel.sin_family = AF_INET;
    channel.sin_port = htons(SERVER_PORT);

    if (argc != 2)
        fatal("Usage: client server-ip");

    // convert ip address to machine readable bytes
    if (inet_pton(AF_INET, argv[1], &channel.sin_addr.s_addr) <= 0)
        fatal("Could not convert address.");
    printf("Got channel.\n");

    c = connect(s, (struct sockaddr *)&channel, sizeof(channel)); // establish tcp connection with server
    if (c < 0)
        fatal("Connect failed.");
    printf("Connected.\n");

    // establish TLS connection
    initialize_openssl();
    SSL_CTX *ctx = create_ssl_context();
    SSL *ssl = SSL_new(ctx);    // SSL structure needed for a connection
    SSL_set_fd(ssl, s);         // pass the socket(file descriptor) to SSL structure

    if (SSL_connect(ssl) <= 0)
        fatal("TLS handshake not successful."); // initiates TLS handshake
    printf("Handshake was successful!\n");

    // check cert after handshake (MTLS)
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Server certificate subject: %s\n", line);
        OPENSSL_free(line);
        X509_free(cert);
    }
    else
    {
        fatal("No certificate presented by the server.");
    }

    // from hmax_sha256.c

    // hmac output variables
	unsigned char output[EVP_MAX_MD_SIZE];
	unsigned int output_len;

	// generate hashed message using HMAC
	unsigned char *hmac_output = HMAC(EVP_sha256(), KEY, strlen(KEY), (unsigned char *)request, strlen(request), output, &output_len);

    // connection is now established; send request
    SSL_write(ssl, request, strlen(request));       // write to the socket the file name
    SSL_write(ssl, output, output_len);             // send hmac output to server
    printf("Sending request...\n");

    // go get the file and write it to stdout
    printf("Request receiving...\n");
    memset(buf, 0, BUF_SIZE);                       // zero out receive buffer each loop
    bytes = SSL_read(ssl, buf, (BUF_SIZE - 1));     // read from socket
    printf("%s\n", buf);                            // write to stdout
    printf("Request received!\n");
}

void initialize_openssl()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_ssl_context()
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx)
        fatal("SSL_CTX creation failed.");      // create ctx object that holds config data for TLS

    // load cert and key
    if (SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM) <= 0)
        fatal("Failed to load client certificate.");
    if (SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0)
    {
        fatal("Failed to load client private key.");
    }

    // trust certs from the server
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    if (!SSL_CTX_load_verify_locations(ctx, "server.crt", NULL))
    {
        fatal("Failed to load CA certificate.");
    }

    return ctx;
}

void fatal(const char *string)
{
    printf("%s\n", string);
    exit(1);
}