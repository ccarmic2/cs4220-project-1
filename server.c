/*
Caroline Duncan
3/23/25
CS 4220 Server
HTTPS server in C

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT 8443  //can be changed
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

void initialize_openssl();
SSL_CTX* create_ssl_context();
void handle_client(SSL *ssl);

int main() {
    initialize_openssl();  //initialize OpenSSL library and algorithms
    SSL_CTX *ctx = create_ssl_context();  //create and configure SSL context (TLS settings, certs, keys)

    //create TCP socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;               //IPv4
    addr.sin_port = htons(SERVER_PORT);      //set port (convert to network byte order)
    addr.sin_addr.s_addr = INADDR_ANY;       //accept connections on any local IP

    //bind socket to IP and port
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    //listening for connections
    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Secure HTTP server running on port %d\n", SERVER_PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);

        //accept client connection
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &len);
        if (client_fd < 0) {
            perror("Client accept failed");
        } else {
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);

            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
            } else {
                handle_client(ssl);  //handle HTTP request/response with SSL
            }

            close(client_fd);
        }
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

//initialize the OpenSSL library
void initialize_openssl() {
    SSL_library_init();            //load SSL/TLS algorithms
    SSL_load_error_strings();      //load human-readable error strings
    OpenSSL_add_ssl_algorithms();  //load cryptographic algorithms
}

//create and configure an SSL context
SSL_CTX* create_ssl_context() {
    //create new SSL context (using TLS server method)
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //set minimum supported TLS version to TLS 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    //load server certificate
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //load the private key
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load CA cert (or client.crt if self-signed)
    if (!SSL_CTX_load_verify_locations(ctx, "client.crt", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

//handle client communication over SSL
void handle_client(SSL *ssl) {
    char buffer[1024] = {0};

    //read request from client
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);

    if (bytes > 0) {
        printf("Received:\n%s\n", buffer);

        //prepare and send simple HTTP response
        const char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, Secure World!";
        SSL_write(ssl, response, strlen(response));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}
