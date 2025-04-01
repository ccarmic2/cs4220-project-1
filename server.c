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

#define PORT 4433
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

// Function prototypes
void initialize_openssl();
SSL_CTX* create_ssl_context();
void handle_client(SSL *ssl);
void fatal(const char *msg);

int main() {
     initialize_openssl();  // Initialize OpenSSL library
    SSL_CTX *ctx = create_ssl_context();  // Create and configure SSL context

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fatal("socket creation failed");
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fatal("bind failed");
    }

    if (listen(server_fd, 10) < 0) {
        fatal("listen failed");
    }
    printf("secure HTTP server running on port %d\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &len);
        if (client_fd < 0) {
            perror("failed");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            handle_client(ssl);
        }

        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

void initialize_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_ssl_context() {
   SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fatal("error- create SSL context");
    }
    
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        fatal("failed to load certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        fatal("failed to load key");
    }

    return ctx;
}

void handle_client(SSL *ssl) {
    char buffer[1024] = {0};
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    
    if (bytes > 0) {
        printf("received:\n%s\n", buffer);
        
        // Send HTTP response
        const char *response = "HTTP......";
        SSL_write(ssl, response, strlen(response));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void fatal(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

