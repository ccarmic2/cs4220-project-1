# CS 4220 Project 1

#### Created by Connor Carmichael, Caroline Duncan, and Christopher Romo

#### CS 4220 Computer Networks : Spring 2025

## Project Overview

We are creating a simple secure client and a simple secure server that accepts packets using OpenSSL. We are doing this to learn more about Transport Layer Security, how to create and utilize certificates, and learn about TLS integration in network applications.

## Project Statement

We have neither given nor received unauthorized assistance on this work.

## Client - Connor Carmichael

Client Overview:
 - Client can be compiled with the steps below.
 - Runs over secure TLS connection on port 8443.
    - Uses client cert and key and verifies with TLS handshake.
 - Sends generic GET HTTP request.
 - Command structure:
    - client \<server-ip\>
    - ex. client 127.0.0.1 
 - Client certs and keys generated with the following command:
    
    ```bash
    openssl req -x509 -newkey rsa:2048 -keyout client.key -out client.crt -days 365 -nodes
    ```

## Server - Caroline Duncan

Server Overview:

- OpenSSL Initialization: initialize_openssl() sets up the OpenSSL library by loading SSL/TLS algorithms, error strings, and cryptographic algorithms.

- SSL Context Creation: create_ssl_context() creates and configures an SSL context using TLS_server_method(). It sets the minimum supported TLS version to TLS 1.2, configures the context to verify client certificates, and loads the server's certificate and private key from PEM files. 

- TCP Socket Setup: A TCP socket is created using the socket() system call and bound to a specified port and address.    

- SSL/TLS Handshake: Once a client connects, the server initiates an SSL/TLS handshake by creating a new SSL object and associating it with the client’s file descriptor.

- Client Handling: After the handshake, the server reads the client’s request and responds with a simple HTTP response.


## HMAC & README - Christopher Romo

HMAC & README Overview:

HMAC was implemented using C's OpenSSL Library in order to securely transfer data between the Client and the Server. SHA256 was used for this project to hash the messages.

- First, a project timeline was created for all members to keep track of the project's progress. Outline can be found in Project One Update assignment.

- Test file `hmac_sha256.c` was created to test hashing a message with a key.

- Running the file will prompt the user for a message via the console, it will then hash the message with a predetermined key, and then the result is returned via the console.

- These systems were then brought over to both the Client and the Server to ensure messages are secure and aren't tampered with.

- `CMakeLists.txt` was created in order to smoothly run the client and the server. Steps for running this file are below.

- Server now outputs a message about the verification of HMAC. The Client now generates HMAC and SHA256 hash, and the server compares the incoming request to it's own variables to verify.

- Code has been refactored across the entire project.

- Completed `README.md` with steps to install the project, steps to run the project, a changelog, the required statement, and general info included.

## Project Installation

1. Be sure the project is extracted.

2. In the project folder, open a WSL (Bash) terminal.

3. Run the following:
    ```bash
    sudo apt update
    sudo apt install cmake build-essential libssl-dev
    ```
   
## Running the Project

1. In the project directory, open a WSL (Bash) terminal.

2. Run the following:
    ```bash
    cmake -S . -B build
    cmake --build build
    ./build/server
    ```

3. In a different WSL (Bash) terminal, run the following:
    ```bash
    ./build/client 127.0.0.1
    ```

## Project Changelog

Listed below are all changes made to the project based on week.

## Week 1 (03/09/2025 - 03/15/2025)

Connor: Started work on client. Using port 80 to test.\
Caroline: Created plan for server, started implementing.\
Christopher: Set up the README and project schedule.


## Week 2 (03/16/2025 - 03/22/2025)

Connor: Finished working client and add TLS support.\
Caroline: Worked on server.\
Christopher: Created a simple 'c' file that encrypts a message using HMAC & SHA256.

## Week 3 (03/30/2025 - 04/05/2025)

Connor: Made sure that client and server communicate on same port and MTLS works.\
Caroline: Finished server, debugging.\
Christopher: Researched HMAC & began implementation.

## Week 4 (04/06/2025 - 04/12/2025)

Connor: Certificates & final testing.\
Caroline: Debugging finished.\
Christopher: Finished HMAC/SHA256 implementation, README, CMakeLists.txt, and refactored.

## Week 5 (04/13/2025 - 04/17/2025)

All: Finished up loose bits & turned in assignment.

---
