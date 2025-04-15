cmake_minimum_required(VERSION 3.10)
project(cs4220_project_server C)

set(CMAKE_C_STANDARD 99)

# OpenSSL setup (adjust these paths if not on macOS/Homebrew)
find_package(OpenSSL REQUIRED)

add_executable(server server.c)
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto)

add_executable(client client.c)
target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto)
