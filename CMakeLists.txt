cmake_minimum_required(VERSION 3.30)
project(PasswordGenerator VERSION 1.2.0 LANGUAGES CXX)

find_package(OpenSSL 3.3 REQUIRED COMPONENTS Crypto)

add_executable(passwdgen src/main.cpp)
target_link_libraries(passwdgen OpenSSL::Crypto)