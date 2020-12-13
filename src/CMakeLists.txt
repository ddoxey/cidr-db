cmake_minimum_required(VERSION 3.16.3)

set(CMAKE_CXX_COMPILER "/usr/bin/g++")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(cidrdb)

set(EXECUTABLE_OUTPUT_PATH "bin")
set(LIBRARY_OUTPUT_PATH "lib")

include_directories(
    /usr/include
    include/rest
    include
)

find_package(Boost 1.67 REQUIRED COMPONENTS thread filesystem program_options)

add_library(reply              rest/reply.cpp)
add_library(server             rest/server.cpp)
add_library(request_parser     rest/request_parser.cpp)
add_library(mime_types         rest/mime_types.cpp)
add_library(request_handler    rest/request_handler.cpp)
add_library(connection         rest/connection.cpp)
add_library(connection_manager rest/connection_manager.cpp)
add_library(cidr_db            cidr_db.cpp)

add_executable(cidrdb_rest rest/main.cpp)

target_link_libraries(cidrdb_rest
    server
    request_handler
    mime_types
    connection
    connection_manager
    reply
    request_parser
    cidr_db
    Boost::thread
    Boost::filesystem
    Boost::program_options
)

add_executable(cidrdb_cli  main.cpp)

target_link_libraries(cidrdb_cli
    cidr_db
    Boost::thread
    Boost::filesystem
    Boost::program_options
)
