cmake_minimum_required(VERSION 3.10)
project(Peer2PeerFileTransfer C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

include_directories(${CMAKE_SOURCE_DIR})

file(GLOB SOURCES "src/*.c")

add_executable(transfer ${SOURCES})
