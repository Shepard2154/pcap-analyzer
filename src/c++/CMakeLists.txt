cmake_minimum_required(VERSION 3.0)
set(CMAKE_OSX_ARCHITECTURES "x86_64" CACHE INTERNAL "" FORCE)
project(pcap-analyzer)
add_executable(app main.cpp)