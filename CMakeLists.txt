cmake_minimum_required(VERSION 3.15)
project(pckcap)

set(CMAKE_CXX_STANDARD 17)

add_executable(analyzer src/main.cpp)
target_link_libraries(analyzer PRIVATE pcap)