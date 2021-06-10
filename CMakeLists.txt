cmake_minimum_required(VERSION 3.20)

project(SniffandSpoof)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories("${PROJECT_BINARY_DIR}")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/")
find_package(PCAP REQUIRED)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}-pthread")

find_package(Boost 1.75.0)
if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  add_executable(sniff_and_then_spoof sniff_and_then_spoof.cpp)
  target_link_libraries(sniff_and_then_spoof ${PCAP_LIBRARY})
endif()