cmake_minimum_required(VERSION 3.15)

project(NetworkPacketAnalyzer
    VERSION 1.0.0
    DESCRIPTION "Modern C++ Real-Time Network Packet and Traffic Monitor"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Core library sources
set(ANALYZER_SOURCES
    src/proc_parser.cpp
    src/traffic_stats.cpp
    src/network_device.cpp
    src/terminal_view.cpp
)

# Main terminal network analyzer application
add_executable(network-analyzer
    src/main.cpp
    ${ANALYZER_SOURCES}
)
target_include_directories(network-analyzer PRIVATE src)

# Unit test suite
enable_testing()
add_executable(test_analyzer
    tests/test_analyzer.cpp
    ${ANALYZER_SOURCES}
)
target_include_directories(test_analyzer PRIVATE src)
add_test(NAME AnalyzerTests COMMAND test_analyzer)
