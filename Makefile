CXX ?= g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -O2 -Isrc

SRCS = src/proc_parser.cpp src/traffic_stats.cpp src/network_device.cpp src/terminal_view.cpp
MAIN_SRC = src/main.cpp
TEST_SRC = tests/test_analyzer.cpp

TARGET = network-analyzer
TEST_TARGET = test_analyzer

all: $(TARGET)

$(TARGET): $(MAIN_SRC) $(SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SRC) $(SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@

clean:
ifeq ($(OS),Windows_NT)
	-del /Q $(TARGET) $(TARGET).exe $(TEST_TARGET) $(TEST_TARGET).exe *.o 2>nul
else
	rm -f $(TARGET) $(TARGET).exe $(TEST_TARGET) $(TEST_TARGET).exe *.o
endif

.PHONY: all test clean

