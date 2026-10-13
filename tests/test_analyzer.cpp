/*
 * Network Packet Analyzer - Unit Test Suite
 */

#include "network_device.hpp"
#include "proc_parser.hpp"
#include "terminal_view.hpp"
#include "traffic_stats.hpp"

#include <cassert>
#include <iostream>

void test_proc_parsing()
{
    // Sample /proc/net/dev line
    const std::string_view line =
        "  eth0: 104857600  100000    1    2    0     0          0         0  52428800   50000    3    4    0     0       0          0";

    auto parsed = ProcParser::parseLine(line);
    assert(parsed.has_value());
    assert(parsed->first == "eth0");

    const auto& stats = parsed->second;
    assert(stats.rx_bytes == 104857600ULL);
    assert(stats.rx_packets == 100000ULL);
    assert(stats.rx_errors == 1ULL);
    assert(stats.rx_dropped == 2ULL);

    assert(stats.tx_bytes == 52428800ULL);
    assert(stats.tx_packets == 50000ULL);
    assert(stats.tx_errors == 3ULL);
    assert(stats.tx_dropped == 4ULL);

    // Reject header
    assert(!ProcParser::parseLine("Inter-|   Receive   |  Transmit").has_value());
    assert(!ProcParser::parseLine("").has_value());

    std::cout << "  [PASS] test_proc_parsing\n";
}

void test_counter_overflow()
{
    // Normal 64-bit value: no wraparound
    assert(NetworkDevice::fixCounterOverflow(5000000000ULL, 4000000000ULL) == 5000000000ULL);

    // 32-bit counter wraparound test:
    // Previous value was close to 4GB: 4,200,000,000
    // Current value wrapped around to:     100,000,000
    const uint64_t prev = 4200000000ULL;
    const uint64_t curr = 100000000ULL;

    const uint64_t fixed = NetworkDevice::fixCounterOverflow(curr, prev);

    // Expected value: 0x100000000 (4,294,967,296) + 100,000,000 = 4,394,967,296
    const uint64_t expected = 0x100000000ULL + curr;
    assert(fixed == expected);

    std::cout << "  [PASS] test_counter_overflow\n";
}

void test_traffic_stats_and_formatting()
{
    TrafficStats stats(20, 5000);

    // Initial reading at t=1000ms
    stats.addSample(1000, 1000000, 100, 0, 0);

    // Reading at t=2000ms (delta: 1 second, +1,000,000 bytes = 8 Mbit/s)
    stats.addSample(2000, 2000000, 200, 0, 0);

    assert(stats.getBytesPerSecond() == 1000000.0);
    assert(stats.getPacketsPerSecond() == 100.0);

    // String formatting
    assert(TrafficStats::formatBytes(500) == "500 B");
    assert(TrafficStats::formatBytes(1024 * 1024) == "1.00 MB");
    assert(TrafficStats::formatBitsPerSec(125000) == "1.00 Mbit/s");

    std::cout << "  [PASS] test_traffic_stats_and_formatting\n";
}

void test_ascii_graph()
{
    std::deque<double> history = { 10.0, 50.0, 100.0, 25.0 };
    const std::string graph = TerminalView::generateAsciiGraph(history, 100.0, 10, 3);
    assert(!graph.empty());
    assert(graph.find('+') != std::string::npos);

    std::cout << "  [PASS] test_ascii_graph\n";
}

int main()
{
    std::cout << "=== Running Network Packet Analyzer Test Suite ===\n";
    test_proc_parsing();
    test_counter_overflow();
    test_traffic_stats_and_formatting();
    test_ascii_graph();
    std::cout << "All tests passed successfully!\n\n";
    return 0;
}

