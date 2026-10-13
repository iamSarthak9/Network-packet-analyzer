/*
 * Network Packet Analyzer
 * Real-Time Linux Network Traffic & Telemetry Monitor
 * Language: C++17
 */

#include "proc_parser.hpp"

#include <charconv>
#include <cmath>
#include <fstream>
#include <string_view>

namespace
{
    // Helper to strip leading and trailing whitespace from string_view in O(1) time
    constexpr std::string_view trimView(std::string_view sv) noexcept
    {
        constexpr std::string_view ws = " \t\r\n";
        const auto start = sv.find_first_not_of(ws);
        if (start == std::string_view::npos)
            return {};
        const auto end = sv.find_last_not_of(ws);
        return sv.substr(start, end - start + 1);
    }
}

std::optional<std::pair<std::string, RawNetStats>> ProcParser::parseLine(std::string_view line)
{
    const auto trimmed = trimView(line);
    if (trimmed.empty())
    {
        return std::nullopt;
    }

    // In /proc/net/dev, each interface row has the format: "<interface_name>: <col0> <col1> ..."
    const auto colonPos = trimmed.find(':');
    if (colonPos == std::string_view::npos)
    {
        // Skips header lines ("Inter-|   Receive ..." or " face |bytes ...")
        return std::nullopt;
    }

    const auto ifaceName = trimView(trimmed.substr(0, colonPos));
    if (ifaceName.empty())
    {
        return std::nullopt;
    }

    // Zero-allocation numerical tokenization via std::string_view and std::from_chars
    std::string_view dataSection = trimmed.substr(colonPos + 1);
    uint64_t columns[16] = {0};
    std::size_t colIndex = 0;

    std::size_t i = 0;
    const std::size_t len = dataSection.size();

    while (i < len && colIndex < 16)
    {
        // Skip whitespace delimiters
        while (i < len && (dataSection[i] == ' ' || dataSection[i] == '\t'))
        {
            ++i;
        }
        if (i >= len)
        {
            break;
        }

        const std::size_t tokenStart = i;
        while (i < len && dataSection[i] != ' ' && dataSection[i] != '\t')
        {
            ++i;
        }

        // Parse integer directly from memory buffer
        const char* first = dataSection.data() + tokenStart;
        const char* last = dataSection.data() + i;
        uint64_t val = 0;

        auto [ptr, ec] = std::from_chars(first, last, val);
        if (ec != std::errc{} || ptr != last)
        {
            return std::nullopt; // Non-numeric token
        }

        columns[colIndex++] = val;
    }

    // Standard Linux kernels provide 16 columns (minimum 12)
    if (colIndex < 12)
    {
        return std::nullopt;
    }

    RawNetStats stats{};
    // Receive metrics
    stats.rx_bytes   = columns[0];
    stats.rx_packets = columns[1];
    stats.rx_errors  = columns[2];
    stats.rx_dropped = columns[3];

    // Transmit metrics
    stats.tx_bytes   = columns[8];
    stats.tx_packets = columns[9];
    stats.tx_errors  = columns[10];
    stats.tx_dropped = columns[11];

    return std::make_pair(std::string(ifaceName), stats);
}

std::vector<std::string> ProcParser::getAvailableInterfaces(const std::string& procFilePath)
{
    std::vector<std::string> interfaces;
    std::ifstream file(procFilePath);
    if (!file.is_open())
    {
        return interfaces;
    }

    std::string line;
    while (std::getline(file, line))
    {
        auto parsed = parseLine(line);
        if (parsed.has_value())
        {
            interfaces.push_back(parsed->first);
        }
    }

    return interfaces;
}

std::optional<RawNetStats> ProcParser::readInterface(
    std::string_view iface,
    const std::string& procFilePath
)
{
    std::ifstream file(procFilePath);
    if (!file.is_open())
    {
        return std::nullopt;
    }

    std::string line;
    while (std::getline(file, line))
    {
        auto parsed = parseLine(line);
        if (parsed.has_value() && parsed->first == iface)
        {
            return parsed->second;
        }
    }

    return std::nullopt;
}

RawNetStats ProcParser::generateSimulatedStats(uint64_t tick)
{
    // Simulates realistic oscillating network traffic (for non-Linux demonstration)
    const double t = static_cast<double>(tick) * 0.15;
    const uint64_t rxRate = static_cast<uint64_t>(1024 * 1024 * (5.0 + 3.0 * std::sin(t)));
    const uint64_t txRate = static_cast<uint64_t>(1024 * 512 * (3.0 + 2.0 * std::cos(t * 1.5)));

    RawNetStats stats{};
    stats.rx_bytes   = tick * rxRate;
    stats.rx_packets = tick * (rxRate / 1400);
    stats.rx_errors  = (tick % 50 == 0) ? 1 : 0;
    stats.rx_dropped = (tick % 70 == 0) ? 1 : 0;

    stats.tx_bytes   = tick * txRate;
    stats.tx_packets = tick * (txRate / 1400);
    stats.tx_errors  = 0;
    stats.tx_dropped = 0;

    return stats;
}
