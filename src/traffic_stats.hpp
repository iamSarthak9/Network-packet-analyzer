/*
 * Network Packet Analyzer
 * Real-Time Linux Network Traffic & Telemetry Monitor
 * Language: C++17
 */

#ifndef TRAFFIC_STATS_HPP
#define TRAFFIC_STATS_HPP

#include <cstdint>
#include <deque>
#include <string>
#include <vector>

/**
 * @brief Computes real-time rates, rolling moving averages, and historical points.
 *
 * Employs `std::deque` as a sliding window buffer for O(1) front evictions,
 * avoiding the O(N) reallocation and memory-shifting overhead of std::vector.
 */
class TrafficStats
{
public:
    struct Snapshot
    {
        uint64_t timestamp_ms{0};
        uint64_t bytes{0};
        uint64_t packets{0};
        uint64_t errors{0};
        uint64_t drops{0};
    };

    explicit TrafficStats(std::size_t maxHistory = 40, uint64_t avgWindowMs = 10000);

    /**
     * @brief Ingests a new telemetry sample and updates instantaneous and moving rates.
     */
    void addSample(uint64_t timestamp_ms, uint64_t totalBytes, uint64_t totalPackets,
                   uint64_t totalErrors, uint64_t totalDrops);

    // Rate getters (per second)
    [[nodiscard]] double getBytesPerSecond() const noexcept { return m_currentBytesPerSec; }
    [[nodiscard]] double getPacketsPerSecond() const noexcept { return m_currentPacketsPerSec; }
    [[nodiscard]] double getAverageBytesPerSecond() const noexcept { return m_averageBytesPerSec; }
    [[nodiscard]] double getMaxBytesPerSecond() const noexcept { return m_maxBytesPerSec; }
    [[nodiscard]] double getMinBytesPerSecond() const noexcept { return m_minBytesPerSec; }
    [[nodiscard]] uint64_t getTotalBytes() const noexcept { return m_totalBytes; }
    [[nodiscard]] uint64_t getTotalPackets() const noexcept { return m_totalPackets; }
    [[nodiscard]] uint64_t getTotalErrors() const noexcept { return m_totalErrors; }
    [[nodiscard]] uint64_t getTotalDrops() const noexcept { return m_totalDrops; }

    // History buffer for ASCII bandwidth graph plotting
    [[nodiscard]] const std::deque<double>& getRateHistory() const noexcept { return m_rateHistory; }

    // Human-readable metric formatting
    [[nodiscard]] static std::string formatBytes(uint64_t bytes);
    [[nodiscard]] static std::string formatBitsPerSec(double bytesPerSec);

private:
    std::size_t m_maxHistory;
    uint64_t m_avgWindowMs;

    uint64_t m_totalBytes{0};
    uint64_t m_totalPackets{0};
    uint64_t m_totalErrors{0};
    uint64_t m_totalDrops{0};

    double m_currentBytesPerSec{0.0};
    double m_currentPacketsPerSec{0.0};
    double m_averageBytesPerSec{0.0};
    double m_maxBytesPerSec{0.0};
    double m_minBytesPerSec{0.0};

    std::deque<Snapshot> m_window;          // Moving average sliding window
    std::deque<double> m_rateHistory;       // Bandwidth rates for ASCII graph
};

#endif // TRAFFIC_STATS_HPP
