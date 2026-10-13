/*
 * Network Packet Analyzer
 * Real-Time Linux Network Traffic & Telemetry Monitor
 * Language: C++17
 */

#ifndef NETWORK_DEVICE_HPP
#define NETWORK_DEVICE_HPP

#include "proc_parser.hpp"
#include "traffic_stats.hpp"

#include <cstdint>
#include <string>

/**
 * @brief Represents an active network interface being monitored.
 *
 * Manages raw kernel telemetry samples and performs 32-bit hardware counter
 * rollover detection and overflow correction.
 */
class NetworkDevice
{
public:
    explicit NetworkDevice(std::string name);

    [[nodiscard]] const std::string& getName() const noexcept { return m_name; }
    [[nodiscard]] const TrafficStats& getRxStats() const noexcept { return m_rxStats; }
    [[nodiscard]] const TrafficStats& getTxStats() const noexcept { return m_txStats; }

    /**
     * @brief Ingests newly sampled raw telemetry counters and updates statistics.
     */
    void update(const RawNetStats& raw, uint64_t timestamp_ms);

    /**
     * @brief Compensates for 32-bit hardware counter rollover on high-speed interfaces.
     * @param current Current value read from OS kernel.
     * @param previous Previous accumulated reading.
     * @return 64-bit monotonically increasing cumulative value.
     */
    [[nodiscard]] static uint64_t fixCounterOverflow(uint64_t current, uint64_t previous);

private:
    std::string m_name;
    TrafficStats m_rxStats;
    TrafficStats m_txStats;

    RawNetStats m_previousRaw{};
    bool m_hasInitialReading{false};
};

#endif // NETWORK_DEVICE_HPP
