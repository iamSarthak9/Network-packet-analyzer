/*
 * Network Packet Analyzer
 * Real-Time Linux Network Traffic & Telemetry Monitor
 * Language: C++17
 */

#ifndef PROC_PARSER_HPP
#define PROC_PARSER_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * ============================================================================
 * LINUX KERNEL TELEMETRY: /proc/net/dev ARCHITECTURE
 * ============================================================================
 *
 * 1. PROCFS VFS INTERNALS:
 * ------------------------
 * The Linux `/proc` filesystem is a virtual pseudo-filesystem synthesized in RAM
 * by the kernel Virtual Filesystem (VFS) layer. Reading `/proc/net/dev` does not
 * incur disk I/O; the VFS invokes `dev_seq_show()` in `net/core/net-procfs.c`.
 *
 * 2. KERNEL TELEMETRY LAYOUT:
 * ---------------------------
 * The kernel polls `struct rtnl_link_stats64` from each active network device driver
 * and formats 16 space-separated numerical columns per interface line:
 *
 *   <interface>: <rx_bytes> <rx_packets> <rx_errs> <rx_drop> <rx_fifo> <rx_frame>
 *                <rx_compressed> <rx_multicast> <tx_bytes> <tx_packets> <tx_errs>
 *                <tx_drop> <tx_fifo> <tx_colls> <tx_carrier> <tx_compressed>
 *
 * 3. ZERO-COPY PARSING:
 * ---------------------
 * Instead of allocating temporary std::string substrings, this parser operates
 * on non-owning `std::string_view` slices and parses numerical fields directly
 * into 64-bit integers using `<charconv>` `std::from_chars`.
 */

struct RawNetStats
{
    // Receive (Inbound / Download)
    uint64_t rx_bytes{0};        // Total good bytes received
    uint64_t rx_packets{0};      // Total good packets received
    uint64_t rx_errors{0};       // Inbound hardware/CRC errors
    uint64_t rx_dropped{0};      // Dropped packets (buffer/queue exhausted)

    // Transmit (Outbound / Upload)
    uint64_t tx_bytes{0};        // Total good bytes transmitted
    uint64_t tx_packets{0};      // Total good packets transmitted
    uint64_t tx_errors{0};       // Outbound transmission errors
    uint64_t tx_dropped{0};      // Transmit drops (tx queue full)
};

class ProcParser
{
public:
    /**
     * @brief Discovers all active network interface names from /proc/net/dev.
     * @param procFilePath Path to file (defaults to /proc/net/dev).
     * @return List of interface names (e.g. ["lo", "eth0", "wlan0"]).
     */
    [[nodiscard]] static std::vector<std::string> getAvailableInterfaces(
        const std::string& procFilePath = "/proc/net/dev"
    );

    /**
     * @brief Reads telemetry for a specific network interface.
     * @param iface Target interface name (e.g. "eth0").
     * @param procFilePath Path to file (defaults to /proc/net/dev).
     * @return RawNetStats if interface was found, std::nullopt otherwise.
     */
    [[nodiscard]] static std::optional<RawNetStats> readInterface(
        std::string_view iface,
        const std::string& procFilePath = "/proc/net/dev"
    );

    /**
     * @brief Parses a single line from /proc/net/dev into interface name and stats.
     * @param line Single line string view.
     * @return Pair of (interface_name, RawNetStats) or std::nullopt.
     */
    [[nodiscard]] static std::optional<std::pair<std::string, RawNetStats>> parseLine(
        std::string_view line
    );

    /**
     * @brief Generates simulated telemetry for cross-platform demonstration (e.g. on Windows/macOS).
     */
    [[nodiscard]] static RawNetStats generateSimulatedStats(uint64_t tick);
};

#endif // PROC_PARSER_HPP
