/*
 * Network Packet Analyzer – Modern C++ Systems Project
 * Created as a personal learning exercise (University student).
 */

#ifndef TERMINAL_VIEW_HPP
#define TERMINAL_VIEW_HPP

#include "network_device.hpp"
#include "packet_inspector.hpp"

#include <cstdint>
#include <deque>
#include <string>

/**
 * @brief Terminal dashboard renderer using portable ANSI escape codes.
 *
 * Renders real-time telemetry metrics, protocol distribution,
 * security anomaly alerts, and ASCII bandwidth graphs – no external
 * libraries required.
 */
class TerminalView
{
public:
    /** @brief Clears the screen and homes the cursor (ANSI escape). */
    static void clearScreen();

    /**
     * @brief Renders the full live monitoring dashboard.
     * @param device          Active network device with RX/TX statistics.
     * @param report          Protocol distribution + anomaly flags from PacketInspector.
     * @param intervalMs      Polling interval in ms (displayed in the header).
     * @param elapsedSeconds  Session uptime in seconds.
     */
    static void renderDashboard(
        const NetworkDevice&  device,
        const ProtocolReport& report,
        uint64_t              intervalMs,
        uint64_t              elapsedSeconds
    );

    /**
     * @brief Generates a multi-line ASCII graph for bandwidth history.
     * @param history   Deque of recent bandwidth samples (bytes/s).
     * @param peakRate  Maximum observed rate – used for vertical scaling.
     * @param width     Character width of the graph.
     * @param height    Number of text rows in the graph.
     */
    [[nodiscard]] static std::string generateAsciiGraph(
        const std::deque<double>& history,
        double peakRate,
        int width  = 50,
        int height = 5
    );

private:
    /** @brief Renders protocol distribution bars and the DDoS anomaly alert. */
    static void renderSecurityPanel(const ProtocolReport& report);
};

#endif // TERMINAL_VIEW_HPP
