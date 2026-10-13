/*
 * Network Packet Analyzer – Modern C++ Systems Project
 * Created as a personal learning exercise (University student).
 */

#include "terminal_view.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

// ─── ANSI colour/style helpers ────────────────────────────────────────────────
static constexpr const char* ANSI_RESET  = "\033[0m";
static constexpr const char* ANSI_BOLD   = "\033[1m";
static constexpr const char* ANSI_RED    = "\033[31m";
static constexpr const char* ANSI_GREEN  = "\033[32m";
static constexpr const char* ANSI_YELLOW = "\033[33m";
static constexpr const char* ANSI_CYAN   = "\033[36m";

// ─── clearScreen ─────────────────────────────────────────────────────────────

void TerminalView::clearScreen()
{
    // \033[2J clears the screen; \033[H moves cursor to row 1, col 1
    std::cout << "\033[2J\033[H";
}

// ─── generateAsciiGraph ──────────────────────────────────────────────────────

std::string TerminalView::generateAsciiGraph(
    const std::deque<double>& history,
    double peakRate,
    int width,
    int height
)
{
    if (history.empty() || peakRate <= 0.0)
        peakRate = 1.0;

    std::vector<double> points(width, 0.0);
    const int startIdx  = std::max(0, static_cast<int>(history.size()) - width);
    const int copyCount = std::min(static_cast<int>(history.size()), width);

    for (int i = 0; i < copyCount; ++i)
        points[width - copyCount + i] = history[startIdx + i];

    std::ostringstream graph;

    for (int row = height - 1; row >= 0; --row)
    {
        const double threshold = (static_cast<double>(row) / static_cast<double>(height)) * peakRate;
        graph << "  |";

        for (int col = 0; col < width; ++col)
        {
            const double val = points[col];
            if (val >= threshold && val > 0.0)
            {
                if (row == height - 1)      graph << "^";
                else if (val >= threshold * 1.5) graph << "#";
                else                        graph << "=";
            }
            else
            {
                graph << " ";
            }
        }
        graph << "\n";
    }

    graph << "  +" << std::string(width, '-')
          << " (Peak: " << TrafficStats::formatBitsPerSec(peakRate) << ")\n";

    return graph.str();
}

// ─── renderSecurityPanel ─────────────────────────────────────────────────────

void TerminalView::renderSecurityPanel(const ProtocolReport& report)
{
    // ── Protocol distribution bars ────────────────────────────────────────────
    const uint64_t total = (report.totalPackets == 0) ? 1 : report.totalPackets;

    const double tcpPct   = 100.0 * static_cast<double>(report.tcpPackets)   / static_cast<double>(total);
    const double udpPct   = 100.0 * static_cast<double>(report.udpPackets)   / static_cast<double>(total);
    const double icmpPct  = 100.0 * static_cast<double>(report.icmpPackets)  / static_cast<double>(total);
    const double otherPct = 100.0 * static_cast<double>(report.otherPackets) / static_cast<double>(total);

    constexpr int BAR_WIDTH = 40;
    auto makeBar = [&](double pct) -> std::string
    {
        const int filled = static_cast<int>((pct / 100.0) * BAR_WIDTH);
        return std::string(filled, '#') + std::string(BAR_WIDTH - filled, '.');
    };

    std::cout << ANSI_BOLD << "  [PROTOCOL DISTRIBUTION]" << ANSI_RESET << "\n"
              << "  Total captured packets: " << report.totalPackets << "\n\n"
              << std::fixed << std::setprecision(1);

    // TCP – cyan
    std::cout << "  " << ANSI_CYAN << "TCP " << ANSI_RESET
              << " [" << makeBar(tcpPct) << "] "
              << std::setw(5) << tcpPct << "% (" << report.tcpPackets << " pkts)\n";

    // UDP – yellow normally, red when flood alert fires
    const char* udpColour = report.udpFloodAlert ? ANSI_RED : ANSI_YELLOW;
    std::cout << "  " << udpColour << "UDP " << ANSI_RESET
              << " [" << makeBar(udpPct) << "] "
              << std::setw(5) << udpPct << "% (" << report.udpPackets << " pkts)\n";

    // ICMP – green
    std::cout << "  " << ANSI_GREEN << "ICMP" << ANSI_RESET
              << " [" << makeBar(icmpPct) << "] "
              << std::setw(5) << icmpPct << "% (" << report.icmpPackets << " pkts)\n";

    // Other
    std::cout << "  Other[" << makeBar(otherPct) << "] "
              << std::setw(5) << otherPct << "% (" << report.otherPackets << " pkts)\n\n";

    // ── Anomaly detection panel ───────────────────────────────────────────────
    std::cout << ANSI_BOLD << "  [ANOMALY DETECTION]" << ANSI_RESET << "\n"
              << "  UDP inbound rate:   "
              << TrafficStats::formatBytes(report.udpBytesPerSec) << "/s  "
              << "(baseline EMA: "
              << TrafficStats::formatBytes(static_cast<uint64_t>(report.udpEmaBytes)) << "/s)\n";

    if (report.udpFloodAlert)
    {
        /*
         * Bold red banner – visible indicator of a potential UDP DDoS.
         * In a real IDS this would also write to a log file and send
         * an alert to a SIEM (Security Information and Event Management) system.
         */
        std::cout << "\n"
                  << ANSI_RED << ANSI_BOLD
                  << "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                  << "  !! ALERT: POTENTIAL UDP FLOOD / DDoS DETECTED           !!\n"
                  << "  !! Inbound UDP traffic is >" << static_cast<int>(SPIKE_MULTIPLIER)
                  << "x above baseline EMA.        !!\n"
                  << "  !! Possible UDP amplification / reflection attack.       !!\n"
                  << "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                  << ANSI_RESET << "\n";
    }
    else
    {
        std::cout << "  " << ANSI_GREEN << "[OK] " << ANSI_RESET
                  << "No anomalies detected. Traffic pattern within normal bounds.\n\n";
    }
}

// ─── renderDashboard ─────────────────────────────────────────────────────────

void TerminalView::renderDashboard(
    const NetworkDevice&  device,
    const ProtocolReport& report,
    uint64_t              intervalMs,
    uint64_t              elapsedSeconds
)
{
    clearScreen();

    const auto& rx = device.getRxStats();
    const auto& tx = device.getTxStats();

    const uint64_t mins = elapsedSeconds / 60;
    const uint64_t secs = elapsedSeconds % 60;

    std::ostringstream timeStr;
    timeStr << std::setfill('0') << std::setw(2) << mins << ":"
            << std::setfill('0') << std::setw(2) << secs;

    // ── Header ────────────────────────────────────────────────────────────────
    std::cout << "================================================================================\n"
              << ANSI_BOLD
              << "  NETWORK PACKET ANALYZER  –  Real-Time Telemetry & Security Monitor\n"
              << ANSI_RESET
              << "================================================================================\n"
              << "  Interface: " << std::left << std::setw(10) << device.getName()
              << " | Interval: " << intervalMs << " ms"
              << " | Uptime: " << timeStr.str() << "\n"
              << "--------------------------------------------------------------------------------\n";

    // ── Inbound (RX / Download) ───────────────────────────────────────────────
    std::cout << ANSI_CYAN << "  [INCOMING TRAFFIC / DOWNLOAD]" << ANSI_RESET << "\n"
              << "  Current Rate: " << std::setw(15) << TrafficStats::formatBitsPerSec(rx.getBytesPerSecond())
              << " | Average: "     << std::setw(15) << TrafficStats::formatBitsPerSec(rx.getAverageBytesPerSecond()) << "\n"
              << "  Peak Rate:    " << std::setw(15) << TrafficStats::formatBitsPerSec(rx.getMaxBytesPerSecond())
              << " | Total:   "     << std::setw(15) << TrafficStats::formatBytes(rx.getTotalBytes()) << "\n"
              << "  Packets:      " << std::fixed << std::setprecision(0)
                                    << rx.getPacketsPerSecond() << " pkts/s"
              << "       | Errors:  " << rx.getTotalErrors()
              << " | Drops: "        << rx.getTotalDrops() << "\n\n"
              << generateAsciiGraph(rx.getRateHistory(), rx.getMaxBytesPerSecond(), 60, 4) << "\n"
              << "--------------------------------------------------------------------------------\n";

    // ── Outbound (TX / Upload) ────────────────────────────────────────────────
    std::cout << ANSI_CYAN << "  [OUTGOING TRAFFIC / UPLOAD]" << ANSI_RESET << "\n"
              << "  Current Rate: " << std::setw(15) << TrafficStats::formatBitsPerSec(tx.getBytesPerSecond())
              << " | Average: "     << std::setw(15) << TrafficStats::formatBitsPerSec(tx.getAverageBytesPerSecond()) << "\n"
              << "  Peak Rate:    " << std::setw(15) << TrafficStats::formatBitsPerSec(tx.getMaxBytesPerSecond())
              << " | Total:   "     << std::setw(15) << TrafficStats::formatBytes(tx.getTotalBytes()) << "\n"
              << "  Packets:      " << std::fixed << std::setprecision(0)
                                    << tx.getPacketsPerSecond() << " pkts/s"
              << "       | Errors:  " << tx.getTotalErrors()
              << " | Drops: "        << tx.getTotalDrops() << "\n\n"
              << generateAsciiGraph(tx.getRateHistory(), tx.getMaxBytesPerSecond(), 60, 4) << "\n"
              << "--------------------------------------------------------------------------------\n";

    // ── Security panel ────────────────────────────────────────────────────────
    renderSecurityPanel(report);

    std::cout << "================================================================================\n"
              << "  Press Ctrl+C to terminate monitor.\n"
              << std::flush;
}
