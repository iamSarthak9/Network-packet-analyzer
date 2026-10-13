/*
 * Network Packet Analyzer – Modern C++ Systems Project
 * Created as a personal learning exercise (University student).
 */

#include "network_device.hpp"
#include "packet_inspector.hpp"
#include "proc_parser.hpp"
#include "terminal_view.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#if defined(_WIN32)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    inline void sleepMs(uint64_t ms)
    {
        Sleep(static_cast<DWORD>(ms));
    }
#else
    #include <thread>
    inline void sleepMs(uint64_t ms)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }
#endif

namespace
{
    // Atomic flag for signal-safe graceful shutdown
    std::atomic<bool> g_running{true};

    void handleSignal(int /*signal*/)
    {
        g_running.store(false);
    }

    void printHelp(const char* progName)
    {
        std::cout << "Usage: " << progName << " [options]\n\n"
                  << "Options:\n"
                  << "  -i, --interface <name>   Network interface to monitor (e.g. eth0, wlan0, lo)\n"
                  << "  -t, --interval <ms>      Refresh interval in milliseconds (default: 500)\n"
                  << "  -s, --simulate           Simulate dynamic network traffic (for non-Linux demo)\n"
                  << "  -l, --list               List all auto-detected interfaces and exit\n"
                  << "  -h, --help               Display this help text\n\n"
                  << "Example:\n"
                  << "  " << progName << " -i eth0 -t 500\n\n";
    }
}

int main(int argc, char* argv[])
{
    std::string interfaceName;
    uint64_t intervalMs = 500;
    bool forceSimulate = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];

        if (arg == "-h" || arg == "--help")
        {
            printHelp(argv[0]);
            return 0;
        }
        else if (arg == "-i" || arg == "--interface")
        {
            if (i + 1 < argc)
            {
                interfaceName = argv[++i];
            }
            else
            {
                std::cerr << "Error: Missing argument for " << arg << "\n";
                return 1;
            }
        }
        else if (arg == "-t" || arg == "--interval")
        {
            if (i + 1 < argc)
            {
                intervalMs = std::max<uint64_t>(50, std::strtoull(argv[++i], nullptr, 10));
            }
            else
            {
                std::cerr << "Error: Missing argument for " << arg << "\n";
                return 1;
            }
        }
        else if (arg == "-s" || arg == "--simulate")
        {
            forceSimulate = true;
        }
        else if (arg == "-l" || arg == "--list")
        {
            const auto ifaces = ProcParser::getAvailableInterfaces();
            std::cout << "Available network interfaces in /proc/net/dev:\n";
            if (ifaces.empty())
            {
                std::cout << "  (None detected or not running on Linux)\n";
            }
            else
            {
                for (const auto& name : ifaces)
                {
                    std::cout << "  - " << name << "\n";
                }
            }
            return 0;
        }
        else
        {
            // Assume positional argument is the interface name
            interfaceName = arg;
        }
    }

    // Auto-detect interface if none specified
    const auto availableIfaces = ProcParser::getAvailableInterfaces();
    if (interfaceName.empty())
    {
        if (!availableIfaces.empty())
        {
            // Pick first non-loopback interface if possible, otherwise first available
            interfaceName = availableIfaces.front();
            for (const auto& name : availableIfaces)
            {
                if (name != "lo")
                {
                    interfaceName = name;
                    break;
                }
            }
        }
        else
        {
            interfaceName = "eth0"; // Default fallback
            forceSimulate = true;   // Auto-enable simulation if /proc/net/dev is absent
        }
    }

    // Register POSIX termination signals
    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    // NetworkDevice: manages /proc/net/dev telemetry and counter rollover
    auto device = std::make_unique<NetworkDevice>(interfaceName);

    // PacketInspector: background raw-socket capture + anomaly detection.
    // On Linux with CAP_NET_RAW it opens an AF_PACKET socket; otherwise
    // it runs a realistic simulation so the UI always shows useful data.
    auto inspector = std::make_unique<PacketInspector>(interfaceName);
    inspector->start();

    uint64_t   tick      = 0;
    const auto startTime = std::chrono::steady_clock::now();

    // Main telemetry collection loop
    while (g_running.load())
    {
        const auto now = std::chrono::system_clock::now();
        const uint64_t timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()
        ).count();

        RawNetStats currentRaw{};

        if (!forceSimulate)
        {
            auto readOpt = ProcParser::readInterface(interfaceName);
            if (readOpt.has_value())
            {
                currentRaw = *readOpt;
            }
            else
            {
                // Fallback: interface absent from procfs – use simulation
                currentRaw = ProcParser::generateSimulatedStats(tick);
            }
        }
        else
        {
            currentRaw = ProcParser::generateSimulatedStats(tick);
        }

        // Push new sample into rolling stats engine
        device->update(currentRaw, timestamp_ms);

        // Compute session uptime
        const auto elapsedSec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - startTime
        ).count();

        // Atomically snapshot protocol distribution and anomaly flags
        const ProtocolReport securityReport = inspector->getReport();

        // Render full dashboard (bandwidth graphs + security panel)
        TerminalView::renderDashboard(
            *device,
            securityReport,
            intervalMs,
            static_cast<uint64_t>(elapsedSec)
        );

        sleepMs(intervalMs);
        ++tick;
    }

    // Graceful shutdown: close raw socket, join capture thread
    inspector->stop();

    std::cout << "\n[!] Monitoring session terminated cleanly.\n";
    return 0;
}
