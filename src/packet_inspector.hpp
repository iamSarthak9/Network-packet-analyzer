/*
 * Network Packet Analyzer - Modern C++ Systems Project
 * Created as a personal learning exercise (University student).
 */

#ifndef PACKET_INSPECTOR_HPP
#define PACKET_INSPECTOR_HPP

/*
 * ============================================================================
 * HOW RAW SOCKET PACKET CAPTURE WORKS (Linux)
 * ============================================================================
 *
 * WHAT IS A RAW SOCKET?
 * A normal socket (SOCK_STREAM/SOCK_DGRAM) delivers only the payload of a
 * protocol layer. A raw socket with AF_PACKET + SOCK_RAW delivers the entire
 * Ethernet frame including all headers. The kernel copies every arriving frame
 * into the socket receive buffer before the protocol stack processes it.
 *
 * ETH_P_ALL (htons(0x0003)) - capture every frame regardless of EtherType.
 *
 * PERFORMANCE DESIGN:
 *   1. Dedicated background thread drains the socket; the main thread never
 *      blocks on I/O and never slows down the packet drain loop.
 *   2. Fixed 65535-byte stack buffer: zero per-packet heap allocations.
 *   3. std::atomic counters (single LOCK XADD CPU instruction) instead of
 *      a mutex (futex syscall) for lock-free statistics sharing.
 *   4. EMA-based anomaly detector distinguishes sustained UDP floods from
 *      normal transient bursts; immune to single-packet false positives.
 *
 * PROTOCOL CLASSIFICATION (Ethernet/IPv4 frame layout):
 *   Bytes  0-11 : Ethernet src/dst MAC addresses
 *   Bytes 12-13 : EtherType (0x0800 = IPv4)
 *   Byte  23    : IPv4 Protocol field (1=ICMP, 6=TCP, 17=UDP)
 * ============================================================================
 */

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

// Anomaly detection tuning constants
inline constexpr double   SPIKE_MULTIPLIER  = 5.0;   // alert if UDP > 5x EMA
inline constexpr double   EMA_ALPHA         = 0.15;  // EMA smoothing factor alpha
inline constexpr uint64_t MIN_EMA_THRESHOLD = 10000; // minimum bytes/s before detection activates

/**
 * @brief Value-type snapshot of protocol distribution and anomaly status.
 *        Cheap to copy: plain integers and a bool only.
 */
struct ProtocolReport
{
    uint64_t tcpPackets{0};
    uint64_t udpPackets{0};
    uint64_t icmpPackets{0};
    uint64_t otherPackets{0};
    uint64_t totalPackets{0};

    uint64_t udpBytesPerSec{0};    // UDP bytes received in the last 1-second window
    double   udpEmaBytes{0.0};     // rolling EMA baseline shown in the UI
    bool     udpFloodAlert{false}; // true = potential UDP DDoS flood detected
};

/**
 * @brief Background raw-socket packet capture and security analysis engine.
 *
 * Usage:
 *   PacketInspector inspector( eth0);
 *   inspector.start();
 *   ProtocolReport r = inspector.getReport(); // wait-free, any thread, any rate
 *   inspector.stop();
 */
class PacketInspector
{
public:
    explicit PacketInspector(std::string interfaceName);
    ~PacketInspector();

    PacketInspector(const PacketInspector&)            = delete;
    PacketInspector& operator=(const PacketInspector&) = delete;

    /** @brief Launches the background capture (or simulation) thread. */
    void start();

    /** @brief Signals stop and blocks until the thread exits cleanly. */
    void stop();

    /**
     * @brief Atomically reads the latest protocol counters and anomaly flags.
     * @return ProtocolReport - safe to call from any thread at any frequency.
     */
    [[nodiscard]] ProtocolReport getReport() const noexcept;

    [[nodiscard]] bool isCapturing() const noexcept { return m_capturing.load(); }

private:
    void captureLoop();   // Linux: drains raw AF_PACKET socket
    void simulateLoop();  // Fallback: generates synthetic protocol data

    void classifyFrame(const unsigned char* buf, int length) noexcept;
    void updateAnomalyDetector(uint64_t udpBytesInInterval) noexcept;

    std::string       m_interfaceName;
    std::thread       m_thread;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_capturing{false};

    // Lock-free packet counters - updated by capture thread, read by main thread
    std::atomic<uint64_t> m_tcpPackets{0};
    std::atomic<uint64_t> m_udpPackets{0};
    std::atomic<uint64_t> m_icmpPackets{0};
    std::atomic<uint64_t> m_otherPackets{0};
    std::atomic<uint64_t> m_totalPackets{0};

    // Anomaly detection state
    std::atomic<uint64_t> m_udpBytesPerSec{0};  // snapshot updated every second
    std::atomic<uint64_t> m_udpBytesAccum{0};   // accumulator between EMA updates
    std::atomic<double>   m_udpEmaBytes{0.0};   // EMA value for the UI
    std::atomic<bool>     m_udpFloodAlert{false};

    int m_sockFd{-1}; // raw socket fd (-1 when not open / non-Linux)
};

#endif // PACKET_INSPECTOR_HPP
