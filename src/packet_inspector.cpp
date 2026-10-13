/*
 * Network Packet Analyzer - Modern C++ Systems Project
 * Created as a personal learning exercise (University student).
 */

#include packet_inspector.hpp

#include <chrono>
#include <cmath>
#include <cstring>
#include <iostream>

#if defined(__linux__)
    #include <arpa/inet.h>
    #include <linux/if_packet.h>
    #include <net/ethernet.h>
    #include <net/if.h>
    #include <sys/socket.h>
    #include <unistd.h>

    static constexpr int      PROTO_ICMP        = 1;
    static constexpr int      PROTO_TCP         = 6;
    static constexpr int      PROTO_UDP         = 17;
    static constexpr int      ETH_ETYPE_OFFSET  = 12;
    static constexpr uint16_t ETYPE_IPV4        = 0x0800;
    static constexpr int      IPV4_PROTO_OFFSET = 23;
    static constexpr int      MIN_FRAME_LEN     = 24;
#endif

static constexpr double   SIM_TCP_RATIO  = 0.72;
static constexpr double   SIM_UDP_RATIO  = 0.22;
static constexpr double   SIM_ICMP_RATIO = 0.04;
static constexpr uint64_t SIM_BASE_PPS   = 1500;

PacketInspector::PacketInspector(std::string interfaceName)
    : m_interfaceName(std::move(interfaceName))
{}

PacketInspector::~PacketInspector()
{
    stop();
}

void PacketInspector::start()
{
    if (m_running.load()) return;
    m_running.store(true);

#if defined(__linux__)
    m_sockFd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (m_sockFd < 0)
    {
        std::cerr << [PacketInspector] Cannot open raw socket (need root or CAP_NET_RAW). 
                     Using simulated protocol data.\n;
        m_thread = std::thread(&PacketInspector::simulateLoop, this);
        return;
    }

    struct sockaddr_ll addr{};
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = static_cast<int>(::if_nametoindex(m_interfaceName.c_str()));

    if (addr.sll_ifindex == 0 ||
        ::bind(m_sockFd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        ::close(m_sockFd);
        m_sockFd = -1;
        m_thread = std::thread(&PacketInspector::simulateLoop, this);
        return;
    }

    m_capturing.store(true);
    m_thread = std::thread(&PacketInspector::captureLoop, this);
#else
    m_thread = std::thread(&PacketInspector::simulateLoop, this);
#endif
}

void PacketInspector::stop()
{
    if (!m_running.load()) return;
    m_running.store(false);

#if defined(__linux__)
    if (m_sockFd >= 0) { ::close(m_sockFd); m_sockFd = -1; }
#endif

    if (m_thread.joinable()) m_thread.join();
}

ProtocolReport PacketInspector::getReport() const noexcept
{
    ProtocolReport r;
    r.tcpPackets    = m_tcpPackets.load(std::memory_order_relaxed);
    r.udpPackets    = m_udpPackets.load(std::memory_order_relaxed);
    r.icmpPackets   = m_icmpPackets.load(std::memory_order_relaxed);
    r.otherPackets  = m_otherPackets.load(std::memory_order_relaxed);
    r.totalPackets  = m_totalPackets.load(std::memory_order_relaxed);
    r.udpBytesPerSec= m_udpBytesPerSec.load(std::memory_order_relaxed);
    r.udpEmaBytes   = m_udpEmaBytes.load(std::memory_order_relaxed);
    r.udpFloodAlert = m_udpFloodAlert.load(std::memory_order_relaxed);
    return r;
}

void PacketInspector::captureLoop()
{
#if defined(__linux__)
    unsigned char frameBuf[65535];
    using Clock = std::chrono::steady_clock;
    auto lastEmaUpdate = Clock::now();

    while (m_running.load())
    {
        const int bytes = static_cast<int>(
            ::recvfrom(m_sockFd, frameBuf, sizeof(frameBuf), 0, nullptr, nullptr));

        if (bytes < 0) break;

        classifyFrame(frameBuf, bytes);

        auto now = Clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastEmaUpdate).count() >= 1)
        {
            updateAnomalyDetector(m_udpBytesAccum.exchange(0, std::memory_order_relaxed));
            lastEmaUpdate = now;
        }
    }
#endif
}

void PacketInspector::classifyFrame(const unsigned char* buf, int length) noexcept
{
#if defined(__linux__)
    m_totalPackets.fetch_add(1, std::memory_order_relaxed);

    if (length < MIN_FRAME_LEN) { m_otherPackets.fetch_add(1, std::memory_order_relaxed); return; }

    const uint16_t etherType =
        (static_cast<uint16_t>(buf[ETH_ETYPE_OFFSET]) << 8) |
         static_cast<uint16_t>(buf[ETH_ETYPE_OFFSET + 1]);

    if (etherType != ETYPE_IPV4) { m_otherPackets.fetch_add(1, std::memory_order_relaxed); return; }

    switch (static_cast<int>(buf[IPV4_PROTO_OFFSET]))
    {
        case PROTO_TCP:
            m_tcpPackets.fetch_add(1, std::memory_order_relaxed); break;
        case PROTO_UDP:
            m_udpPackets.fetch_add(1, std::memory_order_relaxed);
            m_udpBytesAccum.fetch_add(static_cast<uint64_t>(length), std::memory_order_relaxed);
            break;
        case PROTO_ICMP:
            m_icmpPackets.fetch_add(1, std::memory_order_relaxed); break;
        default:
            m_otherPackets.fetch_add(1, std::memory_order_relaxed); break;
    }
#else
    (void)buf; (void)length;
#endif
}

void PacketInspector::updateAnomalyDetector(uint64_t udpBytesInInterval) noexcept
{
    double ema = m_udpEmaBytes.load(std::memory_order_relaxed);
    ema = EMA_ALPHA * static_cast<double>(udpBytesInInterval) + (1.0 - EMA_ALPHA) * ema;
    m_udpEmaBytes.store(ema, std::memory_order_relaxed);
    m_udpBytesPerSec.store(udpBytesInInterval, std::memory_order_relaxed);

    const bool alert = (ema > static_cast<double>(MIN_EMA_THRESHOLD)) &&
                       (static_cast<double>(udpBytesInInterval) > SPIKE_MULTIPLIER * ema);
    m_udpFloodAlert.store(alert, std::memory_order_relaxed);
}

void PacketInspector::simulateLoop()
{
    using Clock = std::chrono::steady_clock;
    auto startTime     = Clock::now();
    auto lastEmaUpdate = Clock::now();

    while (m_running.load())
    {
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - startTime).count();

        // Simulate a 5-second UDP flood window every 30 seconds
        const double udpMult = ((elapsed % 30) >= 25) ? 8.0 : 1.0;

        const uint64_t newTcp  = static_cast<uint64_t>(SIM_BASE_PPS * SIM_TCP_RATIO  * 0.5);
        const uint64_t newUdp  = static_cast<uint64_t>(SIM_BASE_PPS * SIM_UDP_RATIO  * 0.5 * udpMult);
        const uint64_t newIcmp = static_cast<uint64_t>(SIM_BASE_PPS * SIM_ICMP_RATIO * 0.5);

        m_tcpPackets.fetch_add(newTcp,               std::memory_order_relaxed);
        m_udpPackets.fetch_add(newUdp,               std::memory_order_relaxed);
        m_icmpPackets.fetch_add(newIcmp,             std::memory_order_relaxed);
        m_totalPackets.fetch_add(newTcp+newUdp+newIcmp, std::memory_order_relaxed);
        m_udpBytesAccum.fetch_add(newUdp * 1400,    std::memory_order_relaxed);

        auto now = Clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastEmaUpdate).count() >= 1)
        {
            updateAnomalyDetector(m_udpBytesAccum.exchange(0, std::memory_order_relaxed));
            lastEmaUpdate = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}
