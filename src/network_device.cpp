/*
 * Network Packet Analyzer
 * Real-Time Linux Network Traffic & Telemetry Monitor
 * Language: C++17
 */

#include "network_device.hpp"

#include <utility>

NetworkDevice::NetworkDevice(std::string name)
    : m_name(std::move(name))
{
}

uint64_t NetworkDevice::fixCounterOverflow(uint64_t current, uint64_t previous)
{
    /**
     * SYSTEMS PROGRAMMING INSIGHT:
     * On Gigabit and 10-Gigabit links, 32-bit unsigned byte counters
     * (max value: 4,294,967,295 bytes) wrap around back to 0 every few seconds.
     *
     * 1. If 'current' is already > 4GB, the kernel driver natively tracks 64-bit counters.
     * 2. If 'current' is smaller than the lower 32 bits of 'previous', a 32-bit wraparound occurred.
     * 3. We accumulate +2^32 (0x100000000ULL) to preserve the true historical cumulative total.
     */
    if (current > 0xFFFFFFFFULL)
    {
        return current;
    }

    if (current < (previous & 0xFFFFFFFFULL))
    {
        previous += 0x100000000ULL;
    }

    previous &= 0xFFFFFFFF00000000ULL;
    return current | previous;
}

void NetworkDevice::update(const RawNetStats& raw, uint64_t timestamp_ms)
{
    RawNetStats adjusted = raw;

    if (m_hasInitialReading)
    {
        adjusted.rx_bytes   = fixCounterOverflow(raw.rx_bytes, m_previousRaw.rx_bytes);
        adjusted.rx_packets = fixCounterOverflow(raw.rx_packets, m_previousRaw.rx_packets);
        adjusted.rx_errors  = fixCounterOverflow(raw.rx_errors, m_previousRaw.rx_errors);
        adjusted.rx_dropped = fixCounterOverflow(raw.rx_dropped, m_previousRaw.rx_dropped);

        adjusted.tx_bytes   = fixCounterOverflow(raw.tx_bytes, m_previousRaw.tx_bytes);
        adjusted.tx_packets = fixCounterOverflow(raw.tx_packets, m_previousRaw.tx_packets);
        adjusted.tx_errors  = fixCounterOverflow(raw.tx_errors, m_previousRaw.tx_errors);
        adjusted.tx_dropped = fixCounterOverflow(raw.tx_dropped, m_previousRaw.tx_dropped);
    }
    else
    {
        m_hasInitialReading = true;
    }

    m_previousRaw = adjusted;

    // Update Inbound (Rx) and Outbound (Tx) rolling metrics
    m_rxStats.addSample(timestamp_ms, adjusted.rx_bytes, adjusted.rx_packets,
                        adjusted.rx_errors, adjusted.rx_dropped);
    m_txStats.addSample(timestamp_ms, adjusted.tx_bytes, adjusted.tx_packets,
                        adjusted.tx_errors, adjusted.tx_dropped);
}
