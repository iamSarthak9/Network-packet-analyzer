/*
 * Network Packet Analyzer
 * Real-Time Linux Network Traffic & Telemetry Monitor
 * Language: C++17
 */

#include "traffic_stats.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

TrafficStats::TrafficStats(std::size_t maxHistory, uint64_t avgWindowMs)
    : m_maxHistory(maxHistory), m_avgWindowMs(avgWindowMs)
{
}

void TrafficStats::addSample(
    uint64_t timestamp_ms,
    uint64_t totalBytes,
    uint64_t totalPackets,
    uint64_t totalErrors,
    uint64_t totalDrops
)
{
    m_totalBytes   = totalBytes;
    m_totalPackets = totalPackets;
    m_totalErrors  = totalErrors;
    m_totalDrops   = totalDrops;

    Snapshot curSample{timestamp_ms, totalBytes, totalPackets, totalErrors, totalDrops};

    if (!m_window.empty())
    {
        const auto& prev = m_window.back();
        const double deltaSec = static_cast<double>(timestamp_ms - prev.timestamp_ms) / 1000.0;

        if (deltaSec > 0.0001)
        {
            // Instantaneous rates
            m_currentBytesPerSec   = static_cast<double>(totalBytes - prev.bytes) / deltaSec;
            m_currentPacketsPerSec = static_cast<double>(totalPackets - prev.packets) / deltaSec;

            // Track min and max peak throughput
            if (m_maxBytesPerSec == 0.0 && m_minBytesPerSec == 0.0)
            {
                m_maxBytesPerSec = m_currentBytesPerSec;
                m_minBytesPerSec = m_currentBytesPerSec;
            }
            else
            {
                m_maxBytesPerSec = std::max(m_maxBytesPerSec, m_currentBytesPerSec);
                m_minBytesPerSec = std::min(m_minBytesPerSec, m_currentBytesPerSec);
            }

            // Append to rate history buffer
            m_rateHistory.push_back(m_currentBytesPerSec);
            while (m_rateHistory.size() > m_maxHistory)
            {
                m_rateHistory.pop_front();
            }
        }
    }

    m_window.push_back(curSample);

    // Evict old samples outside average window in O(1) amortized time
    while (m_window.size() > 1 && (timestamp_ms - m_window.front().timestamp_ms) > m_avgWindowMs)
    {
        m_window.pop_front();
    }

    // Compute rolling average throughput across the window
    if (m_window.size() > 1)
    {
        const double windowSec = static_cast<double>(m_window.back().timestamp_ms - m_window.front().timestamp_ms) / 1000.0;
        if (windowSec > 0.0001)
        {
            m_averageBytesPerSec = static_cast<double>(m_window.back().bytes - m_window.front().bytes) / windowSec;
        }
    }
    else
    {
        m_averageBytesPerSec = m_currentBytesPerSec;
    }
}

std::string TrafficStats::formatBytes(uint64_t bytes)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    if (bytes < 1024ULL)
    {
        oss << bytes << " B";
    }
    else if (bytes < 1024ULL * 1024ULL)
    {
        oss << (static_cast<double>(bytes) / 1024.0) << " KB";
    }
    else if (bytes < 1024ULL * 1024ULL * 1024ULL)
    {
        oss << (static_cast<double>(bytes) / (1024.0 * 1024.0)) << " MB";
    }
    else
    {
        oss << (static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0)) << " GB";
    }

    return oss.str();
}

std::string TrafficStats::formatBitsPerSec(double bytesPerSec)
{
    const double bitsPerSec = bytesPerSec * 8.0;
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    if (bitsPerSec < 1000.0)
    {
        oss << bitsPerSec << " bit/s";
    }
    else if (bitsPerSec < 1000000.0)
    {
        oss << (bitsPerSec / 1000.0) << " kbit/s";
    }
    else if (bitsPerSec < 1000000000.0)
    {
        oss << (bitsPerSec / 1000000.0) << " Mbit/s";
    }
    else
    {
        oss << (bitsPerSec / 1000000000.0) << " Gbit/s";
    }

    return oss.str();
}
