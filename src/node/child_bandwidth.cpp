// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_bandwidth.h>

#include <algorithm>
#include <limits>

namespace node {

void ChildBandwidthLimiter::RefreshCycle(std::chrono::seconds now) const
{
    AssertLockHeld(m_mutex);
    if (m_cycle_started && now >= m_cycle_start + CHILD_UPLOAD_TIMEFRAME) {
        m_cycle_started = false;
        m_cycle_start = std::chrono::seconds{0};
        m_bytes_sent = 0;
    }
}

bool ChildBandwidthLimiter::TryReserve(
    uint64_t bytes,
    std::chrono::seconds now)
{
    LOCK(m_mutex);
    RefreshCycle(now);
    if (!m_cycle_started) {
        m_cycle_started = true;
        m_cycle_start = now;
    }
    if (m_target != 0 &&
        (m_bytes_sent >= m_target || bytes > m_target - m_bytes_sent)) {
        return false;
    }
    if (bytes > std::numeric_limits<uint64_t>::max() - m_bytes_sent) {
        m_bytes_sent = std::numeric_limits<uint64_t>::max();
    } else {
        m_bytes_sent += bytes;
    }
    return true;
}

ChildBandwidthStats ChildBandwidthLimiter::GetStats(
    std::chrono::seconds now) const
{
    LOCK(m_mutex);
    RefreshCycle(now);
    const bool reached{m_target != 0 && m_bytes_sent >= m_target};
    const std::chrono::seconds time_left{
        m_target == 0 ? std::chrono::seconds{0} :
        !m_cycle_started ? CHILD_UPLOAD_TIMEFRAME :
        std::max(std::chrono::seconds{0},
                 m_cycle_start + CHILD_UPLOAD_TIMEFRAME - now)};
    return {
        .target = m_target,
        .bytes_sent = m_bytes_sent,
        .bytes_left = m_target == 0 || reached ? 0 : m_target - m_bytes_sent,
        .timeframe = CHILD_UPLOAD_TIMEFRAME,
        .time_left = time_left,
        .target_reached = reached,
    };
}

} // namespace node
