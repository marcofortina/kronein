// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_CHILD_BANDWIDTH_H
#define BITCOIN_NODE_CHILD_BANDWIDTH_H

#include <sync.h>

#include <chrono>
#include <cstdint>

namespace node {

inline constexpr std::chrono::seconds CHILD_UPLOAD_TIMEFRAME{
    std::chrono::hours{24}};

struct ChildBandwidthStats {
    uint64_t target{0};
    uint64_t bytes_sent{0};
    uint64_t bytes_left{0};
    std::chrono::seconds timeframe{0};
    std::chrono::seconds time_left{0};
    bool target_reached{false};
};

/** Process-wide block-serving budget shared by every child network. */
class ChildBandwidthLimiter
{
private:
    const uint64_t m_target;
    mutable Mutex m_mutex;
    mutable bool m_cycle_started GUARDED_BY(m_mutex){false};
    mutable std::chrono::seconds m_cycle_start GUARDED_BY(m_mutex){0};
    mutable uint64_t m_bytes_sent GUARDED_BY(m_mutex){0};

    void RefreshCycle(std::chrono::seconds now) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    explicit ChildBandwidthLimiter(uint64_t target) : m_target{target} {}

    bool TryReserve(uint64_t bytes, std::chrono::seconds now)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    ChildBandwidthStats GetStats(std::chrono::seconds now) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};

} // namespace node

#endif // BITCOIN_NODE_CHILD_BANDWIDTH_H
