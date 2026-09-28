// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHILD_NET_EVENTS_H
#define KRONEIN_NODE_CHILD_NET_EVENTS_H

#include <net.h>
#include <node/child_net_processor.h>
#include <sync.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>

namespace node {

class ChildBandwidthLimiter;

inline constexpr uint8_t MAX_CHILD_BLOCK_TIMEOUT_STRIKES{3};
inline constexpr ChildRequestTime CHILD_NET_POLL_INTERVAL{
    std::chrono::milliseconds{100}};

/**
 * CConnman adapter for one child network.
 *
 * It deliberately implements only the child protocol and never forwards a
 * child message to the main-chain PeerManager. Processor access is serialized
 * because CConnman initializes and finalizes peers outside its message thread.
 */
class ChildNetEvents final : public NetEventsInterface
{
private:
    struct AddressRelayState {
        bool requested{false};
        bool received{false};
        bool served{false};
    };

    CConnman& m_connman;
    AddrMan& m_addrman;
    ChildNetProcessor m_processor;
    ChildBandwidthLimiter& m_bandwidth;
    mutable Mutex m_mutex;
    ChildRequestTime m_next_poll GUARDED_BY(m_mutex){0};
    std::map<ChildPeerId, uint8_t> m_timeout_strikes GUARDED_BY(m_mutex);
    std::map<ChildPeerId, AddressRelayState> m_address_relay
        GUARDED_BY(m_mutex);
    uint64_t m_rate_limited_requests GUARDED_BY(m_mutex){0};
    const bool m_discovery;

    void PushOutbound(CNode& current,
                      ChildNetOutbound&& outbound);
    void ApplyResult(CNode& current,
                     ChildNetProcessorResult&& result);
    ChildNetProcessorResult ProcessMessage(
        CNode& node,
        CNetMessage& message);

public:
    ChildNetEvents(
        CConnman& connman,
        AddrMan& addrman,
        ChainManager& manager,
        ChildBandwidthLimiter& bandwidth,
        chainregistry::ReferenceChildDefinition definition,
        bool discovery);

    void InitializeNode(const CNode& node,
                        ServiceFlags our_services) override;
    void FinalizeNode(const CNode& node) override;
    bool HasAllDesirableServiceFlags(ServiceFlags services) const override;
    bool ProcessMessages(CNode& node,
                         std::atomic<bool>& interrupt) override
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);
    bool SendMessages(CNode& node) override
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    size_t PeerCount() const;
    size_t HandshakenPeerCount() const;
    uint64_t RateLimitedRequests() const;
    size_t KnownAddressCount() const;
};

} // namespace node

#endif // KRONEIN_NODE_CHILD_NET_EVENTS_H
