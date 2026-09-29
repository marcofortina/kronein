// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_CHILD_NET_EVENTS_H
#define BITCOIN_NODE_CHILD_NET_EVENTS_H

#include <net.h>
#include <node/child_bandwidth.h>
#include <node/child_net_processor.h>
#include <sync.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>

class CTransaction;

namespace node {

inline constexpr uint8_t MAX_CHILD_BLOCK_TIMEOUT_STRIKES{3};
inline constexpr size_t MAX_CHILD_KNOWN_ADDRESSES{4'096};
inline constexpr size_t MAX_CHILD_INBOUND_PER_NETGROUP{2};
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
        bool inbound_admitted{false};
        uint64_t keyed_netgroup{0};
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
    std::map<uint64_t, size_t> m_inbound_netgroups GUARDED_BY(m_mutex);
    uint64_t m_rate_limited_requests GUARDED_BY(m_mutex){0};
    uint64_t m_inbound_netgroup_rejections GUARDED_BY(m_mutex){0};
    const bool m_discovery;
    const size_t m_max_known_addresses;
    const size_t m_max_inbound_per_netgroup;

    void PushOutbound(CNode& current,
                      ChildNetOutbound&& outbound);
    void ApplyResult(CNode& current,
                     ChildNetProcessorResult&& result);
    ChildNetProcessorResult ProcessMessage(
        CNode& node,
        CNetMessage& message) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    ChildNetEvents(
        CConnman& connman,
        AddrMan& addrman,
        ChainManager& manager,
        ChildBandwidthLimiter& bandwidth,
        chainregistry::ReferenceChildDefinition definition,
        bool discovery,
        size_t max_known_addresses = MAX_CHILD_KNOWN_ADDRESSES,
        size_t max_inbound_per_netgroup = MAX_CHILD_INBOUND_PER_NETGROUP);

    void InitializeNode(const CNode& node,
                        ServiceFlags our_services) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void FinalizeNode(const CNode& node) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool HasAllDesirableServiceFlags(ServiceFlags services) const override;
    bool ProcessMessages(CNode& node,
                         std::atomic<bool>& interrupt) override
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex, !m_mutex);
    bool SendMessages(CNode& node) override
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex, !m_mutex);

    size_t RelayTransaction(const CTransactionRef& transaction)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t PeerCount() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    size_t HandshakenPeerCount() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    uint64_t RateLimitedRequests() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    uint64_t InboundNetgroupRejections() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    size_t KnownAddressCount() const;
};

} // namespace node

#endif // BITCOIN_NODE_CHILD_NET_EVENTS_H
