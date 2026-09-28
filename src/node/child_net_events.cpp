// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_net_events.h>

#include <addrman.h>
#include <chainregistry/child_net.h>
#include <netmessagemaker.h>
#include <node/child_network_manager.h>
#include <util/time.h>

#include <algorithm>
#include <exception>
#include <limits>
#include <set>
#include <string>
#include <utility>
#include <variant>

namespace node {
namespace {

ChildRequestTime RequestTimeNow()
{
    return ChildRequestTime{
        TicksSinceEpoch<std::chrono::microseconds>(
            MockableSteadyClock::now())};
}

int64_t ValidationTimeNow()
{
    return TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
}

ChildNetProcessorResult InvalidAddressMessage()
{
    ChildNetProcessorResult result;
    result.error = ChildNetProcessorError::INVALID_MESSAGE;
    result.disconnect = true;
    return result;
}

std::string ChildMessageType(ChildNetCommand command)
{
    switch (command) {
    case ChildNetCommand::HELLO:
        return std::string{chainregistry::ChildNetMsgType::HELLO};
    case ChildNetCommand::INVENTORY:
        return std::string{chainregistry::ChildNetMsgType::INVENTORY};
    case ChildNetCommand::GET_BLOCKS:
        return std::string{chainregistry::ChildNetMsgType::GET_BLOCKS};
    case ChildNetCommand::BLOCK:
        return std::string{chainregistry::ChildNetMsgType::BLOCK};
    }
    return {};
}

} // namespace

ChildNetEvents::ChildNetEvents(
    CConnman& connman,
    AddrMan& addrman,
    ChainManager& manager,
    ChildBandwidthLimiter& bandwidth,
    chainregistry::ReferenceChildDefinition definition,
    bool discovery)
    : m_connman{connman},
      m_addrman{addrman},
      m_processor{manager, std::move(definition)},
      m_bandwidth{bandwidth},
      m_discovery{discovery}
{
}

void ChildNetEvents::PushOutbound(
    CNode& current,
    ChildNetOutbound&& outbound)
{
    const std::string message_type{ChildMessageType(outbound.command)};
    CSerializedNetMsg message{std::visit(
        [&](auto&& payload) {
            return NetMsg::Make(message_type, payload);
        },
        std::move(outbound.message))};
    if (outbound.command == ChildNetCommand::BLOCK &&
        !m_bandwidth.TryReserve(
            message.data.size(),
            std::chrono::duration_cast<std::chrono::seconds>(
                MockableSteadyClock::now().time_since_epoch()))) {
        return;
    }
    auto push{[&](CNode& target) {
        m_connman.PushMessage(&target, std::move(message));
    }};

    if (outbound.peer == current.GetId()) {
        push(current);
        return;
    }
    m_connman.ForNode(
        outbound.peer,
        [&](CNode* target) {
            push(*target);
            return true;
        });
}

void ChildNetEvents::ApplyResult(
    CNode& current,
    ChildNetProcessorResult&& result)
{
    if (result.disconnect) current.fDisconnect = true;
    for (const ChildPeerId peer : result.disconnect_peers) {
        if (peer == current.GetId()) {
            current.fDisconnect = true;
            continue;
        }
        m_connman.ForNode(
            peer,
            [](CNode* target) {
                target->fDisconnect = true;
                return true;
            });
    }
    for (auto& outbound : result.outbound) {
        PushOutbound(current, std::move(outbound));
    }
}

void ChildNetEvents::InitializeNode(
    const CNode& node,
    ServiceFlags)
{
    LOCK(m_mutex);
    CNode& mutable_node{const_cast<CNode&>(node)};
    m_address_relay.emplace(node.GetId(), AddressRelayState{});
    ApplyResult(
        mutable_node,
        m_processor.Connected(node.GetId(), node.GetLocalNonce()));
}

void ChildNetEvents::FinalizeNode(const CNode& node)
{
    LOCK(m_mutex);
    if (node.fSuccessfullyConnected && !node.IsInboundConn()) {
        m_addrman.Connected(node.addr);
    }
    m_processor.Disconnected(node.GetId());
    m_timeout_strikes.erase(node.GetId());
    m_address_relay.erase(node.GetId());
}

bool ChildNetEvents::HasAllDesirableServiceFlags(ServiceFlags) const
{
    return true;
}

ChildNetProcessorResult ChildNetEvents::ProcessMessage(
    CNode& node,
    CNetMessage& message)
{
    const ChildPeerId peer{node.GetId()};
    if (message.m_type == chainregistry::ChildNetMsgType::HELLO) {
        chainregistry::ChildNetHello hello;
        message.m_recv >> hello;
        if (!message.m_recv.empty()) {
            ChildNetProcessorResult result;
            result.error = ChildNetProcessorError::INVALID_MESSAGE;
            result.disconnect = true;
            return result;
        }
        if (node.IsInboundConn() &&
            !m_connman.CheckIncomingNonce(hello.nonce)) {
            ChildNetProcessorResult result;
            result.error = ChildNetProcessorError::INVALID_MESSAGE;
            result.disconnect = true;
            return result;
        }
        auto result{m_processor.ReceiveHello(peer, hello)};
        if (result.IsValid()) {
            node.fSuccessfullyConnected = true;
            if (!node.IsInboundConn()) m_addrman.Good(node.addr);
            auto relay{m_address_relay.find(peer)};
            if (m_discovery && !node.IsInboundConn() &&
                relay != m_address_relay.end() &&
                !relay->second.requested) {
                m_connman.PushMessage(
                    &node,
                    NetMsg::Make(
                        std::string{
                            chainregistry::ChildNetMsgType::GET_ADDRESSES},
                        chainregistry::ChildAddressRequest{
                            .chain_id = m_processor.ChainId(),
                        }));
                relay->second.requested = true;
            }
        }
        return result;
    }
    if (message.m_type == chainregistry::ChildNetMsgType::GET_ADDRESSES) {
        chainregistry::ChildAddressRequest request;
        message.m_recv >> request;
        if (!message.m_recv.empty() || !m_discovery ||
            !m_processor.IsHandshaken(peer)) {
            return InvalidAddressMessage();
        }
        const auto validation{chainregistry::ValidateChildAddressRequest(
            request, m_processor.ChainId())};
        auto relay{m_address_relay.find(peer)};
        if (validation != chainregistry::ChildNetValidationError::NONE ||
            relay == m_address_relay.end() || relay->second.served) {
            return InvalidAddressMessage();
        }
        relay->second.served = true;

        chainregistry::ChildAddresses response{
            .chain_id = m_processor.ChainId(),
            .addresses = {},
        };
        const CService peer_endpoint{node.addr};
        for (const CAddress& address : m_addrman.GetAddr(
                 chainregistry::MAX_CHILD_RELAY_ADDRESSES,
                 /*max_pct=*/100,
                 /*network=*/std::nullopt)) {
            const CService endpoint{address};
            if (endpoint == peer_endpoint || !endpoint.IsRoutable() ||
                (!endpoint.IsIPv4() && !endpoint.IsIPv6()) ||
                endpoint.GetPort() == 0) {
                continue;
            }
            const int64_t seconds{
                TicksSinceEpoch<std::chrono::seconds>(address.nTime)};
            response.addresses.push_back({
                .time = static_cast<uint32_t>(std::clamp<int64_t>(
                    seconds, 0, std::numeric_limits<uint32_t>::max())),
                .endpoint = endpoint,
            });
        }
        m_connman.PushMessage(
            &node,
            NetMsg::Make(
                std::string{chainregistry::ChildNetMsgType::ADDRESSES},
                response));
        return {};
    }
    if (message.m_type == chainregistry::ChildNetMsgType::ADDRESSES) {
        chainregistry::ChildAddresses received;
        message.m_recv >> received;
        if (!message.m_recv.empty() || !m_discovery ||
            !m_processor.IsHandshaken(peer)) {
            return InvalidAddressMessage();
        }
        const auto validation{chainregistry::ValidateChildAddresses(
            received, m_processor.ChainId())};
        auto relay{m_address_relay.find(peer)};
        if (validation != chainregistry::ChildNetValidationError::NONE ||
            relay == m_address_relay.end() || !relay->second.requested ||
            relay->second.received) {
            return InvalidAddressMessage();
        }
        relay->second.received = true;

        const NodeSeconds now{Now<NodeSeconds>()};
        std::vector<CAddress> addresses;
        addresses.reserve(received.addresses.size());
        for (const auto& address : received.addresses) {
            NodeSeconds seen{
                std::chrono::seconds{address.time}};
            if (seen <= NodeSeconds{std::chrono::seconds{100000000}} ||
                seen > now + std::chrono::minutes{10}) {
                seen = now - std::chrono::hours{5 * 24};
            }
            addresses.emplace_back(
                address.endpoint, NODE_NETWORK, seen);
        }
        m_addrman.Add(
            addresses,
            static_cast<const CNetAddr&>(node.addr),
            std::chrono::hours{2});
        return {};
    }
    if (message.m_type == chainregistry::ChildNetMsgType::INVENTORY) {
        chainregistry::ChildBlockHashes inventory;
        message.m_recv >> inventory;
        if (!message.m_recv.empty()) {
            ChildNetProcessorResult result;
            result.error = ChildNetProcessorError::INVALID_MESSAGE;
            result.disconnect = true;
            return result;
        }
        return m_processor.ReceiveInventory(
            peer, inventory, RequestTimeNow());
    }
    if (message.m_type == chainregistry::ChildNetMsgType::GET_BLOCKS) {
        chainregistry::ChildBlockHashes request;
        message.m_recv >> request;
        if (!message.m_recv.empty()) {
            ChildNetProcessorResult result;
            result.error = ChildNetProcessorError::INVALID_MESSAGE;
            result.disconnect = true;
            return result;
        }
        auto result{m_processor.ReceiveGetBlocks(
            peer, request, RequestTimeNow())};
        if (result.error ==
            ChildNetProcessorError::REQUEST_RATE_LIMITED) {
            ++m_rate_limited_requests;
        }
        return result;
    }
    if (message.m_type == chainregistry::ChildNetMsgType::BLOCK) {
        chainregistry::ChildBlockData block;
        message.m_recv >> block;
        if (!message.m_recv.empty()) {
            ChildNetProcessorResult result;
            result.error = ChildNetProcessorError::INVALID_MESSAGE;
            result.disconnect = true;
            return result;
        }
        auto result{m_processor.ReceiveBlock(
            peer,
            block,
            RequestTimeNow(),
            ValidationTimeNow(),
            /*sync=*/false)};
        if (!result.accepted_blocks.empty()) {
            m_timeout_strikes.erase(peer);
        }
        return result;
    }

    ChildNetProcessorResult result;
    result.error = ChildNetProcessorError::INVALID_MESSAGE;
    result.disconnect = true;
    return result;
}

bool ChildNetEvents::ProcessMessages(
    CNode& node,
    std::atomic<bool>& interrupt)
{
    auto polled{node.PollMessage()};
    if (!polled) return false;
    if (interrupt) return false;

    LOCK(m_mutex);
    try {
        ApplyResult(
            node,
            ProcessMessage(node, polled->first));
    } catch (const std::exception&) {
        node.fDisconnect = true;
    }
    return polled->second;
}

bool ChildNetEvents::SendMessages(CNode& node)
{
    const ChildRequestTime now{RequestTimeNow()};
    LOCK(m_mutex);
    if (now < m_next_poll) return false;
    m_next_poll = now + CHILD_NET_POLL_INTERVAL;

    auto result{m_processor.Poll(
        now, ValidationTimeNow(), /*sync=*/false)};
    std::set<ChildPeerId> stalled;
    for (const ChildBlockRequest& request : result.expired_requests) {
        stalled.insert(request.peer);
    }
    for (const ChildPeerId peer : stalled) {
        uint8_t& strikes{m_timeout_strikes[peer]};
        if (++strikes < MAX_CHILD_BLOCK_TIMEOUT_STRIKES) continue;
        result.disconnect_peers.push_back(peer);
        m_timeout_strikes.erase(peer);
    }
    ApplyResult(node, std::move(result));
    return false;
}

size_t ChildNetEvents::PeerCount() const
{
    LOCK(m_mutex);
    return m_processor.PeerCount();
}

size_t ChildNetEvents::HandshakenPeerCount() const
{
    LOCK(m_mutex);
    return m_processor.HandshakenPeerCount();
}

uint64_t ChildNetEvents::RateLimitedRequests() const
{
    LOCK(m_mutex);
    return m_rate_limited_requests;
}

size_t ChildNetEvents::KnownAddressCount() const
{
    return m_addrman.Size();
}

} // namespace node
