// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_net_processor.h>

#include <consensus/consensus.h>

#include <algorithm>
#include <array>
#include <span>
#include <utility>

namespace node {
namespace {

ChildNetProcessorResult ProcessorError(
    ChildNetProcessorError error,
    bool disconnect = false)
{
    ChildNetProcessorResult result;
    result.error = error;
    result.disconnect = disconnect;
    return result;
}

} // namespace

ChildNetProcessor::ChildNetProcessor(
    ChainManager& manager,
    chainregistry::ReferenceChildDefinition definition)
    : m_manager{manager}, m_definition{std::move(definition)}
{
    const auto registered{m_manager.Definition(m_definition.chain_id)};
    const auto validated{chainregistry::ValidateReferenceChildManifest(
        m_definition.genesis.main_genesis_hash,
        m_definition.genesis.registration_anchor,
        m_definition.manifest)};
    m_ready = !m_definition.chain_id.IsNull() && registered &&
              *registered == m_definition && validated.IsValid() &&
              *validated.definition == m_definition;
}

bool ChildNetProcessor::RequireHandshake(
    ChildPeerId peer,
    ChildNetProcessorResult& result) const
{
    const auto it{m_peers.find(peer)};
    if (it == m_peers.end()) {
        result.error = ChildNetProcessorError::UNKNOWN_PEER;
        result.disconnect = true;
        return false;
    }
    if (!it->second.handshaken) {
        result.error = ChildNetProcessorError::HANDSHAKE_REQUIRED;
        result.disconnect = true;
        return false;
    }
    return true;
}

void ChildNetProcessor::EraseDeferred(const uint256& block_hash)
{
    const auto it{m_deferred.find(block_hash)};
    if (it == m_deferred.end()) return;
    m_deferred_bytes -= it->second.serialized_size;
    m_deferred.erase(it);
}

bool ChildNetProcessor::RefreshPending(ChildNetProcessorResult& result)
{
    const auto view{m_manager.GetPendingBlocksView(m_definition.chain_id)};
    if (!view.IsValid()) {
        result.error = ChildNetProcessorError::PENDING_BLOCKS_UNAVAILABLE;
        return false;
    }

    std::map<uint256, uint32_t> next;
    for (const ChildPendingBlockView& block : view.blocks) {
        next.emplace(block.block_hash, block.oldest_anchor_height);
    }
    for (const auto& entry : m_pending) {
        const uint256& hash{entry.first};
        if (next.contains(hash)) continue;
        m_downloads.ForgetBlock(hash);
        EraseDeferred(hash);
    }
    m_pending = std::move(next);
    return true;
}

void ChildNetProcessor::SchedulePeer(
    ChildPeerId peer,
    ChildRequestTime now,
    ChildNetProcessorResult& result)
{
    const auto hashes{m_downloads.Schedule(peer, now)};
    if (hashes.empty()) return;
    result.outbound.push_back({
        .peer = peer,
        .command = ChildNetCommand::GET_BLOCKS,
        .message = chainregistry::ChildBlockHashes{
            .chain_id = m_definition.chain_id,
            .block_hashes = hashes,
        },
    });
}

void ChildNetProcessor::AnnounceAccepted(
    std::optional<ChildPeerId> source,
    const uint256& block_hash,
    ChildNetProcessorResult& result) const
{
    for (const auto& [peer, state] : m_peers) {
        if (!state.handshaken || (source && peer == *source)) continue;
        result.outbound.push_back({
            .peer = peer,
            .command = ChildNetCommand::INVENTORY,
            .message = chainregistry::ChildBlockHashes{
                .chain_id = m_definition.chain_id,
                .block_hashes = {block_hash},
            },
        });
    }
}

ChildNetProcessorResult ChildNetProcessor::Connected(
    ChildPeerId peer,
    uint64_t local_nonce)
{
    if (!m_ready) {
        return ProcessorError(ChildNetProcessorError::INVALID_DEFINITION);
    }
    if (m_peers.contains(peer)) {
        return ProcessorError(
            ChildNetProcessorError::PEER_ALREADY_CONNECTED,
            /*disconnect=*/true);
    }
    m_peers.emplace(peer, PeerState{});
    ChildNetProcessorResult result;
    result.outbound.push_back({
        .peer = peer,
        .command = ChildNetCommand::HELLO,
        .message = chainregistry::ChildNetHello{
            .nonce = local_nonce,
            .chain_id = m_definition.chain_id,
            .genesis_hash = m_definition.genesis_hash,
        },
    });
    return result;
}

void ChildNetProcessor::Disconnected(ChildPeerId peer)
{
    m_downloads.DisconnectedPeer(peer);
    m_peers.erase(peer);
}

ChildNetProcessorResult ChildNetProcessor::ReceiveHello(
    ChildPeerId peer,
    const chainregistry::ChildNetHello& hello)
{
    ChildNetProcessorResult result;
    const auto peer_it{m_peers.find(peer)};
    if (peer_it == m_peers.end()) {
        return ProcessorError(
            ChildNetProcessorError::UNKNOWN_PEER,
            /*disconnect=*/true);
    }
    result.validation_error = chainregistry::ValidateChildNetHello(
        hello, m_definition.chain_id, m_definition.genesis_hash);
    if (result.validation_error !=
        chainregistry::ChildNetValidationError::NONE) {
        result.error = ChildNetProcessorError::INVALID_MESSAGE;
        result.disconnect = true;
        return result;
    }
    peer_it->second.handshaken = true;

    const auto tip{m_manager.GetTipBlockView(m_definition.chain_id)};
    if (tip.IsValid() && tip.block.block) {
        result.outbound.push_back({
            .peer = peer,
            .command = ChildNetCommand::INVENTORY,
            .message = chainregistry::ChildBlockHashes{
                .chain_id = m_definition.chain_id,
                .block_hashes = {tip.block.block_hash},
            },
        });
    }
    RefreshPending(result);
    return result;
}

ChildNetProcessorResult ChildNetProcessor::ReceiveInventory(
    ChildPeerId peer,
    const chainregistry::ChildBlockHashes& inventory,
    ChildRequestTime now)
{
    ChildNetProcessorResult result;
    if (!RequireHandshake(peer, result)) return result;
    result.validation_error = chainregistry::ValidateChildBlockHashes(
        inventory, m_definition.chain_id);
    if (result.validation_error !=
        chainregistry::ChildNetValidationError::NONE) {
        result.error = ChildNetProcessorError::INVALID_MESSAGE;
        result.disconnect = true;
        return result;
    }
    if (!RefreshPending(result)) return result;

    std::vector<uint256> wanted;
    for (const uint256& hash : inventory.block_hashes) {
        if (m_pending.contains(hash)) {
            wanted.push_back(hash);
            continue;
        }
        if (m_manager.GetBlockView(m_definition.chain_id, hash).IsValid()) {
            continue;
        }
        result.error = ChildNetProcessorError::UNAUTHENTICATED_BLOCK;
        result.disconnect = true;
        return result;
    }
    if (wanted.empty()) return result;

    result.download_error = m_downloads.Announce(peer, wanted);
    if (result.download_error != ChildBlockDownloadError::NONE) {
        result.error = ChildNetProcessorError::DOWNLOAD_REJECTED;
        result.disconnect = true;
        return result;
    }
    for (const uint256& hash : wanted) {
        m_downloads.SetPriority(hash, m_pending.at(hash));
    }
    SchedulePeer(peer, now, result);
    return result;
}

ChildNetProcessorResult ChildNetProcessor::ReceiveGetBlocks(
    ChildPeerId peer,
    const chainregistry::ChildBlockHashes& request,
    ChildRequestTime now)
{
    ChildNetProcessorResult result;
    if (!RequireHandshake(peer, result)) return result;
    result.validation_error = chainregistry::ValidateChildBlockHashes(
        request, m_definition.chain_id);
    if (result.validation_error !=
        chainregistry::ChildNetValidationError::NONE) {
        result.error = ChildNetProcessorError::INVALID_MESSAGE;
        result.disconnect = true;
        return result;
    }

    PeerState& state{m_peers.at(peer)};
    if (!state.block_request_refill_time) {
        state.block_request_refill_time = now;
    } else if (now > *state.block_request_refill_time) {
        const auto intervals{
            (now - *state.block_request_refill_time) /
            CHILD_GETBLOCKS_REFILL_INTERVAL};
        if (intervals > 0) {
            const uint64_t refill{std::min<uint64_t>(
                MAX_CHILD_GETBLOCKS_BURST_HASHES,
                static_cast<uint64_t>(intervals))};
            state.block_request_tokens = std::min(
                MAX_CHILD_GETBLOCKS_BURST_HASHES,
                state.block_request_tokens + refill);
            if (state.block_request_tokens ==
                MAX_CHILD_GETBLOCKS_BURST_HASHES) {
                state.block_request_refill_time = now;
            } else {
                *state.block_request_refill_time +=
                    CHILD_GETBLOCKS_REFILL_INTERVAL * refill;
            }
        }
    }
    if (request.block_hashes.size() > state.block_request_tokens) {
        result.error = ChildNetProcessorError::REQUEST_RATE_LIMITED;
        result.disconnect = true;
        return result;
    }
    state.block_request_tokens -= request.block_hashes.size();

    size_t response_bytes{0};
    for (const uint256& hash : request.block_hashes) {
        const auto view{
            m_manager.GetBlockView(m_definition.chain_id, hash)};
        if (!view.IsValid() || !view.block.block) continue;
        const size_t block_size{
            GetSerializeSize(TX_WITH_WITNESS(*view.block.block))};
        if (block_size > MAX_BLOCK_SERIALIZED_SIZE ||
            block_size > MAX_CHILD_BLOCK_RESPONSE_BYTES - response_bytes) {
            break;
        }
        response_bytes += block_size;
        result.outbound.push_back({
            .peer = peer,
            .command = ChildNetCommand::BLOCK,
            .message = chainregistry::ChildBlockData{
                .chain_id = m_definition.chain_id,
                .block = *view.block.block,
            },
        });
    }
    return result;
}

void ChildNetProcessor::RetryDeferred(
    int64_t current_time,
    bool sync,
    ChildNetProcessorResult& result)
{
    bool advanced{true};
    while (advanced) {
        advanced = false;
        for (auto it{m_deferred.begin()}; it != m_deferred.end();) {
            const uint256 hash{it->first};
            const CBlock& block{it->second.block};
            const ChildPeerId source{it->second.source};
            const auto submitted{m_manager.SubmitBlockData(
                m_definition.chain_id, block, current_time, sync)};
            if (submitted.error == ChainManagerError::RUNTIME_REJECTED &&
                submitted.runtime.error ==
                    ReferenceChildRuntimeError::CHILD_PARENT_UNAVAILABLE) {
                ++it;
                continue;
            }

            m_deferred_bytes -= it->second.serialized_size;
            it = m_deferred.erase(it);
            if (submitted.IsValid()) {
                result.accepted_blocks.push_back(hash);
                m_downloads.ForgetBlock(hash);
                m_pending.erase(hash);
                AnnounceAccepted(std::optional{source}, hash, result);
                advanced = true;
            } else {
                result.rejected_blocks.push_back(hash);
                result.disconnect_peers.push_back(source);
            }
        }
    }
}

ChildNetProcessorResult ChildNetProcessor::ReceiveBlock(
    ChildPeerId peer,
    const chainregistry::ChildBlockData& data,
    ChildRequestTime now,
    int64_t current_time,
    bool sync)
{
    ChildNetProcessorResult result;
    if (!RequireHandshake(peer, result)) return result;

    const uint256 block_hash{data.block.GetHash()};
    result.validation_error = chainregistry::ValidateChildBlockData(
        data, m_definition.chain_id, block_hash);
    if (result.validation_error !=
        chainregistry::ChildNetValidationError::NONE) {
        result.error = ChildNetProcessorError::INVALID_MESSAGE;
        result.disconnect = true;
        return result;
    }
    if (!RefreshPending(result)) return result;
    if (!m_pending.contains(block_hash)) {
        m_downloads.ForgetBlock(block_hash);
        return result;
    }
    result.download_error = m_downloads.ReceivedBlock(peer, block_hash);
    if (result.download_error != ChildBlockDownloadError::NONE) {
        result.error = ChildNetProcessorError::DOWNLOAD_REJECTED;
        result.disconnect = true;
        return result;
    }

    result.submission = m_manager.SubmitBlockData(
        m_definition.chain_id, data.block, current_time, sync);
    if (result.submission.error == ChainManagerError::RUNTIME_REJECTED &&
        result.submission.runtime.error ==
            ReferenceChildRuntimeError::CHILD_PARENT_UNAVAILABLE) {
        const size_t block_size{
            GetSerializeSize(TX_WITH_WITNESS(data.block))};
        if (m_deferred.size() >= MAX_DEFERRED_CHILD_BLOCKS ||
            block_size > MAX_DEFERRED_CHILD_BLOCK_BYTES - m_deferred_bytes) {
            result.error = ChildNetProcessorError::DEFERRED_CACHE_FULL;
            return result;
        }
        m_deferred.emplace(
            block_hash,
            DeferredBlock{
                .block = data.block,
                .serialized_size = block_size,
                .expiry = now + DEFERRED_CHILD_BLOCK_TIMEOUT,
                .source = peer,
            });
        m_deferred_bytes += block_size;
        result.deferred_blocks.push_back(block_hash);

        const uint256& parent_hash{data.block.hashPrevBlock};
        const auto pending_parent{m_pending.find(parent_hash)};
        if (pending_parent != m_pending.end()) {
            const std::array<uint256, 1> parent{parent_hash};
            result.download_error = m_downloads.Announce(peer, parent);
            if (result.download_error == ChildBlockDownloadError::NONE) {
                m_downloads.SetPriority(
                    parent_hash, pending_parent->second);
                SchedulePeer(peer, now, result);
            }
        }
        return result;
    }
    if (!result.submission.IsValid()) {
        result.error = ChildNetProcessorError::BLOCK_REJECTED;
        result.rejected_blocks.push_back(block_hash);
        result.disconnect = true;
        return result;
    }

    result.accepted_blocks.push_back(block_hash);
    AnnounceAccepted(std::optional{peer}, block_hash, result);
    RefreshPending(result);
    RetryDeferred(current_time, sync, result);
    RefreshPending(result);
    return result;
}

ChildNetProcessorResult ChildNetProcessor::Poll(
    ChildRequestTime now,
    int64_t current_time,
    bool sync)
{
    ChildNetProcessorResult result;
    if (!RefreshPending(result)) return result;
    result.expired_requests = m_downloads.Expire(now);

    for (auto it{m_deferred.begin()}; it != m_deferred.end();) {
        if (it->second.expiry > now) {
            ++it;
            continue;
        }
        result.expired_deferred_blocks.push_back(it->first);
        m_deferred_bytes -= it->second.serialized_size;
        it = m_deferred.erase(it);
    }
    RetryDeferred(current_time, sync, result);
    RefreshPending(result);
    for (const auto& [peer, state] : m_peers) {
        if (state.handshaken) SchedulePeer(peer, now, result);
    }
    return result;
}

size_t ChildNetProcessor::HandshakenPeerCount() const
{
    return std::count_if(
        m_peers.begin(), m_peers.end(),
        [](const auto& entry) { return entry.second.handshaken; });
}

bool ChildNetProcessor::IsHandshaken(ChildPeerId peer) const
{
    const auto it{m_peers.find(peer)};
    return it != m_peers.end() && it->second.handshaken;
}

} // namespace node
