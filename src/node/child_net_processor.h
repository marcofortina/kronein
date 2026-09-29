// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_CHILD_NET_PROCESSOR_H
#define BITCOIN_NODE_CHILD_NET_PROCESSOR_H

#include <chainregistry/child_net.h>
#include <chainregistry/child_template.h>
#include <node/chain_manager.h>
#include <node/child_block_download.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <variant>
#include <vector>

namespace node {

inline constexpr size_t MAX_DEFERRED_CHILD_BLOCKS{64};
inline constexpr size_t MAX_DEFERRED_CHILD_BLOCK_BYTES{64 << 20};
inline constexpr ChildRequestTime DEFERRED_CHILD_BLOCK_TIMEOUT{
    std::chrono::minutes{2}};
inline constexpr size_t MAX_CHILD_BLOCK_RESPONSE_BYTES{16 << 20};
inline constexpr uint64_t MAX_CHILD_GETBLOCKS_BURST_HASHES{64};
inline constexpr ChildRequestTime CHILD_GETBLOCKS_REFILL_INTERVAL{
    std::chrono::milliseconds{250}};
inline constexpr uint64_t MAX_CHILD_TRANSACTION_BURST{32};
inline constexpr ChildRequestTime CHILD_TRANSACTION_REFILL_INTERVAL{
    std::chrono::seconds{1}};

using ChildNetMessage = std::variant<
    chainregistry::ChildNetHello,
    chainregistry::ChildBlockHashes,
    chainregistry::ChildBlockData,
    chainregistry::ChildTransactionData>;

enum class ChildNetCommand : uint8_t {
    HELLO,
    INVENTORY,
    GET_BLOCKS,
    BLOCK,
    TRANSACTION,
};

struct ChildNetOutbound {
    ChildPeerId peer{0};
    ChildNetCommand command{ChildNetCommand::HELLO};
    ChildNetMessage message;
};

enum class ChildNetProcessorError : uint8_t {
    NONE,
    PEER_ALREADY_CONNECTED,
    HANDSHAKE_ALREADY_COMPLETED,
    UNKNOWN_PEER,
    HANDSHAKE_REQUIRED,
    INVALID_MESSAGE,
    PENDING_BLOCKS_UNAVAILABLE,
    INVALID_DEFINITION,
    UNAUTHENTICATED_BLOCK,
    DOWNLOAD_REJECTED,
    REQUEST_RATE_LIMITED,
    DEFERRED_CACHE_FULL,
    BLOCK_REJECTED,
    TRANSACTION_REJECTED,
    TRANSACTION_RATE_LIMITED,
};

struct ChildNetProcessorResult {
    ChildNetProcessorError error{ChildNetProcessorError::NONE};
    chainregistry::ChildNetValidationError validation_error{
        chainregistry::ChildNetValidationError::NONE};
    ChildBlockDownloadError download_error{ChildBlockDownloadError::NONE};
    ChainManagerResult submission;
    ChainManagerMempoolAcceptResult transaction_submission;
    std::vector<ChildNetOutbound> outbound;
    std::vector<ChildBlockRequest> expired_requests;
    std::vector<uint256> accepted_blocks;
    std::vector<uint256> deferred_blocks;
    std::vector<uint256> rejected_blocks;
    std::vector<uint256> expired_deferred_blocks;
    std::vector<Txid> accepted_transactions;
    std::vector<ChildPeerId> disconnect_peers;
    bool disconnect{false};

    bool IsValid() const { return error == ChildNetProcessorError::NONE; }
};

/**
 * Single-threaded protocol state for one isolated child-chain network.
 *
 * Only hashes backed by currently active main-chain BMM anchors enter the
 * download tracker. Received children whose authenticated parents have not
 * arrived yet are retained in a strictly bounded, expiring memory cache.
 */
class ChildNetProcessor
{
private:
    struct PeerState {
        bool handshaken{false};
        uint64_t block_request_tokens{MAX_CHILD_GETBLOCKS_BURST_HASHES};
        std::optional<ChildRequestTime> block_request_refill_time;
        uint64_t transaction_tokens{MAX_CHILD_TRANSACTION_BURST};
        std::optional<ChildRequestTime> transaction_refill_time;
    };

    struct DeferredBlock {
        CBlock block;
        size_t serialized_size{0};
        ChildRequestTime expiry{0};
        ChildPeerId source{0};
    };

    ChainManager& m_manager;
    chainregistry::ReferenceChildDefinition m_definition;
    std::map<ChildPeerId, PeerState> m_peers;
    std::map<uint256, uint32_t> m_pending;
    ChildBlockDownloadTracker m_downloads;
    std::map<uint256, DeferredBlock> m_deferred;
    size_t m_deferred_bytes{0};
    bool m_ready{false};

    bool RefreshPending(ChildNetProcessorResult& result);
    void SchedulePeer(ChildPeerId peer,
                      ChildRequestTime now,
                      ChildNetProcessorResult& result);
    void AnnounceAccepted(std::optional<ChildPeerId> source,
                          const uint256& block_hash,
                          ChildNetProcessorResult& result) const;
    void AnnounceTransaction(std::optional<ChildPeerId> source,
                             const CTransaction& transaction,
                             ChildNetProcessorResult& result) const;
    void RetryDeferred(int64_t current_time,
                       bool sync,
                       ChildNetProcessorResult& result);
    bool RequireHandshake(ChildPeerId peer,
                          ChildNetProcessorResult& result) const;
    void EraseDeferred(const uint256& block_hash);

public:
    ChildNetProcessor(
        ChainManager& manager,
        chainregistry::ReferenceChildDefinition definition);

    ChildNetProcessorResult Connected(ChildPeerId peer, uint64_t local_nonce);
    void Disconnected(ChildPeerId peer);

    ChildNetProcessorResult ReceiveHello(
        ChildPeerId peer,
        const chainregistry::ChildNetHello& hello);
    ChildNetProcessorResult ReceiveInventory(
        ChildPeerId peer,
        const chainregistry::ChildBlockHashes& inventory,
        ChildRequestTime now);
    ChildNetProcessorResult ReceiveGetBlocks(
        ChildPeerId peer,
        const chainregistry::ChildBlockHashes& request,
        ChildRequestTime now);
    ChildNetProcessorResult ReceiveBlock(
        ChildPeerId peer,
        const chainregistry::ChildBlockData& data,
        ChildRequestTime now,
        int64_t current_time,
        bool sync = false);
    ChildNetProcessorResult ReceiveTransaction(
        ChildPeerId peer,
        const chainregistry::ChildTransactionData& data,
        ChildRequestTime now,
        int64_t current_time);
    ChildNetProcessorResult RelayTransaction(
        const CTransactionRef& transaction) const;
    ChildNetProcessorResult Poll(
        ChildRequestTime now,
        int64_t current_time,
        bool sync = false);

    size_t PeerCount() const { return m_peers.size(); }
    size_t HandshakenPeerCount() const;
    bool IsHandshaken(ChildPeerId peer) const;
    size_t PendingCount() const { return m_pending.size(); }
    size_t DeferredCount() const { return m_deferred.size(); }
    size_t DeferredBytes() const { return m_deferred_bytes; }
    const ChildBlockDownloadTracker& Downloads() const { return m_downloads; }
    const chainregistry::ChainId& ChainId() const { return m_definition.chain_id; }
};

} // namespace node

#endif // BITCOIN_NODE_CHILD_NET_PROCESSOR_H
