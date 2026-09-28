// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHILD_CHAIN_DB_H
#define KRONEIN_NODE_CHILD_CHAIN_DB_H

#include <chainregistry/child_block.h>
#include <chainregistry/child_fork_choice.h>
#include <chainregistry/deposit_import.h>
#include <chainregistry/mainchain_lightclient.h>
#include <consensus/bmm.h>
#include <coins.h>
#include <dbwrapper.h>
#include <primitives/chainregistry.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace node {

inline constexpr uint8_t CHILD_CHAIN_DB_VERSION{5};
inline constexpr uint8_t CHILD_BMM_ANCHOR_RECORD_VERSION{1};
inline constexpr uint8_t CHILD_PENDING_BMM_ANCHOR_RECORD_VERSION{1};
inline constexpr uint8_t CHILD_CANDIDATE_RECORD_VERSION{1};
inline constexpr uint8_t CHILD_CANDIDATE_BMM_ANCHOR_RECORD_VERSION{1};
inline constexpr uint64_t MAX_CHILD_PENDING_BMM_ANCHORS{256};
inline constexpr uint64_t MAX_CHILD_PENDING_BMM_PROOF_SIZE{4'000'000};
inline constexpr uint64_t MAX_CHILD_PENDING_BMM_BYTES{64 * 1024 * 1024};
inline constexpr uint64_t MAX_CHILD_SIDE_CANDIDATES{1'024};
inline constexpr uint64_t MAX_CHILD_CANDIDATE_RECORD_SIZE{16 * 1024 * 1024};
inline constexpr uint64_t MAX_CHILD_SIDE_CANDIDATE_BYTES{256 * 1024 * 1024};
inline constexpr uint64_t MAX_CHILD_CANDIDATE_BMM_ANCHORS{4'096};
inline constexpr uint64_t MAX_CHILD_CANDIDATE_BMM_BYTES{256 * 1024 * 1024};

struct ChildBmmAnchorRecord {
    uint8_t version{CHILD_BMM_ANCHOR_RECORD_VERSION};
    uint256 child_block_hash;
    chainregistry::BmmAnchorProof proof;

    SERIALIZE_METHODS(ChildBmmAnchorRecord, obj)
    {
        READWRITE(obj.version, obj.child_block_hash, obj.proof);
    }

    friend bool operator==(const ChildBmmAnchorRecord&,
                           const ChildBmmAnchorRecord&) = default;
};

struct ChildPendingBmmAnchorRecord {
    uint8_t version{CHILD_PENDING_BMM_ANCHOR_RECORD_VERSION};
    uint256 child_block_hash;
    uint64_t serialized_size{0};
    chainregistry::BmmAnchorProof proof;

    SERIALIZE_METHODS(ChildPendingBmmAnchorRecord, obj)
    {
        READWRITE(obj.version, obj.child_block_hash, obj.serialized_size, obj.proof);
    }
};

/** A validated, non-canonical child block retained for deterministic fork choice. */
struct ChildCandidateRecord {
    uint8_t version{CHILD_CANDIDATE_RECORD_VERSION};
    uint64_t serialized_size{0};
    CBlock block;
    chainregistry::ReferenceChildBlockUndo undo;

    SERIALIZE_METHODS(ChildCandidateRecord, obj)
    {
        READWRITE(obj.version,
                  obj.serialized_size,
                  TX_WITH_WITNESS(obj.block),
                  obj.undo);
    }
};

/** One authenticated main-chain anchor retained for a known child candidate. */
struct ChildCandidateBmmAnchorRecord {
    uint8_t version{CHILD_CANDIDATE_BMM_ANCHOR_RECORD_VERSION};
    uint256 child_block_hash;
    uint64_t serialized_size{0};
    chainregistry::BmmAnchorProof proof;

    SERIALIZE_METHODS(ChildCandidateBmmAnchorRecord, obj)
    {
        READWRITE(obj.version,
                  obj.child_block_hash,
                  obj.serialized_size,
                  obj.proof);
    }
};

struct ChildChainDBState {
    uint8_t version{CHILD_CHAIN_DB_VERSION};
    chainregistry::ChainId child_chain;
    uint256 main_genesis_hash;
    uint32_t minimum_confirmations{0};
    uint256 main_tip;
    uint64_t header_count{0};
    uint256 child_genesis_hash;
    uint256 child_tip;
    uint32_t child_height{0};
    uint64_t anchor_count{0};
    uint64_t pending_anchor_count{0};
    uint64_t pending_anchor_bytes{0};
    uint64_t side_candidate_count{0};
    uint64_t side_candidate_bytes{0};
    uint64_t candidate_anchor_count{0};
    uint64_t candidate_anchor_bytes{0};
    uint64_t import_count{0};
    uint64_t coin_count{0};
    bool safe_halt{false};

    SERIALIZE_METHODS(ChildChainDBState, obj)
    {
        READWRITE(obj.version,
                  obj.child_chain,
                  obj.main_genesis_hash,
                  obj.minimum_confirmations,
                  obj.main_tip,
                  obj.header_count,
                  obj.child_genesis_hash,
                  obj.child_tip,
                  obj.child_height,
                  obj.anchor_count,
                  obj.pending_anchor_count,
                  obj.pending_anchor_bytes,
                  obj.side_candidate_count,
                  obj.side_candidate_bytes,
                  obj.candidate_anchor_count,
                  obj.candidate_anchor_bytes,
                  obj.import_count,
                  obj.coin_count,
                  obj.safe_halt);
    }

    friend bool operator==(const ChildChainDBState&, const ChildChainDBState&) = default;
};

enum class ChildChainDBLoadError : uint8_t {
    NONE,
    STATE_DECODE_FAILED,
    ORPHANED_DATA,
    UNSUPPORTED_VERSION,
    CONFIGURATION_MISMATCH,
    HEADER_KEY_DECODE_FAILED,
    HEADER_KEY_MISMATCH,
    HEADER_DECODE_FAILED,
    HEADER_COUNT_MISMATCH,
    INVALID_HEADERS,
    IMPORT_KEY_DECODE_FAILED,
    IMPORT_KEY_MISMATCH,
    IMPORT_DECODE_FAILED,
    IMPORT_COUNT_MISMATCH,
    INVALID_IMPORTS,
    SAFE_HALT_MISSING,
    SAFE_HALT_DECODE_FAILED,
    SAFE_HALT_ORPHANED,
    UNACKNOWLEDGED_MAIN_REORG,
    UNDO_KEY_DECODE_FAILED,
    UNDO_DECODE_FAILED,
    INVALID_UNDO,
    BLOCK_KEY_DECODE_FAILED,
    BLOCK_KEY_MISMATCH,
    BLOCK_DECODE_FAILED,
    BLOCK_COUNT_MISMATCH,
    INVALID_BLOCK_CHAIN,
    ANCHOR_KEY_DECODE_FAILED,
    ANCHOR_KEY_MISMATCH,
    ANCHOR_DECODE_FAILED,
    ANCHOR_COUNT_MISMATCH,
    INVALID_BMM_ANCHOR,
    PENDING_ANCHOR_KEY_DECODE_FAILED,
    PENDING_ANCHOR_KEY_MISMATCH,
    PENDING_ANCHOR_DECODE_FAILED,
    PENDING_ANCHOR_COUNT_MISMATCH,
    INVALID_PENDING_BMM_ANCHOR,
    CANDIDATE_KEY_DECODE_FAILED,
    CANDIDATE_KEY_MISMATCH,
    CANDIDATE_DECODE_FAILED,
    CANDIDATE_COUNT_MISMATCH,
    INVALID_CANDIDATE_DAG,
    CANDIDATE_ANCHOR_KEY_DECODE_FAILED,
    CANDIDATE_ANCHOR_KEY_MISMATCH,
    CANDIDATE_ANCHOR_DECODE_FAILED,
    CANDIDATE_ANCHOR_COUNT_MISMATCH,
    INVALID_CANDIDATE_BMM_ANCHOR,
    COIN_KEY_DECODE_FAILED,
    COIN_DECODE_FAILED,
    COIN_COUNT_MISMATCH,
    INVALID_COIN,
};

struct ChildChainDBLoadResult {
    ChildChainDBLoadError error{ChildChainDBLoadError::NONE};
    chainregistry::MainHeaderLoadResult header_result;
    chainregistry::DepositImportLoadResult import_result;
    bool initialized{false};

    bool IsValid() const { return error == ChildChainDBLoadError::NONE; }
};

struct ChildChainDBDisconnect {
    CBlock block;
    chainregistry::ReferenceChildBlockUndo undo;
};

struct ChildChainDBConnect {
    CBlock block;
    chainregistry::ReferenceChildBlockUndo undo;
    chainregistry::BmmAnchorProof primary_anchor;
};

/** Persistent state owned by one explicitly loaded child chain. */
class ChildChainDB : public CCoinsView
{
private:
    CDBWrapper m_db;
    const chainregistry::ChainId m_child_chain;
    const uint256 m_main_genesis_hash;
    const uint32_t m_minimum_confirmations;
    const uint256 m_child_genesis_hash;

    bool WriteMainChainUpdate(
        const chainregistry::MainHeaderChain& main_headers,
        const chainregistry::DepositImportState& imports,
        const CBlockHeader* added_header,
        std::span<const ChildChainDBDisconnect> disconnected_blocks,
        bool sync);

public:
    ChildChainDB(const DBParams& params,
                 chainregistry::ChainId child_chain,
                 uint256 main_genesis_hash,
                 uint32_t minimum_confirmations,
                 uint256 child_genesis_hash);

    ChildChainDBLoadResult Load(chainregistry::MainHeaderChain& main_headers,
                                chainregistry::DepositImportState& imports,
                                ChildChainDBState& state,
                                int64_t current_time,
                                std::optional<std::span<const CBlockHeader>> validated_active_headers = std::nullopt) const;

    bool WriteInitialState(const chainregistry::MainHeaderChain& main_headers,
                           const chainregistry::DepositImportState& imports,
                           bool sync = false);
    bool WriteMainHeader(const chainregistry::MainHeaderChain& main_headers,
                         const chainregistry::DepositImportState& imports,
                         const CBlockHeader& header,
                         bool sync = false);
    bool WriteMainHeaderAndDisconnect(
        const chainregistry::MainHeaderChain& main_headers,
        const chainregistry::DepositImportState& imports,
        const CBlockHeader& header,
        std::span<const ChildChainDBDisconnect> disconnected_blocks,
        bool sync = false);
    bool WriteMainTipAndDisconnect(
        const chainregistry::MainHeaderChain& main_headers,
        const chainregistry::DepositImportState& imports,
        std::span<const ChildChainDBDisconnect> disconnected_blocks,
        bool sync = false);
    bool WritePendingBmmAnchor(
        const chainregistry::MainHeaderChain& main_headers,
        const chainregistry::BmmAnchorProof& anchor_proof,
        bool sync = false);
    bool WriteValidatedChildCandidate(
        const chainregistry::MainHeaderChain& main_headers,
        const CBlock& block,
        const chainregistry::ReferenceChildBlockUndo& undo,
        const chainregistry::BmmAnchorProof& anchor_proof,
        bool sync = false);
    bool WriteCandidateBmmAnchor(
        const chainregistry::MainHeaderChain& main_headers,
        const chainregistry::BmmAnchorProof& anchor_proof,
        bool sync = false);
    bool WriteConnectedChildBlock(const chainregistry::MainHeaderChain& main_headers,
                                  const chainregistry::DepositImportState& imports,
                                  const CBlock& block,
                                  const chainregistry::ReferenceChildBlockUndo& undo,
                                  const chainregistry::BmmAnchorProof& anchor_proof,
                                  bool sync = false);
    bool WriteDisconnectedChildBlock(const chainregistry::MainHeaderChain& main_headers,
                                     const chainregistry::DepositImportState& imports,
                                     const CBlock& block,
                                     const chainregistry::ReferenceChildBlockUndo& undo,
                                     bool sync = false);
    bool WriteChildReorganization(
        const chainregistry::MainHeaderChain& main_headers,
        const chainregistry::DepositImportState& imports,
        std::span<const ChildChainDBDisconnect> disconnected_blocks,
        std::span<const ChildChainDBConnect> connected_blocks,
        bool sync = false);

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override;
    bool HaveCoin(const COutPoint& outpoint) const override;
    uint256 GetBestBlock() const override;
    void BatchWrite(CoinsViewCacheCursor& cursor,
                    const uint256& hash_block) override;
    std::unique_ptr<CCoinsViewCursor> Cursor() const override;
    size_t EstimateSize() const override;

    std::optional<chainregistry::ImportedDeposit> ReadImport(
        const chainregistry::DepositId& deposit_id) const;
    bool ReadState(ChildChainDBState& state) const;
    bool ReadBlock(const uint256& child_block_hash, CBlock& block) const;
    std::optional<ChildCandidateRecord> ReadSideCandidate(
        const uint256& child_block_hash) const;
    std::optional<std::vector<chainregistry::ChildForkCandidate>>
    ReadForkCandidates(
        const chainregistry::MainHeaderChain& main_headers) const;
    bool ReadUndo(const uint256& child_block_hash,
                  chainregistry::ReferenceChildBlockUndo& undo) const;
    std::optional<ChildBmmAnchorRecord> ReadBmmAnchor(
        const uint256& child_block_hash) const;
    std::optional<ChildPendingBmmAnchorRecord> ReadPendingBmmAnchor(
        const uint256& main_block_hash) const;
    std::optional<ChildCandidateBmmAnchorRecord> ReadCandidateBmmAnchor(
        const uint256& main_block_hash) const;
};

} // namespace node

#endif // KRONEIN_NODE_CHILD_CHAIN_DB_H
