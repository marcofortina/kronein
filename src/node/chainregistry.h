// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHAINREGISTRY_H
#define KRONEIN_NODE_CHAINREGISTRY_H

#include <consensus/chainregistry.h>
#include <consensus/deposit_proof.h>
#include <consensus/params.h>
#include <node/chainregistry_db.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <span>

class CBlock;

namespace node {

enum class ChainRegistryStateError : uint8_t {
    NONE,
    NOT_INITIALIZED,
    INVALID_EXPECTED_TIP,
    DATABASE_LOAD_FAILED,
    DATABASE_TIP_MISMATCH,
    DATABASE_ALREADY_INITIALIZED,
    ACTIVE_STATE_REQUIRES_REINDEX,
    SNAPSHOT_HEIGHT_INACTIVE,
    SNAPSHOT_ROOT_MISMATCH,
    NON_SEQUENTIAL_BLOCK,
    INVALID_BLOCK,
    DATABASE_WRITE_FAILED,
    DEPOSIT_INDEX_FAILED,
    ANCHOR_INDEX_FAILED,
    UNDO_MISSING,
    UNDO_FAILED,
};

struct ChainRegistryStateResult {
    ChainRegistryStateError error{ChainRegistryStateError::NONE};
    ChainRegistryDBLoadResult load_result;
    chainregistry::RegistryBlockResult block_result;
    chainregistry::BmmBlockValidationResult bmm_result;

    bool IsValid() const { return error == ChainRegistryStateError::NONE; }
};

enum class BmmAnchorProofBuildError : uint8_t {
    NONE,
    INVALID_INDEX_ENTRY,
    BLOCK_MISMATCH,
    TRANSACTION_MISMATCH,
    ANCHOR_MISMATCH,
    PROOF_INVALID,
};

struct BmmAnchorProofBuildResult {
    BmmAnchorProofBuildError error{BmmAnchorProofBuildError::NONE};
    chainregistry::BmmProofValidationResult validation;
    chainregistry::BmmAnchorProof proof;

    bool IsValid() const { return error == BmmAnchorProofBuildError::NONE; }
};

enum class DepositProofBuildError : uint8_t {
    NONE,
    INVALID_INDEX_ENTRY,
    BLOCK_MISMATCH,
    TRANSACTION_MISMATCH,
    PROOF_INVALID,
};

struct DepositProofBuildResult {
    DepositProofBuildError error{DepositProofBuildError::NONE};
    chainregistry::DepositProofValidationResult validation;
    chainregistry::DepositProof proof;

    bool IsValid() const { return error == DepositProofBuildError::NONE; }
};

/** Build and self-validate a KDPR from one consensus-indexed main deposit. */
DepositProofBuildResult BuildDepositProof(
    const CBlock& block,
    const DepositIndexEntry& entry,
    const uint256& main_genesis_hash);

/** Build and self-validate a KBPR from one consensus-indexed main anchor. */
BmmAnchorProofBuildResult BuildBmmAnchorProof(
    const CBlock& block,
    const BmmAnchorIndexEntry& entry,
    const uint256& main_genesis_hash);

/**
 * Registry state belonging to exactly one chainstate.
 *
 * Keeping this object per-chainstate prevents verification, reindex and future
 * snapshot chainstates from mutating one shared registry view.
 */
class ChainRegistryState
{
private:
    Consensus::Params::ChainRegistryParams m_params;
    uint256 m_main_genesis_hash;
    chainregistry::ChainRegistry m_registry;
    ChainRegistryDBState m_state;
    std::unique_ptr<ChainRegistryDB> m_db;
    bool m_initialized{false};

public:
    ChainRegistryState(Consensus::Params::ChainRegistryParams params,
                       const uint256& main_genesis_hash);

    ChainRegistryStateResult Initialize(const DBParams& db_params,
                                        const uint256& expected_tip,
                                        int expected_height);
    ChainRegistryStateResult InitializeFromSnapshot(
        const DBParams& db_params,
        const uint256& expected_tip,
        int expected_height,
        chainregistry::ChainRegistry registry,
        const uint256& expected_root);

    ChainRegistryStateResult ConnectBlock(const CBlock& block,
                                          int height,
                                          const uint256& block_hash,
                                          bool sync = false);
    ChainRegistryStateResult ValidateBlock(const CBlock& block,
                                           int height,
                                           const uint256& block_hash) const;
    ChainRegistryStateResult DisconnectBlock(const uint256& block_hash,
                                             const uint256& parent_hash,
                                             int parent_height,
                                             bool sync = false);
    ChainRegistryStateResult PruneUndo(std::span<const uint256> block_hashes,
                                       bool sync = false);

    bool Enabled() const { return m_params.Enabled(); }
    bool IsInitialized() const { return m_initialized; }
    const chainregistry::ChainRegistry& Registry() const { return m_registry; }
    const ChainRegistryDBState& State() const { return m_state; }
    std::optional<DepositIndexEntry> FindDeposit(const chainregistry::DepositId& deposit_id) const;
    std::optional<DepositLookupResult> FindDepositsForChild(
        const chainregistry::ChainId& chain_id,
        uint64_t lookup_limit,
        std::optional<chainregistry::DepositId> start_after = std::nullopt) const;
    std::optional<BmmAnchorIndexEntry> FindAnchor(const BmmAnchorId& anchor_id) const;
    std::optional<BmmAnchorLookupResult> FindAnchorsForChildBlocks(
        const chainregistry::ChainId& chain_id,
        std::span<const uint256> child_block_hashes,
        uint64_t lookup_limit) const;
};

} // namespace node

#endif // KRONEIN_NODE_CHAINREGISTRY_H
