// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHILD_CHAIN_H
#define KRONEIN_NODE_CHILD_CHAIN_H

#include <chain.h>
#include <chainregistry/child_block.h>
#include <chainregistry/child_template.h>
#include <chainregistry/deposit_import.h>
#include <chainregistry/mainchain_lightclient.h>
#include <consensus/params.h>
#include <node/child_chain_db.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <vector>

class CCoinsViewCache;

namespace node {

enum class ReferenceChildRuntimeError : uint8_t {
    NONE,
    ALREADY_INITIALIZED,
    NOT_INITIALIZED,
    FAILED_RUNTIME,
    INVALID_DEFINITION,
    WRONG_MAIN_GENESIS,
    DATABASE_LOAD_FAILED,
    DATABASE_INITIALIZE_FAILED,
    CHILD_INDEX_REBUILD_FAILED,
    MAIN_HEADER_REJECTED,
    MAIN_HEADER_PERSIST_FAILED,
    MAIN_REORG_ROLLBACK_FAILED,
    BMM_ANCHOR_REJECTED,
    BMM_ANCHOR_PERSIST_FAILED,
    CHILD_BLOCK_REJECTED,
    CHILD_BLOCK_PERSIST_FAILED,
    CHILD_REORGANIZATION_FAILED,
    CHILD_REORGANIZATION_PERSIST_FAILED,
    CHILD_DISCONNECT_REJECTED,
    CHILD_DISCONNECT_PERSIST_FAILED,
    CACHE_ACKNOWLEDGEMENT_FAILED,
};

struct ReferenceChildRuntimeResult {
    ReferenceChildRuntimeError error{ReferenceChildRuntimeError::NONE};
    ChildChainDBLoadResult database_load;
    chainregistry::MainHeaderResult main_header;
    chainregistry::AuthenticatedBmmAnchorResult bmm_anchor;
    chainregistry::DepositReconcileResult reconcile;
    chainregistry::ReferenceChildBlockResult child_block;
    std::vector<uint256> disconnected_child_blocks;
    bool bmm_anchor_already_known{false};
    bool candidate_stored{false};
    bool reorganization_required{false};
    uint256 selected_child_head;
    bool loaded_existing{false};

    bool IsValid() const { return error == ReferenceChildRuntimeError::NONE; }
};

/**
 * First isolated runtime for one reference-template child chain.
 *
 * It owns one main-header light client, import ledger, child block index and
 * database. Candidate state is validated in temporary caches and becomes
 * visible only after the database commits the corresponding atomic batch.
 */
class ReferenceChildRuntime
{
private:
    Consensus::Params m_main_params;
    chainregistry::ReferenceChildDefinition m_definition;
    std::unique_ptr<chainregistry::MainHeaderChain> m_main_headers;
    chainregistry::DepositImportState m_imports;
    ChildChainDBState m_state;
    std::unique_ptr<ChildChainDB> m_db;
    std::unique_ptr<CBlockIndex> m_genesis;
    std::map<uint256, std::unique_ptr<CBlockIndex>> m_child_index;
    CBlockIndex* m_tip{nullptr};
    bool m_initialized{false};
    bool m_failed{false};

    bool RebuildChildIndex(uint32_t genesis_time);
    bool BuildBranchState(CBlockIndex& parent,
                          int64_t current_time,
                          const chainregistry::MainHeaderChain& main_headers,
                          CCoinsViewCache& coins,
                          chainregistry::DepositImportState& imports,
                          ReferenceChildRuntimeResult& result) const;
    bool ActivateSelectedHead(
        const chainregistry::ChildForkChoiceResult& selected,
        std::span<const chainregistry::ChildForkCandidate> candidates,
        int64_t current_time,
        const chainregistry::MainHeaderChain& main_headers,
        bool sync,
        ReferenceChildRuntimeResult& result);
    bool Usable() const { return m_initialized && !m_failed; }
    ReferenceChildRuntimeResult AddMainHeaderImpl(
        const CBlockHeader& header,
        int64_t current_time,
        bool sync,
        bool validated_by_main_chainstate);
    ReferenceChildRuntimeResult CommitMainChainUpdate(
        std::unique_ptr<chainregistry::MainHeaderChain> candidate_headers,
        ReferenceChildRuntimeResult result,
        const CBlockHeader* added_header,
        int64_t current_time,
        bool sync);

public:
    ReferenceChildRuntime(
        Consensus::Params main_params,
        chainregistry::ReferenceChildDefinition definition);
    ~ReferenceChildRuntime();

    ReferenceChildRuntimeResult Initialize(const DBParams& db_params,
                                           const CBlockHeader& main_genesis,
                                           int64_t current_time,
                                           bool sync = false,
                                           std::optional<std::span<const CBlockHeader>> validated_active_headers = std::nullopt);
    ReferenceChildRuntimeResult AddMainHeader(const CBlockHeader& header,
                                              int64_t current_time,
                                              bool sync = false);
    ReferenceChildRuntimeResult AddValidatedMainHeader(
        const CBlockHeader& header,
        int64_t current_time,
        bool sync = false);
    ReferenceChildRuntimeResult SelectValidatedMainTip(
        const uint256& active_tip,
        int64_t current_time,
        bool sync = false);
    ReferenceChildRuntimeResult StageBmmAnchor(
        const chainregistry::BmmAnchorProof& anchor_proof,
        int64_t current_time,
        bool sync = false);
    ReferenceChildRuntimeResult ConnectBlock(const CBlock& block,
                                             const chainregistry::BmmAnchorProof& anchor_proof,
                                             int64_t current_time,
                                             bool sync = false);
    ReferenceChildRuntimeResult DisconnectTip(bool sync = false);

    bool IsInitialized() const { return m_initialized; }
    bool IsFailed() const { return m_failed; }
    const chainregistry::ReferenceChildDefinition& Definition() const
    {
        return m_definition;
    }
    const chainregistry::MainHeaderChain* MainHeaders() const
    {
        return m_main_headers.get();
    }
    const chainregistry::DepositImportState& Imports() const { return m_imports; }
    const ChildChainDBState& State() const { return m_state; }
    const CBlockIndex* Tip() const { return m_tip; }
    std::optional<uint256> GetBlockHash(int height) const;
    std::optional<Coin> GetCoin(const COutPoint& outpoint) const;
    bool ReadBlock(const uint256& block_hash, CBlock& block) const;
};

} // namespace node

#endif // KRONEIN_NODE_CHILD_CHAIN_H
