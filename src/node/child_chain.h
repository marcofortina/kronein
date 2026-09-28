// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHILD_CHAIN_H
#define KRONEIN_NODE_CHILD_CHAIN_H

#include <blockfilter.h>
#include <chain.h>
#include <chainregistry/child_block.h>
#include <chainregistry/child_fork_choice.h>
#include <chainregistry/child_template.h>
#include <chainregistry/deposit_import.h>
#include <chainregistry/mainchain_lightclient.h>
#include <consensus/params.h>
#include <kernel/coinstats.h>
#include <node/child_chain_db.h>
#include <node/child_mempool.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
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
    BMM_ANCHOR_UNAVAILABLE,
    BMM_ANCHOR_PERSIST_FAILED,
    LOCAL_PROPOSAL_NOT_FOUND,
    LOCAL_PROPOSAL_PERSIST_FAILED,
    CHILD_PARENT_UNAVAILABLE,
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
    std::vector<uint256> pruned_child_candidates;
    std::vector<uint256> pruned_local_proposals;
    std::vector<Txid> removed_mempool_transactions;
    bool bmm_anchor_already_known{false};
    bool local_proposal_found{false};
    bool local_proposal_activated{false};
    ReferenceChildRuntimeError local_proposal_activation_error{
        ReferenceChildRuntimeError::NONE};
    bool candidate_stored{false};
    bool reorganization_required{false};
    uint256 selected_child_head;
    bool loaded_existing{false};

    bool IsValid() const { return error == ReferenceChildRuntimeError::NONE; }
};

enum class ReferenceChildMempoolAcceptError : uint8_t {
    NONE,
    NOT_INITIALIZED,
    FAILED_RUNTIME,
    INVALID_TIME,
    NULL_TRANSACTION,
    COINBASE_NOT_ALLOWED,
    IMPORT_NOT_ALLOWED,
    BUILD_FAILED,
    CONTEXT_REJECTED,
    MAX_FEE_EXCEEDED,
    POOL_REJECTED,
};

struct ReferenceChildMempoolAcceptResult {
    ReferenceChildMempoolAcceptError error{
        ReferenceChildMempoolAcceptError::NONE};
    ChildMempoolError pool_error{ChildMempoolError::NONE};
    chainregistry::ReferenceChildBlockBuildResult build;
    chainregistry::ReferenceChildBlockResult validation;
    Txid txid;
    CAmount fee{0};
    bool already_known{false};

    bool IsValid() const
    {
        return error == ReferenceChildMempoolAcceptError::NONE;
    }
};

struct ReferenceChildMempoolView {
    std::vector<ChildMempoolEntry> entries;
    size_t total_bytes{0};
    CAmount total_fees{0};
    uint64_t sequence{0};
};

struct ReferenceChildBlockView {
    uint256 block_hash;
    std::optional<CBlock> block;
    std::optional<chainregistry::ReferenceChildBlockUndo> undo;
    std::optional<ChildBlockFilterRecord> basic_filter;
    int height{0};
    int confirmations{-1};
    uint32_t time{0};
    int64_t median_time{0};
    uint64_t chain_tx_count{0};
    bool active{false};
    bool virtual_genesis{false};
    std::optional<uint256> next_block_hash;
    chainregistry::ChildForkScore fork_score;
};

struct ReferenceChildChainTipView {
    uint256 block_hash;
    int height{0};
    int branch_length{0};
    bool active{false};
    chainregistry::ChildForkScore fork_score;
};

struct ReferenceChildFilterScanResult {
    bool completed{false};
    int last_scanned_height{0};
    std::vector<uint256> relevant_blocks;
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
    ChildMempool m_mempool;
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
    bool PruneInvalidLocalProposalsImpl(
        int64_t current_time,
        bool sync,
        ReferenceChildRuntimeResult& result);
    ReferenceChildMempoolAcceptResult AcceptMempoolTransaction(
        CTransactionRef transaction,
        int64_t current_time,
        int64_t entry_time,
        uint32_t entry_height,
        std::optional<CAmount> max_fee = std::nullopt);
    void RevalidateMempool(int64_t current_time,
                           ReferenceChildRuntimeResult& result);

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
    /** Validate block data using the newest authenticated pending anchor. */
    ReferenceChildRuntimeResult ConnectStagedBlock(
        const CBlock& block,
        int64_t current_time,
        bool sync = false);
    /** Contextually validate and persist a local block awaiting BMM. */
    ReferenceChildRuntimeResult StoreLocalProposal(
        const CBlock& block,
        int64_t current_time,
        bool sync = false);
    ReferenceChildRuntimeResult SubmitLocalProposal(
        const uint256& block_hash,
        const std::optional<chainregistry::BmmAnchorProof>& anchor_proof,
        int64_t current_time,
        bool sync = false);
    ReferenceChildRuntimeResult RemoveLocalProposal(
        const uint256& block_hash,
        bool sync = false);
    /** Remove proposals that no longer extend the active, authenticated state. */
    ReferenceChildRuntimeResult PruneInvalidLocalProposals(
        int64_t current_time,
        bool sync = false);
    /** Contextually validate a block extending the active tip without persistence. */
    chainregistry::ReferenceChildBlockResult ValidateTipBlock(
        const CBlock& block,
        int64_t current_time) const;
    ReferenceChildMempoolAcceptResult SubmitTransaction(
        CTransactionRef transaction,
        int64_t current_time,
        std::optional<CAmount> max_fee = std::nullopt);
    ReferenceChildMempoolView GetMempool() const;
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
    std::optional<ReferenceChildBlockView> GetBlockView(
        const uint256& block_hash) const;
    std::optional<std::vector<ReferenceChildChainTipView>> GetChainTips() const;
    std::optional<Coin> GetCoin(const COutPoint& outpoint) const;
    /** Return a cursor bound to the current, atomically committed UTXO tip. */
    std::unique_ptr<CCoinsViewCursor> GetUTXOCursor() const;
    std::optional<kernel::CCoinsStats> GetUTXOStats(
        kernel::CoinStatsHashType hash_type,
        const std::function<void()>& interruption_point = {}) const;
    std::optional<ReferenceChildFilterScanResult> ScanBlockFilters(
        int start_height,
        int stop_height,
        const GCSFilter::ElementSet& needles,
        bool filter_false_positives,
        std::atomic<int>& progress,
        std::atomic<int>& progress_height,
        const std::atomic<bool>& should_abort,
        const std::function<void()>& interruption_point = {}) const;
    /** Rebuild and fully validate all persisted runtime state without mutation. */
    bool VerifyDatabase(int64_t current_time) const;
    bool ReadBlock(const uint256& block_hash, CBlock& block) const;
    std::optional<ChildBmmAnchorRecord> GetBmmAnchor(
        const uint256& block_hash) const;
    std::optional<std::vector<ChildPendingBlockView>> GetPendingBlocks() const;
    std::optional<ChildLocalProposalRecord> GetLocalProposal(
        const uint256& block_hash) const;
    std::optional<std::vector<ChildLocalProposalRecord>> GetLocalProposals()
        const;
};

} // namespace node

#endif // KRONEIN_NODE_CHILD_CHAIN_H
