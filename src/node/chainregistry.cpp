// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chainregistry.h>

#include <consensus/merkle.h>
#include <primitives/block.h>
#include <primitives/bmm.h>

#include <limits>
#include <optional>
#include <utility>
#include <vector>

namespace node {
namespace {

ChainRegistryStateResult StateError(ChainRegistryStateError error)
{
    ChainRegistryStateResult result;
    result.error = error;
    return result;
}

bool ExpectedTipIsValid(const uint256& tip, int height)
{
    return (tip.IsNull() && height == -1) || (!tip.IsNull() && height >= 0);
}

std::optional<chainregistry::DepositValidationParams> DepositParamsForHeight(
    const Consensus::Params::ChainRegistryParams& params,
    int height)
{
    if (!params.DepositsActive(height)) return std::nullopt;
    return chainregistry::DepositValidationParams{
        .minimum_amount = params.minimum_deposit_amount,
        .maximum_deposits = params.maximum_deposits,
    };
}

std::optional<std::vector<DepositIndexEntry>> BuildDepositIndexEntries(
    const CBlock& block,
    const uint256& block_hash,
    uint32_t height,
    const chainregistry::ChainRegistry& registry,
    const chainregistry::BlockDepositsResult& deposits)
{
    std::vector<DepositIndexEntry> entries;
    entries.reserve(deposits.deposits.size());
    const uint256 registry_root{registry.ComputeRoot()};
    for (const auto& deposit : deposits.deposits) {
        if (deposit.transaction_index >= block.vtx.size() ||
            block.vtx[deposit.transaction_index]->GetHash() != deposit.outpoint.hash) {
            return std::nullopt;
        }
        const auto* record{registry.Find(deposit.fund.chain_id)};
        const auto proof{registry.GetInclusionProof(deposit.fund.chain_id)};
        if (!record || record->status != chainregistry::ChainStatus::ACTIVE || !proof) {
            return std::nullopt;
        }
        entries.push_back(DepositIndexEntry{
            .deposit_id = deposit.deposit_id,
            .outpoint = deposit.outpoint,
            .amount = deposit.amount,
            .fund = deposit.fund,
            .block_hash = block_hash,
            .block_height = height,
            .transaction_index = deposit.transaction_index,
            .registry_root = registry_root,
            .chain_record = *record,
            .registry_proof = *proof,
        });
    }
    return entries;
}

std::optional<std::vector<BmmAnchorIndexEntry>> BuildBmmAnchorIndexEntries(
    const CBlock& block,
    const uint256& block_hash,
    uint32_t height,
    const chainregistry::ChainRegistry& registry,
    const chainregistry::BmmBlockValidationResult& anchors)
{
    std::vector<BmmAnchorIndexEntry> entries;
    entries.reserve(anchors.anchors.size());
    const uint256 registry_root{registry.ComputeRoot()};
    for (const auto& anchor : anchors.anchors) {
        if (anchor.transaction_index == 0 ||
            anchor.transaction_index >= block.vtx.size() ||
            anchor.output_index >= block.vtx[anchor.transaction_index]->vout.size()) {
            return std::nullopt;
        }
        const CTransaction& transaction{*block.vtx[anchor.transaction_index]};
        const auto* record{registry.Find(anchor.anchor.chain_id)};
        const auto proof{registry.GetInclusionProof(anchor.anchor.chain_id)};
        if (!record || record->status != chainregistry::ChainStatus::ACTIVE ||
            !proof || chainregistry::ParseBmmAnchorScript(
                          transaction.vout[anchor.output_index].scriptPubKey)
                              .anchor != std::optional{anchor.anchor}) {
            return std::nullopt;
        }
        entries.push_back(BmmAnchorIndexEntry{
            .id = {
                .chain_id = anchor.anchor.chain_id,
                .main_block_hash = block_hash,
            },
            .anchor = anchor.anchor,
            .block_height = height,
            .transaction_id = transaction.GetHash(),
            .transaction_index = anchor.transaction_index,
            .output_index = anchor.output_index,
            .registry_root = registry_root,
            .chain_record = *record,
            .registry_proof = *proof,
        });
    }
    return entries;
}

} // namespace

BmmAnchorProofBuildResult BuildBmmAnchorProof(
    const CBlock& block,
    const BmmAnchorIndexEntry& entry,
    const uint256& main_genesis_hash)
{
    BmmAnchorProofBuildResult result;
    if (entry.version != BMM_ANCHOR_INDEX_ENTRY_VERSION ||
        entry.id.chain_id.IsNull() || entry.id.main_block_hash.IsNull() ||
        entry.anchor.chain_id != entry.id.chain_id ||
        entry.chain_record.chain_id != entry.id.chain_id) {
        result.error = BmmAnchorProofBuildError::INVALID_INDEX_ENTRY;
        return result;
    }
    if (block.GetHash() != entry.id.main_block_hash || block.vtx.empty()) {
        result.error = BmmAnchorProofBuildError::BLOCK_MISMATCH;
        return result;
    }
    if (entry.transaction_index == 0 ||
        entry.transaction_index >= block.vtx.size() ||
        block.vtx[entry.transaction_index]->GetHash() !=
            entry.transaction_id ||
        entry.output_index >=
            block.vtx[entry.transaction_index]->vout.size()) {
        result.error = BmmAnchorProofBuildError::TRANSACTION_MISMATCH;
        return result;
    }
    const auto extracted{chainregistry::ExtractTransactionBmmAnchor(
        *block.vtx[entry.transaction_index])};
    if (!extracted.IsValid() || !extracted.anchor ||
        !extracted.output_index || *extracted.anchor != entry.anchor ||
        *extracted.output_index != entry.output_index) {
        result.error = BmmAnchorProofBuildError::ANCHOR_MISMATCH;
        return result;
    }

    result.proof = {
        .main_genesis_hash = main_genesis_hash,
        .block_height = entry.block_height,
        .block_header = static_cast<const CBlockHeader&>(block),
        .anchor_transaction =
            CMutableTransaction{*block.vtx[entry.transaction_index]},
        .transaction_index = entry.transaction_index,
        .transaction_merkle_branch =
            TransactionMerklePath(block, entry.transaction_index),
        .coinbase_transaction = CMutableTransaction{*block.vtx[0]},
        .coinbase_merkle_branch = TransactionMerklePath(block, 0),
        .chain_record = entry.chain_record,
        .registry_proof = entry.registry_proof,
    };
    result.validation = chainregistry::ValidateBmmAnchorProofStructure(
        result.proof, main_genesis_hash, entry.id.chain_id);
    if (!result.validation.IsValid() || !result.validation.anchor ||
        *result.validation.anchor != entry.anchor ||
        result.validation.registry_root != entry.registry_root) {
        result.error = BmmAnchorProofBuildError::PROOF_INVALID;
    }
    return result;
}

ChainRegistryState::ChainRegistryState(Consensus::Params::ChainRegistryParams params,
                                       const uint256& main_genesis_hash)
    : m_params{params}, m_main_genesis_hash{main_genesis_hash}
{
    if (!Enabled()) {
        m_state = MakeChainRegistryDBState({}, 0, m_registry);
        m_initialized = true;
    }
}

ChainRegistryStateResult ChainRegistryState::Initialize(const DBParams& db_params,
                                                        const uint256& expected_tip,
                                                        int expected_height)
{
    if (!ExpectedTipIsValid(expected_tip, expected_height)) {
        return StateError(ChainRegistryStateError::INVALID_EXPECTED_TIP);
    }

    if (!Enabled()) {
        m_state = MakeChainRegistryDBState(expected_tip,
                                           expected_height < 0 ? 0 : static_cast<uint32_t>(expected_height),
                                           m_registry);
        m_initialized = true;
        return {};
    }

    m_db = std::make_unique<ChainRegistryDB>(db_params, m_main_genesis_hash);
    ChainRegistryDBState loaded_state;
    auto load_result{m_db->Load(m_registry, loaded_state)};
    if (!load_result.IsValid()) {
        ChainRegistryStateResult result;
        result.error = ChainRegistryStateError::DATABASE_LOAD_FAILED;
        result.load_result = std::move(load_result);
        return result;
    }

    if (!load_result.initialized) {
        if (m_params.IsActive(expected_height)) {
            return StateError(ChainRegistryStateError::ACTIVE_STATE_REQUIRES_REINDEX);
        }
        loaded_state = MakeChainRegistryDBState(
            expected_tip,
            expected_height < 0 ? 0 : static_cast<uint32_t>(expected_height),
            m_registry);
        if (!m_db->WriteInitialState(m_registry, loaded_state, /*sync=*/true)) {
            return StateError(ChainRegistryStateError::DATABASE_WRITE_FAILED);
        }
    } else if (loaded_state.best_block != expected_tip ||
               (expected_height >= 0 && loaded_state.height != static_cast<uint32_t>(expected_height))) {
        return StateError(ChainRegistryStateError::DATABASE_TIP_MISMATCH);
    }

    m_state = loaded_state;
    m_initialized = true;
    return {};
}

ChainRegistryStateResult ChainRegistryState::InitializeFromSnapshot(
    const DBParams& db_params,
    const uint256& expected_tip,
    int expected_height,
    chainregistry::ChainRegistry registry,
    const uint256& expected_root)
{
    if (!ExpectedTipIsValid(expected_tip, expected_height)) {
        return StateError(ChainRegistryStateError::INVALID_EXPECTED_TIP);
    }
    if (!Enabled() || !m_params.IsActive(expected_height)) {
        return StateError(ChainRegistryStateError::SNAPSHOT_HEIGHT_INACTIVE);
    }
    if (registry.ComputeRoot() != expected_root) {
        return StateError(ChainRegistryStateError::SNAPSHOT_ROOT_MISMATCH);
    }

    m_db = std::make_unique<ChainRegistryDB>(db_params, m_main_genesis_hash);
    chainregistry::ChainRegistry existing_registry;
    ChainRegistryDBState existing_state;
    auto load_result{m_db->Load(existing_registry, existing_state)};
    if (!load_result.IsValid()) {
        ChainRegistryStateResult result;
        result.error = ChainRegistryStateError::DATABASE_LOAD_FAILED;
        result.load_result = std::move(load_result);
        return result;
    }
    if (load_result.initialized) {
        return StateError(ChainRegistryStateError::DATABASE_ALREADY_INITIALIZED);
    }

    const auto snapshot_state{MakeChainRegistryDBState(
        expected_tip,
        static_cast<uint32_t>(expected_height),
        registry,
        static_cast<uint32_t>(expected_height) + 1,
        0,
        static_cast<uint32_t>(expected_height) + 1,
        0)};
    if (!m_db->WriteInitialState(registry, snapshot_state, /*sync=*/true)) {
        return StateError(ChainRegistryStateError::DATABASE_WRITE_FAILED);
    }

    m_registry = std::move(registry);
    m_state = snapshot_state;
    m_initialized = true;
    return {};
}

ChainRegistryStateResult ChainRegistryState::ConnectBlock(const CBlock& block,
                                                          int height,
                                                          const uint256& block_hash,
                                                          bool sync)
{
    auto validation{ValidateBlock(block, height, block_hash)};
    if (!validation.IsValid() || !Enabled()) return validation;

    chainregistry::ChainRegistry candidate{m_registry};
    ChainRegistryDBUndo undo;
    std::vector<DepositIndexEntry> deposits;
    std::vector<BmmAnchorIndexEntry> anchors;
    chainregistry::RegistryBlockResult block_result;
    chainregistry::BmmBlockValidationResult bmm_result;
    if (m_params.IsActive(height)) {
        block_result = candidate.ApplyBlock(block,
                                            static_cast<uint32_t>(height),
                                            m_main_genesis_hash,
                                            m_params.minimum_registration_burn,
                                            m_params.maximum_operations,
                                            chainregistry::CommitmentRequirement::REQUIRED,
                                            DepositParamsForHeight(m_params, height));
        if (!block_result.IsValid()) {
            ChainRegistryStateResult result;
            result.error = ChainRegistryStateError::INVALID_BLOCK;
            result.block_result = std::move(block_result);
            return result;
        }
        undo.registry = *block_result.undo;
        const auto indexed{BuildDepositIndexEntries(
            block, block_hash, static_cast<uint32_t>(height), candidate, block_result.deposits)};
        if (!indexed) return StateError(ChainRegistryStateError::DEPOSIT_INDEX_FAILED);
        deposits = *indexed;
        undo.deposits.reserve(deposits.size());
        for (const auto& deposit : deposits) undo.deposits.push_back(deposit.deposit_id);

        if (m_params.BmmActive(height)) {
            bmm_result = chainregistry::ValidateBlockBmmAnchors(
                block, candidate, m_params.maximum_bmm_anchors);
            if (!bmm_result.IsValid()) {
                ChainRegistryStateResult result;
                result.error = ChainRegistryStateError::INVALID_BLOCK;
                result.block_result = std::move(block_result);
                result.bmm_result = std::move(bmm_result);
                return result;
            }
            const auto indexed_anchors{BuildBmmAnchorIndexEntries(
                block,
                block_hash,
                static_cast<uint32_t>(height),
                candidate,
                bmm_result)};
            if (!indexed_anchors) {
                return StateError(ChainRegistryStateError::ANCHOR_INDEX_FAILED);
            }
            anchors = *indexed_anchors;
            undo.anchors.reserve(anchors.size());
            for (const auto& anchor : anchors) undo.anchors.push_back(anchor.id);
        }
    }

    if (deposits.size() > std::numeric_limits<uint64_t>::max() - m_state.deposit_count) {
        return StateError(ChainRegistryStateError::DEPOSIT_INDEX_FAILED);
    }
    if (anchors.size() > std::numeric_limits<uint64_t>::max() - m_state.anchor_count) {
        return StateError(ChainRegistryStateError::ANCHOR_INDEX_FAILED);
    }
    const auto next_state{MakeChainRegistryDBState(
        block_hash,
        static_cast<uint32_t>(height),
        candidate,
        m_state.deposit_history_start_height,
        m_state.deposit_count + deposits.size(),
        m_state.anchor_history_start_height,
        m_state.anchor_count + anchors.size())};
    if (!m_db->WriteConnectedBlock(
            candidate, next_state, block_hash, undo, deposits, anchors, sync)) {
        return StateError(ChainRegistryStateError::DATABASE_WRITE_FAILED);
    }
    m_registry = std::move(candidate);
    m_state = next_state;

    ChainRegistryStateResult result;
    result.block_result = std::move(block_result);
    result.bmm_result = std::move(bmm_result);
    return result;
}

ChainRegistryStateResult ChainRegistryState::ValidateBlock(const CBlock& block,
                                                           int height,
                                                           const uint256& block_hash) const
{
    if (!m_initialized) return StateError(ChainRegistryStateError::NOT_INITIALIZED);
    if (!Enabled()) return {};
    if (height < 0 || block.GetHash() != block_hash) {
        return StateError(ChainRegistryStateError::NON_SEQUENTIAL_BLOCK);
    }

    const bool connects_genesis{m_state.best_block.IsNull() && height == 0 && block.hashPrevBlock.IsNull()};
    const bool connects_tip{!m_state.best_block.IsNull() &&
                            block.hashPrevBlock == m_state.best_block &&
                            static_cast<uint32_t>(height) == m_state.height + 1};
    if (!connects_genesis && !connects_tip) {
        return StateError(ChainRegistryStateError::NON_SEQUENTIAL_BLOCK);
    }

    if (!m_params.IsActive(height)) return {};

    chainregistry::ChainRegistry candidate{m_registry};
    auto block_result{candidate.ApplyBlock(block,
                                           static_cast<uint32_t>(height),
                                           m_main_genesis_hash,
                                           m_params.minimum_registration_burn,
                                           m_params.maximum_operations,
                                           chainregistry::CommitmentRequirement::REQUIRED,
                                           DepositParamsForHeight(m_params, height))};
    if (!block_result.IsValid()) {
        ChainRegistryStateResult result;
        result.error = ChainRegistryStateError::INVALID_BLOCK;
        result.block_result = std::move(block_result);
        return result;
    }
    chainregistry::BmmBlockValidationResult bmm_result;
    if (m_params.BmmActive(height)) {
        bmm_result = chainregistry::ValidateBlockBmmAnchors(
            block, candidate, m_params.maximum_bmm_anchors);
        if (!bmm_result.IsValid()) {
            ChainRegistryStateResult result;
            result.error = ChainRegistryStateError::INVALID_BLOCK;
            result.block_result = std::move(block_result);
            result.bmm_result = std::move(bmm_result);
            return result;
        }
    }
    ChainRegistryStateResult result;
    result.block_result = std::move(block_result);
    result.bmm_result = std::move(bmm_result);
    return result;
}

ChainRegistryStateResult ChainRegistryState::DisconnectBlock(const uint256& block_hash,
                                                             const uint256& parent_hash,
                                                             int parent_height,
                                                             bool sync)
{
    if (!m_initialized) return StateError(ChainRegistryStateError::NOT_INITIALIZED);
    if (!Enabled()) return {};
    if (m_state.best_block != block_hash || parent_height < -1 ||
        (parent_height < 0 && !parent_hash.IsNull()) ||
        (parent_height >= 0 && parent_hash.IsNull()) ||
        (parent_height < 0 && m_state.height != 0) ||
        (parent_height >= 0 && static_cast<uint32_t>(parent_height + 1) != m_state.height)) {
        return StateError(ChainRegistryStateError::NON_SEQUENTIAL_BLOCK);
    }

    ChainRegistryDBUndo undo;
    if (!m_db->ReadUndo(block_hash, undo)) {
        return StateError(ChainRegistryStateError::UNDO_MISSING);
    }

    chainregistry::ChainRegistry candidate{m_registry};
    if (!candidate.UndoBlock(undo.registry)) {
        return StateError(ChainRegistryStateError::UNDO_FAILED);
    }
    if (undo.deposits.size() > m_state.deposit_count) {
        return StateError(ChainRegistryStateError::UNDO_FAILED);
    }
    if (undo.anchors.size() > m_state.anchor_count) {
        return StateError(ChainRegistryStateError::UNDO_FAILED);
    }
    const auto parent_state{MakeChainRegistryDBState(
        parent_hash,
        parent_height < 0 ? 0 : static_cast<uint32_t>(parent_height),
        candidate,
        m_state.deposit_history_start_height,
        m_state.deposit_count - undo.deposits.size(),
        m_state.anchor_history_start_height,
        m_state.anchor_count - undo.anchors.size())};
    if (!m_db->WriteDisconnectedBlock(candidate, parent_state, block_hash, undo, sync)) {
        return StateError(ChainRegistryStateError::DATABASE_WRITE_FAILED);
    }
    m_registry = std::move(candidate);
    m_state = parent_state;
    return {};
}

ChainRegistryStateResult ChainRegistryState::PruneUndo(std::span<const uint256> block_hashes,
                                                       bool sync)
{
    if (!m_initialized) return StateError(ChainRegistryStateError::NOT_INITIALIZED);
    if (!Enabled() || block_hashes.empty()) return {};
    if (!m_db->EraseUndo(block_hashes, sync)) {
        return StateError(ChainRegistryStateError::DATABASE_WRITE_FAILED);
    }
    return {};
}

std::optional<DepositIndexEntry> ChainRegistryState::FindDeposit(
    const chainregistry::DepositId& deposit_id) const
{
    if (!m_initialized || !m_db) return std::nullopt;
    return m_db->ReadDeposit(deposit_id);
}

std::optional<DepositLookupResult> ChainRegistryState::FindDepositsForChild(
    const chainregistry::ChainId& chain_id,
    uint64_t lookup_limit) const
{
    if (!m_initialized || !m_db) return std::nullopt;
    return m_db->ReadDepositsForChild(chain_id, lookup_limit);
}

std::optional<BmmAnchorIndexEntry> ChainRegistryState::FindAnchor(
    const BmmAnchorId& anchor_id) const
{
    if (!m_initialized || !m_db) return std::nullopt;
    return m_db->ReadAnchor(anchor_id);
}

std::optional<BmmAnchorLookupResult>
ChainRegistryState::FindAnchorsForChildBlocks(
    const chainregistry::ChainId& chain_id,
    std::span<const uint256> child_block_hashes,
    uint64_t lookup_limit) const
{
    if (!m_initialized || !m_db) return std::nullopt;
    return m_db->ReadAnchorsForChildBlocks(
        chain_id, child_block_hashes, lookup_limit);
}

} // namespace node
