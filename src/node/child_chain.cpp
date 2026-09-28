// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain.h>

#include <coins.h>
#include <primitives/block.h>
#include <util/log.h>

#include <algorithm>
#include <exception>
#include <set>
#include <utility>
#include <vector>

namespace node {
namespace {

ReferenceChildRuntimeResult RuntimeError(ReferenceChildRuntimeError error)
{
    ReferenceChildRuntimeResult result;
    result.error = error;
    return result;
}

} // namespace

ReferenceChildRuntime::ReferenceChildRuntime(
    Consensus::Params main_params,
    chainregistry::ReferenceChildDefinition definition)
    : m_main_params{std::move(main_params)},
      m_definition{std::move(definition)},
      m_main_headers{
          std::make_unique<chainregistry::MainHeaderChain>(m_main_params)},
      m_imports{m_definition.chain_id,
                m_definition.parameters.deposit_maturity}
{
}

ReferenceChildRuntime::~ReferenceChildRuntime() = default;

bool ReferenceChildRuntime::RebuildChildIndex(uint32_t genesis_time)
{
    if (!m_db || m_state.child_genesis_hash != m_definition.genesis_hash ||
        m_state.child_tip.IsNull()) {
        return false;
    }

    CBlockHeader genesis_header;
    genesis_header.nTime = genesis_time;
    m_genesis = std::make_unique<CBlockIndex>(genesis_header);
    m_genesis->phashBlock = &m_definition.genesis_hash;
    m_genesis->nHeight = 0;
    m_genesis->nTimeMax = genesis_time;

    m_child_index.clear();
    const auto candidates{m_db->ReadForkCandidates(*m_main_headers)};
    if (!candidates) return false;
    std::map<uint256, const chainregistry::ChildForkCandidate*> by_hash;
    for (const auto& candidate : *candidates) {
        if (!by_hash.emplace(candidate.block_hash, &candidate).second) {
            return false;
        }
    }

    std::set<uint256> visiting;
    const auto build = [&](const auto& self,
                           const uint256& hash) -> CBlockIndex* {
        const auto existing{m_child_index.find(hash)};
        if (existing != m_child_index.end()) return existing->second.get();
        const auto candidate{by_hash.find(hash)};
        if (candidate == by_hash.end() || !visiting.insert(hash).second) {
            return nullptr;
        }
        CBlockIndex* parent{nullptr};
        if (candidate->second->parent_hash == m_definition.genesis_hash) {
            parent = m_genesis.get();
        } else {
            parent = self(self, candidate->second->parent_hash);
        }
        if (!parent) return nullptr;

        CBlock block;
        chainregistry::ReferenceChildBlockUndo undo;
        if (!m_db->ReadBlock(hash, block) ||
            !m_db->ReadUndo(hash, undo) || block.GetHash() != hash ||
            block.hashPrevBlock != parent->GetBlockHash() ||
            undo.block_hash != hash ||
            undo.parent_hash != block.hashPrevBlock ||
            undo.block_height != static_cast<uint32_t>(parent->nHeight + 1)) {
            return nullptr;
        }
        auto index{std::make_unique<CBlockIndex>(block)};
        index->pprev = parent;
        index->nHeight = parent->nHeight + 1;
        index->nTimeMax = std::max(parent->nTimeMax, index->nTime);
        index->nTx = block.vtx.size();
        index->BuildSkip();
        auto [stored, inserted]{
            m_child_index.emplace(hash, std::move(index))};
        if (!inserted) return nullptr;
        stored->second->phashBlock = &stored->first;
        visiting.erase(hash);
        return stored->second.get();
    };
    for (const auto& [hash, candidate] : by_hash) {
        if (!build(build, hash)) return false;
    }

    if (m_state.child_tip == m_definition.genesis_hash) {
        m_tip = m_genesis.get();
    } else {
        const auto tip{m_child_index.find(m_state.child_tip)};
        if (tip == m_child_index.end()) return false;
        m_tip = tip->second.get();
    }
    if (m_tip->nHeight != static_cast<int>(m_state.child_height)) {
        return false;
    }
    return true;
}

bool ReferenceChildRuntime::BuildBranchState(
    CBlockIndex& parent,
    int64_t current_time,
    const chainregistry::MainHeaderChain& main_headers,
    CCoinsViewCache& coins,
    chainregistry::DepositImportState& imports,
    ReferenceChildRuntimeResult& result) const
{
    if (!m_tip || parent.GetAncestor(0) != m_genesis.get()) return false;
    CBlockIndex* canonical{m_tip};
    CBlockIndex* branch{&parent};
    std::vector<CBlockIndex*> branch_path;
    while (canonical->nHeight > branch->nHeight) {
        CBlock block;
        chainregistry::ReferenceChildBlockUndo undo;
        const uint256 hash{canonical->GetBlockHash()};
        if (!m_db->ReadBlock(hash, block) || !m_db->ReadUndo(hash, undo)) {
            return false;
        }
        result.child_block = chainregistry::DisconnectReferenceChildBlock(
            block, undo, coins, imports);
        if (!result.child_block.IsValid()) return false;
        canonical = canonical->pprev;
    }
    while (branch->nHeight > canonical->nHeight) {
        branch_path.push_back(branch);
        branch = branch->pprev;
    }
    while (canonical != branch) {
        CBlock block;
        chainregistry::ReferenceChildBlockUndo undo;
        const uint256 hash{canonical->GetBlockHash()};
        if (!m_db->ReadBlock(hash, block) || !m_db->ReadUndo(hash, undo)) {
            return false;
        }
        result.child_block = chainregistry::DisconnectReferenceChildBlock(
            block, undo, coins, imports);
        if (!result.child_block.IsValid()) return false;
        canonical = canonical->pprev;
        branch_path.push_back(branch);
        branch = branch->pprev;
    }

    std::reverse(branch_path.begin(), branch_path.end());
    for (CBlockIndex* entry : branch_path) {
        CBlock block;
        chainregistry::ReferenceChildBlockUndo stored_undo;
        const uint256 hash{entry->GetBlockHash()};
        if (!m_db->ReadBlock(hash, block) ||
            !m_db->ReadUndo(hash, stored_undo)) {
            return false;
        }
        result.child_block = chainregistry::ConnectReferenceChildBlock(
            block,
            *entry->pprev,
            current_time,
            m_definition,
            main_headers,
            coins,
            imports);
        if (!result.child_block.IsValid() || !result.child_block.undo ||
            *result.child_block.undo != stored_undo) {
            return false;
        }
    }
    return coins.GetBestBlock() == parent.GetBlockHash();
}

bool ReferenceChildRuntime::ActivateSelectedHead(
    const chainregistry::ChildForkChoiceResult& selected,
    std::span<const chainregistry::ChildForkCandidate> candidates,
    int64_t current_time,
    const chainregistry::MainHeaderChain& main_headers,
    bool sync,
    ReferenceChildRuntimeResult& result)
{
    if (!selected.IsValid() || selected.head.IsNull() || !m_tip ||
        selected.head == m_tip->GetBlockHash()) {
        return false;
    }
    CBlockIndex* selected_tip{m_genesis.get()};
    if (selected.head != m_definition.genesis_hash) {
        const auto selected_entry{m_child_index.find(selected.head)};
        if (selected_entry == m_child_index.end()) return false;
        selected_tip = selected_entry->second.get();
    }

    CBlockIndex* old_branch{m_tip};
    CBlockIndex* new_branch{selected_tip};
    std::vector<CBlockIndex*> disconnected_index;
    std::vector<CBlockIndex*> connected_index;
    while (old_branch->nHeight > new_branch->nHeight) {
        disconnected_index.push_back(old_branch);
        old_branch = old_branch->pprev;
    }
    while (new_branch->nHeight > old_branch->nHeight) {
        connected_index.push_back(new_branch);
        new_branch = new_branch->pprev;
    }
    while (old_branch != new_branch) {
        disconnected_index.push_back(old_branch);
        connected_index.push_back(new_branch);
        old_branch = old_branch->pprev;
        new_branch = new_branch->pprev;
    }
    if (disconnected_index.empty() && connected_index.empty()) return false;
    std::reverse(connected_index.begin(), connected_index.end());

    std::map<uint256, const chainregistry::ChildForkCandidate*> by_hash;
    for (const auto& candidate : candidates) {
        if (!by_hash.emplace(candidate.block_hash, &candidate).second) {
            return false;
        }
    }

    std::vector<ChildChainDBDisconnect> disconnected;
    disconnected.reserve(disconnected_index.size());
    for (CBlockIndex* entry : disconnected_index) {
        ChildChainDBDisconnect record;
        if (!m_db->ReadBlock(entry->GetBlockHash(), record.block) ||
            !m_db->ReadUndo(entry->GetBlockHash(), record.undo)) {
            return false;
        }
        disconnected.push_back(std::move(record));
    }

    std::vector<ChildChainDBConnect> connected;
    connected.reserve(connected_index.size());
    for (CBlockIndex* entry : connected_index) {
        const uint256 hash{entry->GetBlockHash()};
        const auto candidate{by_hash.find(hash)};
        const auto score{selected.scores.find(hash)};
        if (candidate == by_hash.end() || score == selected.scores.end() ||
            !score->second.eligible) {
            return false;
        }
        const auto primary{std::find_if(
            candidate->second->anchors.begin(),
            candidate->second->anchors.end(),
            [&](const chainregistry::ChildForkAnchor& anchor) {
                return anchor.main_height ==
                    score->second.activation_main_height;
            })};
        if (primary == candidate->second->anchors.end()) return false;
        const auto anchor{m_db->ReadCandidateBmmAnchor(
            primary->main_block_hash)};
        ChildChainDBConnect record;
        if (!anchor || anchor->child_block_hash != hash ||
            !m_db->ReadBlock(hash, record.block) ||
            !m_db->ReadUndo(hash, record.undo)) {
            return false;
        }
        record.primary_anchor = anchor->proof;
        connected.push_back(std::move(record));
    }

    CCoinsViewCache candidate_coins{m_db.get(), /*deterministic=*/true};
    chainregistry::DepositImportState candidate_imports{m_imports};
    if (!BuildBranchState(
            *selected_tip,
            current_time,
            main_headers,
            candidate_coins,
            candidate_imports,
            result)) {
        return false;
    }
    if (!m_db->WriteChildReorganization(
            main_headers,
            candidate_imports,
            disconnected,
            connected,
            sync)) {
        result.error =
            ReferenceChildRuntimeError::CHILD_REORGANIZATION_PERSIST_FAILED;
        return false;
    }
    try {
        candidate_coins.Flush();
    } catch (const std::exception&) {
        m_failed = true;
        result.error =
            ReferenceChildRuntimeError::CACHE_ACKNOWLEDGEMENT_FAILED;
        return false;
    }
    m_imports = std::move(candidate_imports);
    if (!m_db->ReadState(m_state)) {
        m_failed = true;
        result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
        return false;
    }
    m_tip = selected_tip;
    result.disconnected_child_blocks.reserve(disconnected_index.size());
    for (const CBlockIndex* entry : disconnected_index) {
        result.disconnected_child_blocks.push_back(entry->GetBlockHash());
    }
    result.selected_child_head = m_tip->GetBlockHash();
    result.reorganization_required = false;
    return true;
}

ReferenceChildRuntimeResult ReferenceChildRuntime::Initialize(
    const DBParams& db_params,
    const CBlockHeader& main_genesis,
    int64_t current_time,
    bool sync,
    std::optional<std::span<const CBlockHeader>> validated_active_headers)
{
    if (m_initialized || m_db) {
        return RuntimeError(ReferenceChildRuntimeError::ALREADY_INITIALIZED);
    }
    const auto validated{chainregistry::ValidateReferenceChildManifest(
        m_definition.genesis.main_genesis_hash,
        m_definition.genesis.registration_anchor,
        m_definition.manifest)};
    if (!validated.IsValid() || *validated.definition != m_definition) {
        return RuntimeError(ReferenceChildRuntimeError::INVALID_DEFINITION);
    }
    if (m_main_params.hashGenesisBlock !=
            m_definition.genesis.main_genesis_hash ||
        main_genesis.GetHash() != m_main_params.hashGenesisBlock) {
        return RuntimeError(ReferenceChildRuntimeError::WRONG_MAIN_GENESIS);
    }

    m_db = std::make_unique<ChildChainDB>(
        db_params,
        m_definition.chain_id,
        m_definition.genesis.main_genesis_hash,
        m_definition.parameters.deposit_maturity,
        m_definition.genesis_hash);
    ReferenceChildRuntimeResult result;
    result.database_load =
        m_db->Load(
            *m_main_headers,
            m_imports,
            m_state,
            current_time,
            validated_active_headers);
    if (!result.database_load.IsValid()) {
        result.error = ReferenceChildRuntimeError::DATABASE_LOAD_FAILED;
        m_failed = true;
        return result;
    }
    result.loaded_existing = result.database_load.initialized;
    if (!result.loaded_existing) {
        result.main_header = m_main_headers->Initialize(main_genesis);
        if (!result.main_header.IsValid()) {
            result.error = ReferenceChildRuntimeError::MAIN_HEADER_REJECTED;
            m_failed = true;
            return result;
        }
        for (const CBlockHeader& header :
             validated_active_headers.value_or(std::span<const CBlockHeader>{})) {
            result.main_header =
                m_main_headers->AddValidatedHeader(header, current_time);
            if (!result.main_header.IsValid()) {
                result.error =
                    ReferenceChildRuntimeError::MAIN_HEADER_REJECTED;
                m_failed = true;
                return result;
            }
        }
        if (!m_db->WriteInitialState(*m_main_headers, m_imports, sync) ||
            !m_db->ReadState(m_state)) {
            result.error = ReferenceChildRuntimeError::DATABASE_INITIALIZE_FAILED;
            m_failed = true;
            return result;
        }
    }
    if (!RebuildChildIndex(main_genesis.nTime)) {
        result.error = ReferenceChildRuntimeError::CHILD_INDEX_REBUILD_FAILED;
        m_failed = true;
        return result;
    }
    const auto candidates{m_db->ReadForkCandidates(*m_main_headers)};
    if (!candidates) {
        result.error = ReferenceChildRuntimeError::CHILD_INDEX_REBUILD_FAILED;
        m_failed = true;
        return result;
    }
    const auto selected{chainregistry::SelectChildFork(
        m_definition.genesis_hash, *candidates)};
    if (!selected.IsValid()) {
        result.error = ReferenceChildRuntimeError::CHILD_INDEX_REBUILD_FAILED;
        m_failed = true;
        return result;
    }
    if (selected.head != m_tip->GetBlockHash() &&
        !ActivateSelectedHead(
            selected,
            *candidates,
            current_time,
            *m_main_headers,
            sync,
            result)) {
        if (result.error == ReferenceChildRuntimeError::NONE) {
            result.error =
                ReferenceChildRuntimeError::CHILD_REORGANIZATION_FAILED;
        }
        m_failed = true;
        return result;
    }
    m_initialized = true;
    if (result.loaded_existing && validated_active_headers) {
        for (const CBlockHeader& header : *validated_active_headers) {
            auto advanced{AddValidatedMainHeader(
                header, current_time, sync)};
            if (!advanced.IsValid()) {
                advanced.loaded_existing = true;
                return advanced;
            }
            result.main_header = std::move(advanced.main_header);
            result.reconcile = std::move(advanced.reconcile);
            result.disconnected_child_blocks.insert(
                result.disconnected_child_blocks.end(),
                advanced.disconnected_child_blocks.begin(),
                advanced.disconnected_child_blocks.end());
        }
        const uint256 active_tip{validated_active_headers->empty()
            ? m_main_params.hashGenesisBlock
            : validated_active_headers->back().GetHash()};
        auto selected{SelectValidatedMainTip(
            active_tip, current_time, sync)};
        if (!selected.IsValid()) {
            selected.loaded_existing = true;
            return selected;
        }
        result.main_header = std::move(selected.main_header);
        result.reconcile = std::move(selected.reconcile);
        result.disconnected_child_blocks.insert(
            result.disconnected_child_blocks.end(),
            selected.disconnected_child_blocks.begin(),
            selected.disconnected_child_blocks.end());
    }
    return result;
}

ReferenceChildRuntimeResult ReferenceChildRuntime::AddMainHeader(
    const CBlockHeader& header,
    int64_t current_time,
    bool sync)
{
    return AddMainHeaderImpl(
        header,
        current_time,
        sync,
        /*validated_by_main_chainstate=*/false);
}

ReferenceChildRuntimeResult ReferenceChildRuntime::AddValidatedMainHeader(
    const CBlockHeader& header,
    int64_t current_time,
    bool sync)
{
    return AddMainHeaderImpl(
        header,
        current_time,
        sync,
        /*validated_by_main_chainstate=*/true);
}

ReferenceChildRuntimeResult ReferenceChildRuntime::AddMainHeaderImpl(
    const CBlockHeader& header,
    int64_t current_time,
    bool sync,
    bool validated_by_main_chainstate)
{
    if (!m_initialized) {
        return RuntimeError(ReferenceChildRuntimeError::NOT_INITIALIZED);
    }
    if (m_failed) {
        return RuntimeError(ReferenceChildRuntimeError::FAILED_RUNTIME);
    }

    if (m_main_headers->Find(header.GetHash())) {
        ReferenceChildRuntimeResult result;
        result.main_header = validated_by_main_chainstate
            ? m_main_headers->AddValidatedHeader(header, current_time)
            : m_main_headers->AddHeader(header, current_time);
        return result;
    }
    auto candidate_headers{
        std::make_unique<chainregistry::MainHeaderChain>(*m_main_headers)};

    ReferenceChildRuntimeResult result;
    result.main_header = validated_by_main_chainstate
        ? candidate_headers->AddValidatedHeader(header, current_time)
        : candidate_headers->AddHeader(header, current_time);
    if (!result.main_header.IsValid()) {
        result.error = ReferenceChildRuntimeError::MAIN_HEADER_REJECTED;
        return result;
    }
    if (result.main_header.already_known) return result;
    return CommitMainChainUpdate(
        std::move(candidate_headers),
        std::move(result),
        &header,
        current_time,
        sync);
}

ReferenceChildRuntimeResult ReferenceChildRuntime::SelectValidatedMainTip(
    const uint256& active_tip,
    int64_t current_time,
    bool sync)
{
    if (!m_initialized) {
        return RuntimeError(ReferenceChildRuntimeError::NOT_INITIALIZED);
    }
    if (m_failed) {
        return RuntimeError(ReferenceChildRuntimeError::FAILED_RUNTIME);
    }
    if (m_main_headers->Tip()->GetBlockHash() == active_tip) {
        ReferenceChildRuntimeResult result;
        result.main_header = m_main_headers->SelectValidatedTip(active_tip);
        return result;
    }
    auto candidate_headers{
        std::make_unique<chainregistry::MainHeaderChain>(*m_main_headers)};
    ReferenceChildRuntimeResult result;
    result.main_header = candidate_headers->SelectValidatedTip(active_tip);
    if (!result.main_header.IsValid()) {
        result.error = ReferenceChildRuntimeError::MAIN_HEADER_REJECTED;
        return result;
    }
    return CommitMainChainUpdate(
        std::move(candidate_headers),
        std::move(result),
        nullptr,
        current_time,
        sync);
}

ReferenceChildRuntimeResult ReferenceChildRuntime::CommitMainChainUpdate(
    std::unique_ptr<chainregistry::MainHeaderChain> candidate_headers,
    ReferenceChildRuntimeResult result,
    const CBlockHeader* added_header,
    int64_t current_time,
    bool sync)
{
    chainregistry::DepositImportState candidate_imports{m_imports};
    result.reconcile = candidate_imports.Reconcile(*candidate_headers);
    CCoinsViewCache candidate_coins{m_db.get(), /*deterministic=*/true};
    CBlockIndex* candidate_child_tip{m_tip};
    std::vector<ChildChainDBDisconnect> disconnected_blocks;
    std::vector<uint256> disconnected_hashes;
    if (!candidate_imports.IsSafeHalted()) {
        while (candidate_child_tip != m_genesis.get()) {
            const uint256 child_hash{candidate_child_tip->GetBlockHash()};
            const auto anchor{m_db->ReadBmmAnchor(child_hash)};
            if (!anchor) {
                result.error =
                    ReferenceChildRuntimeError::MAIN_REORG_ROLLBACK_FAILED;
                return result;
            }
            const auto authenticated{candidate_headers->AuthenticateBmmAnchor(
                anchor->proof,
                m_definition.chain_id,
                /*minimum_confirmations=*/1)};
            if (authenticated.IsValid()) break;
            if (authenticated.error !=
                chainregistry::AuthenticatedBmmAnchorError::HEADER_NOT_ACTIVE) {
                result.error =
                    ReferenceChildRuntimeError::MAIN_REORG_ROLLBACK_FAILED;
                return result;
            }

            ChildChainDBDisconnect disconnected;
            if (!m_db->ReadBlock(child_hash, disconnected.block) ||
                !m_db->ReadUndo(child_hash, disconnected.undo)) {
                result.error =
                    ReferenceChildRuntimeError::MAIN_REORG_ROLLBACK_FAILED;
                return result;
            }
            result.child_block =
                chainregistry::DisconnectReferenceChildBlock(
                    disconnected.block,
                    disconnected.undo,
                    candidate_coins,
                    candidate_imports);
            if (!result.child_block.IsValid()) {
                result.error =
                    ReferenceChildRuntimeError::MAIN_REORG_ROLLBACK_FAILED;
                return result;
            }
            disconnected_hashes.push_back(child_hash);
            disconnected_blocks.push_back(std::move(disconnected));
            candidate_child_tip = candidate_child_tip->pprev;
        }
    }
    const bool persisted{added_header
        ? m_db->WriteMainHeaderAndDisconnect(
              *candidate_headers,
              candidate_imports,
              *added_header,
              disconnected_blocks,
              sync)
        : m_db->WriteMainTipAndDisconnect(
              *candidate_headers,
              candidate_imports,
              disconnected_blocks,
              sync)};
    if (!persisted) {
        result.error = ReferenceChildRuntimeError::MAIN_HEADER_PERSIST_FAILED;
        return result;
    }
    if (!disconnected_blocks.empty()) {
        try {
            candidate_coins.Flush();
        } catch (const std::exception&) {
            m_failed = true;
            result.error =
                ReferenceChildRuntimeError::CACHE_ACKNOWLEDGEMENT_FAILED;
            return result;
        }
    }
    m_main_headers = std::move(candidate_headers);
    m_imports = std::move(candidate_imports);
    if (!m_db->ReadState(m_state)) {
        m_failed = true;
        result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
        return result;
    }
    m_tip = candidate_child_tip;
    result.disconnected_child_blocks = std::move(disconnected_hashes);
    if (!m_imports.IsSafeHalted()) {
        const auto candidates{m_db->ReadForkCandidates(*m_main_headers)};
        if (!candidates) {
            m_failed = true;
            result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
            return result;
        }
        const auto selected{chainregistry::SelectChildFork(
            m_definition.genesis_hash, *candidates)};
        if (!selected.IsValid()) {
            m_failed = true;
            result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
            return result;
        }
        result.selected_child_head = selected.head;
        result.reorganization_required =
            selected.head != m_tip->GetBlockHash();
        if (result.reorganization_required &&
            !ActivateSelectedHead(
                selected,
                *candidates,
                current_time,
                *m_main_headers,
                sync,
                result)) {
            if (result.error == ReferenceChildRuntimeError::NONE) {
                result.error =
                    ReferenceChildRuntimeError::CHILD_REORGANIZATION_FAILED;
            }
            return result;
        }
    }
    return result;
}

ReferenceChildRuntimeResult ReferenceChildRuntime::StageBmmAnchor(
    const chainregistry::BmmAnchorProof& anchor_proof,
    int64_t current_time,
    bool sync)
{
    if (!m_initialized) {
        return RuntimeError(ReferenceChildRuntimeError::NOT_INITIALIZED);
    }
    if (m_failed) {
        return RuntimeError(ReferenceChildRuntimeError::FAILED_RUNTIME);
    }

    ReferenceChildRuntimeResult result;
    result.bmm_anchor = m_main_headers->AuthenticateBmmAnchor(
        anchor_proof,
        m_definition.chain_id,
        /*minimum_confirmations=*/1);
    if (!result.bmm_anchor.IsValid()) {
        result.error = ReferenceChildRuntimeError::BMM_ANCHOR_REJECTED;
        return result;
    }
    const uint256 main_block_hash{anchor_proof.block_header.GetHash()};
    const uint256 child_block_hash{
        result.bmm_anchor.proof.anchor->child_block_hash};
    CBlock known_block;
    const bool child_block_known{m_db->ReadBlock(
        child_block_hash, known_block)};
    const auto primary_anchor{m_db->ReadBmmAnchor(child_block_hash)};
    const bool already_known{
        m_db->ReadPendingBmmAnchor(main_block_hash).has_value() ||
        m_db->ReadCandidateBmmAnchor(main_block_hash).has_value() ||
        (primary_anchor &&
         primary_anchor->proof.block_header.GetHash() == main_block_hash)};
    const bool persisted{child_block_known
        ? m_db->WriteCandidateBmmAnchor(
              *m_main_headers, anchor_proof, sync)
        : m_db->WritePendingBmmAnchor(
              *m_main_headers, anchor_proof, sync)};
    if (!persisted) {
        result.error = ReferenceChildRuntimeError::BMM_ANCHOR_PERSIST_FAILED;
        return result;
    }
    if (!m_db->ReadState(m_state)) {
        m_failed = true;
        result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
        return result;
    }
    result.bmm_anchor_already_known = already_known;
    if (child_block_known) {
        const auto candidates{m_db->ReadForkCandidates(*m_main_headers)};
        if (!candidates) {
            m_failed = true;
            result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
            return result;
        }
        const auto selected{chainregistry::SelectChildFork(
            m_definition.genesis_hash, *candidates)};
        if (!selected.IsValid()) {
            m_failed = true;
            result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
            return result;
        }
        result.selected_child_head = selected.head;
        result.reorganization_required =
            selected.head != m_tip->GetBlockHash();
        if (result.reorganization_required &&
            !ActivateSelectedHead(
                selected,
                *candidates,
                current_time,
                *m_main_headers,
                sync,
                result)) {
            if (result.error == ReferenceChildRuntimeError::NONE) {
                result.error =
                    ReferenceChildRuntimeError::CHILD_REORGANIZATION_FAILED;
            }
        }
    }
    return result;
}

ReferenceChildRuntimeResult ReferenceChildRuntime::ConnectBlock(
    const CBlock& block,
    const chainregistry::BmmAnchorProof& anchor_proof,
    int64_t current_time,
    bool sync)
{
    if (!m_initialized) {
        return RuntimeError(ReferenceChildRuntimeError::NOT_INITIALIZED);
    }
    if (m_failed) {
        return RuntimeError(ReferenceChildRuntimeError::FAILED_RUNTIME);
    }
    const uint256 block_hash{block.GetHash()};
    ReferenceChildRuntimeResult result;
    result.bmm_anchor = m_main_headers->AuthenticateBmmAnchor(
        anchor_proof,
        m_definition.chain_id,
        /*minimum_confirmations=*/1);
    if (!result.bmm_anchor.IsValid() || !result.bmm_anchor.proof.anchor ||
        result.bmm_anchor.proof.anchor->child_block_hash != block_hash) {
        result.error = ReferenceChildRuntimeError::BMM_ANCHOR_REJECTED;
        return result;
    }
    CBlockIndex* parent{nullptr};
    if (block.hashPrevBlock == m_definition.genesis_hash) {
        parent = m_genesis.get();
    } else {
        const auto found_parent{m_child_index.find(block.hashPrevBlock)};
        if (found_parent != m_child_index.end()) {
            parent = found_parent->second.get();
        }
    }
    if (!parent) {
        return RuntimeError(ReferenceChildRuntimeError::CHILD_BLOCK_REJECTED);
    }
    auto [slot, inserted]{m_child_index.try_emplace(block_hash)};
    if (!inserted) {
        return RuntimeError(ReferenceChildRuntimeError::CHILD_BLOCK_REJECTED);
    }
    slot->second = std::make_unique<CBlockIndex>(block);
    slot->second->phashBlock = &slot->first;
    slot->second->pprev = parent;
    slot->second->nHeight = parent->nHeight + 1;
    slot->second->nTimeMax = std::max(parent->nTimeMax, slot->second->nTime);
    slot->second->nTx = block.vtx.size();
    slot->second->BuildSkip();

    CCoinsViewCache candidate_coins{m_db.get(), /*deterministic=*/true};
    chainregistry::DepositImportState candidate_imports{m_imports};
    if (!BuildBranchState(
            *parent,
            current_time,
            *m_main_headers,
            candidate_coins,
            candidate_imports,
            result)) {
        m_child_index.erase(slot);
        result.error = ReferenceChildRuntimeError::CHILD_BLOCK_REJECTED;
        return result;
    }
    result.child_block = chainregistry::ConnectReferenceChildBlock(
        block,
        *parent,
        current_time,
        m_definition,
        *m_main_headers,
        candidate_coins,
        candidate_imports);
    if (!result.child_block.IsValid()) {
        m_child_index.erase(slot);
        result.error = ReferenceChildRuntimeError::CHILD_BLOCK_REJECTED;
        return result;
    }
    if (parent != m_tip) {
        std::vector<uint256> pruned_candidates;
        if (!m_db->WriteValidatedChildCandidate(
                *m_main_headers,
                block,
                *result.child_block.undo,
                anchor_proof,
                sync,
                &pruned_candidates)) {
            m_child_index.erase(slot);
            result.error =
                ReferenceChildRuntimeError::CHILD_BLOCK_PERSIST_FAILED;
            return result;
        }
        for (const uint256& hash : pruned_candidates) {
            if (hash == m_tip->GetBlockHash() ||
                m_child_index.erase(hash) != 1) {
                m_failed = true;
                result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
                return result;
            }
        }
        result.pruned_child_candidates = std::move(pruned_candidates);
        if (!m_db->ReadState(m_state)) {
            m_failed = true;
            result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
            return result;
        }
        const auto candidates{m_db->ReadForkCandidates(*m_main_headers)};
        if (!candidates) {
            m_failed = true;
            result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
            return result;
        }
        const auto selected{chainregistry::SelectChildFork(
            m_definition.genesis_hash, *candidates)};
        if (!selected.IsValid()) {
            m_failed = true;
            result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
            return result;
        }
        result.candidate_stored = true;
        result.selected_child_head = selected.head;
        result.reorganization_required =
            selected.head != m_tip->GetBlockHash();
        if (result.reorganization_required &&
            !ActivateSelectedHead(
                selected,
                *candidates,
                current_time,
                *m_main_headers,
                sync,
                result)) {
            if (result.error == ReferenceChildRuntimeError::NONE) {
                result.error =
                    ReferenceChildRuntimeError::CHILD_REORGANIZATION_FAILED;
            }
        }
        return result;
    }
    if (!m_db->WriteConnectedChildBlock(
            *m_main_headers,
            candidate_imports,
            block,
            *result.child_block.undo,
            anchor_proof,
            sync)) {
        m_child_index.erase(slot);
        result.error = ReferenceChildRuntimeError::CHILD_BLOCK_PERSIST_FAILED;
        return result;
    }
    try {
        candidate_coins.Flush();
    } catch (const std::exception&) {
        m_failed = true;
        result.error =
            ReferenceChildRuntimeError::CACHE_ACKNOWLEDGEMENT_FAILED;
        return result;
    }
    m_imports = std::move(candidate_imports);
    if (!m_db->ReadState(m_state)) {
        m_failed = true;
        result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
        return result;
    }
    m_tip = slot->second.get();
    result.selected_child_head = m_tip->GetBlockHash();
    return result;
}

ReferenceChildRuntimeResult ReferenceChildRuntime::DisconnectTip(bool sync)
{
    if (!m_initialized) {
        return RuntimeError(ReferenceChildRuntimeError::NOT_INITIALIZED);
    }
    if (m_failed) {
        return RuntimeError(ReferenceChildRuntimeError::FAILED_RUNTIME);
    }
    if (!m_tip || m_tip == m_genesis.get()) {
        return RuntimeError(
            ReferenceChildRuntimeError::CHILD_DISCONNECT_REJECTED);
    }

    const uint256 block_hash{m_tip->GetBlockHash()};
    CBlock block;
    chainregistry::ReferenceChildBlockUndo undo;
    if (!m_db->ReadBlock(block_hash, block) ||
        !m_db->ReadUndo(block_hash, undo)) {
        m_failed = true;
        return RuntimeError(ReferenceChildRuntimeError::FAILED_RUNTIME);
    }

    CCoinsViewCache candidate_coins{m_db.get(), /*deterministic=*/true};
    chainregistry::DepositImportState candidate_imports{m_imports};
    ReferenceChildRuntimeResult result;
    result.child_block = chainregistry::DisconnectReferenceChildBlock(
        block, undo, candidate_coins, candidate_imports);
    if (!result.child_block.IsValid()) {
        result.error =
            ReferenceChildRuntimeError::CHILD_DISCONNECT_REJECTED;
        return result;
    }
    if (!m_db->WriteDisconnectedChildBlock(
            *m_main_headers, candidate_imports, block, undo, sync)) {
        result.error =
            ReferenceChildRuntimeError::CHILD_DISCONNECT_PERSIST_FAILED;
        return result;
    }
    try {
        candidate_coins.Flush();
    } catch (const std::exception&) {
        m_failed = true;
        result.error =
            ReferenceChildRuntimeError::CACHE_ACKNOWLEDGEMENT_FAILED;
        return result;
    }
    m_imports = std::move(candidate_imports);
    if (!m_db->ReadState(m_state)) {
        m_failed = true;
        result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
        return result;
    }
    m_tip = m_tip->pprev;
    m_child_index.erase(block_hash);
    return result;
}

std::optional<Coin> ReferenceChildRuntime::GetCoin(
    const COutPoint& outpoint) const
{
    if (!Usable() || !m_db) return std::nullopt;
    return m_db->GetCoin(outpoint);
}

std::optional<uint256> ReferenceChildRuntime::GetBlockHash(int height) const
{
    if (!Usable() || !m_tip || height < 0 || height > m_tip->nHeight) {
        return std::nullopt;
    }
    const CBlockIndex* index{m_tip->GetAncestor(height)};
    if (!index) return std::nullopt;
    return index->GetBlockHash();
}

std::optional<ReferenceChildBlockView> ReferenceChildRuntime::GetBlockView(
    const uint256& block_hash) const
{
    if (!Usable() || !m_tip || !m_genesis || !m_db) return std::nullopt;

    const CBlockIndex* index{nullptr};
    const bool virtual_genesis{block_hash == m_definition.genesis_hash};
    if (virtual_genesis) {
        index = m_genesis.get();
    } else {
        const auto found{m_child_index.find(block_hash)};
        if (found == m_child_index.end()) return std::nullopt;
        index = found->second.get();
    }

    ReferenceChildBlockView result{
        .block_hash = block_hash,
        .block = std::nullopt,
        .undo = std::nullopt,
        .height = index->nHeight,
        .confirmations = -1,
        .time = index->nTime,
        .median_time = index->GetMedianTimePast(),
        .active = false,
        .virtual_genesis = virtual_genesis,
        .next_block_hash = std::nullopt,
        .fork_score = {},
    };
    const CBlockIndex* active{m_tip->GetAncestor(index->nHeight)};
    result.active = active && active->GetBlockHash() == block_hash;
    if (result.active) {
        result.confirmations = m_tip->nHeight - index->nHeight + 1;
        if (index->nHeight < m_tip->nHeight) {
            const CBlockIndex* next{m_tip->GetAncestor(index->nHeight + 1)};
            Assume(next);
            result.next_block_hash = next->GetBlockHash();
        }
    }
    if (virtual_genesis) return result;

    CBlock block;
    chainregistry::ReferenceChildBlockUndo undo;
    if (!m_db->ReadBlock(block_hash, block) ||
        !m_db->ReadUndo(block_hash, undo) ||
        block.GetHash() != block_hash ||
        undo.block_hash != block_hash ||
        undo.parent_hash != block.hashPrevBlock ||
        undo.block_height != static_cast<uint32_t>(index->nHeight) ||
        undo.coins.vtxundo.size() + 1 != block.vtx.size()) {
        return std::nullopt;
    }
    for (size_t transaction{1}; transaction < block.vtx.size(); ++transaction) {
        const auto& spent{undo.coins.vtxundo[transaction - 1].vprevout};
        const size_t expected{chainregistry::IsReferenceChildImport(*block.vtx[transaction])
                ? 0
                : block.vtx[transaction]->vin.size()};
        if (spent.size() != expected) return std::nullopt;
    }
    result.block = std::move(block);
    result.undo = std::move(undo);
    const auto candidates{m_db->ReadForkCandidates(*m_main_headers)};
    if (!candidates) return std::nullopt;
    const auto selected{chainregistry::SelectChildFork(
        m_definition.genesis_hash, *candidates)};
    if (!selected.IsValid()) return std::nullopt;
    const auto score{selected.scores.find(block_hash)};
    if (score == selected.scores.end()) return std::nullopt;
    result.fork_score = score->second;
    return result;
}

std::optional<std::vector<ReferenceChildChainTipView>>
ReferenceChildRuntime::GetChainTips() const
{
    if (!Usable() || !m_tip || !m_genesis || !m_db) return std::nullopt;

    const auto candidates{m_db->ReadForkCandidates(*m_main_headers)};
    if (!candidates) return std::nullopt;
    const auto selected{chainregistry::SelectChildFork(
        m_definition.genesis_hash, *candidates)};
    if (!selected.IsValid()) return std::nullopt;

    std::set<uint256> parents;
    for (const auto& [_, index] : m_child_index) {
        Assume(index->pprev);
        parents.insert(index->pprev->GetBlockHash());
    }

    std::set<uint256> tip_hashes{m_tip->GetBlockHash()};
    for (const auto& [hash, _] : m_child_index) {
        if (!parents.contains(hash)) tip_hashes.insert(hash);
    }

    std::vector<ReferenceChildChainTipView> result;
    result.reserve(tip_hashes.size());
    for (const uint256& hash : tip_hashes) {
        const CBlockIndex* index;
        if (hash == m_definition.genesis_hash) {
            index = m_genesis.get();
        } else {
            const auto found{m_child_index.find(hash)};
            if (found == m_child_index.end()) return std::nullopt;
            index = found->second.get();
        }

        const CBlockIndex* branch{index};
        const CBlockIndex* active{m_tip};
        while (branch->nHeight > active->nHeight) branch = branch->pprev;
        while (active->nHeight > branch->nHeight) active = active->pprev;
        while (branch != active) {
            if (!branch || !active) return std::nullopt;
            branch = branch->pprev;
            active = active->pprev;
        }
        Assume(branch);

        ReferenceChildChainTipView view{
            .block_hash = hash,
            .height = index->nHeight,
            .branch_length = index->nHeight - branch->nHeight,
            .active = hash == m_tip->GetBlockHash(),
            .fork_score = {},
        };
        if (hash != m_definition.genesis_hash) {
            const auto score{selected.scores.find(hash)};
            if (score == selected.scores.end()) return std::nullopt;
            view.fork_score = score->second;
        }
        result.push_back(std::move(view));
    }
    std::sort(result.begin(), result.end(),
              [](const auto& left, const auto& right) {
                  if (left.height != right.height) {
                      return left.height > right.height;
                  }
                  return left.block_hash < right.block_hash;
              });
    return result;
}

std::optional<kernel::CCoinsStats> ReferenceChildRuntime::GetUTXOStats(
    kernel::CoinStatsHashType hash_type,
    const std::function<void()>& interruption_point) const
{
    if (!Usable() || !m_tip || !m_db ||
        m_tip->GetBlockHash() != m_state.child_tip ||
        m_tip->nHeight != static_cast<int>(m_state.child_height)) {
        return std::nullopt;
    }
    auto stats{kernel::ComputeUTXOStatsAtHeight(
        hash_type, m_db.get(), m_tip->nHeight, interruption_point)};
    if (!stats || stats->hashBlock != m_state.child_tip ||
        stats->nHeight != m_tip->nHeight ||
        stats->coins_count != m_state.coin_count ||
        stats->nTransactionOutputs != m_state.coin_count) {
        return std::nullopt;
    }
    return stats;
}

bool ReferenceChildRuntime::VerifyDatabase(int64_t current_time) const
{
    if (!Usable() || !m_tip || !m_main_headers || !m_db) return false;

    chainregistry::MainHeaderChain headers{m_main_params};
    chainregistry::DepositImportState imports{
        m_definition.chain_id,
        m_imports.MinimumConfirmations()};
    ChildChainDBState state;
    const auto loaded{m_db->Load(
        headers, imports, state, current_time)};
    if (!loaded.IsValid()) {
        LogError("Child chain verification failed while loading database: %d\n",
                 static_cast<int>(loaded.error));
        return false;
    }
    if (!loaded.initialized || state != m_state) {
        LogError("Child chain verification found a runtime state mismatch\n");
        return false;
    }
    if (!headers.Tip() || !m_main_headers->Tip() ||
        headers.Tip()->GetBlockHash() != m_main_headers->Tip()->GetBlockHash()) {
        LogError("Child chain verification found a main-header tip mismatch\n");
        return false;
    }
    if (imports.Imports() != m_imports.Imports() ||
        imports.SafeHalt() != m_imports.SafeHalt()) {
        LogError("Child chain verification found an import state mismatch\n");
        return false;
    }
    if (state.child_tip != m_tip->GetBlockHash() ||
        state.child_height != static_cast<uint32_t>(m_tip->nHeight)) {
        LogError("Child chain verification found a child tip mismatch\n");
        return false;
    }
    const auto stored_headers{headers.ExportHeaders()};
    const auto active_headers{m_main_headers->ExportHeaders()};
    if (stored_headers.size() != active_headers.size()) {
        LogError("Child chain verification found a main-header count mismatch\n");
        return false;
    }
    for (size_t index{0}; index < stored_headers.size(); ++index) {
        if (stored_headers[index].version != active_headers[index].version ||
            stored_headers[index].height != active_headers[index].height ||
            stored_headers[index].header.GetHash() !=
                active_headers[index].header.GetHash()) {
            LogError("Child chain verification found a main-header record mismatch\n");
            return false;
        }
    }
    return true;
}

bool ReferenceChildRuntime::ReadBlock(const uint256& block_hash,
                                      CBlock& block) const
{
    return Usable() && m_db && m_db->ReadBlock(block_hash, block);
}

} // namespace node
