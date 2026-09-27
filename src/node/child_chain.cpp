// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain.h>

#include <coins.h>
#include <primitives/block.h>

#include <algorithm>
#include <exception>
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

    std::vector<CBlock> reverse_blocks;
    reverse_blocks.reserve(m_state.child_height);
    uint256 block_hash{m_state.child_tip};
    for (uint32_t height{m_state.child_height}; height > 0; --height) {
        CBlock block;
        if (!m_db->ReadBlock(block_hash, block) ||
            block.GetHash() != block_hash) {
            return false;
        }
        block_hash = block.hashPrevBlock;
        reverse_blocks.push_back(std::move(block));
    }
    if (block_hash != m_definition.genesis_hash) return false;
    std::reverse(reverse_blocks.begin(), reverse_blocks.end());

    m_child_index.clear();
    CBlockIndex* parent{m_genesis.get()};
    for (uint32_t height{1}; height <= reverse_blocks.size(); ++height) {
        const CBlock& block{reverse_blocks[height - 1]};
        if (block.hashPrevBlock != parent->GetBlockHash()) return false;
        const uint256 hash{block.GetHash()};
        auto index{std::make_unique<CBlockIndex>(block)};
        index->pprev = parent;
        index->nHeight = static_cast<int>(height);
        index->nTimeMax = std::max(parent->nTimeMax, index->nTime);
        index->nTx = block.vtx.size();
        index->BuildSkip();
        auto [stored, inserted]{m_child_index.emplace(hash, std::move(index))};
        if (!inserted) return false;
        stored->second->phashBlock = &stored->first;
        parent = stored->second.get();
    }
    if (parent->GetBlockHash() != m_state.child_tip ||
        parent->nHeight != static_cast<int>(m_state.child_height)) {
        return false;
    }
    m_tip = parent;
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
        auto selected{SelectValidatedMainTip(active_tip, sync)};
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
        std::move(candidate_headers), std::move(result), &header, sync);
}

ReferenceChildRuntimeResult ReferenceChildRuntime::SelectValidatedMainTip(
    const uint256& active_tip,
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
        std::move(candidate_headers), std::move(result), nullptr, sync);
}

ReferenceChildRuntimeResult ReferenceChildRuntime::CommitMainChainUpdate(
    std::unique_ptr<chainregistry::MainHeaderChain> candidate_headers,
    ReferenceChildRuntimeResult result,
    const CBlockHeader* added_header,
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
    for (const auto& child_hash : disconnected_hashes) {
        m_child_index.erase(child_hash);
    }
    result.disconnected_child_blocks = std::move(disconnected_hashes);
    return result;
}

ReferenceChildRuntimeResult ReferenceChildRuntime::StageBmmAnchor(
    const chainregistry::BmmAnchorProof& anchor_proof,
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
    const bool already_known{
        m_db->ReadPendingBmmAnchor(main_block_hash).has_value()};
    if (!m_db->WritePendingBmmAnchor(
            *m_main_headers, anchor_proof, sync)) {
        result.error = ReferenceChildRuntimeError::BMM_ANCHOR_PERSIST_FAILED;
        return result;
    }
    if (!m_db->ReadState(m_state)) {
        m_failed = true;
        result.error = ReferenceChildRuntimeError::FAILED_RUNTIME;
        return result;
    }
    result.pending_anchor_already_known = already_known;
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
    if (m_tip != m_genesis.get()) {
        const auto previous{m_db->ReadBmmAnchor(m_tip->GetBlockHash())};
        if (!previous ||
            anchor_proof.block_height <= previous->proof.block_height) {
            result.error = ReferenceChildRuntimeError::BMM_ANCHOR_REJECTED;
            return result;
        }
    }
    auto [slot, inserted]{m_child_index.try_emplace(block_hash)};
    if (!inserted) {
        return RuntimeError(ReferenceChildRuntimeError::CHILD_BLOCK_REJECTED);
    }
    slot->second = std::make_unique<CBlockIndex>(block);
    slot->second->phashBlock = &slot->first;
    slot->second->pprev = m_tip;
    slot->second->nHeight = m_tip->nHeight + 1;
    slot->second->nTimeMax = std::max(m_tip->nTimeMax, slot->second->nTime);
    slot->second->nTx = block.vtx.size();
    slot->second->BuildSkip();

    CCoinsViewCache candidate_coins{m_db.get(), /*deterministic=*/true};
    chainregistry::DepositImportState candidate_imports{m_imports};
    result.child_block = chainregistry::ConnectReferenceChildBlock(
        block,
        *m_tip,
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
            candidate_imports, block, undo, sync)) {
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

bool ReferenceChildRuntime::ReadBlock(const uint256& block_hash,
                                      CBlock& block) const
{
    return Usable() && m_db && m_db->ReadBlock(block_hash, block);
}

} // namespace node
