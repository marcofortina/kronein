// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain_notifications.h>

#include <kernel/types.h>
#include <logging.h>
#include <node/chain_manager.h>
#include <node/chainregistry.h>
#include <node/child_network_manager.h>
#include <primitives/bmm.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>

#include <map>
#include <set>
#include <utility>
#include <vector>

namespace node {
namespace {

const char* UnloadReasonName(ChainManagerUnloadReason reason)
{
    switch (reason) {
    case ChainManagerUnloadReason::REGISTRY_MISSING:
        return "missing registry record";
    case ChainManagerUnloadReason::REGISTRY_RETIRED:
        return "retired registry record";
    case ChainManagerUnloadReason::REGISTRY_DEFINITION_MISMATCH:
        return "registry definition mismatch";
    case ChainManagerUnloadReason::MAIN_HEADER_REJECTED:
        return "main header rejection";
    }
    return "unknown reason";
}

void LogUnloaded(const ChainManagerRuntimeEvent& event)
{
    LogWarning(
        "Unloaded child chain %s after %s (runtime error %u); catalog and data are preserved\n",
        event.chain_id.GetHex(),
        UnloadReasonName(event.reason),
        static_cast<unsigned>(event.runtime_error));
}

} // namespace

ChildChainNotifications::ChildChainNotifications(
    ChainManager& manager,
    ChildNetworkManager& networks,
    ChainstateManager& chainman)
    : m_manager{manager}, m_networks{networks}, m_chainman{chainman}
{
}

ChildChainNotifications::~ChildChainNotifications() = default;

ChildAnchorCatchUpResult ChildChainNotifications::CatchUpBmmAnchors(
    const chainregistry::ChainId& chain_id)
{
    static_assert(MAX_CHILD_ANCHOR_CATCH_UP_LOOKUPS >=
                  MAX_CHILD_LOCAL_PROPOSALS);

    ChildAnchorCatchUpResult result;
    const auto proposals{m_manager.GetProposalsView(chain_id)};
    if (!proposals.IsValid()) {
        result.error = ChildAnchorCatchUpError::PROPOSALS_UNAVAILABLE;
        return result;
    }
    result.proposals = proposals.proposals.size();
    if (proposals.proposals.empty()) return result;

    std::vector<uint256> proposal_hashes;
    proposal_hashes.reserve(proposals.proposals.size());
    for (const auto& proposal : proposals.proposals) {
        proposal_hashes.push_back(proposal.block.GetHash());
    }

    struct Candidate {
        BmmAnchorIndexEntry entry;
        const CBlockIndex* block_index;
        bool have_block_data;
    };
    std::vector<Candidate> candidates;
    {
        LOCK(cs_main);
        const Chainstate& chainstate{m_chainman.ActiveChainstate()};
        const auto indexed{
            chainstate.ChainRegistryState().FindAnchorsForChildBlocks(
                chain_id,
                proposal_hashes,
                MAX_CHILD_ANCHOR_CATCH_UP_LOOKUPS)};
        if (!indexed) {
            result.error = ChildAnchorCatchUpError::ANCHOR_INDEX_UNAVAILABLE;
            return result;
        }
        result.index_complete = indexed->complete;
        result.index_lookups = indexed->lookups;
        result.anchors_found = indexed->anchors.size();
        candidates.reserve(indexed->anchors.size());
        for (const auto& entry : indexed->anchors) {
            const CBlockIndex* block_index{
                m_chainman.m_blockman.LookupBlockIndex(
                    entry.id.main_block_hash)};
            if (!block_index ||
                block_index->nHeight != static_cast<int>(entry.block_height) ||
                !chainstate.m_chain.Contains(block_index)) {
                result.error =
                    ChildAnchorCatchUpError::ANCHOR_INDEX_INCONSISTENT;
                return result;
            }
            candidates.push_back({
                .entry = entry,
                .block_index = block_index,
                .have_block_data =
                    static_cast<bool>(block_index->nStatus & BLOCK_HAVE_DATA),
            });
        }
    }

    const uint256 main_genesis_hash{
        m_chainman.GetConsensus().hashGenesisBlock};
    const int64_t current_time{
        Now<NodeSeconds>().time_since_epoch().count()};
    std::set<uint256> reconciled;
    for (const auto& candidate : candidates) {
        const uint256& child_block_hash{
            candidate.entry.anchor.child_block_hash};
        if (reconciled.contains(child_block_hash)) continue;
        if (!candidate.have_block_data) {
            ++result.block_data_unavailable;
            continue;
        }

        CBlock block;
        if (!m_chainman.m_blockman.ReadBlock(
                block, *candidate.block_index)) {
            ++result.block_data_unavailable;
            continue;
        }
        const auto built{BuildBmmAnchorProof(
            block, candidate.entry, main_genesis_hash)};
        if (!built.IsValid()) {
            result.error = ChildAnchorCatchUpError::PROOF_BUILD_FAILED;
            LogError(
                "Failed to rebuild historical BMM proof for child %s from main block %s (build error %u, validation error %u)\n",
                chain_id.GetHex(),
                candidate.entry.id.main_block_hash.GetHex(),
                static_cast<unsigned>(built.error),
                static_cast<unsigned>(built.validation.error));
            return result;
        }
        ++result.proofs_built;

        const auto staged{m_manager.StageBmmAnchor(
            chain_id, built.proof, current_time, /*sync=*/true)};
        if (!staged.IsValid()) {
            ++result.stage_failures;
            LogWarning(
                "Failed to ingest historical BMM proof for child %s from main block %s (manager error %u, runtime error %u)\n",
                chain_id.GetHex(),
                candidate.entry.id.main_block_hash.GetHex(),
                static_cast<unsigned>(staged.error),
                static_cast<unsigned>(staged.runtime.error));
            continue;
        }
        ++result.anchors_staged;
        reconciled.insert(child_block_hash);
        if (staged.runtime.local_proposal_activated) {
            ++result.proposals_activated;
            LogInfo(
                "Activated historical local child proposal %s for chain %s from main block %s\n",
                child_block_hash.GetHex(),
                chain_id.GetHex(),
                candidate.entry.id.main_block_hash.GetHex());
        } else if (staged.runtime.local_proposal_found &&
                   staged.runtime.local_proposal_activation_error !=
                       ReferenceChildRuntimeError::NONE) {
            ++result.activation_failures;
        }
    }
    return result;
}

ChildDepositProposalResult ChildChainNotifications::BuildDepositProposal(
    const chainregistry::ChainId& chain_id,
    std::optional<chainregistry::DepositId> start_after)
{
    ChildDepositProposalResult result;
    const auto definition{m_manager.Definition(chain_id)};
    const auto child_state{m_manager.GetBmmStatusView(chain_id)};
    if (!definition || !child_state.IsValid()) {
        result.error = ChildDepositProposalError::CHILD_STATE_UNAVAILABLE;
        return result;
    }
    if (child_state.entry.safe_halt) {
        result.safe_halt = true;
        return result;
    }
    if (!child_state.proposals.empty()) {
        result.proposal_pending = true;
        return result;
    }

    struct Candidate {
        DepositIndexEntry entry;
        const CBlockIndex* block_index;
        bool have_block_data;
    };
    std::vector<Candidate> candidates;
    {
        LOCK(cs_main);
        const Chainstate& chainstate{m_chainman.ActiveChainstate()};
        const auto indexed{chainstate.ChainRegistryState()
                               .FindDepositsForChild(
                                   chain_id,
                                   MAX_CHILD_DEPOSIT_PROPOSER_LOOKUPS,
                                   start_after)};
        if (!indexed) {
            result.error =
                ChildDepositProposalError::DEPOSIT_INDEX_UNAVAILABLE;
            return result;
        }
        result.index_complete = indexed->complete;
        result.index_lookups = indexed->lookups;
        result.continuation = indexed->continuation;
        result.indexed = indexed->deposits.size();
        candidates.reserve(indexed->deposits.size());
        for (const auto& entry : indexed->deposits) {
            const CBlockIndex* block_index{
                m_chainman.m_blockman.LookupBlockIndex(entry.block_hash)};
            if (!block_index ||
                block_index->nHeight != static_cast<int>(entry.block_height) ||
                !chainstate.m_chain.Contains(block_index)) {
                result.error =
                    ChildDepositProposalError::DEPOSIT_INDEX_INCONSISTENT;
                return result;
            }
            const int confirmations{
                chainstate.m_chain.Height() - block_index->nHeight + 1};
            if (confirmations < static_cast<int>(
                                    definition->parameters.deposit_maturity)) {
                ++result.immature;
                continue;
            }
            candidates.push_back({
                .entry = entry,
                .block_index = block_index,
                .have_block_data = static_cast<bool>(
                    block_index->nStatus & BLOCK_HAVE_DATA),
            });
        }
    }

    const uint256 main_genesis_hash{
        m_chainman.GetConsensus().hashGenesisBlock};
    std::map<uint256, CBlock> blocks;
    std::vector<chainregistry::DepositProof> proofs;
    std::vector<DepositIndexEntry> selected;
    proofs.reserve(candidates.size());
    selected.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        if (!candidate.have_block_data) {
            ++result.block_data_unavailable;
            continue;
        }
        auto [block, inserted]{blocks.try_emplace(candidate.entry.block_hash)};
        if (inserted && !m_chainman.m_blockman.ReadBlock(
                            block->second, *candidate.block_index)) {
            blocks.erase(block);
            ++result.block_data_unavailable;
            continue;
        }
        const auto built{BuildDepositProof(
            block->second, candidate.entry, main_genesis_hash)};
        if (!built.IsValid()) {
            result.error = ChildDepositProposalError::PROOF_BUILD_FAILED;
            LogError(
                "Failed to build automatic deposit proof %s for child %s (build error %u, validation error %u)\n",
                candidate.entry.deposit_id.GetHex(),
                chain_id.GetHex(),
                static_cast<unsigned>(built.error),
                static_cast<unsigned>(built.validation.error));
            return result;
        }
        const auto imported{
            m_manager.BuildImportTransaction(chain_id, built.proof)};
        if (imported.error == ChainManagerImportBuildError::ALREADY_IMPORTED) {
            ++result.already_imported;
            continue;
        }
        if (!imported.IsValid()) {
            if (imported.error == ChainManagerImportBuildError::SAFE_HALT) {
                result.safe_halt = true;
                return result;
            }
            result.error =
                ChildDepositProposalError::IMPORT_AUTHENTICATION_FAILED;
            return result;
        }
        proofs.push_back(built.proof);
        selected.push_back(candidate.entry);
    }
    result.proofs_built = proofs.size();
    if (proofs.empty()) return result;

    {
        LOCK(cs_main);
        const Chainstate& chainstate{m_chainman.ActiveChainstate()};
        for (const auto& entry : selected) {
            const auto current{
                chainstate.ChainRegistryState().FindDeposit(entry.deposit_id)};
            const CBlockIndex* block_index{
                m_chainman.m_blockman.LookupBlockIndex(entry.block_hash)};
            if (!current || *current != entry || !block_index ||
                block_index->nHeight != static_cast<int>(entry.block_height) ||
                !chainstate.m_chain.Contains(block_index) ||
                chainstate.m_chain.Height() - block_index->nHeight + 1 <
                    static_cast<int>(definition->parameters.deposit_maturity)) {
                result.error =
                    ChildDepositProposalError::DEPOSIT_INDEX_INCONSISTENT;
                return result;
            }
        }
    }

    const auto proposed{m_manager.BuildImportBlock(
        chain_id,
        proofs,
        Now<NodeSeconds>().time_since_epoch().count(),
        /*sync=*/false,
        /*require_empty_proposal_queue=*/true)};
    if (proposed.error ==
        ChainManagerImportBlockBuildError::PROPOSAL_PENDING) {
        result.proposal_pending = true;
        return result;
    }
    if (!proposed.IsValid() || !proposed.build.block) {
        result.error = ChildDepositProposalError::PROPOSAL_BUILD_FAILED;
        return result;
    }
    result.proposal_stored = true;
    result.proposal_hash = proposed.build.block->GetHash();
    return result;
}

void ChildChainNotifications::ProcessDepositProposals()
{
    for (const auto& entry : m_manager.List()) {
        if (!entry.loaded) continue;
        std::optional<chainregistry::DepositId> start_after;
        {
            LOCK(m_proposer_mutex);
            const auto cursor{m_deposit_cursors.find(entry.chain_id)};
            if (cursor != m_deposit_cursors.end()) {
                start_after = cursor->second;
            }
        }
        const auto proposed{BuildDepositProposal(entry.chain_id, start_after)};
        if (!proposed.IsValid()) {
            LogWarning(
                "Automatic child proposer failed for chain %s (error %u)\n",
                entry.chain_id.GetHex(),
                static_cast<unsigned>(proposed.error));
            continue;
        }
        if (!proposed.proposal_pending && !proposed.safe_halt) {
            LOCK(m_proposer_mutex);
            if (proposed.continuation) {
                m_deposit_cursors[entry.chain_id] = *proposed.continuation;
            } else if (proposed.index_complete) {
                m_deposit_cursors.erase(entry.chain_id);
            }
        }
        if (proposed.proposal_stored) {
            LogInfo(
                "Stored automatic child proposal %s for chain %s from %u authenticated deposits\n",
                proposed.proposal_hash.GetHex(),
                entry.chain_id.GetHex(),
                proposed.proofs_built);
        }
    }
}

void ChildChainNotifications::HandleUnloaded(
    const ChainManagerRuntimeEvent& event)
{
    if (m_networks.IsRunning(event.chain_id)) {
        const auto stopped{m_networks.Stop(event.chain_id)};
        if (!stopped.IsValid()) {
            LogWarning(
                "Failed to stop child network %s after runtime unload (network error %u)\n",
                event.chain_id.GetHex(),
                static_cast<unsigned>(stopped.error));
        }
    }
    LogUnloaded(event);
}

void ChildChainNotifications::BlockConnected(
    const kernel::ChainstateRole& role,
    const std::shared_ptr<const CBlock>& block,
    const CBlockIndex* index)
{
    if (role.historical) return;
    const auto update{m_manager.AddMainHeader(
        static_cast<const CBlockHeader&>(*block),
        Now<NodeSeconds>().time_since_epoch().count(),
        /*sync=*/false)};
    for (const auto& event : update.unloaded) HandleUnloaded(event);
    ProcessBmmAnchors(*block, index);
    ProcessDepositProposals();
}

void ChildChainNotifications::ProcessBmmAnchors(
    const CBlock& block,
    const CBlockIndex* index)
{
    if (!index || block.GetHash() != index->GetBlockHash()) {
        LogWarning("Cannot process child BMM anchors from a mismatched main block callback\n");
        return;
    }

    std::vector<BmmAnchorIndexEntry> entries;
    {
        LOCK(cs_main);
        const Chainstate& chainstate{m_chainman.ActiveChainstate()};
        if (!chainstate.m_chain.Contains(index)) return;
        const auto& registry_state{chainstate.ChainRegistryState()};
        for (size_t transaction_index{1};
             transaction_index < block.vtx.size();
             ++transaction_index) {
            const auto extracted{chainregistry::ExtractTransactionBmmAnchor(
                *block.vtx[transaction_index])};
            if (!extracted.IsValid() || !extracted.anchor) continue;
            const auto indexed{registry_state.FindAnchor({
                .chain_id = extracted.anchor->chain_id,
                .main_block_hash = index->GetBlockHash(),
            })};
            if (indexed) entries.push_back(*indexed);
        }
    }

    const int64_t current_time{
        Now<NodeSeconds>().time_since_epoch().count()};
    const uint256 main_genesis_hash{
        m_chainman.GetConsensus().hashGenesisBlock};
    for (const auto& entry : entries) {
        if (!m_manager.IsLoaded(entry.id.chain_id)) continue;
        const auto built{
            BuildBmmAnchorProof(block, entry, main_genesis_hash)};
        if (!built.IsValid()) {
            LogError(
                "Failed to build automatic BMM proof for child %s from main block %s (build error %u, validation error %u)\n",
                entry.id.chain_id.GetHex(),
                entry.id.main_block_hash.GetHex(),
                static_cast<unsigned>(built.error),
                static_cast<unsigned>(built.validation.error));
            continue;
        }
        const auto staged{m_manager.StageBmmAnchor(
            entry.id.chain_id,
            built.proof,
            current_time,
            /*sync=*/false)};
        if (!staged.IsValid()) {
            LogWarning(
                "Failed to ingest automatic BMM proof for child %s from main block %s (manager error %u, runtime error %u)\n",
                entry.id.chain_id.GetHex(),
                entry.id.main_block_hash.GetHex(),
                static_cast<unsigned>(staged.error),
                static_cast<unsigned>(staged.runtime.error));
            continue;
        }
        if (staged.runtime.local_proposal_activated) {
            LogInfo(
                "Activated local child proposal %s for chain %s from main block %s\n",
                entry.anchor.child_block_hash.GetHex(),
                entry.id.chain_id.GetHex(),
                entry.id.main_block_hash.GetHex());
        }
    }
}

void ChildChainNotifications::UpdatedBlockTip(
    const CBlockIndex*,
    const CBlockIndex*,
    bool)
{
    Synchronize();
}

void ChildChainNotifications::BlockDisconnected(
    const std::shared_ptr<const CBlock>&,
    const CBlockIndex*)
{
    Synchronize();
}

void ChildChainNotifications::Synchronize()
{
    std::map<chainregistry::ChainId, chainregistry::ChainRecord> records;
    std::vector<CBlockHeader> active_headers;
    uint256 active_tip;
    {
        LOCK(cs_main);
        const CChain& active{m_chainman.ActiveChain()};
        if (active.Tip()) {
            active_tip = active.Tip()->GetBlockHash();
            active_headers.reserve(active.Height());
            for (int height{1}; height <= active.Height(); ++height) {
                active_headers.push_back(
                    Assert(active[height])->GetBlockHeader());
            }
        }
        records = m_chainman.ActiveChainstate()
                      .ChainRegistryState()
                      .Registry()
                      .Records();
    }
    const auto main_update{m_manager.SynchronizeMainChain(
        active_headers,
        active_tip,
        Now<NodeSeconds>().time_since_epoch().count(),
        /*sync=*/false)};
    for (const auto& event : main_update.unloaded) HandleUnloaded(event);
    const auto registry_update{m_manager.ReconcileRegistry(records)};
    for (const auto& event : registry_update.unloaded) HandleUnloaded(event);
}

} // namespace node
