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
