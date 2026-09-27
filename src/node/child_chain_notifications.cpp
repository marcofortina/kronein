// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain_notifications.h>

#include <kernel/types.h>
#include <logging.h>
#include <node/chain_manager.h>
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
    ChainstateManager& chainman)
    : m_manager{manager}, m_chainman{chainman}
{
}

ChildChainNotifications::~ChildChainNotifications() = default;

void ChildChainNotifications::BlockConnected(
    const kernel::ChainstateRole& role,
    const std::shared_ptr<const CBlock>& block,
    const CBlockIndex*)
{
    if (role.historical) return;
    const auto update{m_manager.AddMainHeader(
        static_cast<const CBlockHeader&>(*block),
        Now<NodeSeconds>().time_since_epoch().count(),
        /*sync=*/false)};
    for (const auto& event : update.unloaded) LogUnloaded(event);
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
    for (const auto& event : main_update.unloaded) LogUnloaded(event);
    const auto registry_update{m_manager.ReconcileRegistry(records)};
    for (const auto& event : registry_update.unloaded) LogUnloaded(event);
}

} // namespace node
