// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHILD_CHAIN_NOTIFICATIONS_H
#define KRONEIN_NODE_CHILD_CHAIN_NOTIFICATIONS_H

#include <validationinterface.h>

class ChainstateManager;

namespace node {

class ChainManager;
class ChildNetworkManager;
struct ChainManagerRuntimeEvent;

/**
 * Feeds active main-chain progress into loaded child runtimes.
 *
 * Block callbacks advance each child light client in validation order. Tip
 * callbacks then reconcile loaded runtimes against the active registry. A
 * retired, orphaned, mismatched, or header-rejecting runtime is unloaded
 * fail-closed while its catalog entry and on-disk data are preserved.
 */
class ChildChainNotifications final : public CValidationInterface
{
private:
    ChainManager& m_manager;
    ChildNetworkManager& m_networks;
    ChainstateManager& m_chainman;
    void HandleUnloaded(const ChainManagerRuntimeEvent& event);
    void ProcessBmmAnchors(const CBlock& block, const CBlockIndex* index);
    void Synchronize();

protected:
    void BlockConnected(const kernel::ChainstateRole& role,
                        const std::shared_ptr<const CBlock>& block,
                        const CBlockIndex* index) override;
    void BlockDisconnected(const std::shared_ptr<const CBlock>& block,
                           const CBlockIndex* index) override;
    void UpdatedBlockTip(const CBlockIndex* index,
                         const CBlockIndex* fork_index,
                         bool is_ibd) override;

public:
    ChildChainNotifications(ChainManager& manager,
                            ChildNetworkManager& networks,
                            ChainstateManager& chainman);
    ~ChildChainNotifications();
};

} // namespace node

#endif // KRONEIN_NODE_CHILD_CHAIN_NOTIFICATIONS_H
