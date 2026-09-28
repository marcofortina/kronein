// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHILD_CHAIN_NOTIFICATIONS_H
#define KRONEIN_NODE_CHILD_CHAIN_NOTIFICATIONS_H

#include <consensus/chainregistry.h>
#include <validationinterface.h>

#include <cstddef>
#include <cstdint>

class ChainstateManager;

namespace node {

class ChainManager;
class ChildNetworkManager;
struct ChainManagerRuntimeEvent;

inline constexpr uint64_t MAX_CHILD_ANCHOR_CATCH_UP_LOOKUPS{1024};

enum class ChildAnchorCatchUpError : uint8_t {
    NONE,
    PROPOSALS_UNAVAILABLE,
    ANCHOR_INDEX_UNAVAILABLE,
    ANCHOR_INDEX_INCONSISTENT,
    PROOF_BUILD_FAILED,
};

struct ChildAnchorCatchUpResult {
    ChildAnchorCatchUpError error{ChildAnchorCatchUpError::NONE};
    bool index_complete{true};
    uint64_t index_lookups{0};
    size_t proposals{0};
    size_t anchors_found{0};
    size_t block_data_unavailable{0};
    size_t proofs_built{0};
    size_t anchors_staged{0};
    size_t proposals_activated{0};
    size_t activation_failures{0};
    size_t stage_failures{0};

    bool IsValid() const { return error == ChildAnchorCatchUpError::NONE; }
};

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

    /**
     * Reconcile durable local proposals with active historical main-chain
     * anchors missed while their child runtime was unloaded.
     */
    ChildAnchorCatchUpResult CatchUpBmmAnchors(
        const chainregistry::ChainId& chain_id);
};

} // namespace node

#endif // KRONEIN_NODE_CHILD_CHAIN_NOTIFICATIONS_H
