// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHAINREGISTRY_H
#define KRONEIN_NODE_CHAINREGISTRY_H

#include <consensus/chainregistry.h>
#include <consensus/params.h>
#include <node/chainregistry_db.h>
#include <uint256.h>

#include <cstdint>
#include <memory>

class CBlock;

namespace node {

enum class ChainRegistryStateError : uint8_t {
    NONE,
    NOT_INITIALIZED,
    INVALID_EXPECTED_TIP,
    DATABASE_LOAD_FAILED,
    DATABASE_TIP_MISMATCH,
    ACTIVE_STATE_REQUIRES_REINDEX,
    NON_SEQUENTIAL_BLOCK,
    INVALID_BLOCK,
    DATABASE_WRITE_FAILED,
    UNDO_MISSING,
    UNDO_FAILED,
};

struct ChainRegistryStateResult {
    ChainRegistryStateError error{ChainRegistryStateError::NONE};
    ChainRegistryDBLoadResult load_result;
    chainregistry::RegistryBlockResult block_result;

    bool IsValid() const { return error == ChainRegistryStateError::NONE; }
};

/**
 * Registry state belonging to exactly one chainstate.
 *
 * Keeping this object per-chainstate prevents verification, reindex and future
 * snapshot chainstates from mutating one shared registry view.
 */
class ChainRegistryState
{
private:
    Consensus::Params::ChainRegistryParams m_params;
    uint256 m_main_genesis_hash;
    chainregistry::ChainRegistry m_registry;
    ChainRegistryDBState m_state;
    std::unique_ptr<ChainRegistryDB> m_db;
    bool m_initialized{false};

public:
    ChainRegistryState(Consensus::Params::ChainRegistryParams params,
                       const uint256& main_genesis_hash);

    ChainRegistryStateResult Initialize(const DBParams& db_params,
                                        const uint256& expected_tip,
                                        int expected_height);

    ChainRegistryStateResult ConnectBlock(const CBlock& block,
                                          int height,
                                          const uint256& block_hash,
                                          bool sync = false);
    ChainRegistryStateResult ValidateBlock(const CBlock& block,
                                           int height,
                                           const uint256& block_hash) const;
    ChainRegistryStateResult DisconnectBlock(const uint256& block_hash,
                                             const uint256& parent_hash,
                                             int parent_height,
                                             bool sync = false);

    bool Enabled() const { return m_params.Enabled(); }
    bool IsInitialized() const { return m_initialized; }
    const chainregistry::ChainRegistry& Registry() const { return m_registry; }
    const ChainRegistryDBState& State() const { return m_state; }
};

} // namespace node

#endif // KRONEIN_NODE_CHAINREGISTRY_H
