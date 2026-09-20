// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHAINREGISTRY_DB_H
#define KRONEIN_NODE_CHAINREGISTRY_DB_H

#include <consensus/chainregistry.h>
#include <dbwrapper.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <span>

namespace node {

inline constexpr uint8_t CHAIN_REGISTRY_DB_VERSION{1};

struct ChainRegistryDBState {
    uint8_t version{CHAIN_REGISTRY_DB_VERSION};
    uint256 best_block;
    uint32_t height{0};
    uint256 registry_root;
    uint64_t record_count{0};

    SERIALIZE_METHODS(ChainRegistryDBState, obj)
    {
        READWRITE(obj.version,
                  obj.best_block,
                  obj.height,
                  obj.registry_root,
                  obj.record_count);
    }

    friend bool operator==(const ChainRegistryDBState&, const ChainRegistryDBState&) = default;
};

enum class ChainRegistryDBLoadError : uint8_t {
    NONE,
    STATE_DECODE_FAILED,
    ORPHANED_DATA,
    UNSUPPORTED_VERSION,
    RECORD_KEY_DECODE_FAILED,
    RECORD_KEY_MISMATCH,
    RECORD_DECODE_FAILED,
    INVALID_RECORDS,
    RECORD_COUNT_MISMATCH,
    ROOT_MISMATCH,
};

struct ChainRegistryDBLoadResult {
    ChainRegistryDBLoadError error{ChainRegistryDBLoadError::NONE};
    chainregistry::RegistryLoadResult registry_result;
    bool initialized{false};

    bool IsValid() const { return error == ChainRegistryDBLoadError::NONE; }
};

ChainRegistryDBState MakeChainRegistryDBState(const uint256& best_block,
                                              uint32_t height,
                                              const chainregistry::ChainRegistry& registry);

class ChainRegistryDB
{
private:
    CDBWrapper m_db;

public:
    explicit ChainRegistryDB(const DBParams& params) : m_db{params} {}

    ChainRegistryDBLoadResult Load(chainregistry::ChainRegistry& registry,
                                   ChainRegistryDBState& state) const;

    bool WriteInitialState(const chainregistry::ChainRegistry& registry,
                           const ChainRegistryDBState& state,
                           bool sync = false);

    bool WriteConnectedBlock(const chainregistry::ChainRegistry& registry,
                             const ChainRegistryDBState& state,
                             const uint256& block_hash,
                             const chainregistry::RegistryBlockUndo& undo,
                             bool sync = false);

    bool WriteDisconnectedBlock(const chainregistry::ChainRegistry& registry,
                                const ChainRegistryDBState& parent_state,
                                const uint256& disconnected_block_hash,
                                const chainregistry::RegistryBlockUndo& undo,
                                bool sync = false);

    bool EraseUndo(std::span<const uint256> block_hashes, bool sync = false);

    bool ReadUndo(const uint256& block_hash, chainregistry::RegistryBlockUndo& undo) const;
    bool ReadRecord(const chainregistry::ChainId& chain_id, chainregistry::ChainRecord& record) const;
};

} // namespace node

#endif // KRONEIN_NODE_CHAINREGISTRY_DB_H
