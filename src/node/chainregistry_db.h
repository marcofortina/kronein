// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHAINREGISTRY_DB_H
#define KRONEIN_NODE_CHAINREGISTRY_DB_H

#include <consensus/bmm.h>
#include <consensus/chainregistry.h>
#include <dbwrapper.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace node {

inline constexpr uint8_t CHAIN_REGISTRY_DB_VERSION{7};
inline constexpr uint8_t DEPOSIT_INDEX_ENTRY_VERSION{1};
inline constexpr uint8_t BMM_ANCHOR_INDEX_ENTRY_VERSION{1};

struct BmmAnchorId {
    chainregistry::ChainId chain_id;
    uint256 main_block_hash;

    SERIALIZE_METHODS(BmmAnchorId, obj)
    {
        READWRITE(obj.chain_id, obj.main_block_hash);
    }

    friend bool operator==(const BmmAnchorId&, const BmmAnchorId&) = default;
};

struct BmmAnchorIndexEntry {
    uint8_t version{BMM_ANCHOR_INDEX_ENTRY_VERSION};
    BmmAnchorId id;
    chainregistry::BmmAnchor anchor;
    uint32_t block_height{0};
    Txid transaction_id;
    uint32_t transaction_index{0};
    uint32_t output_index{0};
    uint256 registry_root;
    chainregistry::ChainRecord chain_record;
    chainregistry::RegistryInclusionProof registry_proof;

    SERIALIZE_METHODS(BmmAnchorIndexEntry, obj)
    {
        READWRITE(obj.version,
                  obj.id,
                  obj.anchor,
                  obj.block_height,
                  obj.transaction_id,
                  obj.transaction_index,
                  obj.output_index,
                  obj.registry_root,
                  obj.chain_record,
                  obj.registry_proof);
    }

    friend bool operator==(const BmmAnchorIndexEntry&, const BmmAnchorIndexEntry&) = default;
};

struct BmmAnchorLookupResult {
    std::vector<BmmAnchorIndexEntry> anchors;
    uint64_t lookups{0};
    bool complete{true};
};

struct DepositIndexEntry {
    uint8_t version{DEPOSIT_INDEX_ENTRY_VERSION};
    chainregistry::DepositId deposit_id;
    COutPoint outpoint;
    CAmount amount{0};
    chainregistry::FundChain fund;
    uint256 block_hash;
    uint32_t block_height{0};
    uint32_t transaction_index{0};
    uint256 registry_root;
    chainregistry::ChainRecord chain_record;
    chainregistry::RegistryInclusionProof registry_proof;

    SERIALIZE_METHODS(DepositIndexEntry, obj)
    {
        READWRITE(obj.version,
                  obj.deposit_id,
                  obj.outpoint,
                  obj.amount,
                  obj.fund,
                  obj.block_hash,
                  obj.block_height,
                  obj.transaction_index,
                  obj.registry_root,
                  obj.chain_record,
                  obj.registry_proof);
    }

    friend bool operator==(const DepositIndexEntry&, const DepositIndexEntry&) = default;
};

struct DepositLookupResult {
    std::vector<DepositIndexEntry> deposits;
    uint64_t lookups{0};
    bool complete{true};
    std::optional<chainregistry::DepositId> continuation;
};

struct ChainRegistryDBUndo {
    uint256 parent_block;
    chainregistry::RegistryBlockUndo registry;
    std::vector<chainregistry::DepositId> deposits;
    std::vector<BmmAnchorId> anchors;

    SERIALIZE_METHODS(ChainRegistryDBUndo, obj)
    {
        READWRITE(obj.parent_block, obj.registry, obj.deposits, obj.anchors);
    }

    friend bool operator==(const ChainRegistryDBUndo&, const ChainRegistryDBUndo&) = default;
};

struct ChainRegistryDBState {
    uint8_t version{CHAIN_REGISTRY_DB_VERSION};
    uint256 best_block;
    uint32_t height{0};
    uint256 registry_root;
    uint64_t record_count{0};
    /** First height for which this database has complete deposit history. */
    uint32_t deposit_history_start_height{0};
    uint64_t deposit_count{0};
    /** First height for which this database has complete BMM anchor history. */
    uint32_t anchor_history_start_height{0};
    uint64_t anchor_count{0};

    SERIALIZE_METHODS(ChainRegistryDBState, obj)
    {
        READWRITE(obj.version,
                  obj.best_block,
                  obj.height,
                  obj.registry_root,
                  obj.record_count,
                  obj.deposit_history_start_height,
                  obj.deposit_count,
                  obj.anchor_history_start_height,
                  obj.anchor_count);
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
    DEPOSIT_KEY_DECODE_FAILED,
    DEPOSIT_KEY_MISMATCH,
    DEPOSIT_DECODE_FAILED,
    INVALID_DEPOSIT,
    INVALID_DEPOSIT_HISTORY_RANGE,
    DEPOSIT_COUNT_MISMATCH,
    DEPOSIT_CHILD_KEY_DECODE_FAILED,
    DEPOSIT_CHILD_VALUE_DECODE_FAILED,
    DEPOSIT_CHILD_INDEX_MISMATCH,
    DEPOSIT_CHILD_COUNT_MISMATCH,
    ANCHOR_KEY_DECODE_FAILED,
    ANCHOR_KEY_MISMATCH,
    ANCHOR_DECODE_FAILED,
    INVALID_ANCHOR,
    INVALID_ANCHOR_HISTORY_RANGE,
    ANCHOR_COUNT_MISMATCH,
    ANCHOR_CHILD_KEY_DECODE_FAILED,
    ANCHOR_CHILD_VALUE_DECODE_FAILED,
    ANCHOR_CHILD_INDEX_MISMATCH,
    ANCHOR_CHILD_COUNT_MISMATCH,
};

struct ChainRegistryDBLoadResult {
    ChainRegistryDBLoadError error{ChainRegistryDBLoadError::NONE};
    chainregistry::RegistryLoadResult registry_result;
    bool initialized{false};

    bool IsValid() const { return error == ChainRegistryDBLoadError::NONE; }
};

ChainRegistryDBState MakeChainRegistryDBState(const uint256& best_block,
                                              uint32_t height,
                                              const chainregistry::ChainRegistry& registry,
                                              uint32_t deposit_history_start_height = 0,
                                              uint64_t deposit_count = 0,
                                              uint32_t anchor_history_start_height = 0,
                                              uint64_t anchor_count = 0);

class ChainRegistryDB
{
private:
    CDBWrapper m_db;
    const uint256 m_main_genesis_hash;

public:
    ChainRegistryDB(const DBParams& params, const uint256& main_genesis_hash)
        : m_db{params}, m_main_genesis_hash{main_genesis_hash}
    {
    }

    ChainRegistryDBLoadResult Load(chainregistry::ChainRegistry& registry,
                                   ChainRegistryDBState& state) const;

    bool WriteInitialState(const chainregistry::ChainRegistry& registry,
                           const ChainRegistryDBState& state,
                           bool sync = false);

    bool WriteConnectedBlock(const chainregistry::ChainRegistry& registry,
                             const ChainRegistryDBState& state,
                             const uint256& block_hash,
                             const ChainRegistryDBUndo& undo,
                             std::span<const DepositIndexEntry> deposits = {},
                             std::span<const BmmAnchorIndexEntry> anchors = {},
                             bool sync = false);

    bool WriteDisconnectedBlock(const chainregistry::ChainRegistry& registry,
                                const ChainRegistryDBState& parent_state,
                                const uint256& disconnected_block_hash,
                                const ChainRegistryDBUndo& undo,
                                bool sync = false);

    bool EraseUndo(std::span<const uint256> block_hashes, bool sync = false);

    bool ReadUndo(const uint256& block_hash, ChainRegistryDBUndo& undo) const;
    bool ReadRecord(const chainregistry::ChainId& chain_id, chainregistry::ChainRecord& record) const;
    std::optional<DepositIndexEntry> ReadDeposit(const chainregistry::DepositId& deposit_id) const;
    std::optional<DepositLookupResult> ReadDepositsForChild(
        const chainregistry::ChainId& chain_id,
        uint64_t lookup_limit,
        std::optional<chainregistry::DepositId> start_after = std::nullopt) const;
    std::optional<BmmAnchorIndexEntry> ReadAnchor(const BmmAnchorId& anchor_id) const;
    std::optional<BmmAnchorLookupResult> ReadAnchorsForChildBlocks(
        const chainregistry::ChainId& chain_id,
        std::span<const uint256> child_block_hashes,
        uint64_t lookup_limit) const;
};

} // namespace node

#endif // KRONEIN_NODE_CHAINREGISTRY_DB_H
