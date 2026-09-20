// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chainregistry_db.h>

#include <memory>
#include <utility>
#include <vector>

namespace node {
namespace {

constexpr uint8_t DB_REGISTRY_RECORD{'R'};
constexpr uint8_t DB_REGISTRY_STATE{'S'};
constexpr uint8_t DB_REGISTRY_UNDO{'U'};

using RecordKey = std::pair<uint8_t, chainregistry::ChainId>;
using UndoKey = std::pair<uint8_t, uint256>;

ChainRegistryDBLoadResult LoadError(ChainRegistryDBLoadError error,
                                    chainregistry::RegistryLoadResult registry_result = {})
{
    ChainRegistryDBLoadResult result;
    result.error = error;
    result.registry_result = std::move(registry_result);
    return result;
}

bool IsConsistent(const chainregistry::ChainRegistry& registry,
                  const ChainRegistryDBState& state)
{
    return state.version == CHAIN_REGISTRY_DB_VERSION &&
           state.record_count == registry.Size() &&
           state.registry_root == registry.ComputeRoot();
}

bool HasKeyWithPrefix(const CDBWrapper& db, uint8_t prefix)
{
    std::unique_ptr<CDBIterator> cursor{const_cast<CDBWrapper&>(db).NewIterator()};
    cursor->Seek(prefix);
    if (!cursor->Valid()) return false;
    uint8_t stored_prefix;
    return cursor->GetKey(stored_prefix) && stored_prefix == prefix;
}

void WriteChangedRecords(CDBBatch& batch,
                         const chainregistry::ChainRegistry& registry,
                         const chainregistry::RegistryBlockUndo& undo)
{
    for (const auto& operation : undo.operations) {
        const RecordKey key{DB_REGISTRY_RECORD, operation.chain_id};
        if (const auto* record{registry.Find(operation.chain_id)}) {
            batch.Write(key, *record);
        } else {
            batch.Erase(key);
        }
    }
}

} // namespace

ChainRegistryDBState MakeChainRegistryDBState(const uint256& best_block,
                                              uint32_t height,
                                              const chainregistry::ChainRegistry& registry)
{
    return {
        .version = CHAIN_REGISTRY_DB_VERSION,
        .best_block = best_block,
        .height = height,
        .registry_root = registry.ComputeRoot(),
        .record_count = registry.Size(),
    };
}

ChainRegistryDBLoadResult ChainRegistryDB::Load(chainregistry::ChainRegistry& registry,
                                                ChainRegistryDBState& state) const
{
    ChainRegistryDBState stored_state;
    if (!m_db.Read(DB_REGISTRY_STATE, stored_state)) {
        if (m_db.Exists(DB_REGISTRY_STATE)) {
            return LoadError(ChainRegistryDBLoadError::STATE_DECODE_FAILED);
        }
        if (HasKeyWithPrefix(m_db, DB_REGISTRY_RECORD) ||
            HasKeyWithPrefix(m_db, DB_REGISTRY_UNDO)) {
            return LoadError(ChainRegistryDBLoadError::ORPHANED_DATA);
        }
        const auto registry_result{registry.LoadRecords({})};
        state = MakeChainRegistryDBState({}, 0, registry);
        return {
            .registry_result = registry_result,
            .initialized = false,
        };
    }
    if (stored_state.version != CHAIN_REGISTRY_DB_VERSION) {
        return LoadError(ChainRegistryDBLoadError::UNSUPPORTED_VERSION);
    }

    std::vector<chainregistry::ChainRecord> records;
    std::unique_ptr<CDBIterator> cursor{const_cast<CDBWrapper&>(m_db).NewIterator()};
    cursor->Seek(RecordKey{DB_REGISTRY_RECORD, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(ChainRegistryDBLoadError::RECORD_KEY_DECODE_FAILED);
        }
        if (prefix != DB_REGISTRY_RECORD) break;

        RecordKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(ChainRegistryDBLoadError::RECORD_KEY_DECODE_FAILED);
        }

        chainregistry::ChainRecord record;
        if (!cursor->GetValue(record)) {
            return LoadError(ChainRegistryDBLoadError::RECORD_DECODE_FAILED);
        }
        if (record.chain_id != key.second) {
            return LoadError(ChainRegistryDBLoadError::RECORD_KEY_MISMATCH);
        }
        records.push_back(std::move(record));
        cursor->Next();
    }

    chainregistry::ChainRegistry loaded_registry;
    auto registry_result{loaded_registry.LoadRecords(std::move(records))};
    if (!registry_result.IsValid()) {
        return LoadError(ChainRegistryDBLoadError::INVALID_RECORDS, std::move(registry_result));
    }
    if (stored_state.record_count != loaded_registry.Size()) {
        return LoadError(ChainRegistryDBLoadError::RECORD_COUNT_MISMATCH);
    }
    if (stored_state.registry_root != loaded_registry.ComputeRoot()) {
        return LoadError(ChainRegistryDBLoadError::ROOT_MISMATCH);
    }

    registry = std::move(loaded_registry);
    state = stored_state;
    ChainRegistryDBLoadResult result;
    result.initialized = true;
    return result;
}

bool ChainRegistryDB::WriteInitialState(const chainregistry::ChainRegistry& registry,
                                        const ChainRegistryDBState& state,
                                        bool sync)
{
    if (!IsConsistent(registry, state) || m_db.Exists(DB_REGISTRY_STATE)) return false;

    CDBBatch batch{m_db};
    for (const auto& [chain_id, record] : registry.Records()) {
        batch.Write(RecordKey{DB_REGISTRY_RECORD, chain_id}, record);
    }
    batch.Write(DB_REGISTRY_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChainRegistryDB::WriteConnectedBlock(const chainregistry::ChainRegistry& registry,
                                          const ChainRegistryDBState& state,
                                          const uint256& block_hash,
                                          const chainregistry::RegistryBlockUndo& undo,
                                          bool sync)
{
    if (state.best_block != block_hash || !IsConsistent(registry, state)) return false;

    CDBBatch batch{m_db};
    WriteChangedRecords(batch, registry, undo);
    batch.Write(UndoKey{DB_REGISTRY_UNDO, block_hash}, undo);
    batch.Write(DB_REGISTRY_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChainRegistryDB::WriteDisconnectedBlock(const chainregistry::ChainRegistry& registry,
                                             const ChainRegistryDBState& parent_state,
                                             const uint256& disconnected_block_hash,
                                             const chainregistry::RegistryBlockUndo& undo,
                                             bool sync)
{
    if (!IsConsistent(registry, parent_state)) return false;

    CDBBatch batch{m_db};
    WriteChangedRecords(batch, registry, undo);
    batch.Erase(UndoKey{DB_REGISTRY_UNDO, disconnected_block_hash});
    batch.Write(DB_REGISTRY_STATE, parent_state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChainRegistryDB::ReadUndo(const uint256& block_hash, chainregistry::RegistryBlockUndo& undo) const
{
    return m_db.Read(UndoKey{DB_REGISTRY_UNDO, block_hash}, undo);
}

bool ChainRegistryDB::ReadRecord(const chainregistry::ChainId& chain_id, chainregistry::ChainRecord& record) const
{
    return m_db.Read(RecordKey{DB_REGISTRY_RECORD, chain_id}, record);
}

} // namespace node
