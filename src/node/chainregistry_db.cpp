// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chainregistry_db.h>

#include <limits>
#include <memory>
#include <set>
#include <utility>
#include <vector>

namespace node {
namespace {

constexpr uint8_t DB_REGISTRY_RECORD{'R'};
constexpr uint8_t DB_REGISTRY_STATE{'S'};
constexpr uint8_t DB_REGISTRY_UNDO{'U'};
constexpr uint8_t DB_DEPOSIT{'D'};

using RecordKey = std::pair<uint8_t, chainregistry::ChainId>;
using UndoKey = std::pair<uint8_t, uint256>;
using DepositKey = std::pair<uint8_t, chainregistry::DepositId>;

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
           state.registry_root == registry.ComputeRoot() &&
           state.deposit_history_start_height <= static_cast<uint64_t>(state.height) + 1;
}

bool IsValidDeposit(const DepositIndexEntry& deposit, const uint256& main_genesis_hash)
{
    return deposit.version == DEPOSIT_INDEX_ENTRY_VERSION &&
           !deposit.deposit_id.IsNull() &&
           !deposit.outpoint.IsNull() &&
           deposit.deposit_id == chainregistry::DeriveDepositId(main_genesis_hash, deposit.outpoint) &&
           deposit.amount > 0 && MoneyRange(deposit.amount) &&
           chainregistry::ValidateFund(deposit.fund) == chainregistry::FundValidationError::NONE &&
           !deposit.block_hash.IsNull() &&
           deposit.fund.chain_id == deposit.chain_record.chain_id &&
           deposit.chain_record.status == chainregistry::ChainStatus::ACTIVE &&
           chainregistry::VerifyRegistryInclusion(
               deposit.chain_record, deposit.registry_proof, deposit.registry_root);
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
                                              const chainregistry::ChainRegistry& registry,
                                              uint32_t deposit_history_start_height,
                                              uint64_t deposit_count)
{
    return {
        .version = CHAIN_REGISTRY_DB_VERSION,
        .best_block = best_block,
        .height = height,
        .registry_root = registry.ComputeRoot(),
        .record_count = registry.Size(),
        .deposit_history_start_height = deposit_history_start_height,
        .deposit_count = deposit_count,
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
            HasKeyWithPrefix(m_db, DB_REGISTRY_UNDO) ||
            HasKeyWithPrefix(m_db, DB_DEPOSIT)) {
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
    if (stored_state.deposit_history_start_height >
        static_cast<uint64_t>(stored_state.height) + 1) {
        return LoadError(ChainRegistryDBLoadError::INVALID_DEPOSIT_HISTORY_RANGE);
    }

    uint64_t deposit_count{0};
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(DepositKey{DB_DEPOSIT, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(ChainRegistryDBLoadError::DEPOSIT_KEY_DECODE_FAILED);
        }
        if (prefix != DB_DEPOSIT) break;

        DepositKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(ChainRegistryDBLoadError::DEPOSIT_KEY_DECODE_FAILED);
        }
        DepositIndexEntry deposit;
        if (!cursor->GetValue(deposit)) {
            return LoadError(ChainRegistryDBLoadError::DEPOSIT_DECODE_FAILED);
        }
        if (deposit.deposit_id != key.second) {
            return LoadError(ChainRegistryDBLoadError::DEPOSIT_KEY_MISMATCH);
        }
        if (!IsValidDeposit(deposit, m_main_genesis_hash) ||
            deposit.block_height < stored_state.deposit_history_start_height ||
            deposit.block_height > stored_state.height) {
            return LoadError(ChainRegistryDBLoadError::INVALID_DEPOSIT);
        }
        ++deposit_count;
        cursor->Next();
    }
    if (stored_state.deposit_count != deposit_count) {
        return LoadError(ChainRegistryDBLoadError::DEPOSIT_COUNT_MISMATCH);
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
    if (!IsConsistent(registry, state) || state.deposit_count != 0 ||
        m_db.Exists(DB_REGISTRY_STATE) || HasKeyWithPrefix(m_db, DB_DEPOSIT)) return false;

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
                                          const ChainRegistryDBUndo& undo,
                                          std::span<const DepositIndexEntry> deposits,
                                          bool sync)
{
    if (state.best_block != block_hash || !IsConsistent(registry, state)) return false;
    ChainRegistryDBState previous_state;
    if (!m_db.Read(DB_REGISTRY_STATE, previous_state) ||
        previous_state.version != CHAIN_REGISTRY_DB_VERSION ||
        m_db.Exists(UndoKey{DB_REGISTRY_UNDO, block_hash}) ||
        ((previous_state.best_block.IsNull() && previous_state.height == 0)
             ? state.height != 0
             : state.height != previous_state.height + 1) ||
        previous_state.deposit_history_start_height != state.deposit_history_start_height ||
        deposits.size() > std::numeric_limits<uint64_t>::max() - previous_state.deposit_count ||
        state.deposit_count != previous_state.deposit_count + deposits.size() ||
        undo.deposits.size() != deposits.size()) return false;

    std::set<chainregistry::DepositId> unique_deposits;
    for (size_t index{0}; index < deposits.size(); ++index) {
        if (!IsValidDeposit(deposits[index], m_main_genesis_hash) ||
            deposits[index].block_hash != block_hash ||
            deposits[index].block_height != state.height ||
            undo.deposits[index] != deposits[index].deposit_id ||
            !unique_deposits.insert(deposits[index].deposit_id).second ||
            m_db.Exists(DepositKey{DB_DEPOSIT, deposits[index].deposit_id})) return false;
    }

    CDBBatch batch{m_db};
    WriteChangedRecords(batch, registry, undo.registry);
    for (const auto& deposit : deposits) {
        batch.Write(DepositKey{DB_DEPOSIT, deposit.deposit_id}, deposit);
    }
    batch.Write(UndoKey{DB_REGISTRY_UNDO, block_hash}, undo);
    batch.Write(DB_REGISTRY_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChainRegistryDB::WriteDisconnectedBlock(const chainregistry::ChainRegistry& registry,
                                             const ChainRegistryDBState& parent_state,
                                             const uint256& disconnected_block_hash,
                                             const ChainRegistryDBUndo& undo,
                                             bool sync)
{
    if (!IsConsistent(registry, parent_state)) return false;
    ChainRegistryDBState current_state;
    ChainRegistryDBUndo stored_undo;
    if (!m_db.Read(DB_REGISTRY_STATE, current_state) ||
        !m_db.Read(UndoKey{DB_REGISTRY_UNDO, disconnected_block_hash}, stored_undo) ||
        stored_undo != undo ||
        current_state.version != CHAIN_REGISTRY_DB_VERSION ||
        current_state.best_block != disconnected_block_hash ||
        ((parent_state.best_block.IsNull() && parent_state.height == 0)
             ? current_state.height != 0
             : current_state.height != parent_state.height + 1) ||
        current_state.deposit_history_start_height != parent_state.deposit_history_start_height ||
        undo.deposits.size() > std::numeric_limits<uint64_t>::max() - parent_state.deposit_count ||
        current_state.deposit_count != parent_state.deposit_count + undo.deposits.size()) return false;

    std::set<chainregistry::DepositId> unique_deposits;
    for (const auto& deposit_id : undo.deposits) {
        const auto deposit{ReadDeposit(deposit_id)};
        if (!unique_deposits.insert(deposit_id).second || !deposit ||
            deposit->block_hash != disconnected_block_hash) return false;
    }

    CDBBatch batch{m_db};
    WriteChangedRecords(batch, registry, undo.registry);
    for (const auto& deposit_id : undo.deposits) {
        batch.Erase(DepositKey{DB_DEPOSIT, deposit_id});
    }
    batch.Erase(UndoKey{DB_REGISTRY_UNDO, disconnected_block_hash});
    batch.Write(DB_REGISTRY_STATE, parent_state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChainRegistryDB::EraseUndo(std::span<const uint256> block_hashes, bool sync)
{
    if (block_hashes.empty()) return true;

    CDBBatch batch{m_db};
    for (const auto& block_hash : block_hashes) {
        batch.Erase(UndoKey{DB_REGISTRY_UNDO, block_hash});
    }
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChainRegistryDB::ReadUndo(const uint256& block_hash, ChainRegistryDBUndo& undo) const
{
    return m_db.Read(UndoKey{DB_REGISTRY_UNDO, block_hash}, undo);
}

std::optional<DepositIndexEntry> ChainRegistryDB::ReadDeposit(
    const chainregistry::DepositId& deposit_id) const
{
    DepositIndexEntry deposit;
    if (!m_db.Read(DepositKey{DB_DEPOSIT, deposit_id}, deposit)) return std::nullopt;
    return deposit;
}

bool ChainRegistryDB::ReadRecord(const chainregistry::ChainId& chain_id, chainregistry::ChainRecord& record) const
{
    return m_db.Read(RecordKey{DB_REGISTRY_RECORD, chain_id}, record);
}

} // namespace node
