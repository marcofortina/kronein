// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chainregistry_db.h>

#include <algorithm>
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
constexpr uint8_t DB_DEPOSIT_BY_CHILD{'E'};
constexpr uint8_t DB_BMM_ANCHOR{'A'};
constexpr uint8_t DB_BMM_ANCHOR_BY_CHILD{'B'};

struct BmmAnchorByChildId {
    chainregistry::ChainId chain_id;
    uint256 child_block_hash;
    uint256 main_block_hash;

    SERIALIZE_METHODS(BmmAnchorByChildId, obj)
    {
        READWRITE(obj.chain_id, obj.child_block_hash, obj.main_block_hash);
    }

    friend bool operator==(const BmmAnchorByChildId&,
                           const BmmAnchorByChildId&) = default;
};

struct DepositByChildId {
    chainregistry::ChainId chain_id;
    chainregistry::DepositId deposit_id;

    SERIALIZE_METHODS(DepositByChildId, obj)
    {
        READWRITE(obj.chain_id, obj.deposit_id);
    }

    friend bool operator==(const DepositByChildId&,
                           const DepositByChildId&) = default;
};

using RecordKey = std::pair<uint8_t, chainregistry::ChainId>;
using UndoKey = std::pair<uint8_t, uint256>;
using DepositKey = std::pair<uint8_t, chainregistry::DepositId>;
using DepositByChildKey = std::pair<uint8_t, DepositByChildId>;
using AnchorKey = std::pair<uint8_t, BmmAnchorId>;
using AnchorByChildKey = std::pair<uint8_t, BmmAnchorByChildId>;

BmmAnchorByChildId AnchorByChildId(const BmmAnchorIndexEntry& anchor)
{
    return {
        .chain_id = anchor.id.chain_id,
        .child_block_hash = anchor.anchor.child_block_hash,
        .main_block_hash = anchor.id.main_block_hash,
    };
}

DepositByChildId DepositByChild(const DepositIndexEntry& deposit)
{
    return {
        .chain_id = deposit.fund.chain_id,
        .deposit_id = deposit.deposit_id,
    };
}

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
           state.deposit_history_start_height <= static_cast<uint64_t>(state.height) + 1 &&
           state.anchor_history_start_height <= static_cast<uint64_t>(state.height) + 1;
}

bool IsValidAnchor(const BmmAnchorIndexEntry& anchor)
{
    return anchor.version == BMM_ANCHOR_INDEX_ENTRY_VERSION &&
           !anchor.id.chain_id.IsNull() &&
           !anchor.id.main_block_hash.IsNull() &&
           chainregistry::ValidateBmmAnchor(anchor.anchor) ==
               chainregistry::BmmAnchorValidationError::NONE &&
           anchor.anchor.chain_id == anchor.id.chain_id &&
           !anchor.transaction_id.IsNull() &&
           anchor.transaction_index > 0 &&
           anchor.chain_record.chain_id == anchor.id.chain_id &&
           anchor.chain_record.status == chainregistry::ChainStatus::ACTIVE &&
           chainregistry::VerifyRegistryInclusion(
               anchor.chain_record, anchor.registry_proof, anchor.registry_root);
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
                                              uint64_t deposit_count,
                                              uint32_t anchor_history_start_height,
                                              uint64_t anchor_count)
{
    return {
        .version = CHAIN_REGISTRY_DB_VERSION,
        .best_block = best_block,
        .height = height,
        .registry_root = registry.ComputeRoot(),
        .record_count = registry.Size(),
        .deposit_history_start_height = deposit_history_start_height,
        .deposit_count = deposit_count,
        .anchor_history_start_height = anchor_history_start_height,
        .anchor_count = anchor_count,
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
            HasKeyWithPrefix(m_db, DB_DEPOSIT) ||
            HasKeyWithPrefix(m_db, DB_BMM_ANCHOR) ||
            HasKeyWithPrefix(m_db, DB_BMM_ANCHOR_BY_CHILD)) {
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

    uint64_t child_deposit_count{0};
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(DepositByChildKey{DB_DEPOSIT_BY_CHILD, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(
                ChainRegistryDBLoadError::DEPOSIT_CHILD_KEY_DECODE_FAILED);
        }
        if (prefix != DB_DEPOSIT_BY_CHILD) break;

        DepositByChildKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(
                ChainRegistryDBLoadError::DEPOSIT_CHILD_KEY_DECODE_FAILED);
        }
        chainregistry::DepositId deposit_id;
        if (!cursor->GetValue(deposit_id)) {
            return LoadError(
                ChainRegistryDBLoadError::DEPOSIT_CHILD_VALUE_DECODE_FAILED);
        }
        const auto deposit{ReadDeposit(deposit_id)};
        if (!deposit || deposit_id != key.second.deposit_id ||
            deposit->fund.chain_id != key.second.chain_id) {
            return LoadError(
                ChainRegistryDBLoadError::DEPOSIT_CHILD_INDEX_MISMATCH);
        }
        ++child_deposit_count;
        cursor->Next();
    }
    if (stored_state.deposit_count != child_deposit_count) {
        return LoadError(
            ChainRegistryDBLoadError::DEPOSIT_CHILD_COUNT_MISMATCH);
    }

    if (stored_state.anchor_history_start_height >
        static_cast<uint64_t>(stored_state.height) + 1) {
        return LoadError(ChainRegistryDBLoadError::INVALID_ANCHOR_HISTORY_RANGE);
    }
    uint64_t anchor_count{0};
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(AnchorKey{DB_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(ChainRegistryDBLoadError::ANCHOR_KEY_DECODE_FAILED);
        }
        if (prefix != DB_BMM_ANCHOR) break;

        AnchorKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(ChainRegistryDBLoadError::ANCHOR_KEY_DECODE_FAILED);
        }
        BmmAnchorIndexEntry anchor;
        if (!cursor->GetValue(anchor)) {
            return LoadError(ChainRegistryDBLoadError::ANCHOR_DECODE_FAILED);
        }
        if (anchor.id != key.second) {
            return LoadError(ChainRegistryDBLoadError::ANCHOR_KEY_MISMATCH);
        }
        if (!IsValidAnchor(anchor) ||
            anchor.block_height < stored_state.anchor_history_start_height ||
            anchor.block_height > stored_state.height) {
            return LoadError(ChainRegistryDBLoadError::INVALID_ANCHOR);
        }
        ++anchor_count;
        cursor->Next();
    }
    if (stored_state.anchor_count != anchor_count) {
        return LoadError(ChainRegistryDBLoadError::ANCHOR_COUNT_MISMATCH);
    }

    uint64_t child_anchor_count{0};
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(AnchorByChildKey{DB_BMM_ANCHOR_BY_CHILD, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(
                ChainRegistryDBLoadError::ANCHOR_CHILD_KEY_DECODE_FAILED);
        }
        if (prefix != DB_BMM_ANCHOR_BY_CHILD) break;

        AnchorByChildKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(
                ChainRegistryDBLoadError::ANCHOR_CHILD_KEY_DECODE_FAILED);
        }
        BmmAnchorId anchor_id;
        if (!cursor->GetValue(anchor_id)) {
            return LoadError(
                ChainRegistryDBLoadError::ANCHOR_CHILD_VALUE_DECODE_FAILED);
        }
        const auto anchor{ReadAnchor(anchor_id)};
        if (!anchor || anchor_id.chain_id != key.second.chain_id ||
            anchor_id.main_block_hash != key.second.main_block_hash ||
            anchor->anchor.child_block_hash != key.second.child_block_hash) {
            return LoadError(
                ChainRegistryDBLoadError::ANCHOR_CHILD_INDEX_MISMATCH);
        }
        ++child_anchor_count;
        cursor->Next();
    }
    if (stored_state.anchor_count != child_anchor_count) {
        return LoadError(
            ChainRegistryDBLoadError::ANCHOR_CHILD_COUNT_MISMATCH);
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
        state.anchor_count != 0 || m_db.Exists(DB_REGISTRY_STATE) ||
        HasKeyWithPrefix(m_db, DB_DEPOSIT) ||
        HasKeyWithPrefix(m_db, DB_DEPOSIT_BY_CHILD) ||
        HasKeyWithPrefix(m_db, DB_BMM_ANCHOR) ||
        HasKeyWithPrefix(m_db, DB_BMM_ANCHOR_BY_CHILD)) return false;

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
                                          std::span<const BmmAnchorIndexEntry> anchors,
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
        previous_state.anchor_history_start_height != state.anchor_history_start_height ||
        deposits.size() > std::numeric_limits<uint64_t>::max() - previous_state.deposit_count ||
        anchors.size() > std::numeric_limits<uint64_t>::max() - previous_state.anchor_count ||
        state.deposit_count != previous_state.deposit_count + deposits.size() ||
        state.anchor_count != previous_state.anchor_count + anchors.size() ||
        undo.deposits.size() != deposits.size() ||
        undo.anchors.size() != anchors.size()) return false;

    std::set<chainregistry::DepositId> unique_deposits;
    for (size_t index{0}; index < deposits.size(); ++index) {
        if (!IsValidDeposit(deposits[index], m_main_genesis_hash) ||
            deposits[index].block_hash != block_hash ||
            deposits[index].block_height != state.height ||
            undo.deposits[index] != deposits[index].deposit_id ||
            !unique_deposits.insert(deposits[index].deposit_id).second ||
            m_db.Exists(DepositKey{DB_DEPOSIT, deposits[index].deposit_id}) ||
            m_db.Exists(DepositByChildKey{
                DB_DEPOSIT_BY_CHILD, DepositByChild(deposits[index])})) return false;
    }

    std::set<chainregistry::ChainId> unique_anchor_chains;
    for (size_t index{0}; index < anchors.size(); ++index) {
        if (!IsValidAnchor(anchors[index]) ||
            anchors[index].id.main_block_hash != block_hash ||
            anchors[index].block_height != state.height ||
            undo.anchors[index] != anchors[index].id ||
            !unique_anchor_chains.insert(anchors[index].id.chain_id).second ||
            m_db.Exists(AnchorKey{DB_BMM_ANCHOR, anchors[index].id}) ||
            m_db.Exists(AnchorByChildKey{
                DB_BMM_ANCHOR_BY_CHILD, AnchorByChildId(anchors[index])})) return false;
    }

    CDBBatch batch{m_db};
    WriteChangedRecords(batch, registry, undo.registry);
    for (const auto& deposit : deposits) {
        batch.Write(DepositKey{DB_DEPOSIT, deposit.deposit_id}, deposit);
        batch.Write(DepositByChildKey{
                        DB_DEPOSIT_BY_CHILD, DepositByChild(deposit)},
                    deposit.deposit_id);
    }
    for (const auto& anchor : anchors) {
        batch.Write(AnchorKey{DB_BMM_ANCHOR, anchor.id}, anchor);
        batch.Write(AnchorByChildKey{
                        DB_BMM_ANCHOR_BY_CHILD, AnchorByChildId(anchor)},
                    anchor.id);
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
        current_state.anchor_history_start_height != parent_state.anchor_history_start_height ||
        undo.deposits.size() > std::numeric_limits<uint64_t>::max() - parent_state.deposit_count ||
        undo.anchors.size() > std::numeric_limits<uint64_t>::max() - parent_state.anchor_count ||
        current_state.deposit_count != parent_state.deposit_count + undo.deposits.size() ||
        current_state.anchor_count != parent_state.anchor_count + undo.anchors.size()) return false;

    std::set<chainregistry::DepositId> unique_deposits;
    for (const auto& deposit_id : undo.deposits) {
        const auto deposit{ReadDeposit(deposit_id)};
        if (!unique_deposits.insert(deposit_id).second || !deposit ||
            deposit->block_hash != disconnected_block_hash ||
            !m_db.Exists(DepositByChildKey{
                DB_DEPOSIT_BY_CHILD, DepositByChild(*deposit)})) return false;
    }

    std::set<chainregistry::ChainId> unique_anchor_chains;
    for (const auto& anchor_id : undo.anchors) {
        const auto anchor{ReadAnchor(anchor_id)};
        if (!unique_anchor_chains.insert(anchor_id.chain_id).second || !anchor ||
            anchor->id.main_block_hash != disconnected_block_hash ||
            !m_db.Exists(AnchorByChildKey{
                DB_BMM_ANCHOR_BY_CHILD, AnchorByChildId(*anchor)})) return false;
    }

    CDBBatch batch{m_db};
    WriteChangedRecords(batch, registry, undo.registry);
    for (const auto& deposit_id : undo.deposits) {
        const auto deposit{ReadDeposit(deposit_id)};
        if (!deposit) return false;
        batch.Erase(DepositKey{DB_DEPOSIT, deposit_id});
        batch.Erase(DepositByChildKey{
            DB_DEPOSIT_BY_CHILD, DepositByChild(*deposit)});
    }
    for (const auto& anchor_id : undo.anchors) {
        const auto anchor{ReadAnchor(anchor_id)};
        if (!anchor) return false;
        batch.Erase(AnchorKey{DB_BMM_ANCHOR, anchor_id});
        batch.Erase(AnchorByChildKey{
            DB_BMM_ANCHOR_BY_CHILD, AnchorByChildId(*anchor)});
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

std::optional<DepositLookupResult> ChainRegistryDB::ReadDepositsForChild(
    const chainregistry::ChainId& chain_id,
    uint64_t lookup_limit,
    std::optional<chainregistry::DepositId> start_after) const
{
    DepositLookupResult result;
    if (chain_id.IsNull() || (start_after && start_after->IsNull())) {
        return result;
    }
    if (lookup_limit == 0) {
        result.complete = false;
        return result;
    }

    std::unique_ptr<CDBIterator> cursor{
        const_cast<CDBWrapper&>(m_db).NewIterator()};
    cursor->Seek(DepositByChildKey{
        DB_DEPOSIT_BY_CHILD, {chain_id, start_after.value_or(chainregistry::DepositId{})}});
    if (start_after && cursor->Valid()) {
        DepositByChildKey key;
        if (!cursor->GetKey(key)) return std::nullopt;
        if (key.first == DB_DEPOSIT_BY_CHILD &&
            key.second.chain_id == chain_id &&
            key.second.deposit_id == *start_after) {
            cursor->Next();
        }
    }
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) return std::nullopt;
        if (prefix != DB_DEPOSIT_BY_CHILD) break;
        DepositByChildKey key;
        if (!cursor->GetKey(key)) return std::nullopt;
        if (key.second.chain_id != chain_id) break;
        if (result.lookups == lookup_limit) {
            result.complete = false;
            result.continuation = result.deposits.back().deposit_id;
            break;
        }
        ++result.lookups;
        chainregistry::DepositId deposit_id;
        if (!cursor->GetValue(deposit_id) ||
            deposit_id != key.second.deposit_id) {
            return std::nullopt;
        }
        const auto deposit{ReadDeposit(deposit_id)};
        if (!deposit || !IsValidDeposit(*deposit, m_main_genesis_hash) ||
            deposit->fund.chain_id != chain_id) {
            return std::nullopt;
        }
        result.deposits.push_back(*deposit);
        cursor->Next();
    }
    std::ranges::sort(result.deposits, [](const auto& left,
                                          const auto& right) {
        if (left.block_height != right.block_height) {
            return left.block_height < right.block_height;
        }
        if (left.transaction_index != right.transaction_index) {
            return left.transaction_index < right.transaction_index;
        }
        if (left.outpoint.n != right.outpoint.n) {
            return left.outpoint.n < right.outpoint.n;
        }
        return left.deposit_id < right.deposit_id;
    });
    return result;
}

std::optional<BmmAnchorIndexEntry> ChainRegistryDB::ReadAnchor(
    const BmmAnchorId& anchor_id) const
{
    BmmAnchorIndexEntry anchor;
    if (!m_db.Read(AnchorKey{DB_BMM_ANCHOR, anchor_id}, anchor)) {
        return std::nullopt;
    }
    return anchor;
}

std::optional<BmmAnchorLookupResult>
ChainRegistryDB::ReadAnchorsForChildBlocks(
    const chainregistry::ChainId& chain_id,
    std::span<const uint256> child_block_hashes,
    uint64_t lookup_limit) const
{
    BmmAnchorLookupResult result;
    if (chain_id.IsNull() || child_block_hashes.empty()) return result;

    std::set<uint256> targets;
    for (const uint256& hash : child_block_hashes) {
        if (!hash.IsNull()) targets.insert(hash);
    }
    if (targets.empty()) return result;
    if (lookup_limit == 0) {
        result.complete = false;
        return result;
    }

    std::unique_ptr<CDBIterator> cursor;
    size_t target_index{0};
    for (const uint256& child_block_hash : targets) {
        const uint64_t remaining_budget{lookup_limit - result.lookups};
        const size_t remaining_targets{targets.size() - target_index++};
        if (remaining_budget == 0) {
            result.complete = false;
            break;
        }
        const uint64_t target_limit{std::max<uint64_t>(
            1, remaining_budget / remaining_targets)};
        uint64_t target_lookups{0};
        cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
        cursor->Seek(AnchorByChildKey{
            DB_BMM_ANCHOR_BY_CHILD,
            {chain_id, child_block_hash, {}}});
        while (cursor->Valid()) {
            uint8_t prefix;
            if (!cursor->GetKey(prefix)) return std::nullopt;
            if (prefix != DB_BMM_ANCHOR_BY_CHILD) break;
            AnchorByChildKey key;
            if (!cursor->GetKey(key)) return std::nullopt;
            if (key.second.chain_id != chain_id ||
                key.second.child_block_hash != child_block_hash) {
                break;
            }
            if (target_lookups == target_limit) {
                result.complete = false;
                break;
            }
            ++result.lookups;
            ++target_lookups;
            BmmAnchorId anchor_id;
            if (!cursor->GetValue(anchor_id) ||
                anchor_id.chain_id != chain_id ||
                anchor_id.main_block_hash != key.second.main_block_hash) {
                return std::nullopt;
            }
            const auto anchor{ReadAnchor(anchor_id)};
            if (!anchor || !IsValidAnchor(*anchor) ||
                anchor->anchor.child_block_hash != child_block_hash) {
                return std::nullopt;
            }
            result.anchors.push_back(*anchor);
            cursor->Next();
        }
    }
    std::ranges::sort(result.anchors, [](const auto& left, const auto& right) {
        if (left.anchor.child_block_hash != right.anchor.child_block_hash) {
            return left.anchor.child_block_hash < right.anchor.child_block_hash;
        }
        if (left.block_height != right.block_height) {
            return left.block_height > right.block_height;
        }
        return left.id.main_block_hash < right.id.main_block_hash;
    });
    return result;
}

bool ChainRegistryDB::ReadRecord(const chainregistry::ChainId& chain_id, chainregistry::ChainRecord& record) const
{
    return m_db.Read(RecordKey{DB_REGISTRY_RECORD, chain_id}, record);
}

} // namespace node
