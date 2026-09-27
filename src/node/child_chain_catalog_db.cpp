// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain_catalog_db.h>

#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <utility>

namespace node {
namespace {

constexpr uint8_t DB_CATALOG_RECORD{'R'};
constexpr uint8_t DB_CATALOG_STATE{'S'};

using RecordKey = std::pair<uint8_t, chainregistry::ChainId>;

ChildChainCatalogLoadResult LoadError(ChildChainCatalogLoadError error)
{
    ChildChainCatalogLoadResult result;
    result.error = error;
    return result;
}

bool HasRecords(const CDBWrapper& db)
{
    std::unique_ptr<CDBIterator> cursor{
        const_cast<CDBWrapper&>(db).NewIterator()};
    cursor->Seek(RecordKey{DB_CATALOG_RECORD, {}});
    if (!cursor->Valid()) return false;
    uint8_t prefix;
    return cursor->GetKey(prefix) && prefix == DB_CATALOG_RECORD;
}

std::optional<chainregistry::ReferenceChildDefinition> ValidateEntry(
    const ChildChainCatalogEntry& entry,
    const chainregistry::ChainId& key_chain_id,
    const uint256& main_genesis_hash)
{
    if (entry.version != CHILD_CHAIN_CATALOG_ENTRY_VERSION ||
        entry.chain_id.IsNull() || entry.chain_id != key_chain_id ||
        entry.registration_anchor.IsNull()) {
        return std::nullopt;
    }
    auto result{chainregistry::ValidateReferenceChildManifest(
        main_genesis_hash, entry.registration_anchor, entry.manifest)};
    if (!result.IsValid() || !result.definition ||
        result.definition->chain_id != entry.chain_id) {
        return std::nullopt;
    }
    return std::move(result.definition);
}

ChildChainCatalogEntry MakeEntry(
    const chainregistry::ReferenceChildDefinition& definition)
{
    return {
        .chain_id = definition.chain_id,
        .registration_anchor = definition.genesis.registration_anchor,
        .manifest = definition.manifest,
    };
}

} // namespace

ChildChainCatalogLoadResult ChildChainCatalogDB::Load() const
{
    ChildChainCatalogState state;
    if (!m_db.Read(DB_CATALOG_STATE, state)) {
        if (m_db.Exists(DB_CATALOG_STATE)) {
            return LoadError(ChildChainCatalogLoadError::STATE_DECODE_FAILED);
        }
        if (HasRecords(m_db)) {
            return LoadError(ChildChainCatalogLoadError::ORPHANED_DATA);
        }
        return {};
    }
    if (state.version != CHILD_CHAIN_CATALOG_DB_VERSION) {
        return LoadError(ChildChainCatalogLoadError::UNSUPPORTED_VERSION);
    }
    if (state.main_genesis_hash != m_main_genesis_hash) {
        return LoadError(ChildChainCatalogLoadError::WRONG_MAIN_GENESIS);
    }

    ChildChainCatalogLoadResult result;
    result.initialized = true;
    if (state.record_count > std::numeric_limits<size_t>::max()) {
        return LoadError(ChildChainCatalogLoadError::RECORD_COUNT_MISMATCH);
    }
    result.definitions.reserve(static_cast<size_t>(state.record_count));
    std::set<chainregistry::ChainId> unique_ids;

    std::unique_ptr<CDBIterator> cursor{
        const_cast<CDBWrapper&>(m_db).NewIterator()};
    cursor->Seek(RecordKey{DB_CATALOG_RECORD, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(
                ChildChainCatalogLoadError::RECORD_KEY_DECODE_FAILED);
        }
        if (prefix != DB_CATALOG_RECORD) break;

        RecordKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(
                ChildChainCatalogLoadError::RECORD_KEY_DECODE_FAILED);
        }
        ChildChainCatalogEntry entry;
        if (!cursor->GetValue(entry)) {
            return LoadError(
                ChildChainCatalogLoadError::RECORD_DECODE_FAILED);
        }
        if (entry.chain_id != key.second) {
            return LoadError(
                ChildChainCatalogLoadError::RECORD_KEY_MISMATCH);
        }
        auto definition{ValidateEntry(entry, key.second, m_main_genesis_hash)};
        if (!definition) {
            return LoadError(ChildChainCatalogLoadError::INVALID_RECORD);
        }
        if (!unique_ids.insert(definition->chain_id).second) {
            return LoadError(ChildChainCatalogLoadError::DUPLICATE_RECORD);
        }
        result.definitions.push_back(std::move(*definition));
        cursor->Next();
    }
    if (result.definitions.size() != state.record_count) {
        return LoadError(
            ChildChainCatalogLoadError::RECORD_COUNT_MISMATCH);
    }
    return result;
}

bool ChildChainCatalogDB::WriteInitialState(bool sync)
{
    if (m_db.Exists(DB_CATALOG_STATE) || HasRecords(m_db)) return false;
    m_db.Write(
        DB_CATALOG_STATE,
        ChildChainCatalogState{.main_genesis_hash = m_main_genesis_hash},
        sync);
    return true;
}

bool ChildChainCatalogDB::WriteDefinition(
    const chainregistry::ReferenceChildDefinition& definition,
    uint64_t previous_record_count,
    bool sync)
{
    if (previous_record_count == std::numeric_limits<uint64_t>::max()) {
        return false;
    }
    ChildChainCatalogState state;
    if (!m_db.Read(DB_CATALOG_STATE, state) ||
        state.version != CHILD_CHAIN_CATALOG_DB_VERSION ||
        state.main_genesis_hash != m_main_genesis_hash ||
        state.record_count != previous_record_count ||
        m_db.Exists(RecordKey{DB_CATALOG_RECORD, definition.chain_id})) {
        return false;
    }
    const auto entry{MakeEntry(definition)};
    if (!ValidateEntry(entry, definition.chain_id, m_main_genesis_hash)) {
        return false;
    }

    ++state.record_count;
    CDBBatch batch{m_db};
    batch.Write(RecordKey{DB_CATALOG_RECORD, definition.chain_id}, entry);
    batch.Write(DB_CATALOG_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChildChainCatalogDB::EraseDefinition(
    const chainregistry::ChainId& chain_id,
    uint64_t previous_record_count,
    bool sync)
{
    if (chain_id.IsNull() || previous_record_count == 0) return false;
    ChildChainCatalogState state;
    const RecordKey key{DB_CATALOG_RECORD, chain_id};
    if (!m_db.Read(DB_CATALOG_STATE, state) ||
        state.version != CHILD_CHAIN_CATALOG_DB_VERSION ||
        state.main_genesis_hash != m_main_genesis_hash ||
        state.record_count != previous_record_count || !m_db.Exists(key)) {
        return false;
    }

    --state.record_count;
    CDBBatch batch{m_db};
    batch.Erase(key);
    batch.Write(DB_CATALOG_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

} // namespace node
