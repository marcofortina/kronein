// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain_db.h>

#include <limits>
#include <memory>
#include <set>
#include <utility>
#include <vector>

namespace node {
namespace {

constexpr uint8_t DB_STATE{'S'};
constexpr uint8_t DB_HEADER{'H'};
constexpr uint8_t DB_IMPORT{'I'};
constexpr uint8_t DB_UNDO{'U'};
constexpr uint8_t DB_SAFE_HALT{'X'};

using HeaderKey = std::pair<uint8_t, uint256>;
using ImportKey = std::pair<uint8_t, chainregistry::DepositId>;
using UndoKey = std::pair<uint8_t, uint256>;

ChildChainDBLoadResult LoadError(
    ChildChainDBLoadError error,
    chainregistry::MainHeaderLoadResult header_result = {},
    chainregistry::DepositImportLoadResult import_result = {})
{
    ChildChainDBLoadResult result;
    result.error = error;
    result.header_result = std::move(header_result);
    result.import_result = std::move(import_result);
    return result;
}

bool HasKeyWithPrefix(const CDBWrapper& db, uint8_t prefix)
{
    std::unique_ptr<CDBIterator> cursor{const_cast<CDBWrapper&>(db).NewIterator()};
    cursor->Seek(prefix);
    if (!cursor->Valid()) return false;
    uint8_t stored_prefix;
    return cursor->GetKey(stored_prefix) && stored_prefix == prefix;
}

bool ValidConfiguration(const ChildChainDBState& state,
                        const chainregistry::ChainId& child_chain,
                        const uint256& main_genesis_hash,
                        uint32_t minimum_confirmations,
                        const uint256& child_genesis_hash)
{
    return state.version == CHILD_CHAIN_DB_VERSION &&
           !state.child_chain.IsNull() && state.child_chain == child_chain &&
           !state.main_genesis_hash.IsNull() &&
           state.main_genesis_hash == main_genesis_hash &&
           state.minimum_confirmations != 0 &&
           state.minimum_confirmations == minimum_confirmations &&
           !state.main_tip.IsNull() && state.header_count != 0 &&
           !state.child_genesis_hash.IsNull() &&
           state.child_genesis_hash == child_genesis_hash &&
           !state.child_tip.IsNull();
}

bool ImportsMatchMainChain(const chainregistry::MainHeaderChain& main_headers,
                           const chainregistry::DepositImportState& imports)
{
    for (const auto& [deposit_id, imported] : imports.Imports()) {
        const auto status{main_headers.GetStatus(imported.main_block_hash)};
        if (!status.known || !status.active ||
            status.height != static_cast<int>(imported.main_block_height)) {
            return imports.IsSafeHalted();
        }
    }
    return true;
}

} // namespace

ChildChainDB::ChildChainDB(const DBParams& params,
                           chainregistry::ChainId child_chain,
                           uint256 main_genesis_hash,
                           uint32_t minimum_confirmations,
                           uint256 child_genesis_hash)
    : m_db{params},
      m_child_chain{std::move(child_chain)},
      m_main_genesis_hash{std::move(main_genesis_hash)},
      m_minimum_confirmations{minimum_confirmations},
      m_child_genesis_hash{std::move(child_genesis_hash)}
{
}

ChildChainDBLoadResult ChildChainDB::Load(
    chainregistry::MainHeaderChain& main_headers,
    chainregistry::DepositImportState& imports,
    ChildChainDBState& state,
    int64_t current_time) const
{
    ChildChainDBState stored_state;
    if (!m_db.Read(DB_STATE, stored_state)) {
        if (m_db.Exists(DB_STATE)) {
            return LoadError(ChildChainDBLoadError::STATE_DECODE_FAILED);
        }
        if (HasKeyWithPrefix(m_db, DB_HEADER) ||
            HasKeyWithPrefix(m_db, DB_IMPORT) ||
            HasKeyWithPrefix(m_db, DB_UNDO) ||
            m_db.Exists(DB_SAFE_HALT)) {
            return LoadError(ChildChainDBLoadError::ORPHANED_DATA);
        }
        ChildChainDBLoadResult result;
        result.initialized = false;
        return result;
    }
    if (stored_state.version != CHILD_CHAIN_DB_VERSION) {
        return LoadError(ChildChainDBLoadError::UNSUPPORTED_VERSION);
    }
    if (!ValidConfiguration(stored_state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        main_headers.Params().hashGenesisBlock != m_main_genesis_hash ||
        imports.ChildChain() != m_child_chain ||
        imports.MinimumConfirmations() != m_minimum_confirmations) {
        return LoadError(ChildChainDBLoadError::CONFIGURATION_MISMATCH);
    }

    std::vector<chainregistry::MainHeaderRecord> header_records;
    std::unique_ptr<CDBIterator> cursor{const_cast<CDBWrapper&>(m_db).NewIterator()};
    cursor->Seek(HeaderKey{DB_HEADER, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(ChildChainDBLoadError::HEADER_KEY_DECODE_FAILED);
        }
        if (prefix != DB_HEADER) break;
        HeaderKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(ChildChainDBLoadError::HEADER_KEY_DECODE_FAILED);
        }
        chainregistry::MainHeaderRecord record;
        if (!cursor->GetValue(record)) {
            return LoadError(ChildChainDBLoadError::HEADER_DECODE_FAILED);
        }
        if (record.header.GetHash() != key.second) {
            return LoadError(ChildChainDBLoadError::HEADER_KEY_MISMATCH);
        }
        header_records.push_back(std::move(record));
        cursor->Next();
    }
    if (header_records.size() != stored_state.header_count) {
        return LoadError(ChildChainDBLoadError::HEADER_COUNT_MISMATCH);
    }
    auto header_result{main_headers.LoadHeaders(
        header_records, stored_state.main_tip, current_time)};
    if (!header_result.IsValid()) {
        return LoadError(
            ChildChainDBLoadError::INVALID_HEADERS, std::move(header_result));
    }

    std::vector<chainregistry::ImportedDeposit> import_records;
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(ImportKey{DB_IMPORT, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(ChildChainDBLoadError::IMPORT_KEY_DECODE_FAILED);
        }
        if (prefix != DB_IMPORT) break;
        ImportKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(ChildChainDBLoadError::IMPORT_KEY_DECODE_FAILED);
        }
        chainregistry::ImportedDeposit record;
        if (!cursor->GetValue(record)) {
            return LoadError(ChildChainDBLoadError::IMPORT_DECODE_FAILED);
        }
        if (record.deposit_id != key.second) {
            return LoadError(ChildChainDBLoadError::IMPORT_KEY_MISMATCH);
        }
        import_records.push_back(std::move(record));
        cursor->Next();
    }
    if (import_records.size() != stored_state.import_count) {
        return LoadError(ChildChainDBLoadError::IMPORT_COUNT_MISMATCH);
    }

    std::optional<chainregistry::DepositSafeHalt> safe_halt;
    if (stored_state.safe_halt) {
        chainregistry::DepositSafeHalt loaded_halt;
        if (!m_db.Read(DB_SAFE_HALT, loaded_halt)) {
            return LoadError(m_db.Exists(DB_SAFE_HALT)
                                 ? ChildChainDBLoadError::SAFE_HALT_DECODE_FAILED
                                 : ChildChainDBLoadError::SAFE_HALT_MISSING);
        }
        safe_halt = std::move(loaded_halt);
    } else if (m_db.Exists(DB_SAFE_HALT)) {
        return LoadError(ChildChainDBLoadError::SAFE_HALT_ORPHANED);
    }
    auto import_result{imports.LoadRecords(
        import_records, std::move(safe_halt), m_main_genesis_hash)};
    if (!import_result.IsValid()) {
        return LoadError(ChildChainDBLoadError::INVALID_IMPORTS,
                         {},
                         std::move(import_result));
    }
    if (!ImportsMatchMainChain(main_headers, imports)) {
        return LoadError(ChildChainDBLoadError::UNACKNOWLEDGED_MAIN_REORG);
    }

    std::set<chainregistry::DepositId> undo_imports;
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(UndoKey{DB_UNDO, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(ChildChainDBLoadError::UNDO_KEY_DECODE_FAILED);
        }
        if (prefix != DB_UNDO) break;
        UndoKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(ChildChainDBLoadError::UNDO_KEY_DECODE_FAILED);
        }
        chainregistry::DepositImportUndo undo;
        if (!cursor->GetValue(undo)) {
            return LoadError(ChildChainDBLoadError::UNDO_DECODE_FAILED);
        }
        std::set<chainregistry::DepositId> local;
        for (const auto& deposit_id : undo.imports) {
            const auto* imported{imports.Find(deposit_id)};
            if (!local.insert(deposit_id).second ||
                !undo_imports.insert(deposit_id).second || !imported ||
                imported->child_block_hash != key.second) {
                return LoadError(ChildChainDBLoadError::INVALID_UNDO);
            }
        }
        cursor->Next();
    }
    if (undo_imports.size() != imports.Size()) {
        return LoadError(ChildChainDBLoadError::INVALID_UNDO);
    }

    state = stored_state;
    ChildChainDBLoadResult result;
    result.initialized = true;
    return result;
}

bool ChildChainDB::WriteInitialState(
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::DepositImportState& imports,
    bool sync)
{
    const auto headers{main_headers.ExportHeaders()};
    if (m_child_chain.IsNull() || m_main_genesis_hash.IsNull() ||
        m_minimum_confirmations == 0 || m_child_genesis_hash.IsNull() ||
        main_headers.Params().hashGenesisBlock != m_main_genesis_hash ||
        !main_headers.IsInitialized() || headers.size() != 1 ||
        headers.front().height != 0 ||
        headers.front().header.GetHash() != m_main_genesis_hash ||
        imports.ChildChain() != m_child_chain ||
        imports.MinimumConfirmations() != m_minimum_confirmations ||
        imports.Size() != 0 || imports.IsSafeHalted() ||
        m_db.Exists(DB_STATE) || HasKeyWithPrefix(m_db, DB_HEADER) ||
        HasKeyWithPrefix(m_db, DB_IMPORT) || HasKeyWithPrefix(m_db, DB_UNDO) ||
        m_db.Exists(DB_SAFE_HALT)) {
        return false;
    }

    const ChildChainDBState state{
        .child_chain = m_child_chain,
        .main_genesis_hash = m_main_genesis_hash,
        .minimum_confirmations = m_minimum_confirmations,
        .main_tip = m_main_genesis_hash,
        .header_count = 1,
        .child_genesis_hash = m_child_genesis_hash,
        .child_tip = m_child_genesis_hash,
    };
    CDBBatch batch{m_db};
    batch.Write(HeaderKey{DB_HEADER, m_main_genesis_hash}, headers.front());
    batch.Write(DB_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChildChainDB::WriteMainHeader(
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::DepositImportState& imports,
    const CBlockHeader& header,
    bool sync)
{
    ChildChainDBState state;
    if (!m_db.Read(DB_STATE, state) ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        imports.ChildChain() != m_child_chain ||
        imports.MinimumConfirmations() != m_minimum_confirmations ||
        imports.Size() != state.import_count ||
        main_headers.Params().hashGenesisBlock != m_main_genesis_hash ||
        !main_headers.IsInitialized() ||
        main_headers.ExportHeaders().size() != state.header_count + 1 ||
        !ImportsMatchMainChain(main_headers, imports)) {
        return false;
    }
    const uint256 hash{header.GetHash()};
    const CBlockIndex* entry{main_headers.Find(hash)};
    if (!entry || m_db.Exists(HeaderKey{DB_HEADER, hash})) return false;

    std::optional<chainregistry::DepositSafeHalt> stored_halt;
    if (state.safe_halt) {
        chainregistry::DepositSafeHalt halt;
        if (!m_db.Read(DB_SAFE_HALT, halt) || !imports.SafeHalt() ||
            halt != *imports.SafeHalt()) return false;
        stored_halt = std::move(halt);
    } else if (m_db.Exists(DB_SAFE_HALT)) {
        return false;
    }
    if (state.safe_halt && !imports.IsSafeHalted()) return false;

    state.main_tip = main_headers.Tip()->GetBlockHash();
    ++state.header_count;
    state.safe_halt = imports.IsSafeHalted();
    const chainregistry::MainHeaderRecord record{
        .height = static_cast<uint32_t>(entry->nHeight),
        .header = header,
    };
    CDBBatch batch{m_db};
    batch.Write(HeaderKey{DB_HEADER, hash}, record);
    if (!stored_halt && imports.SafeHalt()) {
        batch.Write(DB_SAFE_HALT, *imports.SafeHalt());
    }
    batch.Write(DB_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChildChainDB::WriteConnectedChildBlock(
    const chainregistry::DepositImportState& imports,
    const uint256& child_block_hash,
    uint32_t child_block_height,
    const chainregistry::DepositImportUndo& undo,
    bool sync)
{
    ChildChainDBState state;
    if (!m_db.Read(DB_STATE, state) ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        state.safe_halt || imports.IsSafeHalted() || child_block_hash.IsNull() ||
        child_block_height != static_cast<uint64_t>(state.child_height) + 1 ||
        undo.imports.size() > std::numeric_limits<uint64_t>::max() - state.import_count ||
        imports.Size() != state.import_count + undo.imports.size() ||
        m_db.Exists(UndoKey{DB_UNDO, child_block_hash})) {
        return false;
    }

    std::set<chainregistry::DepositId> unique;
    for (const auto& deposit_id : undo.imports) {
        const auto* imported{imports.Find(deposit_id)};
        if (!unique.insert(deposit_id).second || !imported ||
            imported->child_block_hash != child_block_hash ||
            imported->child_block_height != child_block_height ||
            m_db.Exists(ImportKey{DB_IMPORT, deposit_id})) {
            return false;
        }
    }

    state.child_tip = child_block_hash;
    state.child_height = child_block_height;
    state.import_count += undo.imports.size();
    CDBBatch batch{m_db};
    for (const auto& deposit_id : undo.imports) {
        batch.Write(ImportKey{DB_IMPORT, deposit_id}, *imports.Find(deposit_id));
    }
    batch.Write(UndoKey{DB_UNDO, child_block_hash}, undo);
    batch.Write(DB_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChildChainDB::WriteDisconnectedChildBlock(
    const chainregistry::DepositImportState& imports,
    const uint256& disconnected_child_block,
    const uint256& parent_child_block,
    uint32_t parent_child_height,
    const chainregistry::DepositImportUndo& undo,
    bool sync)
{
    ChildChainDBState state;
    chainregistry::DepositImportUndo stored_undo;
    if (!m_db.Read(DB_STATE, state) ||
        !m_db.Read(UndoKey{DB_UNDO, disconnected_child_block}, stored_undo) ||
        stored_undo != undo ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        state.child_tip != disconnected_child_block ||
        state.child_height != parent_child_height + 1 ||
        parent_child_block.IsNull() ||
        undo.imports.size() > state.import_count ||
        imports.Size() != state.import_count - undo.imports.size() ||
        imports.IsSafeHalted() != state.safe_halt) {
        return false;
    }
    for (const auto& deposit_id : undo.imports) {
        const auto stored{ReadImport(deposit_id)};
        if (!stored || stored->child_block_hash != disconnected_child_block ||
            imports.Find(deposit_id)) return false;
    }

    state.child_tip = parent_child_block;
    state.child_height = parent_child_height;
    state.import_count -= undo.imports.size();
    CDBBatch batch{m_db};
    for (const auto& deposit_id : undo.imports) {
        batch.Erase(ImportKey{DB_IMPORT, deposit_id});
    }
    batch.Erase(UndoKey{DB_UNDO, disconnected_child_block});
    batch.Write(DB_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

std::optional<chainregistry::ImportedDeposit> ChildChainDB::ReadImport(
    const chainregistry::DepositId& deposit_id) const
{
    chainregistry::ImportedDeposit imported;
    if (!m_db.Read(ImportKey{DB_IMPORT, deposit_id}, imported)) return std::nullopt;
    return imported;
}

bool ChildChainDB::ReadUndo(const uint256& child_block_hash,
                            chainregistry::DepositImportUndo& undo) const
{
    return m_db.Read(UndoKey{DB_UNDO, child_block_hash}, undo);
}

} // namespace node
