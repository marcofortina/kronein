// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain_db.h>

#include <consensus/amount.h>
#include <primitives/block.h>

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace node {
namespace {

constexpr uint8_t DB_STATE{'S'};
constexpr uint8_t DB_BLOCK{'B'};
constexpr uint8_t DB_COIN{'C'};
constexpr uint8_t DB_HEADER{'H'};
constexpr uint8_t DB_IMPORT{'I'};
constexpr uint8_t DB_UNDO{'U'};
constexpr uint8_t DB_SAFE_HALT{'X'};
constexpr uint8_t DB_BMM_ANCHOR{'A'};

using AnchorKey = std::pair<uint8_t, uint256>;
using BlockKey = std::pair<uint8_t, uint256>;
using CoinKey = std::pair<uint8_t, COutPoint>;
using HeaderKey = std::pair<uint8_t, uint256>;
using ImportKey = std::pair<uint8_t, chainregistry::DepositId>;
using UndoKey = std::pair<uint8_t, uint256>;
using CoinSet = std::map<COutPoint, Coin>;
using CoinChanges = std::map<COutPoint, std::optional<Coin>>;

struct CoinTransition {
    CoinChanges changes;
    int64_t count_delta{0};
};

struct StoredChildBlock {
    CBlock block;

    SERIALIZE_METHODS(StoredChildBlock, obj)
    {
        READWRITE(TX_WITH_WITNESS(obj.block));
    }
};

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
           !state.child_tip.IsNull() &&
           state.anchor_count == state.child_height;
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

bool IsValidStoredAnchor(
    const ChildBmmAnchorRecord& record,
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::ChainId& child_chain,
    bool allow_inactive)
{
    if (record.version != CHILD_BMM_ANCHOR_RECORD_VERSION ||
        record.child_block_hash.IsNull()) {
        return false;
    }
    const auto structural{chainregistry::ValidateBmmAnchorProofStructure(
        record.proof,
        main_headers.Params().hashGenesisBlock,
        child_chain)};
    if (!structural.IsValid() || !structural.anchor ||
        structural.anchor->child_block_hash != record.child_block_hash) {
        return false;
    }
    const auto status{main_headers.GetStatus(
        record.proof.block_header.GetHash())};
    if (!status.known ||
        status.height != static_cast<int>(record.proof.block_height)) {
        return false;
    }
    if (allow_inactive) return true;
    return main_headers.AuthenticateBmmAnchor(
        record.proof, child_chain, /*minimum_confirmations=*/1).IsValid();
}

bool StoredAnchorsMatchMainChain(
    const CDBWrapper& db,
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::ChainId& child_chain,
    uint64_t expected_count,
    bool allow_inactive)
{
    uint64_t count{0};
    std::unique_ptr<CDBIterator> cursor{const_cast<CDBWrapper&>(db).NewIterator()};
    cursor->Seek(AnchorKey{DB_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) return false;
        if (prefix != DB_BMM_ANCHOR) break;
        AnchorKey key;
        ChildBmmAnchorRecord record;
        if (!cursor->GetKey(key) || !cursor->GetValue(record) ||
            key.second != record.child_block_hash ||
            !IsValidStoredAnchor(
                record, main_headers, child_chain, allow_inactive) ||
            count == std::numeric_limits<uint64_t>::max()) {
            return false;
        }
        ++count;
        cursor->Next();
    }
    return count == expected_count;
}

bool CoinsEqual(const Coin& left, const Coin& right)
{
    return left.out == right.out && left.nHeight == right.nHeight &&
           left.IsCoinBase() == right.IsCoinBase();
}

bool BlocksEqual(const CBlock& left, const CBlock& right)
{
    if (left.nVersion != right.nVersion ||
        left.hashPrevBlock != right.hashPrevBlock ||
        left.hashMerkleRoot != right.hashMerkleRoot ||
        left.nTime != right.nTime || left.nBits != right.nBits ||
        left.nNonce != right.nNonce || left.vtx.size() != right.vtx.size()) {
        return false;
    }
    for (size_t index{0}; index < left.vtx.size(); ++index) {
        if (*left.vtx[index] != *right.vtx[index]) return false;
    }
    return true;
}

bool IsValidStoredCoin(const Coin& coin, uint32_t maximum_height)
{
    return !coin.IsSpent() && coin.nHeight > 0 &&
           coin.nHeight <= maximum_height && MoneyRange(coin.out.nValue) &&
           !coin.out.scriptPubKey.IsUnspendable();
}

std::optional<std::vector<chainregistry::DepositId>> BlockImportIds(
    const CBlock& block)
{
    std::vector<chainregistry::DepositId> imports;
    for (size_t index{1}; index < block.vtx.size(); ++index) {
        const CTransaction& transaction{*block.vtx[index]};
        if (!chainregistry::IsReferenceChildImport(transaction)) continue;
        if (transaction.vin.empty()) return std::nullopt;
        imports.push_back(chainregistry::DepositId::FromUint256(
            transaction.vin.front().prevout.hash.ToUint256()));
    }
    return imports;
}

bool ApplyBlockToCoinSet(const CBlock& block,
                         const chainregistry::ReferenceChildBlockUndo& undo,
                         CoinSet& coins)
{
    if (block.vtx.empty() || undo.coins.vtxundo.size() + 1 != block.vtx.size()) {
        return false;
    }
    const auto block_imports{BlockImportIds(block)};
    if (!block_imports || *block_imports != undo.imports.imports) return false;
    for (size_t index{0}; index < block.vtx.size(); ++index) {
        const CTransaction& transaction{*block.vtx[index]};
        if (index > 0) {
            const CTxUndo& transaction_undo{undo.coins.vtxundo[index - 1]};
            if (chainregistry::IsReferenceChildImport(transaction)) {
                if (!transaction_undo.vprevout.empty()) return false;
            } else {
                if (transaction_undo.vprevout.size() != transaction.vin.size()) {
                    return false;
                }
                for (size_t input_index{0};
                     input_index < transaction.vin.size();
                     ++input_index) {
                    const COutPoint& previous{transaction.vin[input_index].prevout};
                    const auto coin{coins.find(previous)};
                    if (coin == coins.end() ||
                        !CoinsEqual(coin->second,
                                    transaction_undo.vprevout[input_index])) {
                        return false;
                    }
                    coins.erase(coin);
                }
            }
        }
        for (size_t output_index{0};
             output_index < transaction.vout.size();
             ++output_index) {
            const CTxOut& output{transaction.vout[output_index]};
            if (output.scriptPubKey.IsUnspendable()) continue;
            const COutPoint outpoint{transaction.GetHash(),
                                     static_cast<uint32_t>(output_index)};
            if (!coins.emplace(outpoint,
                               Coin{output,
                                    static_cast<int>(undo.block_height),
                                    transaction.IsCoinBase()})
                     .second) {
                return false;
            }
        }
    }
    return true;
}

std::optional<Coin> CurrentCoin(const CCoinsView& view,
                                const CoinChanges& changes,
                                const COutPoint& outpoint)
{
    const auto changed{changes.find(outpoint)};
    if (changed != changes.end()) return changed->second;
    return view.GetCoin(outpoint);
}

std::optional<CoinTransition> BuildConnectCoinTransition(
    const CCoinsView& view,
    const CBlock& block,
    const chainregistry::ReferenceChildBlockUndo& undo)
{
    if (block.vtx.empty() || undo.coins.vtxundo.size() + 1 != block.vtx.size()) {
        return std::nullopt;
    }
    CoinTransition result;
    for (size_t index{0}; index < block.vtx.size(); ++index) {
        const CTransaction& transaction{*block.vtx[index]};
        for (size_t output_index{0};
             output_index < transaction.vout.size();
             ++output_index) {
            const CTxOut& output{transaction.vout[output_index]};
            if (output.scriptPubKey.IsUnspendable()) continue;
            if (CurrentCoin(
                    view,
                    result.changes,
                    COutPoint{transaction.GetHash(),
                              static_cast<uint32_t>(output_index)})) {
                return std::nullopt;
            }
        }
        if (index > 0) {
            const CTxUndo& transaction_undo{undo.coins.vtxundo[index - 1]};
            if (chainregistry::IsReferenceChildImport(transaction)) {
                if (!transaction_undo.vprevout.empty()) return std::nullopt;
            } else {
                if (transaction_undo.vprevout.size() != transaction.vin.size()) {
                    return std::nullopt;
                }
                for (size_t input_index{0};
                     input_index < transaction.vin.size();
                     ++input_index) {
                    const COutPoint& previous{transaction.vin[input_index].prevout};
                    const auto current{CurrentCoin(view, result.changes, previous)};
                    const Coin& expected{transaction_undo.vprevout[input_index]};
                    if (!current ||
                        !IsValidStoredCoin(expected, undo.block_height) ||
                        !CoinsEqual(*current, expected)) {
                        return std::nullopt;
                    }
                    result.changes[previous] = std::nullopt;
                    --result.count_delta;
                }
            }
        }
        for (size_t output_index{0};
             output_index < transaction.vout.size();
             ++output_index) {
            const CTxOut& output{transaction.vout[output_index]};
            if (output.scriptPubKey.IsUnspendable()) continue;
            const COutPoint outpoint{transaction.GetHash(),
                                     static_cast<uint32_t>(output_index)};
            Coin coin{output,
                      static_cast<int>(undo.block_height),
                      transaction.IsCoinBase()};
            if (!IsValidStoredCoin(coin, undo.block_height)) {
                return std::nullopt;
            }
            result.changes[outpoint] = std::move(coin);
            ++result.count_delta;
        }
    }
    return result;
}

std::optional<CoinTransition> BuildDisconnectCoinTransition(
    const CCoinsView& view,
    const CBlock& block,
    const chainregistry::ReferenceChildBlockUndo& undo)
{
    if (block.vtx.empty() || undo.coins.vtxundo.size() + 1 != block.vtx.size()) {
        return std::nullopt;
    }
    CoinTransition result;
    for (size_t reverse_index{block.vtx.size()}; reverse_index > 0;) {
        const size_t index{--reverse_index};
        const CTransaction& transaction{*block.vtx[index]};
        for (size_t output_index{0};
             output_index < transaction.vout.size();
             ++output_index) {
            const CTxOut& output{transaction.vout[output_index]};
            if (output.scriptPubKey.IsUnspendable()) continue;
            const COutPoint outpoint{transaction.GetHash(),
                                     static_cast<uint32_t>(output_index)};
            const auto current{CurrentCoin(view, result.changes, outpoint)};
            const Coin expected{output,
                                static_cast<int>(undo.block_height),
                                transaction.IsCoinBase()};
            if (!current || !CoinsEqual(*current, expected)) {
                return std::nullopt;
            }
            result.changes[outpoint] = std::nullopt;
            --result.count_delta;
        }
        if (index == 0) continue;
        const CTxUndo& transaction_undo{undo.coins.vtxundo[index - 1]};
        if (chainregistry::IsReferenceChildImport(transaction)) {
            if (!transaction_undo.vprevout.empty()) return std::nullopt;
            continue;
        }
        if (transaction_undo.vprevout.size() != transaction.vin.size()) {
            return std::nullopt;
        }
        for (size_t reverse_input{transaction.vin.size()}; reverse_input > 0;) {
            const size_t input_index{--reverse_input};
            const COutPoint& previous{transaction.vin[input_index].prevout};
            const Coin& restored{transaction_undo.vprevout[input_index]};
            if (CurrentCoin(view, result.changes, previous) ||
                !IsValidStoredCoin(restored, undo.block_height)) {
                return std::nullopt;
            }
            result.changes[previous] = restored;
            ++result.count_delta;
        }
    }
    return result;
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
        if (HasKeyWithPrefix(m_db, DB_BLOCK) ||
            HasKeyWithPrefix(m_db, DB_BMM_ANCHOR) ||
            HasKeyWithPrefix(m_db, DB_COIN) ||
            HasKeyWithPrefix(m_db, DB_HEADER) ||
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

    std::map<uint256, CBlock> blocks;
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(BlockKey{DB_BLOCK, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(ChildChainDBLoadError::BLOCK_KEY_DECODE_FAILED);
        }
        if (prefix != DB_BLOCK) break;
        BlockKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(ChildChainDBLoadError::BLOCK_KEY_DECODE_FAILED);
        }
        StoredChildBlock stored_block;
        if (!cursor->GetValue(stored_block)) {
            return LoadError(ChildChainDBLoadError::BLOCK_DECODE_FAILED);
        }
        CBlock& block{stored_block.block};
        if (block.GetHash() != key.second) {
            return LoadError(ChildChainDBLoadError::BLOCK_KEY_MISMATCH);
        }
        blocks.emplace(key.second, std::move(block));
        cursor->Next();
    }
    if (blocks.size() != stored_state.child_height) {
        return LoadError(ChildChainDBLoadError::BLOCK_COUNT_MISMATCH);
    }

    std::map<uint256, ChildBmmAnchorRecord> anchors;
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(AnchorKey{DB_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(
                ChildChainDBLoadError::ANCHOR_KEY_DECODE_FAILED);
        }
        if (prefix != DB_BMM_ANCHOR) break;
        AnchorKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(
                ChildChainDBLoadError::ANCHOR_KEY_DECODE_FAILED);
        }
        ChildBmmAnchorRecord record;
        if (!cursor->GetValue(record)) {
            return LoadError(ChildChainDBLoadError::ANCHOR_DECODE_FAILED);
        }
        if (record.child_block_hash != key.second) {
            return LoadError(ChildChainDBLoadError::ANCHOR_KEY_MISMATCH);
        }
        if (!IsValidStoredAnchor(
                record, main_headers, m_child_chain, stored_state.safe_halt) ||
            !anchors.emplace(key.second, std::move(record)).second) {
            return LoadError(ChildChainDBLoadError::INVALID_BMM_ANCHOR);
        }
        cursor->Next();
    }
    if (anchors.size() != stored_state.anchor_count ||
        anchors.size() != blocks.size()) {
        return LoadError(ChildChainDBLoadError::ANCHOR_COUNT_MISMATCH);
    }

    std::map<uint256, chainregistry::ReferenceChildBlockUndo> undos;
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
        chainregistry::ReferenceChildBlockUndo undo;
        if (!cursor->GetValue(undo)) {
            return LoadError(ChildChainDBLoadError::UNDO_DECODE_FAILED);
        }
        if (!undos.emplace(key.second, std::move(undo)).second) {
            return LoadError(ChildChainDBLoadError::INVALID_UNDO);
        }
        cursor->Next();
    }
    if (undos.size() != blocks.size()) {
        return LoadError(ChildChainDBLoadError::INVALID_UNDO);
    }

    std::vector<std::pair<const CBlock*,
                          const chainregistry::ReferenceChildBlockUndo*>>
        active_blocks;
    active_blocks.reserve(blocks.size());
    uint256 expected_hash{stored_state.child_tip};
    for (uint32_t height{stored_state.child_height}; height > 0; --height) {
        const auto block{blocks.find(expected_hash)};
        const auto undo{undos.find(expected_hash)};
        if (block == blocks.end() || undo == undos.end() ||
            undo->second.version !=
                chainregistry::REFERENCE_CHILD_BLOCK_UNDO_VERSION ||
            undo->second.block_hash != expected_hash ||
            undo->second.parent_hash != block->second.hashPrevBlock ||
            undo->second.block_height != height) {
            return LoadError(ChildChainDBLoadError::INVALID_BLOCK_CHAIN);
        }
        active_blocks.emplace_back(&block->second, &undo->second);
        expected_hash = block->second.hashPrevBlock;
    }
    if (expected_hash != stored_state.child_genesis_hash ||
        active_blocks.size() != blocks.size()) {
        return LoadError(ChildChainDBLoadError::INVALID_BLOCK_CHAIN);
    }
    std::reverse(active_blocks.begin(), active_blocks.end());

    std::set<chainregistry::DepositId> undo_imports;
    CoinSet expected_coins;
    uint32_t previous_anchor_height{0};
    for (const auto& [block, undo] : active_blocks) {
        const auto anchor{anchors.find(undo->block_hash)};
        if (anchor == anchors.end() ||
            anchor->second.proof.block_height <= previous_anchor_height) {
            return LoadError(ChildChainDBLoadError::INVALID_BMM_ANCHOR);
        }
        previous_anchor_height = anchor->second.proof.block_height;
        std::set<chainregistry::DepositId> local;
        for (const auto& deposit_id : undo->imports.imports) {
            const auto* imported{imports.Find(deposit_id)};
            if (!local.insert(deposit_id).second ||
                !undo_imports.insert(deposit_id).second || !imported ||
                imported->child_block_hash != undo->block_hash ||
                imported->child_block_height != undo->block_height) {
                return LoadError(ChildChainDBLoadError::INVALID_UNDO);
            }
        }
        if (!ApplyBlockToCoinSet(*block, *undo, expected_coins)) {
            return LoadError(ChildChainDBLoadError::INVALID_UNDO);
        }
    }
    if (undo_imports.size() != imports.Size()) {
        return LoadError(ChildChainDBLoadError::INVALID_UNDO);
    }

    CoinSet stored_coins;
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(CoinKey{DB_COIN, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(ChildChainDBLoadError::COIN_KEY_DECODE_FAILED);
        }
        if (prefix != DB_COIN) break;
        CoinKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(ChildChainDBLoadError::COIN_KEY_DECODE_FAILED);
        }
        Coin coin;
        if (!cursor->GetValue(coin)) {
            return LoadError(ChildChainDBLoadError::COIN_DECODE_FAILED);
        }
        if (!IsValidStoredCoin(coin, stored_state.child_height) ||
            !stored_coins.emplace(key.second, std::move(coin)).second) {
            return LoadError(ChildChainDBLoadError::INVALID_COIN);
        }
        cursor->Next();
    }
    if (stored_coins.size() != stored_state.coin_count) {
        return LoadError(ChildChainDBLoadError::COIN_COUNT_MISMATCH);
    }
    if (stored_coins.size() != expected_coins.size()) {
        return LoadError(ChildChainDBLoadError::INVALID_COIN);
    }
    for (const auto& [outpoint, expected] : expected_coins) {
        const auto stored{stored_coins.find(outpoint)};
        if (stored == stored_coins.end() ||
            !CoinsEqual(stored->second, expected)) {
            return LoadError(ChildChainDBLoadError::INVALID_COIN);
        }
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
        m_db.Exists(DB_STATE) || HasKeyWithPrefix(m_db, DB_BLOCK) ||
        HasKeyWithPrefix(m_db, DB_BMM_ANCHOR) ||
        HasKeyWithPrefix(m_db, DB_COIN) ||
        HasKeyWithPrefix(m_db, DB_HEADER) ||
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
        !ImportsMatchMainChain(main_headers, imports) ||
        !StoredAnchorsMatchMainChain(
            m_db,
            main_headers,
            m_child_chain,
            state.anchor_count,
            imports.IsSafeHalted())) {
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
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::DepositImportState& imports,
    const CBlock& block,
    const chainregistry::ReferenceChildBlockUndo& undo,
    const chainregistry::BmmAnchorProof& anchor_proof,
    bool sync)
{
    const uint256 child_block_hash{block.GetHash()};
    ChildChainDBState state;
    const ChildBmmAnchorRecord anchor_record{
        .child_block_hash = child_block_hash,
        .proof = anchor_proof,
    };
    if (!m_db.Read(DB_STATE, state) ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        state.safe_halt || imports.IsSafeHalted() || child_block_hash.IsNull() ||
        main_headers.Params().hashGenesisBlock != m_main_genesis_hash ||
        !main_headers.IsInitialized() ||
        main_headers.Tip()->GetBlockHash() != state.main_tip ||
        !IsValidStoredAnchor(
            anchor_record, main_headers, m_child_chain, /*allow_inactive=*/false) ||
        state.child_height == std::numeric_limits<uint32_t>::max() ||
        block.hashPrevBlock != state.child_tip ||
        undo.version != chainregistry::REFERENCE_CHILD_BLOCK_UNDO_VERSION ||
        undo.block_hash != child_block_hash ||
        undo.parent_hash != block.hashPrevBlock ||
        undo.block_height != state.child_height + 1 ||
        undo.imports.imports.size() >
            std::numeric_limits<uint64_t>::max() - state.import_count ||
        imports.Size() !=
            state.import_count + undo.imports.imports.size() ||
        m_db.Exists(BlockKey{DB_BLOCK, child_block_hash}) ||
        m_db.Exists(UndoKey{DB_UNDO, child_block_hash}) ||
        m_db.Exists(AnchorKey{DB_BMM_ANCHOR, child_block_hash})) {
        return false;
    }
    if (state.child_height > 0) {
        const auto previous{ReadBmmAnchor(state.child_tip)};
        if (!previous ||
            anchor_proof.block_height <= previous->proof.block_height) {
            return false;
        }
    }

    const auto expected_imports{BlockImportIds(block)};
    if (!expected_imports || *expected_imports != undo.imports.imports) {
        return false;
    }

    std::set<chainregistry::DepositId> unique;
    for (const auto& deposit_id : undo.imports.imports) {
        const auto* imported{imports.Find(deposit_id)};
        if (!unique.insert(deposit_id).second || !imported ||
            imported->child_block_hash != child_block_hash ||
            imported->child_block_height != undo.block_height ||
            m_db.Exists(ImportKey{DB_IMPORT, deposit_id})) {
            return false;
        }
    }

    const auto transition{BuildConnectCoinTransition(*this, block, undo)};
    if (!transition) return false;
    if ((transition->count_delta < 0 &&
         static_cast<uint64_t>(-transition->count_delta) > state.coin_count) ||
        (transition->count_delta > 0 &&
         static_cast<uint64_t>(transition->count_delta) >
             std::numeric_limits<uint64_t>::max() - state.coin_count)) {
        return false;
    }

    state.child_tip = child_block_hash;
    state.child_height = undo.block_height;
    ++state.anchor_count;
    if (state.anchor_count != state.child_height) return false;
    state.import_count += undo.imports.imports.size();
    if (transition->count_delta < 0) {
        state.coin_count -= static_cast<uint64_t>(-transition->count_delta);
    } else {
        state.coin_count += static_cast<uint64_t>(transition->count_delta);
    }
    CDBBatch batch{m_db};
    for (const auto& deposit_id : undo.imports.imports) {
        batch.Write(ImportKey{DB_IMPORT, deposit_id}, *imports.Find(deposit_id));
    }
    for (const auto& [outpoint, coin] : transition->changes) {
        if (coin) {
            batch.Write(CoinKey{DB_COIN, outpoint}, *coin);
        } else {
            batch.Erase(CoinKey{DB_COIN, outpoint});
        }
    }
    batch.Write(BlockKey{DB_BLOCK, child_block_hash}, StoredChildBlock{block});
    batch.Write(UndoKey{DB_UNDO, child_block_hash}, undo);
    batch.Write(AnchorKey{DB_BMM_ANCHOR, child_block_hash}, anchor_record);
    batch.Write(DB_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChildChainDB::WriteDisconnectedChildBlock(
    const chainregistry::DepositImportState& imports,
    const CBlock& block,
    const chainregistry::ReferenceChildBlockUndo& undo,
    bool sync)
{
    const uint256 disconnected_child_block{block.GetHash()};
    ChildChainDBState state;
    StoredChildBlock stored_block;
    chainregistry::ReferenceChildBlockUndo stored_undo;
    ChildBmmAnchorRecord stored_anchor;
    if (!m_db.Read(DB_STATE, state) ||
        !m_db.Read(BlockKey{DB_BLOCK, disconnected_child_block}, stored_block) ||
        !m_db.Read(UndoKey{DB_UNDO, disconnected_child_block}, stored_undo) ||
        !m_db.Read(AnchorKey{DB_BMM_ANCHOR, disconnected_child_block},
                   stored_anchor) ||
        !BlocksEqual(stored_block.block, block) || stored_undo != undo ||
        stored_anchor.child_block_hash != disconnected_child_block ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        state.child_tip != disconnected_child_block ||
        undo.version != chainregistry::REFERENCE_CHILD_BLOCK_UNDO_VERSION ||
        undo.block_hash != disconnected_child_block ||
        undo.parent_hash != block.hashPrevBlock || undo.parent_hash.IsNull() ||
        undo.block_height != state.child_height || state.child_height == 0 ||
        state.anchor_count != state.child_height ||
        undo.imports.imports.size() > state.import_count ||
        imports.Size() !=
            state.import_count - undo.imports.imports.size() ||
        imports.IsSafeHalted() != state.safe_halt) {
        return false;
    }
    const auto expected_imports{BlockImportIds(block)};
    if (!expected_imports || *expected_imports != undo.imports.imports) {
        return false;
    }
    for (const auto& deposit_id : undo.imports.imports) {
        const auto stored{ReadImport(deposit_id)};
        if (!stored || stored->child_block_hash != disconnected_child_block ||
            imports.Find(deposit_id)) return false;
    }

    const auto transition{BuildDisconnectCoinTransition(*this, block, undo)};
    if (!transition) return false;
    if ((transition->count_delta < 0 &&
         static_cast<uint64_t>(-transition->count_delta) > state.coin_count) ||
        (transition->count_delta > 0 &&
         static_cast<uint64_t>(transition->count_delta) >
             std::numeric_limits<uint64_t>::max() - state.coin_count)) {
        return false;
    }

    state.child_tip = undo.parent_hash;
    --state.child_height;
    --state.anchor_count;
    state.import_count -= undo.imports.imports.size();
    if (transition->count_delta < 0) {
        state.coin_count -= static_cast<uint64_t>(-transition->count_delta);
    } else {
        state.coin_count += static_cast<uint64_t>(transition->count_delta);
    }
    CDBBatch batch{m_db};
    for (const auto& deposit_id : undo.imports.imports) {
        batch.Erase(ImportKey{DB_IMPORT, deposit_id});
    }
    for (const auto& [outpoint, coin] : transition->changes) {
        if (coin) {
            batch.Write(CoinKey{DB_COIN, outpoint}, *coin);
        } else {
            batch.Erase(CoinKey{DB_COIN, outpoint});
        }
    }
    batch.Erase(BlockKey{DB_BLOCK, disconnected_child_block});
    batch.Erase(UndoKey{DB_UNDO, disconnected_child_block});
    batch.Erase(AnchorKey{DB_BMM_ANCHOR, disconnected_child_block});
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

bool ChildChainDB::ReadState(ChildChainDBState& state) const
{
    return m_db.Read(DB_STATE, state);
}

std::optional<Coin> ChildChainDB::GetCoin(const COutPoint& outpoint) const
{
    Coin coin;
    if (!m_db.Read(CoinKey{DB_COIN, outpoint}, coin)) return std::nullopt;
    if (coin.IsSpent()) {
        throw std::runtime_error("child chain database contains a spent coin");
    }
    return coin;
}

bool ChildChainDB::HaveCoin(const COutPoint& outpoint) const
{
    return m_db.Exists(CoinKey{DB_COIN, outpoint});
}

uint256 ChildChainDB::GetBestBlock() const
{
    ChildChainDBState state;
    if (!m_db.Read(DB_STATE, state)) return {};
    return state.child_tip;
}

void ChildChainDB::BatchWrite(CoinsViewCacheCursor& cursor,
                              const uint256& hash_block)
{
    ChildChainDBState state;
    if (!m_db.Read(DB_STATE, state) || hash_block.IsNull() ||
        state.child_tip != hash_block) {
        throw std::logic_error(
            "child coin cache does not match the atomically committed tip");
    }
    for (auto* entry{cursor.Begin()}; entry != cursor.End();) {
        if (entry->second.IsDirty()) {
            const auto stored{GetCoin(entry->first)};
            if ((entry->second.coin.IsSpent() && stored) ||
                (!entry->second.coin.IsSpent() &&
                 (!stored || !CoinsEqual(*stored, entry->second.coin)))) {
                throw std::logic_error(
                    "child coin cache differs from the atomically committed UTXO set");
            }
        }
        entry = cursor.NextAndMaybeErase(*entry);
    }
}

bool ChildChainDB::ReadBlock(const uint256& child_block_hash,
                             CBlock& block) const
{
    StoredChildBlock stored;
    if (!m_db.Read(BlockKey{DB_BLOCK, child_block_hash}, stored)) return false;
    block = std::move(stored.block);
    return true;
}

bool ChildChainDB::ReadUndo(const uint256& child_block_hash,
                            chainregistry::ReferenceChildBlockUndo& undo) const
{
    return m_db.Read(UndoKey{DB_UNDO, child_block_hash}, undo);
}

std::optional<ChildBmmAnchorRecord> ChildChainDB::ReadBmmAnchor(
    const uint256& child_block_hash) const
{
    ChildBmmAnchorRecord record;
    if (!m_db.Read(AnchorKey{DB_BMM_ANCHOR, child_block_hash}, record)) {
        return std::nullopt;
    }
    return record;
}

} // namespace node
