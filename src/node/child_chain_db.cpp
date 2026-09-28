// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain_db.h>

#include <consensus/amount.h>
#include <hash.h>
#include <pow.h>
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
constexpr uint8_t DB_PENDING_BMM_ANCHOR{'P'};
constexpr uint8_t DB_SIDE_CANDIDATE{'D'};
constexpr uint8_t DB_CANDIDATE_BMM_ANCHOR{'V'};

using AnchorKey = std::pair<uint8_t, uint256>;
using BlockKey = std::pair<uint8_t, uint256>;
using CoinKey = std::pair<uint8_t, COutPoint>;
using CandidateKey = std::pair<uint8_t, uint256>;
using CandidateAnchorKey = std::pair<uint8_t, uint256>;
using HeaderKey = std::pair<uint8_t, uint256>;
using ImportKey = std::pair<uint8_t, chainregistry::DepositId>;
using PendingAnchorKey = std::pair<uint8_t, uint256>;
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
           state.anchor_count == state.child_height &&
           state.pending_anchor_count <= MAX_CHILD_PENDING_BMM_ANCHORS &&
           state.pending_anchor_bytes <= MAX_CHILD_PENDING_BMM_BYTES &&
           state.side_candidate_count <= MAX_CHILD_SIDE_CANDIDATES &&
           state.side_candidate_bytes <= MAX_CHILD_SIDE_CANDIDATE_BYTES &&
           state.candidate_anchor_count <=
               MAX_CHILD_CANDIDATE_BMM_ANCHORS &&
           state.candidate_anchor_bytes <=
               MAX_CHILD_CANDIDATE_BMM_BYTES;
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

uint256 BmmProofHash(const chainregistry::BmmAnchorProof& proof)
{
    return (HashWriter{} << proof).GetHash();
}

bool IsValidStoredPendingAnchor(
    const ChildPendingBmmAnchorRecord& record,
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::ChainId& child_chain,
    bool allow_inactive)
{
    if (record.version != CHILD_PENDING_BMM_ANCHOR_RECORD_VERSION ||
        record.child_block_hash.IsNull() || record.serialized_size == 0 ||
        record.serialized_size > MAX_CHILD_PENDING_BMM_PROOF_SIZE ||
        record.serialized_size != GetSerializeSize(record.proof)) {
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
    const auto status{
        main_headers.GetStatus(record.proof.block_header.GetHash())};
    if (!status.known ||
        status.height != static_cast<int>(record.proof.block_height)) {
        return false;
    }
    if (allow_inactive) return true;
    return main_headers.AuthenticateBmmAnchor(
        record.proof, child_chain, /*minimum_confirmations=*/1).IsValid();
}

bool IsValidStoredCandidateAnchor(
    const ChildCandidateBmmAnchorRecord& record,
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::ChainId& child_chain)
{
    if (record.version != CHILD_CANDIDATE_BMM_ANCHOR_RECORD_VERSION ||
        record.child_block_hash.IsNull() || record.serialized_size == 0 ||
        record.serialized_size > MAX_CHILD_PENDING_BMM_PROOF_SIZE ||
        record.serialized_size != GetSerializeSize(record.proof)) {
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
    const auto status{
        main_headers.GetStatus(record.proof.block_header.GetHash())};
    return status.known &&
           status.height == static_cast<int>(record.proof.block_height);
}

std::optional<ChildBmmAnchorRecord> PrimaryAnchorForMainBlock(
    const CDBWrapper& db,
    const uint256& main_block_hash)
{
    std::unique_ptr<CDBIterator> cursor{const_cast<CDBWrapper&>(db).NewIterator()};
    cursor->Seek(AnchorKey{DB_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix) || prefix != DB_BMM_ANCHOR) break;
        ChildBmmAnchorRecord record;
        if (!cursor->GetValue(record)) return std::nullopt;
        if (record.proof.block_header.GetHash() == main_block_hash) {
            return record;
        }
        cursor->Next();
    }
    return std::nullopt;
}

bool PruneInactivePendingAnchors(
    const CDBWrapper& db,
    CDBBatch& batch,
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::ChainId& child_chain,
    ChildChainDBState& state)
{
    uint64_t stored_count{0};
    uint64_t stored_bytes{0};
    uint64_t active_count{0};
    uint64_t active_bytes{0};
    std::unique_ptr<CDBIterator> cursor{const_cast<CDBWrapper&>(db).NewIterator()};
    cursor->Seek(PendingAnchorKey{DB_PENDING_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) return false;
        if (prefix != DB_PENDING_BMM_ANCHOR) break;
        PendingAnchorKey key;
        ChildPendingBmmAnchorRecord record;
        if (!cursor->GetKey(key) || !cursor->GetValue(record) ||
            key.second != record.proof.block_header.GetHash() ||
            !IsValidStoredPendingAnchor(
                record, main_headers, child_chain, /*allow_inactive=*/true) ||
            stored_count == std::numeric_limits<uint64_t>::max() ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() - stored_bytes) {
            return false;
        }
        ++stored_count;
        stored_bytes += record.serialized_size;
        const auto status{main_headers.GetStatus(key.second)};
        if (status.active) {
            if (active_count == std::numeric_limits<uint64_t>::max() ||
                record.serialized_size >
                    std::numeric_limits<uint64_t>::max() - active_bytes) {
                return false;
            }
            ++active_count;
            active_bytes += record.serialized_size;
        } else {
            batch.Erase(key);
        }
        cursor->Next();
    }
    if (stored_count != state.pending_anchor_count ||
        stored_bytes != state.pending_anchor_bytes ||
        active_count > MAX_CHILD_PENDING_BMM_ANCHORS ||
        active_bytes > MAX_CHILD_PENDING_BMM_BYTES) {
        return false;
    }
    state.pending_anchor_count = active_count;
    state.pending_anchor_bytes = active_bytes;
    return true;
}

bool CollectPendingAnchorsForChild(
    const CDBWrapper& db,
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::ChainId& child_chain,
    const uint256& child_block_hash,
    const ChildChainDBState& state,
    std::vector<std::pair<PendingAnchorKey, ChildPendingBmmAnchorRecord>>& matches)
{
    uint64_t count{0};
    uint64_t bytes{0};
    std::unique_ptr<CDBIterator> cursor{const_cast<CDBWrapper&>(db).NewIterator()};
    cursor->Seek(PendingAnchorKey{DB_PENDING_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) return false;
        if (prefix != DB_PENDING_BMM_ANCHOR) break;
        PendingAnchorKey key;
        ChildPendingBmmAnchorRecord record;
        if (!cursor->GetKey(key) || !cursor->GetValue(record) ||
            key.second != record.proof.block_header.GetHash() ||
            !IsValidStoredPendingAnchor(
                record, main_headers, child_chain, /*allow_inactive=*/false) ||
            count == std::numeric_limits<uint64_t>::max() ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() - bytes) {
            return false;
        }
        ++count;
        bytes += record.serialized_size;
        if (record.child_block_hash == child_block_hash) {
            matches.emplace_back(key, std::move(record));
        }
        cursor->Next();
    }
    return count == state.pending_anchor_count &&
           bytes == state.pending_anchor_bytes;
}

bool CollectCandidateAnchorsForChild(
    const CDBWrapper& db,
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::ChainId& child_chain,
    const uint256& child_block_hash,
    const ChildChainDBState& state,
    std::vector<std::pair<CandidateAnchorKey,
                          ChildCandidateBmmAnchorRecord>>& matches,
    const std::set<uint256>* ignored = nullptr)
{
    uint64_t count{0};
    uint64_t bytes{0};
    std::unique_ptr<CDBIterator> cursor{const_cast<CDBWrapper&>(db).NewIterator()};
    cursor->Seek(CandidateAnchorKey{DB_CANDIDATE_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) return false;
        if (prefix != DB_CANDIDATE_BMM_ANCHOR) break;
        CandidateAnchorKey key;
        ChildCandidateBmmAnchorRecord record;
        if (!cursor->GetKey(key) || !cursor->GetValue(record) ||
            key.second != record.proof.block_header.GetHash() ||
            !IsValidStoredCandidateAnchor(
                record, main_headers, child_chain) ||
            count == std::numeric_limits<uint64_t>::max() ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() - bytes) {
            return false;
        }
        if (ignored && ignored->contains(key.second)) {
            cursor->Next();
            continue;
        }
        ++count;
        bytes += record.serialized_size;
        if (record.child_block_hash == child_block_hash) {
            matches.emplace_back(key, std::move(record));
        }
        cursor->Next();
    }
    return count == state.candidate_anchor_count &&
           bytes == state.candidate_anchor_bytes;
}

bool IsValidStoredCandidate(const ChildCandidateRecord& record,
                            const uint256& expected_hash);

struct CandidatePruningPlan {
    chainregistry::ChildForkPruneResult selection;
    std::map<uint256, std::vector<CandidateAnchorKey>> anchor_keys;
};

std::optional<CandidatePruningPlan> PlanCandidatePruning(
    const CDBWrapper& db,
    const ChildChainDBState& state,
    const std::vector<chainregistry::ChildForkCandidate>& current_candidates,
    const uint256& child_genesis_hash,
    std::optional<chainregistry::ChildForkPruneCandidate> added_candidate)
{
    std::map<uint256, chainregistry::ChildForkPruneCandidate> candidates;
    for (const auto& candidate : current_candidates) {
        if (!candidates.emplace(
                candidate.block_hash,
                chainregistry::ChildForkPruneCandidate{
                    .candidate = candidate,
                }).second) {
            return std::nullopt;
        }
    }

    uint64_t side_count{0};
    uint64_t side_bytes{0};
    std::unique_ptr<CDBIterator> cursor{const_cast<CDBWrapper&>(db).NewIterator()};
    cursor->Seek(CandidateKey{DB_SIDE_CANDIDATE, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        CandidateKey key;
        ChildCandidateRecord record;
        if (!cursor->GetKey(prefix)) return std::nullopt;
        if (prefix != DB_SIDE_CANDIDATE) break;
        if (!cursor->GetKey(key) || !cursor->GetValue(record)) {
            return std::nullopt;
        }
        const auto stored{candidates.find(key.second)};
        if (stored == candidates.end() || stored->second.prunable ||
            !IsValidStoredCandidate(record, key.second) ||
            side_count == std::numeric_limits<uint64_t>::max() ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() - side_bytes) {
            return std::nullopt;
        }
        ++side_count;
        side_bytes += record.serialized_size;
        stored->second.prunable = true;
        stored->second.side_candidate_bytes = record.serialized_size;
        cursor->Next();
    }
    if (side_count != state.side_candidate_count ||
        side_bytes != state.side_candidate_bytes) {
        return std::nullopt;
    }

    CandidatePruningPlan plan;
    uint64_t anchor_count{0};
    uint64_t anchor_bytes{0};
    cursor.reset(const_cast<CDBWrapper&>(db).NewIterator());
    cursor->Seek(CandidateAnchorKey{DB_CANDIDATE_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        CandidateAnchorKey key;
        ChildCandidateBmmAnchorRecord record;
        if (!cursor->GetKey(prefix)) return std::nullopt;
        if (prefix != DB_CANDIDATE_BMM_ANCHOR) break;
        if (!cursor->GetKey(key) || !cursor->GetValue(record) ||
            key.second != record.proof.block_header.GetHash()) {
            return std::nullopt;
        }
        const auto candidate{candidates.find(record.child_block_hash)};
        if (candidate == candidates.end() ||
            anchor_count == std::numeric_limits<uint64_t>::max() ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() - anchor_bytes ||
            candidate->second.candidate_anchor_count ==
                std::numeric_limits<uint64_t>::max() ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() -
                    candidate->second.candidate_anchor_bytes) {
            return std::nullopt;
        }
        ++anchor_count;
        anchor_bytes += record.serialized_size;
        ++candidate->second.candidate_anchor_count;
        candidate->second.candidate_anchor_bytes += record.serialized_size;
        plan.anchor_keys[record.child_block_hash].push_back(key);
        cursor->Next();
    }
    if (anchor_count != state.candidate_anchor_count ||
        anchor_bytes != state.candidate_anchor_bytes) {
        return std::nullopt;
    }
    for (const auto& [hash, candidate] : candidates) {
        if (candidate.prunable && candidate.candidate_anchor_count == 0) {
            return std::nullopt;
        }
    }

    if (added_candidate &&
        !candidates.emplace(
            added_candidate->candidate.block_hash,
            std::move(*added_candidate)).second) {
        return std::nullopt;
    }

    std::vector<chainregistry::ChildForkPruneCandidate> unordered;
    unordered.reserve(candidates.size());
    for (auto& [hash, candidate] : candidates) {
        unordered.push_back(std::move(candidate));
    }
    plan.selection = chainregistry::SelectChildForkPruning(
        child_genesis_hash,
        unordered,
        {
            .side_candidate_count = MAX_CHILD_SIDE_CANDIDATES,
            .side_candidate_bytes = MAX_CHILD_SIDE_CANDIDATE_BYTES,
            .candidate_anchor_count = MAX_CHILD_CANDIDATE_BMM_ANCHORS,
            .candidate_anchor_bytes = MAX_CHILD_CANDIDATE_BMM_BYTES,
        });
    if (!plan.selection.IsValid()) return std::nullopt;
    return plan;
}

bool StoredAnchorsMatchMainChain(
    const CDBWrapper& db,
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::ChainId& child_chain,
    uint64_t expected_count,
    bool allow_inactive,
    const std::set<uint256>* ignored = nullptr)
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
            key.second != record.child_block_hash) {
            return false;
        }
        if (ignored && ignored->contains(key.second)) {
            cursor->Next();
            continue;
        }
        if (!IsValidStoredAnchor(
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

bool HeadersMatchValidatedActivePrefix(
    std::span<const chainregistry::MainHeaderRecord> records,
    std::span<const CBlockHeader> validated_active_headers,
    const uint256& main_genesis_hash,
    const uint256& stored_tip)
{
    if (records.empty() || records.size() > validated_active_headers.size() + 1) {
        return false;
    }
    std::vector<chainregistry::MainHeaderRecord> ordered{
        records.begin(), records.end()};
    std::sort(ordered.begin(), ordered.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.height != rhs.height) return lhs.height < rhs.height;
        return lhs.header.GetHash() < rhs.header.GetHash();
    });
    if (ordered.front().height != 0 ||
        ordered.front().header.GetHash() != main_genesis_hash) {
        return false;
    }
    for (size_t index{1}; index < ordered.size(); ++index) {
        if (ordered[index].height != index ||
            ordered[index].header.GetHash() !=
                validated_active_headers[index - 1].GetHash()) {
            return false;
        }
    }
    return ordered.back().header.GetHash() == stored_tip;
}

bool TipMatchesValidatedActiveChain(
    std::span<const CBlockHeader> validated_active_headers,
    const uint256& main_genesis_hash,
    const uint256& stored_tip)
{
    if (stored_tip == main_genesis_hash) return true;
    return std::any_of(
        validated_active_headers.begin(),
        validated_active_headers.end(),
        [&](const CBlockHeader& header) {
            return header.GetHash() == stored_tip;
        });
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

bool IsValidStoredCandidate(const ChildCandidateRecord& record,
                            const uint256& expected_hash)
{
    if (record.version != CHILD_CANDIDATE_RECORD_VERSION ||
        expected_hash.IsNull() || record.block.GetHash() != expected_hash ||
        record.block.hashPrevBlock.IsNull() || record.block.vtx.empty() ||
        record.undo.version !=
            chainregistry::REFERENCE_CHILD_BLOCK_UNDO_VERSION ||
        record.undo.block_hash != expected_hash ||
        record.undo.parent_hash != record.block.hashPrevBlock ||
        record.undo.block_height == 0 || record.serialized_size == 0 ||
        record.serialized_size > MAX_CHILD_CANDIDATE_RECORD_SIZE ||
        record.serialized_size != GetSerializeSize(record)) {
        return false;
    }
    const auto imports{BlockImportIds(record.block)};
    return imports && *imports == record.undo.imports.imports &&
           record.undo.coins.vtxundo.size() + 1 == record.block.vtx.size();
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

bool ApplyConnectCoinTransition(
    const CCoinsView& view,
    const CBlock& block,
    const chainregistry::ReferenceChildBlockUndo& undo,
    CoinTransition& result)
{
    if (block.vtx.empty() || undo.coins.vtxundo.size() + 1 != block.vtx.size()) {
        return false;
    }
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
                return false;
            }
        }
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
                    const auto current{CurrentCoin(view, result.changes, previous)};
                    const Coin& expected{transaction_undo.vprevout[input_index]};
                    if (!current ||
                        !IsValidStoredCoin(expected, undo.block_height) ||
                        !CoinsEqual(*current, expected)) {
                        return false;
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
                return false;
            }
            result.changes[outpoint] = std::move(coin);
            ++result.count_delta;
        }
    }
    return true;
}

std::optional<CoinTransition> BuildConnectCoinTransition(
    const CCoinsView& view,
    const CBlock& block,
    const chainregistry::ReferenceChildBlockUndo& undo)
{
    CoinTransition result;
    if (!ApplyConnectCoinTransition(view, block, undo, result)) {
        return std::nullopt;
    }
    return result;
}

bool ApplyDisconnectCoinTransition(
    const CCoinsView& view,
    const CBlock& block,
    const chainregistry::ReferenceChildBlockUndo& undo,
    CoinTransition& result)
{
    if (block.vtx.empty() || undo.coins.vtxundo.size() + 1 != block.vtx.size()) {
        return false;
    }
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
                return false;
            }
            result.changes[outpoint] = std::nullopt;
            --result.count_delta;
        }
        if (index == 0) continue;
        const CTxUndo& transaction_undo{undo.coins.vtxundo[index - 1]};
        if (chainregistry::IsReferenceChildImport(transaction)) {
            if (!transaction_undo.vprevout.empty()) return false;
            continue;
        }
        if (transaction_undo.vprevout.size() != transaction.vin.size()) {
            return false;
        }
        for (size_t reverse_input{transaction.vin.size()}; reverse_input > 0;) {
            const size_t input_index{--reverse_input};
            const COutPoint& previous{transaction.vin[input_index].prevout};
            const Coin& restored{transaction_undo.vprevout[input_index]};
            if (CurrentCoin(view, result.changes, previous) ||
                !IsValidStoredCoin(restored, undo.block_height)) {
                return false;
            }
            result.changes[previous] = restored;
            ++result.count_delta;
        }
    }
    return true;
}

std::optional<CoinTransition> BuildDisconnectCoinTransition(
    const CCoinsView& view,
    const CBlock& block,
    const chainregistry::ReferenceChildBlockUndo& undo)
{
    CoinTransition result;
    if (!ApplyDisconnectCoinTransition(view, block, undo, result)) {
        return std::nullopt;
    }
    return result;
}

std::optional<uint32_t> StoredChildHeight(
    const CDBWrapper& db,
    const uint256& child_genesis_hash,
    const uint256& block_hash)
{
    if (block_hash == child_genesis_hash) return 0;
    chainregistry::ReferenceChildBlockUndo canonical_undo;
    if (db.Read(UndoKey{DB_UNDO, block_hash}, canonical_undo)) {
        return canonical_undo.block_height;
    }
    ChildCandidateRecord candidate;
    if (db.Read(CandidateKey{DB_SIDE_CANDIDATE, block_hash}, candidate)) {
        return candidate.undo.block_height;
    }
    return std::nullopt;
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
    int64_t current_time,
    std::optional<std::span<const CBlockHeader>> validated_active_headers) const
{
    ChildChainDBState stored_state;
    if (!m_db.Read(DB_STATE, stored_state)) {
        if (m_db.Exists(DB_STATE)) {
            return LoadError(ChildChainDBLoadError::STATE_DECODE_FAILED);
        }
        if (HasKeyWithPrefix(m_db, DB_BLOCK) ||
            HasKeyWithPrefix(m_db, DB_BMM_ANCHOR) ||
            HasKeyWithPrefix(m_db, DB_PENDING_BMM_ANCHOR) ||
            HasKeyWithPrefix(m_db, DB_SIDE_CANDIDATE) ||
            HasKeyWithPrefix(m_db, DB_CANDIDATE_BMM_ANCHOR) ||
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
    const bool matches_validated_main{
        validated_active_headers &&
        HeadersMatchValidatedActivePrefix(
            header_records,
            *validated_active_headers,
            m_main_genesis_hash,
            stored_state.main_tip)};
    chainregistry::MainHeaderLoadResult header_result;
    if (matches_validated_main) {
        header_result = main_headers.LoadValidatedHeaders(
            header_records, stored_state.main_tip, current_time);
    } else if (validated_active_headers &&
               TipMatchesValidatedActiveChain(
                   *validated_active_headers,
                   m_main_genesis_hash,
                   stored_state.main_tip)) {
        header_result = main_headers.LoadHeadersWithValidatedTip(
            header_records, stored_state.main_tip, current_time);
    } else {
        header_result = main_headers.LoadHeaders(
            header_records, stored_state.main_tip, current_time);
    }
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

    uint64_t pending_count{0};
    uint64_t pending_bytes{0};
    std::set<uint256> pending_main_blocks;
    std::set<uint256> pending_child_blocks;
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(PendingAnchorKey{DB_PENDING_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(
                ChildChainDBLoadError::PENDING_ANCHOR_KEY_DECODE_FAILED);
        }
        if (prefix != DB_PENDING_BMM_ANCHOR) break;
        PendingAnchorKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(
                ChildChainDBLoadError::PENDING_ANCHOR_KEY_DECODE_FAILED);
        }
        ChildPendingBmmAnchorRecord record;
        if (!cursor->GetValue(record)) {
            return LoadError(
                ChildChainDBLoadError::PENDING_ANCHOR_DECODE_FAILED);
        }
        if (key.second != record.proof.block_header.GetHash()) {
            return LoadError(
                ChildChainDBLoadError::PENDING_ANCHOR_KEY_MISMATCH);
        }
        if (!IsValidStoredPendingAnchor(
                record,
                main_headers,
                m_child_chain,
                /*allow_inactive=*/false) ||
            blocks.contains(record.child_block_hash) ||
            !pending_main_blocks.insert(key.second).second ||
            pending_count == std::numeric_limits<uint64_t>::max() ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() - pending_bytes) {
            return LoadError(
                ChildChainDBLoadError::INVALID_PENDING_BMM_ANCHOR);
        }
        ++pending_count;
        pending_bytes += record.serialized_size;
        pending_child_blocks.insert(record.child_block_hash);
        cursor->Next();
    }
    if (pending_count != stored_state.pending_anchor_count ||
        pending_bytes != stored_state.pending_anchor_bytes ||
        pending_count > MAX_CHILD_PENDING_BMM_ANCHORS ||
        pending_bytes > MAX_CHILD_PENDING_BMM_BYTES) {
        return LoadError(
            ChildChainDBLoadError::PENDING_ANCHOR_COUNT_MISMATCH);
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

    std::map<uint256, ChildCandidateRecord> side_candidates;
    uint64_t side_candidate_bytes{0};
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(CandidateKey{DB_SIDE_CANDIDATE, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(
                ChildChainDBLoadError::CANDIDATE_KEY_DECODE_FAILED);
        }
        if (prefix != DB_SIDE_CANDIDATE) break;
        CandidateKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(
                ChildChainDBLoadError::CANDIDATE_KEY_DECODE_FAILED);
        }
        ChildCandidateRecord record;
        if (!cursor->GetValue(record)) {
            return LoadError(
                ChildChainDBLoadError::CANDIDATE_DECODE_FAILED);
        }
        if (record.block.GetHash() != key.second) {
            return LoadError(
                ChildChainDBLoadError::CANDIDATE_KEY_MISMATCH);
        }
        if (blocks.contains(key.second) ||
            !IsValidStoredCandidate(record, key.second) ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() - side_candidate_bytes ||
            !side_candidates.emplace(key.second, std::move(record)).second) {
            return LoadError(ChildChainDBLoadError::INVALID_CANDIDATE_DAG);
        }
        side_candidate_bytes += side_candidates.at(key.second).serialized_size;
        cursor->Next();
    }
    if (side_candidates.size() != stored_state.side_candidate_count ||
        side_candidate_bytes != stored_state.side_candidate_bytes ||
        side_candidates.size() > MAX_CHILD_SIDE_CANDIDATES ||
        side_candidate_bytes > MAX_CHILD_SIDE_CANDIDATE_BYTES) {
        return LoadError(
            ChildChainDBLoadError::CANDIDATE_COUNT_MISMATCH);
    }
    for (const auto& [hash, candidate] : side_candidates) {
        if (pending_child_blocks.contains(hash)) {
            return LoadError(
                ChildChainDBLoadError::INVALID_PENDING_BMM_ANCHOR);
        }
    }

    enum class CandidateVisit : uint8_t {
        UNVISITED,
        VISITING,
        VISITED,
    };
    std::map<uint256, CandidateVisit> candidate_visits;
    const auto validate_candidate = [&](const auto& self,
                                        const uint256& hash) -> bool {
        CandidateVisit& visit{candidate_visits[hash]};
        if (visit == CandidateVisit::VISITED) return true;
        if (visit == CandidateVisit::VISITING) return false;
        visit = CandidateVisit::VISITING;
        const ChildCandidateRecord& candidate{side_candidates.at(hash)};
        uint32_t parent_height{0};
        if (candidate.block.hashPrevBlock != stored_state.child_genesis_hash) {
            const auto side_parent{
                side_candidates.find(candidate.block.hashPrevBlock)};
            if (side_parent != side_candidates.end()) {
                if (!self(self, side_parent->first)) return false;
                parent_height = side_parent->second.undo.block_height;
            } else {
                const auto canonical_parent{
                    undos.find(candidate.block.hashPrevBlock)};
                if (canonical_parent == undos.end()) return false;
                parent_height = canonical_parent->second.block_height;
            }
        }
        if (parent_height == std::numeric_limits<uint32_t>::max() ||
            candidate.undo.block_height != parent_height + 1) {
            return false;
        }
        visit = CandidateVisit::VISITED;
        return true;
    };
    for (const auto& [hash, candidate] : side_candidates) {
        if (!validate_candidate(validate_candidate, hash)) {
            return LoadError(ChildChainDBLoadError::INVALID_CANDIDATE_DAG);
        }
    }

    std::set<uint256> anchored_main_blocks{pending_main_blocks};
    for (const auto& [hash, anchor] : anchors) {
        if (!anchored_main_blocks
                 .insert(anchor.proof.block_header.GetHash())
                 .second) {
            return LoadError(ChildChainDBLoadError::INVALID_BMM_ANCHOR);
        }
    }
    std::map<uint256, uint64_t> side_anchor_counts;
    uint64_t candidate_anchor_count{0};
    uint64_t candidate_anchor_bytes{0};
    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(CandidateAnchorKey{DB_CANDIDATE_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) {
            return LoadError(
                ChildChainDBLoadError::CANDIDATE_ANCHOR_KEY_DECODE_FAILED);
        }
        if (prefix != DB_CANDIDATE_BMM_ANCHOR) break;
        CandidateAnchorKey key;
        if (!cursor->GetKey(key)) {
            return LoadError(
                ChildChainDBLoadError::CANDIDATE_ANCHOR_KEY_DECODE_FAILED);
        }
        ChildCandidateBmmAnchorRecord record;
        if (!cursor->GetValue(record)) {
            return LoadError(
                ChildChainDBLoadError::CANDIDATE_ANCHOR_DECODE_FAILED);
        }
        if (record.proof.block_header.GetHash() != key.second) {
            return LoadError(
                ChildChainDBLoadError::CANDIDATE_ANCHOR_KEY_MISMATCH);
        }
        if ((!blocks.contains(record.child_block_hash) &&
             !side_candidates.contains(record.child_block_hash)) ||
            !IsValidStoredCandidateAnchor(
                record, main_headers, m_child_chain) ||
            !anchored_main_blocks.insert(key.second).second ||
            candidate_anchor_count == std::numeric_limits<uint64_t>::max() ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() -
                    candidate_anchor_bytes) {
            return LoadError(
                ChildChainDBLoadError::INVALID_CANDIDATE_BMM_ANCHOR);
        }
        ++candidate_anchor_count;
        candidate_anchor_bytes += record.serialized_size;
        if (side_candidates.contains(record.child_block_hash)) {
            ++side_anchor_counts[record.child_block_hash];
        }
        cursor->Next();
    }
    if (candidate_anchor_count != stored_state.candidate_anchor_count ||
        candidate_anchor_bytes != stored_state.candidate_anchor_bytes ||
        candidate_anchor_count > MAX_CHILD_CANDIDATE_BMM_ANCHORS ||
        candidate_anchor_bytes > MAX_CHILD_CANDIDATE_BMM_BYTES) {
        return LoadError(
            ChildChainDBLoadError::CANDIDATE_ANCHOR_COUNT_MISMATCH);
    }
    for (const auto& [hash, candidate] : side_candidates) {
        if (side_anchor_counts[hash] == 0) {
            return LoadError(
                ChildChainDBLoadError::INVALID_CANDIDATE_BMM_ANCHOR);
        }
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
        !main_headers.IsInitialized() || headers.empty() ||
        headers.front().height != 0 ||
        headers.front().header.GetHash() != m_main_genesis_hash ||
        imports.ChildChain() != m_child_chain ||
        imports.MinimumConfirmations() != m_minimum_confirmations ||
        imports.Size() != 0 || imports.IsSafeHalted() ||
        m_db.Exists(DB_STATE) || HasKeyWithPrefix(m_db, DB_BLOCK) ||
        HasKeyWithPrefix(m_db, DB_BMM_ANCHOR) ||
        HasKeyWithPrefix(m_db, DB_PENDING_BMM_ANCHOR) ||
        HasKeyWithPrefix(m_db, DB_SIDE_CANDIDATE) ||
        HasKeyWithPrefix(m_db, DB_CANDIDATE_BMM_ANCHOR) ||
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
        .main_tip = main_headers.Tip()->GetBlockHash(),
        .header_count = headers.size(),
        .child_genesis_hash = m_child_genesis_hash,
        .child_tip = m_child_genesis_hash,
    };
    CDBBatch batch{m_db};
    for (const auto& header : headers) {
        batch.Write(HeaderKey{DB_HEADER, header.header.GetHash()}, header);
    }
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
    return WriteMainHeaderAndDisconnect(
        main_headers, imports, header, {}, sync);
}

bool ChildChainDB::WriteMainHeaderAndDisconnect(
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::DepositImportState& imports,
    const CBlockHeader& header,
    std::span<const ChildChainDBDisconnect> disconnected_blocks,
    bool sync)
{
    return WriteMainChainUpdate(
        main_headers, imports, &header, disconnected_blocks, sync);
}

bool ChildChainDB::WriteMainTipAndDisconnect(
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::DepositImportState& imports,
    std::span<const ChildChainDBDisconnect> disconnected_blocks,
    bool sync)
{
    return WriteMainChainUpdate(
        main_headers, imports, nullptr, disconnected_blocks, sync);
}

bool ChildChainDB::WriteMainChainUpdate(
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::DepositImportState& imports,
    const CBlockHeader* added_header,
    std::span<const ChildChainDBDisconnect> disconnected_blocks,
    bool sync)
{
    ChildChainDBState state;
    const auto headers{main_headers.ExportHeaders()};
    if (!m_db.Read(DB_STATE, state) ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        imports.ChildChain() != m_child_chain ||
        imports.MinimumConfirmations() != m_minimum_confirmations ||
        main_headers.Params().hashGenesisBlock != m_main_genesis_hash ||
        !main_headers.IsInitialized() ||
        headers.size() != state.header_count + (added_header ? 1 : 0) ||
        (imports.IsSafeHalted() && !disconnected_blocks.empty())) {
        return false;
    }
    const uint256 added_hash{added_header ? added_header->GetHash() : uint256{}};
    const CBlockIndex* added_entry{
        added_header ? main_headers.Find(added_hash) : nullptr};
    if (added_header &&
        (!added_entry || m_db.Exists(HeaderKey{DB_HEADER, added_hash}))) {
        return false;
    }
    if (!added_header && state.main_tip == main_headers.Tip()->GetBlockHash()) {
        return false;
    }

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

    CDBBatch batch{m_db};
    if (!PruneInactivePendingAnchors(
            m_db, batch, main_headers, m_child_chain, state)) {
        return false;
    }
    CoinTransition coin_transition;
    std::set<uint256> disconnected_hashes;
    for (const auto& disconnected : disconnected_blocks) {
        const CBlock& block{disconnected.block};
        const chainregistry::ReferenceChildBlockUndo& undo{disconnected.undo};
        const uint256 block_hash{block.GetHash()};
        StoredChildBlock stored_block;
        chainregistry::ReferenceChildBlockUndo stored_undo;
        ChildBmmAnchorRecord stored_anchor;
        if (!disconnected_hashes.insert(block_hash).second ||
            !m_db.Read(BlockKey{DB_BLOCK, block_hash}, stored_block) ||
            !m_db.Read(UndoKey{DB_UNDO, block_hash}, stored_undo) ||
            !m_db.Read(AnchorKey{DB_BMM_ANCHOR, block_hash}, stored_anchor) ||
            !BlocksEqual(stored_block.block, block) || stored_undo != undo ||
            stored_anchor.child_block_hash != block_hash ||
            !IsValidStoredAnchor(
                stored_anchor,
                main_headers,
                m_child_chain,
                /*allow_inactive=*/true) ||
            main_headers.GetStatus(stored_anchor.proof.block_header.GetHash()).active ||
            state.child_tip != block_hash || state.child_height == 0 ||
            undo.version != chainregistry::REFERENCE_CHILD_BLOCK_UNDO_VERSION ||
            undo.block_hash != block_hash ||
            undo.parent_hash != block.hashPrevBlock || undo.parent_hash.IsNull() ||
            undo.block_height != state.child_height ||
            undo.imports.imports.size() > state.import_count ||
            state.anchor_count != state.child_height) {
            return false;
        }
        const auto expected_imports{BlockImportIds(block)};
        if (!expected_imports || *expected_imports != undo.imports.imports) {
            return false;
        }
        for (const auto& deposit_id : undo.imports.imports) {
            const auto stored{ReadImport(deposit_id)};
            if (!stored || stored->child_block_hash != block_hash ||
                imports.Find(deposit_id)) {
                return false;
            }
            batch.Erase(ImportKey{DB_IMPORT, deposit_id});
        }

        ChildCandidateRecord candidate{
            .block = block,
            .undo = undo,
        };
        candidate.serialized_size = GetSerializeSize(candidate);
        const uint256 main_block_hash{
            stored_anchor.proof.block_header.GetHash()};
        const CandidateAnchorKey candidate_anchor_key{
            DB_CANDIDATE_BMM_ANCHOR, main_block_hash};
        const uint64_t candidate_anchor_size{
            GetSerializeSize(stored_anchor.proof)};
        const ChildCandidateBmmAnchorRecord candidate_anchor{
            .child_block_hash = block_hash,
            .serialized_size = candidate_anchor_size,
            .proof = stored_anchor.proof,
        };
        if (!IsValidStoredCandidate(candidate, block_hash) ||
            !IsValidStoredCandidateAnchor(
                candidate_anchor, main_headers, m_child_chain) ||
            m_db.Exists(CandidateKey{DB_SIDE_CANDIDATE, block_hash}) ||
            m_db.Exists(candidate_anchor_key) ||
            state.side_candidate_count == MAX_CHILD_SIDE_CANDIDATES ||
            candidate.serialized_size >
                MAX_CHILD_SIDE_CANDIDATE_BYTES -
                    state.side_candidate_bytes ||
            state.candidate_anchor_count ==
                MAX_CHILD_CANDIDATE_BMM_ANCHORS ||
            candidate_anchor_size >
                MAX_CHILD_CANDIDATE_BMM_BYTES -
                    state.candidate_anchor_bytes) {
            return false;
        }
        ++state.side_candidate_count;
        state.side_candidate_bytes += candidate.serialized_size;
        ++state.candidate_anchor_count;
        state.candidate_anchor_bytes += candidate_anchor_size;

        const int64_t previous_delta{coin_transition.count_delta};
        if (!ApplyDisconnectCoinTransition(
                *this, block, undo, coin_transition)) {
            return false;
        }
        const int64_t delta{coin_transition.count_delta - previous_delta};
        if ((delta < 0 &&
             static_cast<uint64_t>(-delta) > state.coin_count) ||
            (delta > 0 &&
             static_cast<uint64_t>(delta) >
                 std::numeric_limits<uint64_t>::max() - state.coin_count)) {
            return false;
        }
        const bool subtract{delta < 0};
        const uint64_t magnitude{subtract ? static_cast<uint64_t>(-delta)
                                          : static_cast<uint64_t>(delta)};
        state.coin_count = subtract ? state.coin_count - magnitude
                                    : state.coin_count + magnitude;
        state.child_tip = undo.parent_hash;
        --state.child_height;
        --state.anchor_count;
        state.import_count -= undo.imports.imports.size();
        batch.Erase(BlockKey{DB_BLOCK, block_hash});
        batch.Erase(UndoKey{DB_UNDO, block_hash});
        batch.Erase(AnchorKey{DB_BMM_ANCHOR, block_hash});
        batch.Write(
            CandidateKey{DB_SIDE_CANDIDATE, block_hash}, candidate);
        batch.Write(candidate_anchor_key, candidate_anchor);
    }

    if (imports.Size() != state.import_count ||
        !ImportsMatchMainChain(main_headers, imports) ||
        !StoredAnchorsMatchMainChain(
            m_db,
            main_headers,
            m_child_chain,
            state.anchor_count,
            imports.IsSafeHalted(),
            &disconnected_hashes)) {
        return false;
    }
    for (const auto& [outpoint, coin] : coin_transition.changes) {
        if (coin) {
            batch.Write(CoinKey{DB_COIN, outpoint}, *coin);
        } else {
            batch.Erase(CoinKey{DB_COIN, outpoint});
        }
    }

    state.main_tip = main_headers.Tip()->GetBlockHash();
    state.safe_halt = imports.IsSafeHalted();
    if (added_header) {
        ++state.header_count;
        const chainregistry::MainHeaderRecord record{
            .height = static_cast<uint32_t>(added_entry->nHeight),
            .header = *added_header,
        };
        batch.Write(HeaderKey{DB_HEADER, added_hash}, record);
    }
    if (!stored_halt && imports.SafeHalt()) {
        batch.Write(DB_SAFE_HALT, *imports.SafeHalt());
    }
    batch.Write(DB_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChildChainDB::WritePendingBmmAnchor(
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::BmmAnchorProof& anchor_proof,
    bool sync)
{
    ChildChainDBState state;
    const auto authenticated{main_headers.AuthenticateBmmAnchor(
        anchor_proof, m_child_chain, /*minimum_confirmations=*/1)};
    if (!authenticated.IsValid() || !authenticated.proof.anchor) return false;
    const uint256 child_block_hash{
        authenticated.proof.anchor->child_block_hash};
    const uint256 main_block_hash{anchor_proof.block_header.GetHash()};
    const uint64_t serialized_size{GetSerializeSize(anchor_proof)};
    const ChildPendingBmmAnchorRecord record{
        .child_block_hash = child_block_hash,
        .serialized_size = serialized_size,
        .proof = anchor_proof,
    };
    if (!m_db.Read(DB_STATE, state) ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        state.safe_halt || serialized_size == 0 ||
        serialized_size > MAX_CHILD_PENDING_BMM_PROOF_SIZE ||
        main_headers.Params().hashGenesisBlock != m_main_genesis_hash ||
        !main_headers.IsInitialized() ||
        main_headers.Tip()->GetBlockHash() != state.main_tip ||
        m_db.Exists(BlockKey{DB_BLOCK, child_block_hash}) ||
        m_db.Exists(CandidateKey{DB_SIDE_CANDIDATE, child_block_hash}) ||
        PrimaryAnchorForMainBlock(m_db, main_block_hash) ||
        m_db.Exists(CandidateAnchorKey{
            DB_CANDIDATE_BMM_ANCHOR, main_block_hash})) {
        return false;
    }

    const PendingAnchorKey key{DB_PENDING_BMM_ANCHOR, main_block_hash};
    ChildPendingBmmAnchorRecord existing;
    if (m_db.Read(key, existing)) {
        return existing.child_block_hash == child_block_hash &&
               existing.serialized_size == serialized_size &&
               BmmProofHash(existing.proof) == BmmProofHash(anchor_proof);
    }
    if (m_db.Exists(key) ||
        state.pending_anchor_count == MAX_CHILD_PENDING_BMM_ANCHORS ||
        serialized_size >
            MAX_CHILD_PENDING_BMM_BYTES - state.pending_anchor_bytes) {
        return false;
    }

    ++state.pending_anchor_count;
    state.pending_anchor_bytes += serialized_size;
    CDBBatch batch{m_db};
    batch.Write(key, record);
    batch.Write(DB_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChildChainDB::WriteValidatedChildCandidate(
    const chainregistry::MainHeaderChain& main_headers,
    const CBlock& block,
    const chainregistry::ReferenceChildBlockUndo& undo,
    const chainregistry::BmmAnchorProof& anchor_proof,
    bool sync,
    std::vector<uint256>* pruned_candidates)
{
    const uint256 child_block_hash{block.GetHash()};
    const auto authenticated{main_headers.AuthenticateBmmAnchor(
        anchor_proof, m_child_chain, /*minimum_confirmations=*/1)};
    if (!authenticated.IsValid() || !authenticated.proof.anchor ||
        authenticated.proof.anchor->child_block_hash != child_block_hash) {
        return false;
    }

    ChildCandidateRecord candidate{
        .block = block,
        .undo = undo,
    };
    candidate.serialized_size = GetSerializeSize(candidate);
    ChildChainDBState state;
    const auto parent_height{
        StoredChildHeight(m_db, m_child_genesis_hash, block.hashPrevBlock)};
    if (!m_db.Read(DB_STATE, state) ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        state.safe_halt || !parent_height ||
        *parent_height == std::numeric_limits<uint32_t>::max() ||
        undo.block_height != *parent_height + 1 ||
        !IsValidStoredCandidate(candidate, child_block_hash) ||
        main_headers.Params().hashGenesisBlock != m_main_genesis_hash ||
        !main_headers.IsInitialized() ||
        main_headers.Tip()->GetBlockHash() != state.main_tip ||
        m_db.Exists(BlockKey{DB_BLOCK, child_block_hash}) ||
        m_db.Exists(UndoKey{DB_UNDO, child_block_hash}) ||
        m_db.Exists(CandidateKey{DB_SIDE_CANDIDATE, child_block_hash})) {
        return false;
    }

    std::vector<std::pair<PendingAnchorKey, ChildPendingBmmAnchorRecord>> pending;
    if (!CollectPendingAnchorsForChild(
            m_db,
            main_headers,
            m_child_chain,
            child_block_hash,
            state,
            pending)) {
        return false;
    }

    std::map<uint256, ChildCandidateBmmAnchorRecord> anchors;
    uint64_t removed_pending_bytes{0};
    for (const auto& [key, record] : pending) {
        if (record.serialized_size >
            std::numeric_limits<uint64_t>::max() - removed_pending_bytes) {
            return false;
        }
        removed_pending_bytes += record.serialized_size;
        anchors.emplace(
            key.second,
            ChildCandidateBmmAnchorRecord{
                .child_block_hash = child_block_hash,
                .serialized_size = record.serialized_size,
                .proof = record.proof,
            });
    }
    const uint256 supplied_main_block{anchor_proof.block_header.GetHash()};
    const uint64_t supplied_size{GetSerializeSize(anchor_proof)};
    const auto supplied{anchors.find(supplied_main_block)};
    if (supplied != anchors.end()) {
        if (BmmProofHash(supplied->second.proof) !=
            BmmProofHash(anchor_proof)) {
            return false;
        }
    } else {
        anchors.emplace(
            supplied_main_block,
            ChildCandidateBmmAnchorRecord{
                .child_block_hash = child_block_hash,
                .serialized_size = supplied_size,
                .proof = anchor_proof,
            });
    }

    uint64_t added_anchor_bytes{0};
    for (const auto& [main_block_hash, record] : anchors) {
        if (!IsValidStoredCandidateAnchor(
                record, main_headers, m_child_chain) ||
            PrimaryAnchorForMainBlock(m_db, main_block_hash) ||
            m_db.Exists(CandidateAnchorKey{
                DB_CANDIDATE_BMM_ANCHOR, main_block_hash}) ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() - added_anchor_bytes) {
            return false;
        }
        added_anchor_bytes += record.serialized_size;
    }
    if (pending.size() > state.pending_anchor_count ||
        removed_pending_bytes > state.pending_anchor_bytes) {
        return false;
    }

    const auto current_candidates{ReadForkCandidates(main_headers)};
    if (!current_candidates) return false;
    chainregistry::ChildForkPruneCandidate added{
        .candidate = {
            .block_hash = child_block_hash,
            .parent_hash = block.hashPrevBlock,
            .anchors = {},
        },
        .side_candidate_bytes = candidate.serialized_size,
        .candidate_anchor_count = anchors.size(),
        .candidate_anchor_bytes = added_anchor_bytes,
        .prunable = true,
    };
    for (const auto& [main_block_hash, record] : anchors) {
        const auto status{main_headers.GetStatus(main_block_hash)};
        const CBlockIndex* entry{main_headers.Find(main_block_hash)};
        if (!status.known || !status.active || !entry ||
            status.height != static_cast<int>(record.proof.block_height)) {
            return false;
        }
        const arith_uint256 work{GetBlockProof(*entry)};
        if (work == 0) return false;
        added.candidate.anchors.push_back({
            .main_block_hash = main_block_hash,
            .main_height = record.proof.block_height,
            .work = work,
        });
    }
    const auto pruning{PlanCandidatePruning(
        m_db,
        state,
        *current_candidates,
        m_child_genesis_hash,
        std::move(added))};
    if (!pruning || std::find(
            pruning->selection.pruned.begin(),
            pruning->selection.pruned.end(),
            child_block_hash) !=
            pruning->selection.pruned.end()) {
        return false;
    }

    state.side_candidate_count = pruning->selection.side_candidate_count;
    state.side_candidate_bytes = pruning->selection.side_candidate_bytes;
    state.candidate_anchor_count =
        pruning->selection.candidate_anchor_count;
    state.candidate_anchor_bytes = pruning->selection.candidate_anchor_bytes;
    state.pending_anchor_count -= pending.size();
    state.pending_anchor_bytes -= removed_pending_bytes;
    CDBBatch batch{m_db};
    for (const uint256& hash : pruning->selection.pruned) {
        batch.Erase(CandidateKey{DB_SIDE_CANDIDATE, hash});
        const auto anchor_keys{pruning->anchor_keys.find(hash)};
        if (anchor_keys == pruning->anchor_keys.end()) return false;
        for (const CandidateAnchorKey& key : anchor_keys->second) {
            batch.Erase(key);
        }
    }
    batch.Write(
        CandidateKey{DB_SIDE_CANDIDATE, child_block_hash}, candidate);
    for (const auto& [main_block_hash, record] : anchors) {
        batch.Write(
            CandidateAnchorKey{DB_CANDIDATE_BMM_ANCHOR, main_block_hash},
            record);
    }
    for (const auto& [key, record] : pending) batch.Erase(key);
    batch.Write(DB_STATE, state);
    m_db.WriteBatch(batch, sync);
    if (pruned_candidates) {
        *pruned_candidates = pruning->selection.pruned;
    }
    return true;
}

bool ChildChainDB::WriteCandidateBmmAnchor(
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::BmmAnchorProof& anchor_proof,
    bool sync)
{
    const auto authenticated{main_headers.AuthenticateBmmAnchor(
        anchor_proof, m_child_chain, /*minimum_confirmations=*/1)};
    if (!authenticated.IsValid() || !authenticated.proof.anchor) return false;
    const uint256 child_block_hash{
        authenticated.proof.anchor->child_block_hash};
    const uint256 main_block_hash{anchor_proof.block_header.GetHash()};
    const uint64_t serialized_size{GetSerializeSize(anchor_proof)};
    const ChildCandidateBmmAnchorRecord record{
        .child_block_hash = child_block_hash,
        .serialized_size = serialized_size,
        .proof = anchor_proof,
    };

    ChildChainDBState state;
    if (!m_db.Read(DB_STATE, state) ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        state.safe_halt ||
        (!m_db.Exists(BlockKey{DB_BLOCK, child_block_hash}) &&
         !m_db.Exists(CandidateKey{
             DB_SIDE_CANDIDATE, child_block_hash})) ||
        !IsValidStoredCandidateAnchor(record, main_headers, m_child_chain) ||
        main_headers.Tip()->GetBlockHash() != state.main_tip) {
        return false;
    }

    const CandidateAnchorKey key{
        DB_CANDIDATE_BMM_ANCHOR, main_block_hash};
    ChildCandidateBmmAnchorRecord existing;
    if (m_db.Read(key, existing)) {
        return existing.child_block_hash == child_block_hash &&
               existing.serialized_size == serialized_size &&
               BmmProofHash(existing.proof) == BmmProofHash(anchor_proof);
    }
    const auto primary{PrimaryAnchorForMainBlock(m_db, main_block_hash)};
    if (primary) {
        return primary->child_block_hash == child_block_hash &&
               BmmProofHash(primary->proof) == BmmProofHash(anchor_proof);
    }
    if (m_db.Exists(key) ||
        state.candidate_anchor_count ==
            MAX_CHILD_CANDIDATE_BMM_ANCHORS ||
        serialized_size >
            MAX_CHILD_CANDIDATE_BMM_BYTES -
                state.candidate_anchor_bytes) {
        return false;
    }

    const PendingAnchorKey pending_key{
        DB_PENDING_BMM_ANCHOR, main_block_hash};
    ChildPendingBmmAnchorRecord pending;
    bool erase_pending{false};
    if (m_db.Read(pending_key, pending)) {
        if (pending.child_block_hash != child_block_hash ||
            pending.serialized_size != serialized_size ||
            BmmProofHash(pending.proof) != BmmProofHash(anchor_proof) ||
            state.pending_anchor_count == 0 ||
            serialized_size > state.pending_anchor_bytes) {
            return false;
        }
        erase_pending = true;
    } else if (m_db.Exists(pending_key)) {
        return false;
    }

    ++state.candidate_anchor_count;
    state.candidate_anchor_bytes += serialized_size;
    if (erase_pending) {
        --state.pending_anchor_count;
        state.pending_anchor_bytes -= serialized_size;
    }
    CDBBatch batch{m_db};
    batch.Write(key, record);
    if (erase_pending) batch.Erase(pending_key);
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
    ChildCandidateRecord stored_candidate;
    const CandidateKey candidate_key{
        DB_SIDE_CANDIDATE, child_block_hash};
    const bool promoting_candidate{m_db.Read(candidate_key, stored_candidate)};
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
        m_db.Exists(AnchorKey{DB_BMM_ANCHOR, child_block_hash}) ||
        (!promoting_candidate && m_db.Exists(candidate_key)) ||
        (promoting_candidate &&
         (!IsValidStoredCandidate(stored_candidate, child_block_hash) ||
          !BlocksEqual(stored_candidate.block, block) ||
          stored_candidate.undo != undo || state.side_candidate_count == 0 ||
          stored_candidate.serialized_size > state.side_candidate_bytes))) {
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
    std::vector<std::pair<PendingAnchorKey, ChildPendingBmmAnchorRecord>> pending;
    if (!CollectPendingAnchorsForChild(
            m_db,
            main_headers,
            m_child_chain,
            child_block_hash,
            state,
            pending)) {
        return false;
    }
    const uint256 supplied_main_block{anchor_proof.block_header.GetHash()};
    const CandidateAnchorKey supplied_candidate_anchor_key{
        DB_CANDIDATE_BMM_ANCHOR, supplied_main_block};
    ChildCandidateBmmAnchorRecord supplied_candidate_anchor;
    const bool erase_supplied_candidate_anchor{
        m_db.Read(supplied_candidate_anchor_key,
                  supplied_candidate_anchor)};
    if (erase_supplied_candidate_anchor &&
        (supplied_candidate_anchor.child_block_hash != child_block_hash ||
         supplied_candidate_anchor.serialized_size >
             state.candidate_anchor_bytes ||
         state.candidate_anchor_count == 0 ||
         BmmProofHash(supplied_candidate_anchor.proof) !=
             BmmProofHash(anchor_proof))) {
        return false;
    }
    if (!erase_supplied_candidate_anchor &&
        m_db.Exists(supplied_candidate_anchor_key)) {
        return false;
    }
    uint64_t removed_pending_bytes{0};
    uint64_t retained_anchor_bytes{0};
    std::map<uint256, ChildCandidateBmmAnchorRecord>
        retained_pending_anchors;
    for (const auto& [key, record] : pending) {
        if (key.second == supplied_main_block &&
            BmmProofHash(record.proof) != BmmProofHash(anchor_proof)) {
            return false;
        }
        if (record.serialized_size >
            std::numeric_limits<uint64_t>::max() - removed_pending_bytes) {
            return false;
        }
        removed_pending_bytes += record.serialized_size;
        if (key.second == supplied_main_block) continue;
        ChildCandidateBmmAnchorRecord retained{
            .child_block_hash = child_block_hash,
            .serialized_size = record.serialized_size,
            .proof = record.proof,
        };
        if (!IsValidStoredCandidateAnchor(
                retained, main_headers, m_child_chain) ||
            PrimaryAnchorForMainBlock(m_db, key.second) ||
            m_db.Exists(CandidateAnchorKey{
                DB_CANDIDATE_BMM_ANCHOR, key.second}) ||
            record.serialized_size >
                std::numeric_limits<uint64_t>::max() -
                    retained_anchor_bytes) {
            return false;
        }
        retained_anchor_bytes += record.serialized_size;
        retained_pending_anchors.emplace(key.second, std::move(retained));
    }
    if (pending.size() > state.pending_anchor_count ||
        removed_pending_bytes > state.pending_anchor_bytes ||
        retained_pending_anchors.size() >
            MAX_CHILD_CANDIDATE_BMM_ANCHORS -
                state.candidate_anchor_count ||
        retained_anchor_bytes >
            MAX_CHILD_CANDIDATE_BMM_BYTES -
                state.candidate_anchor_bytes) {
        return false;
    }
    state.pending_anchor_count -= pending.size();
    state.pending_anchor_bytes -= removed_pending_bytes;
    state.candidate_anchor_count += retained_pending_anchors.size();
    state.candidate_anchor_bytes += retained_anchor_bytes;
    if (promoting_candidate) {
        --state.side_candidate_count;
        state.side_candidate_bytes -= stored_candidate.serialized_size;
    }
    if (erase_supplied_candidate_anchor) {
        --state.candidate_anchor_count;
        state.candidate_anchor_bytes -=
            supplied_candidate_anchor.serialized_size;
    }
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
    if (promoting_candidate) batch.Erase(candidate_key);
    if (erase_supplied_candidate_anchor) {
        batch.Erase(supplied_candidate_anchor_key);
    }
    for (const auto& [main_block_hash, record] :
         retained_pending_anchors) {
        batch.Write(
            CandidateAnchorKey{DB_CANDIDATE_BMM_ANCHOR, main_block_hash},
            record);
    }
    for (const auto& pending_entry : pending) batch.Erase(pending_entry.first);
    batch.Write(DB_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChildChainDB::WriteDisconnectedChildBlock(
    const chainregistry::MainHeaderChain& main_headers,
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
        main_headers.Params().hashGenesisBlock != m_main_genesis_hash ||
        !main_headers.IsInitialized() ||
        main_headers.Tip()->GetBlockHash() != state.main_tip ||
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

    std::vector<std::pair<CandidateAnchorKey,
                          ChildCandidateBmmAnchorRecord>>
        candidate_anchors;
    if (!CollectCandidateAnchorsForChild(
            m_db,
            main_headers,
            m_child_chain,
            disconnected_child_block,
            state,
            candidate_anchors)) {
        return false;
    }
    uint64_t removed_anchor_bytes{0};
    for (const auto& [key, record] : candidate_anchors) {
        if (record.serialized_size >
            std::numeric_limits<uint64_t>::max() - removed_anchor_bytes) {
            return false;
        }
        removed_anchor_bytes += record.serialized_size;
    }
    if (candidate_anchors.size() > state.candidate_anchor_count ||
        removed_anchor_bytes > state.candidate_anchor_bytes) {
        return false;
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
    state.candidate_anchor_count -= candidate_anchors.size();
    state.candidate_anchor_bytes -= removed_anchor_bytes;
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
    for (const auto& [key, record] : candidate_anchors) batch.Erase(key);
    batch.Write(DB_STATE, state);
    m_db.WriteBatch(batch, sync);
    return true;
}

bool ChildChainDB::WriteChildReorganization(
    const chainregistry::MainHeaderChain& main_headers,
    const chainregistry::DepositImportState& imports,
    std::span<const ChildChainDBDisconnect> disconnected_blocks,
    std::span<const ChildChainDBConnect> connected_blocks,
    bool sync)
{
    ChildChainDBState state;
    if ((disconnected_blocks.empty() && connected_blocks.empty()) ||
        !m_db.Read(DB_STATE, state) ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        state.safe_halt || imports.IsSafeHalted() ||
        main_headers.Params().hashGenesisBlock != m_main_genesis_hash ||
        !main_headers.IsInitialized() ||
        main_headers.Tip()->GetBlockHash() != state.main_tip) {
        return false;
    }

    struct DemotedBlock {
        uint256 hash;
        ChildCandidateRecord candidate;
        ChildBmmAnchorRecord primary_anchor;
        CandidateAnchorKey candidate_anchor_key;
        ChildCandidateBmmAnchorRecord candidate_anchor;
    };
    struct PromotedBlock {
        uint256 hash;
        ChildCandidateRecord candidate;
        CandidateAnchorKey candidate_anchor_key;
        ChildCandidateBmmAnchorRecord candidate_anchor;
        ChildBmmAnchorRecord primary_anchor;
    };

    std::vector<DemotedBlock> demoted;
    demoted.reserve(disconnected_blocks.size());
    std::set<uint256> child_hashes;
    std::set<chainregistry::DepositId> disconnected_imports;
    uint256 fork_hash{state.child_tip};
    uint32_t fork_height{state.child_height};
    uint64_t demoted_bytes{0};
    uint64_t demoted_anchor_bytes{0};
    CoinTransition coin_transition;
    for (const auto& disconnected : disconnected_blocks) {
        const uint256 hash{disconnected.block.GetHash()};
        StoredChildBlock stored_block;
        chainregistry::ReferenceChildBlockUndo stored_undo;
        ChildBmmAnchorRecord primary_anchor;
        if (!child_hashes.insert(hash).second || hash != fork_hash ||
            fork_height == 0 ||
            !m_db.Read(BlockKey{DB_BLOCK, hash}, stored_block) ||
            !m_db.Read(UndoKey{DB_UNDO, hash}, stored_undo) ||
            !m_db.Read(AnchorKey{DB_BMM_ANCHOR, hash}, primary_anchor) ||
            !BlocksEqual(stored_block.block, disconnected.block) ||
            stored_undo != disconnected.undo ||
            disconnected.undo.block_height != fork_height ||
            disconnected.undo.block_hash != hash ||
            disconnected.undo.parent_hash !=
                disconnected.block.hashPrevBlock ||
            primary_anchor.child_block_hash != hash ||
            !IsValidStoredAnchor(
                primary_anchor,
                main_headers,
                m_child_chain,
                /*allow_inactive=*/false) ||
            m_db.Exists(CandidateKey{DB_SIDE_CANDIDATE, hash})) {
            return false;
        }
        ChildCandidateRecord candidate{
            .block = disconnected.block,
            .undo = disconnected.undo,
        };
        candidate.serialized_size = GetSerializeSize(candidate);
        const uint256 main_block_hash{
            primary_anchor.proof.block_header.GetHash()};
        const CandidateAnchorKey candidate_anchor_key{
            DB_CANDIDATE_BMM_ANCHOR, main_block_hash};
        const uint64_t anchor_size{GetSerializeSize(primary_anchor.proof)};
        ChildCandidateBmmAnchorRecord candidate_anchor{
            .child_block_hash = hash,
            .serialized_size = anchor_size,
            .proof = primary_anchor.proof,
        };
        if (!IsValidStoredCandidate(candidate, hash) ||
            !IsValidStoredCandidateAnchor(
                candidate_anchor, main_headers, m_child_chain) ||
            m_db.Exists(candidate_anchor_key) ||
            candidate.serialized_size >
                std::numeric_limits<uint64_t>::max() - demoted_bytes ||
            anchor_size >
                std::numeric_limits<uint64_t>::max() -
                    demoted_anchor_bytes ||
            !ApplyDisconnectCoinTransition(
                *this,
                disconnected.block,
                disconnected.undo,
                coin_transition)) {
            return false;
        }
        demoted_bytes += candidate.serialized_size;
        demoted_anchor_bytes += anchor_size;
        for (const auto& deposit_id : disconnected.undo.imports.imports) {
            const auto stored{ReadImport(deposit_id)};
            if (!disconnected_imports.insert(deposit_id).second || !stored ||
                stored->child_block_hash != hash) {
                return false;
            }
        }
        fork_hash = disconnected.undo.parent_hash;
        --fork_height;
        demoted.push_back({
            .hash = hash,
            .candidate = std::move(candidate),
            .primary_anchor = std::move(primary_anchor),
            .candidate_anchor_key = candidate_anchor_key,
            .candidate_anchor = std::move(candidate_anchor),
        });
    }

    uint32_t previous_anchor_height{0};
    if (fork_height > 0) {
        const auto fork_anchor{ReadBmmAnchor(fork_hash)};
        if (!fork_anchor) return false;
        previous_anchor_height = fork_anchor->proof.block_height;
    } else if (fork_hash != m_child_genesis_hash) {
        return false;
    }

    std::vector<PromotedBlock> promoted;
    promoted.reserve(connected_blocks.size());
    std::set<chainregistry::DepositId> connected_imports;
    uint256 expected_parent{fork_hash};
    uint32_t expected_height{fork_height};
    uint64_t promoted_bytes{0};
    uint64_t promoted_anchor_bytes{0};
    for (const auto& connected : connected_blocks) {
        const uint256 hash{connected.block.GetHash()};
        if (expected_height == std::numeric_limits<uint32_t>::max()) {
            return false;
        }
        ++expected_height;
        const CandidateKey candidate_key{DB_SIDE_CANDIDATE, hash};
        ChildCandidateRecord candidate;
        if (!child_hashes.insert(hash).second ||
            connected.block.hashPrevBlock != expected_parent ||
            connected.undo.block_hash != hash ||
            connected.undo.parent_hash != expected_parent ||
            connected.undo.block_height != expected_height ||
            !m_db.Read(candidate_key, candidate) ||
            !IsValidStoredCandidate(candidate, hash) ||
            !BlocksEqual(candidate.block, connected.block) ||
            candidate.undo != connected.undo ||
            connected.primary_anchor.block_height <=
                previous_anchor_height ||
            m_db.Exists(BlockKey{DB_BLOCK, hash}) ||
            m_db.Exists(UndoKey{DB_UNDO, hash}) ||
            m_db.Exists(AnchorKey{DB_BMM_ANCHOR, hash})) {
            return false;
        }
        const auto authenticated{main_headers.AuthenticateBmmAnchor(
            connected.primary_anchor,
            m_child_chain,
            /*minimum_confirmations=*/1)};
        if (!authenticated.IsValid() || !authenticated.proof.anchor ||
            authenticated.proof.anchor->child_block_hash != hash) {
            return false;
        }
        const uint256 main_block_hash{
            connected.primary_anchor.block_header.GetHash()};
        const CandidateAnchorKey candidate_anchor_key{
            DB_CANDIDATE_BMM_ANCHOR, main_block_hash};
        ChildCandidateBmmAnchorRecord candidate_anchor;
        if (!m_db.Read(candidate_anchor_key, candidate_anchor) ||
            candidate_anchor.child_block_hash != hash ||
            BmmProofHash(candidate_anchor.proof) !=
                BmmProofHash(connected.primary_anchor) ||
            !IsValidStoredCandidateAnchor(
                candidate_anchor, main_headers, m_child_chain) ||
            candidate.serialized_size >
                std::numeric_limits<uint64_t>::max() - promoted_bytes ||
            candidate_anchor.serialized_size >
                std::numeric_limits<uint64_t>::max() -
                    promoted_anchor_bytes ||
            !ApplyConnectCoinTransition(
                *this,
                connected.block,
                connected.undo,
                coin_transition)) {
            return false;
        }
        promoted_bytes += candidate.serialized_size;
        promoted_anchor_bytes += candidate_anchor.serialized_size;
        for (const auto& deposit_id : connected.undo.imports.imports) {
            const auto* imported{imports.Find(deposit_id)};
            if (!connected_imports.insert(deposit_id).second || !imported ||
                imported->child_block_hash != hash ||
                imported->child_block_height != expected_height ||
                (m_db.Exists(ImportKey{DB_IMPORT, deposit_id}) &&
                 !disconnected_imports.contains(deposit_id))) {
                return false;
            }
        }
        previous_anchor_height = connected.primary_anchor.block_height;
        expected_parent = hash;
        promoted.push_back({
            .hash = hash,
            .candidate = std::move(candidate),
            .candidate_anchor_key = candidate_anchor_key,
            .candidate_anchor = std::move(candidate_anchor),
            .primary_anchor = {
                .child_block_hash = hash,
                .proof = connected.primary_anchor,
            },
        });
    }

    if (promoted.size() > state.side_candidate_count ||
        promoted_bytes > state.side_candidate_bytes ||
        promoted.size() > state.candidate_anchor_count ||
        promoted_anchor_bytes > state.candidate_anchor_bytes ||
        demoted.size() >
            MAX_CHILD_SIDE_CANDIDATES -
                (state.side_candidate_count - promoted.size()) ||
        demoted_bytes >
            MAX_CHILD_SIDE_CANDIDATE_BYTES -
                (state.side_candidate_bytes - promoted_bytes) ||
        demoted.size() >
            MAX_CHILD_CANDIDATE_BMM_ANCHORS -
                (state.candidate_anchor_count - promoted.size()) ||
        demoted_anchor_bytes >
            MAX_CHILD_CANDIDATE_BMM_BYTES -
                (state.candidate_anchor_bytes - promoted_anchor_bytes) ||
        disconnected_imports.size() > state.import_count ||
        imports.Size() !=
            state.import_count - disconnected_imports.size() +
                connected_imports.size() ||
        !ImportsMatchMainChain(main_headers, imports)) {
        return false;
    }

    if ((coin_transition.count_delta < 0 &&
         static_cast<uint64_t>(-coin_transition.count_delta) >
             state.coin_count) ||
        (coin_transition.count_delta > 0 &&
         static_cast<uint64_t>(coin_transition.count_delta) >
             std::numeric_limits<uint64_t>::max() - state.coin_count)) {
        return false;
    }

    state.child_tip = expected_parent;
    state.child_height = expected_height;
    state.anchor_count = expected_height;
    state.side_candidate_count =
        state.side_candidate_count - promoted.size() + demoted.size();
    state.side_candidate_bytes =
        state.side_candidate_bytes - promoted_bytes + demoted_bytes;
    state.candidate_anchor_count =
        state.candidate_anchor_count - promoted.size() + demoted.size();
    state.candidate_anchor_bytes =
        state.candidate_anchor_bytes - promoted_anchor_bytes +
        demoted_anchor_bytes;
    state.import_count = imports.Size();
    const bool subtract_coins{coin_transition.count_delta < 0};
    const uint64_t coin_magnitude{subtract_coins
        ? static_cast<uint64_t>(-coin_transition.count_delta)
        : static_cast<uint64_t>(coin_transition.count_delta)};
    state.coin_count = subtract_coins
        ? state.coin_count - coin_magnitude
        : state.coin_count + coin_magnitude;

    CDBBatch batch{m_db};
    for (const auto& deposit_id : disconnected_imports) {
        batch.Erase(ImportKey{DB_IMPORT, deposit_id});
    }
    for (const auto& deposit_id : connected_imports) {
        batch.Write(ImportKey{DB_IMPORT, deposit_id}, *imports.Find(deposit_id));
    }
    for (const auto& [outpoint, coin] : coin_transition.changes) {
        if (coin) {
            batch.Write(CoinKey{DB_COIN, outpoint}, *coin);
        } else {
            batch.Erase(CoinKey{DB_COIN, outpoint});
        }
    }
    for (const auto& entry : demoted) {
        batch.Erase(BlockKey{DB_BLOCK, entry.hash});
        batch.Erase(UndoKey{DB_UNDO, entry.hash});
        batch.Erase(AnchorKey{DB_BMM_ANCHOR, entry.hash});
        batch.Write(
            CandidateKey{DB_SIDE_CANDIDATE, entry.hash}, entry.candidate);
        batch.Write(entry.candidate_anchor_key, entry.candidate_anchor);
    }
    for (const auto& entry : promoted) {
        batch.Erase(CandidateKey{DB_SIDE_CANDIDATE, entry.hash});
        batch.Erase(entry.candidate_anchor_key);
        batch.Write(
            BlockKey{DB_BLOCK, entry.hash},
            StoredChildBlock{entry.candidate.block});
        batch.Write(UndoKey{DB_UNDO, entry.hash}, entry.candidate.undo);
        batch.Write(
            AnchorKey{DB_BMM_ANCHOR, entry.hash}, entry.primary_anchor);
    }
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

namespace {

class ChildChainCoinsCursor final : public CCoinsViewCursor
{
public:
    ChildChainCoinsCursor(CDBIterator* cursor, const uint256& best_block)
        : CCoinsViewCursor{best_block}, m_cursor{cursor}
    {
        m_cursor->Seek(CoinKey{DB_COIN, {}});
        ReadKey();
    }

    bool GetKey(COutPoint& key) const override
    {
        if (!Valid()) return false;
        key = m_key.second;
        return true;
    }

    bool GetValue(Coin& coin) const override
    {
        return Valid() && m_cursor->GetValue(coin);
    }

    bool Valid() const override { return m_valid; }

    void Next() override
    {
        if (!m_valid) return;
        m_cursor->Next();
        ReadKey();
    }

private:
    void ReadKey()
    {
        m_valid = m_cursor->Valid() && m_cursor->GetKey(m_key) &&
                  m_key.first == DB_COIN;
    }

    std::unique_ptr<CDBIterator> m_cursor;
    CoinKey m_key;
    bool m_valid{false};
};

} // namespace

std::unique_ptr<CCoinsViewCursor> ChildChainDB::Cursor() const
{
    return std::make_unique<ChildChainCoinsCursor>(
        const_cast<CDBWrapper&>(m_db).NewIterator(), GetBestBlock());
}

size_t ChildChainDB::EstimateSize() const
{
    return m_db.EstimateSize(DB_COIN, uint8_t{DB_COIN + 1});
}

bool ChildChainDB::ReadBlock(const uint256& child_block_hash,
                             CBlock& block) const
{
    StoredChildBlock stored;
    if (m_db.Read(BlockKey{DB_BLOCK, child_block_hash}, stored)) {
        block = std::move(stored.block);
        return true;
    }
    const auto candidate{ReadSideCandidate(child_block_hash)};
    if (!candidate) return false;
    block = candidate->block;
    return true;
}

std::optional<ChildCandidateRecord> ChildChainDB::ReadSideCandidate(
    const uint256& child_block_hash) const
{
    ChildCandidateRecord record;
    if (!m_db.Read(
            CandidateKey{DB_SIDE_CANDIDATE, child_block_hash}, record)) {
        return std::nullopt;
    }
    return record;
}

std::optional<std::vector<chainregistry::ChildForkCandidate>>
ChildChainDB::ReadForkCandidates(
    const chainregistry::MainHeaderChain& main_headers) const
{
    ChildChainDBState state;
    if (!m_db.Read(DB_STATE, state) ||
        !ValidConfiguration(state,
                            m_child_chain,
                            m_main_genesis_hash,
                            m_minimum_confirmations,
                            m_child_genesis_hash) ||
        main_headers.Params().hashGenesisBlock != m_main_genesis_hash ||
        !main_headers.IsInitialized() ||
        main_headers.Tip()->GetBlockHash() != state.main_tip) {
        return std::nullopt;
    }

    std::map<uint256, chainregistry::ChildForkCandidate> candidates;
    std::unique_ptr<CDBIterator> cursor{
        const_cast<CDBWrapper&>(m_db).NewIterator()};
    cursor->Seek(BlockKey{DB_BLOCK, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) return std::nullopt;
        if (prefix != DB_BLOCK) break;
        BlockKey key;
        StoredChildBlock stored;
        if (!cursor->GetKey(key) || !cursor->GetValue(stored) ||
            stored.block.GetHash() != key.second ||
            !candidates.emplace(
                key.second,
                chainregistry::ChildForkCandidate{
                    .block_hash = key.second,
                    .parent_hash = stored.block.hashPrevBlock,
                    .anchors = {},
                }).second) {
            return std::nullopt;
        }
        cursor->Next();
    }

    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(CandidateKey{DB_SIDE_CANDIDATE, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) return std::nullopt;
        if (prefix != DB_SIDE_CANDIDATE) break;
        CandidateKey key;
        ChildCandidateRecord stored;
        if (!cursor->GetKey(key) || !cursor->GetValue(stored) ||
            !IsValidStoredCandidate(stored, key.second) ||
            !candidates.emplace(
                key.second,
                chainregistry::ChildForkCandidate{
                    .block_hash = key.second,
                    .parent_hash = stored.block.hashPrevBlock,
                    .anchors = {},
                }).second) {
            return std::nullopt;
        }
        cursor->Next();
    }
    if (candidates.size() != state.child_height + state.side_candidate_count) {
        return std::nullopt;
    }

    const auto add_anchor = [&](const uint256& child_block_hash,
                                const chainregistry::BmmAnchorProof& proof)
        -> bool {
        auto candidate{candidates.find(child_block_hash)};
        if (candidate == candidates.end()) return false;
        const uint256 main_block_hash{proof.block_header.GetHash()};
        const auto status{main_headers.GetStatus(main_block_hash)};
        if (!status.known ||
            status.height != static_cast<int>(proof.block_height)) {
            return false;
        }
        if (!status.active) return true;
        const CBlockIndex* entry{main_headers.Find(main_block_hash)};
        if (!entry) return false;
        const arith_uint256 work{GetBlockProof(*entry)};
        if (work == 0) return false;
        candidate->second.anchors.push_back({
            .main_block_hash = main_block_hash,
            .main_height = proof.block_height,
            .work = work,
        });
        return true;
    };

    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(AnchorKey{DB_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) return std::nullopt;
        if (prefix != DB_BMM_ANCHOR) break;
        AnchorKey key;
        ChildBmmAnchorRecord record;
        if (!cursor->GetKey(key) || !cursor->GetValue(record) ||
            key.second != record.child_block_hash ||
            !IsValidStoredAnchor(
                record,
                main_headers,
                m_child_chain,
                /*allow_inactive=*/true) ||
            !add_anchor(record.child_block_hash, record.proof)) {
            return std::nullopt;
        }
        cursor->Next();
    }

    cursor.reset(const_cast<CDBWrapper&>(m_db).NewIterator());
    cursor->Seek(CandidateAnchorKey{DB_CANDIDATE_BMM_ANCHOR, {}});
    while (cursor->Valid()) {
        uint8_t prefix;
        if (!cursor->GetKey(prefix)) return std::nullopt;
        if (prefix != DB_CANDIDATE_BMM_ANCHOR) break;
        CandidateAnchorKey key;
        ChildCandidateBmmAnchorRecord record;
        if (!cursor->GetKey(key) || !cursor->GetValue(record) ||
            key.second != record.proof.block_header.GetHash() ||
            !IsValidStoredCandidateAnchor(
                record, main_headers, m_child_chain) ||
            !add_anchor(record.child_block_hash, record.proof)) {
            return std::nullopt;
        }
        cursor->Next();
    }

    std::vector<chainregistry::ChildForkCandidate> result;
    result.reserve(candidates.size());
    for (auto& [hash, candidate] : candidates) {
        result.push_back(std::move(candidate));
    }
    return result;
}

bool ChildChainDB::ReadUndo(const uint256& child_block_hash,
                            chainregistry::ReferenceChildBlockUndo& undo) const
{
    if (m_db.Read(UndoKey{DB_UNDO, child_block_hash}, undo)) return true;
    const auto candidate{ReadSideCandidate(child_block_hash)};
    if (!candidate) return false;
    undo = candidate->undo;
    return true;
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

std::optional<ChildPendingBmmAnchorRecord>
ChildChainDB::ReadPendingBmmAnchor(const uint256& main_block_hash) const
{
    ChildPendingBmmAnchorRecord record;
    if (!m_db.Read(
            PendingAnchorKey{DB_PENDING_BMM_ANCHOR, main_block_hash}, record)) {
        return std::nullopt;
    }
    return record;
}

std::optional<ChildCandidateBmmAnchorRecord>
ChildChainDB::ReadCandidateBmmAnchor(const uint256& main_block_hash) const
{
    ChildCandidateBmmAnchorRecord record;
    if (!m_db.Read(
            CandidateAnchorKey{DB_CANDIDATE_BMM_ANCHOR, main_block_hash},
            record)) {
        return std::nullopt;
    }
    return record;
}

} // namespace node
