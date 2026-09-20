// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/chainregistry.h>

#include <hash.h>
#include <primitives/block.h>
#include <streams.h>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace chainregistry {
namespace {

RegistryTransitionResult TransitionError(RegistryError error,
                                         std::optional<ChainId> chain_id = std::nullopt,
                                         TxOperationError tx_error = TxOperationError::NONE,
                                         OperationParseError parse_error = OperationParseError::NONE)
{
    RegistryTransitionResult result;
    result.error = error;
    result.tx_error = tx_error;
    result.parse_error = parse_error;
    result.chain_id = std::move(chain_id);
    return result;
}

uint256 FinalizeRegistryRoot(uint64_t leaf_count, const uint256& tree_root)
{
    auto hasher{TaggedHash(std::string{REGISTRY_ROOT_HASH_TAG})};
    hasher << leaf_count << tree_root;
    return hasher.GetSHA256();
}

size_t RegistryProofDepth(uint64_t leaf_count)
{
    size_t depth{0};
    while (leaf_count > 1) {
        leaf_count = (leaf_count + 1) / 2;
        ++depth;
    }
    return depth;
}

RegistryInclusionProof BuildRegistryInclusionProof(std::vector<uint256> level, uint64_t leaf_index)
{
    RegistryInclusionProof proof;
    proof.leaf_count = level.size();
    proof.leaf_index = leaf_index;
    uint64_t index{leaf_index};
    while (level.size() > 1) {
        const size_t sibling_index{static_cast<size_t>(index ^ 1)};
        proof.siblings.push_back(sibling_index < level.size() ? level[sibling_index] : level[index]);
        if (level.size() % 2 != 0) level.push_back(level.back());
        for (size_t i{0}; i < level.size(); i += 2) {
            level[i / 2] = ComputeRegistryNodeHash(level[i], level[i + 1]);
        }
        level.resize(level.size() / 2);
        index /= 2;
    }
    return proof;
}

} // namespace

uint256 ComputeRegistryLeafHash(const ChainRecord& record)
{
    auto hasher{TaggedHash(std::string{REGISTRY_LEAF_HASH_TAG})};
    hasher << record;
    return hasher.GetSHA256();
}

RecordValidationError ValidateChainRecord(const ChainRecord& record)
{
    if (record.record_version != CHAIN_RECORD_VERSION) return RecordValidationError::UNSUPPORTED_VERSION;
    if (record.chain_id.IsNull()) return RecordValidationError::NULL_CHAIN_ID;
    if (record.manifest_hash.IsNull()) return RecordValidationError::NULL_MANIFEST_HASH;
    if (record.template_id == 0) return RecordValidationError::INVALID_TEMPLATE_ID;
    if (record.template_version == 0) return RecordValidationError::INVALID_TEMPLATE_VERSION;
    if (record.control_outpoint.IsNull()) return RecordValidationError::NULL_CONTROL_OUTPOINT;
    if (record.metadata_hash.IsNull()) return RecordValidationError::NULL_METADATA_HASH;
    if (record.updated_height < record.registered_height) return RecordValidationError::INVALID_HEIGHTS;
    if (record.status == ChainStatus::ACTIVE) {
        if (record.retired_height != 0) return RecordValidationError::INVALID_HEIGHTS;
    } else if (record.status == ChainStatus::RETIRED) {
        if (record.retired_height == 0 || record.retired_height != record.updated_height) {
            return RecordValidationError::INVALID_HEIGHTS;
        }
    } else {
        return RecordValidationError::UNKNOWN_STATUS;
    }
    return RecordValidationError::NONE;
}

uint256 ComputeRegistryNodeHash(const uint256& left, const uint256& right)
{
    auto hasher{TaggedHash(std::string{REGISTRY_NODE_HASH_TAG})};
    hasher << left << right;
    return hasher.GetSHA256();
}

uint256 ComputeRegistryRootFromLeaves(std::vector<uint256> ordered_leaves)
{
    const uint64_t record_count{ordered_leaves.size()};
    while (ordered_leaves.size() > 1) {
        if (ordered_leaves.size() % 2 != 0) ordered_leaves.push_back(ordered_leaves.back());
        for (size_t i{0}; i < ordered_leaves.size(); i += 2) {
            ordered_leaves[i / 2] = ComputeRegistryNodeHash(ordered_leaves[i], ordered_leaves[i + 1]);
        }
        ordered_leaves.resize(ordered_leaves.size() / 2);
    }

    const uint256 tree_root{ordered_leaves.empty() ? uint256{} : ordered_leaves.front()};
    return FinalizeRegistryRoot(record_count, tree_root);
}

bool VerifyRegistryInclusion(const ChainRecord& record,
                             const RegistryInclusionProof& proof,
                             const uint256& expected_root)
{
    if (proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count) return false;
    if (proof.siblings.size() != RegistryProofDepth(proof.leaf_count)) return false;

    uint256 current{ComputeRegistryLeafHash(record)};
    uint64_t index{proof.leaf_index};
    uint64_t width{proof.leaf_count};
    for (const uint256& sibling : proof.siblings) {
        if ((index & 1U) == 0) {
            if (index + 1 >= width && sibling != current) return false;
            current = ComputeRegistryNodeHash(current, sibling);
        } else {
            current = ComputeRegistryNodeHash(sibling, current);
        }
        index /= 2;
        width = (width + 1) / 2;
    }
    return FinalizeRegistryRoot(proof.leaf_count, current) == expected_root;
}

bool VerifyRegistryNonInclusion(const ChainId& chain_id,
                                const RegistryNonInclusionProof& proof,
                                const uint256& expected_root)
{
    if (proof.leaf_count == 0) {
        return !proof.has_left && !proof.has_right &&
               expected_root == ComputeRegistryRootFromLeaves({});
    }
    if (!proof.has_left && !proof.has_right) return false;

    if (proof.has_left) {
        if (proof.left.proof.leaf_count != proof.leaf_count ||
            !(proof.left.record.chain_id < chain_id) ||
            !VerifyRegistryInclusion(proof.left.record, proof.left.proof, expected_root)) {
            return false;
        }
    }
    if (proof.has_right) {
        if (proof.right.proof.leaf_count != proof.leaf_count ||
            !(chain_id < proof.right.record.chain_id) ||
            !VerifyRegistryInclusion(proof.right.record, proof.right.proof, expected_root)) {
            return false;
        }
    }

    if (proof.has_left && proof.has_right) {
        return proof.left.proof.leaf_index + 1 == proof.right.proof.leaf_index;
    }
    if (proof.has_left) return proof.left.proof.leaf_index + 1 == proof.leaf_count;
    return proof.right.proof.leaf_index == 0;
}

CScript BuildRegistryCommitment(const uint256& registry_root)
{
    std::vector<unsigned char> data{REGISTRY_COMMITMENT_MAGIC.begin(), REGISTRY_COMMITMENT_MAGIC.end()};
    VectorWriter writer{data, data.size()};
    writer << REGISTRY_COMMITMENT_VERSION << registry_root;
    return CScript{} << OP_RETURN << data;
}

CommitmentParseResult ParseRegistryCommitment(const CScript& script)
{
    auto cursor{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(cursor, opcode) || opcode != OP_RETURN) {
        return {CommitmentParseError::NOT_COMMITMENT, std::nullopt};
    }
    if (!script.GetOp(cursor, opcode, data)) {
        return {CommitmentParseError::NOT_COMMITMENT, std::nullopt};
    }
    if (data.size() < REGISTRY_COMMITMENT_MAGIC.size() ||
        !std::equal(REGISTRY_COMMITMENT_MAGIC.begin(), REGISTRY_COMMITMENT_MAGIC.end(), data.begin())) {
        return {CommitmentParseError::NOT_COMMITMENT, std::nullopt};
    }
    if (opcode > OP_PUSHDATA4 || cursor != script.end()) {
        return {CommitmentParseError::MALFORMED_SCRIPT, std::nullopt};
    }
    if (script != (CScript{} << OP_RETURN << data)) {
        return {CommitmentParseError::NON_CANONICAL_SCRIPT, std::nullopt};
    }
    constexpr size_t EXPECTED_SIZE{REGISTRY_COMMITMENT_MAGIC.size() + sizeof(uint8_t) + uint256::size()};
    if (data.size() != EXPECTED_SIZE) {
        return {CommitmentParseError::INVALID_LENGTH, std::nullopt};
    }

    SpanReader reader{std::span{data}.subspan(REGISTRY_COMMITMENT_MAGIC.size())};
    uint8_t version;
    uint256 root;
    reader >> version >> root;
    if (version != REGISTRY_COMMITMENT_VERSION) {
        return {CommitmentParseError::UNSUPPORTED_VERSION, std::nullopt};
    }
    return {CommitmentParseError::NONE, root};
}

CommitmentTxResult ExtractRegistryCommitment(const CTransaction& tx)
{
    CommitmentTxResult result;
    for (size_t output_index{0}; output_index < tx.vout.size(); ++output_index) {
        const auto parsed{ParseRegistryCommitment(tx.vout[output_index].scriptPubKey)};
        if (parsed.error == CommitmentParseError::NOT_COMMITMENT) continue;
        if (!parsed) {
            result.error = CommitmentTxError::INVALID_COMMITMENT;
            result.parse_error = parsed.error;
            result.output_index.reset();
            result.root.reset();
            return result;
        }
        if (result.root) {
            result.error = CommitmentTxError::MULTIPLE_COMMITMENTS;
            result.output_index.reset();
            result.root.reset();
            return result;
        }
        if (tx.vout[output_index].nValue != 0) {
            result.error = CommitmentTxError::NONZERO_VALUE;
            return result;
        }
        result.output_index = static_cast<uint32_t>(output_index);
        result.root = *parsed.root;
    }
    return result;
}

const ChainRecord* ChainRegistry::Find(const ChainId& chain_id) const
{
    const auto it{m_records.find(chain_id)};
    return it == m_records.end() ? nullptr : &it->second;
}

RegistryLoadResult ChainRegistry::LoadRecords(std::vector<ChainRecord> records)
{
    std::map<ChainId, ChainRecord> loaded_records;
    std::map<COutPoint, ChainId> loaded_controls;
    for (auto& record : records) {
        const RecordValidationError record_error{ValidateChainRecord(record)};
        if (record_error != RecordValidationError::NONE) {
            RegistryLoadResult result;
            result.error = RegistryLoadError::INVALID_RECORD;
            result.record_error = record_error;
            result.chain_id = record.chain_id;
            return result;
        }
        const ChainId chain_id{record.chain_id};
        const auto [_, inserted]{loaded_records.emplace(chain_id, std::move(record))};
        if (!inserted) {
            RegistryLoadResult result;
            result.error = RegistryLoadError::DUPLICATE_CHAIN_ID;
            result.chain_id = chain_id;
            return result;
        }
        const ChainRecord& stored{loaded_records.at(chain_id)};
        if (stored.status == ChainStatus::ACTIVE &&
            !loaded_controls.emplace(stored.control_outpoint, chain_id).second) {
            RegistryLoadResult result;
            result.error = RegistryLoadError::DUPLICATE_ACTIVE_CONTROL;
            result.chain_id = chain_id;
            return result;
        }
    }

    m_records = std::move(loaded_records);
    m_control_index = std::move(loaded_controls);
    return {};
}

uint256 ChainRegistry::ComputeRoot() const
{
    std::vector<uint256> leaves;
    leaves.reserve(m_records.size());
    for (const auto& entry : m_records) {
        leaves.push_back(ComputeRegistryLeafHash(entry.second));
    }
    return ComputeRegistryRootFromLeaves(std::move(leaves));
}

std::optional<RegistryInclusionProof> ChainRegistry::GetInclusionProof(const ChainId& chain_id) const
{
    const auto target{m_records.find(chain_id)};
    if (target == m_records.end()) return std::nullopt;

    std::vector<uint256> leaves;
    leaves.reserve(m_records.size());
    uint64_t target_index{0};
    uint64_t index{0};
    for (const auto& entry : m_records) {
        if (entry.first == chain_id) target_index = index;
        leaves.push_back(ComputeRegistryLeafHash(entry.second));
        ++index;
    }
    return BuildRegistryInclusionProof(std::move(leaves), target_index);
}

std::optional<RegistryNonInclusionProof> ChainRegistry::GetNonInclusionProof(const ChainId& chain_id) const
{
    const auto right_it{m_records.lower_bound(chain_id)};
    if (right_it != m_records.end() && right_it->first == chain_id) return std::nullopt;

    RegistryNonInclusionProof proof;
    proof.leaf_count = m_records.size();
    if (right_it != m_records.end()) {
        proof.has_right = true;
        proof.right.record = right_it->second;
        proof.right.proof = *GetInclusionProof(right_it->first);
    }
    if (right_it != m_records.begin()) {
        const auto left_it{std::prev(right_it)};
        proof.has_left = true;
        proof.left.record = left_it->second;
        proof.left.proof = *GetInclusionProof(left_it->first);
    }
    return proof;
}

RegistryTransitionResult ChainRegistry::ApplyTransaction(const CTransaction& tx,
                                                         uint32_t height,
                                                         const uint256& main_genesis_hash,
                                                         CAmount minimum_registration_burn)
{
    const auto extracted{ExtractTransactionOperation(tx, minimum_registration_burn)};
    if (!extracted.IsValid()) {
        return TransitionError(RegistryError::INVALID_TRANSACTION_OPERATION,
                               std::nullopt,
                               extracted.error,
                               extracted.parse_error);
    }

    std::map<ChainId, size_t> spent_controls;
    for (const auto& input : tx.vin) {
        if (const auto it{m_control_index.find(input.prevout)}; it != m_control_index.end()) {
            ++spent_controls[it->second];
        }
    }

    if (!extracted.operation) {
        if (!spent_controls.empty()) return TransitionError(RegistryError::CONTROL_SPEND_WITHOUT_OPERATION);
        return {};
    }

    const RegistryOperation& operation{extracted.operation->operation};
    if (const auto* registration{std::get_if<RegisterChain>(&operation)}) {
        if (!spent_controls.empty()) return TransitionError(RegistryError::WRONG_CONTROL_OUTPOINT);

        const COutPoint& anchor{tx.vin[registration->anchor_input].prevout};
        const ChainSpecHash spec_hash{ComputeChainSpecHash(registration->manifest.spec)};
        const ChainId chain_id{DeriveChainId(main_genesis_hash, anchor, spec_hash)};
        if (m_records.contains(chain_id)) {
            return TransitionError(RegistryError::DUPLICATE_CHAIN_ID, chain_id);
        }

        ChainRecord record{
            .record_version = CHAIN_RECORD_VERSION,
            .chain_id = chain_id,
            .manifest_hash = ComputeManifestHash(registration->manifest),
            .template_id = registration->manifest.spec.template_id,
            .template_version = registration->manifest.spec.template_version,
            .control_outpoint = COutPoint{tx.GetHash(), registration->control_output},
            .metadata_hash = registration->manifest.initial_metadata_hash,
            .status = ChainStatus::ACTIVE,
            .registered_height = height,
            .updated_height = height,
            .retired_height = 0,
        };
        m_control_index.emplace(record.control_outpoint, chain_id);
        m_records.emplace(chain_id, record);
        return {
            .chain_id = chain_id,
            .undo = RegistryUndo{.chain_id = chain_id, .had_previous = false, .previous = {}},
        };
    }

    const ChainId& chain_id{std::get_if<UpdateChain>(&operation)
                                ? std::get<UpdateChain>(operation).chain_id
                                : std::get<RetireChain>(operation).chain_id};
    const auto record_it{m_records.find(chain_id)};
    if (record_it == m_records.end()) {
        return TransitionError(RegistryError::UNKNOWN_CHAIN, chain_id);
    }
    if (record_it->second.status == ChainStatus::RETIRED) {
        return TransitionError(RegistryError::RETIRED_CHAIN, chain_id);
    }
    if (spent_controls.size() > 1 ||
        (spent_controls.size() == 1 && spent_controls.begin()->second > 1)) {
        return TransitionError(RegistryError::MULTIPLE_CONTROL_OUTPOINTS, chain_id);
    }
    if (spent_controls.size() != 1 || spent_controls.begin()->first != chain_id) {
        return TransitionError(RegistryError::WRONG_CONTROL_OUTPOINT, chain_id);
    }

    const RegistryUndo undo{
        .chain_id = chain_id,
        .had_previous = true,
        .previous = record_it->second,
    };
    m_control_index.erase(record_it->second.control_outpoint);

    if (const auto* update{std::get_if<UpdateChain>(&operation)}) {
        record_it->second.control_outpoint = COutPoint{tx.GetHash(), update->control_output};
        record_it->second.metadata_hash = update->metadata_hash;
        record_it->second.updated_height = height;
        m_control_index.emplace(record_it->second.control_outpoint, chain_id);
    } else {
        record_it->second.status = ChainStatus::RETIRED;
        record_it->second.updated_height = height;
        record_it->second.retired_height = height;
    }

    return {.chain_id = chain_id, .undo = undo};
}

bool ChainRegistry::Undo(const RegistryUndo& undo)
{
    const auto current{m_records.find(undo.chain_id)};
    if (current == m_records.end()) return false;
    if (undo.had_previous && undo.previous.chain_id != undo.chain_id) return false;
    if (undo.had_previous && undo.previous.status == ChainStatus::ACTIVE) {
        const auto existing{m_control_index.find(undo.previous.control_outpoint)};
        if (existing != m_control_index.end() && existing->second != undo.chain_id) return false;
    }
    if (current->second.status == ChainStatus::ACTIVE) {
        m_control_index.erase(current->second.control_outpoint);
    }

    if (!undo.had_previous) {
        m_records.erase(current);
        return true;
    }
    current->second = undo.previous;
    if (undo.previous.status == ChainStatus::ACTIVE) {
        const auto [_, inserted]{m_control_index.emplace(undo.previous.control_outpoint, undo.chain_id)};
        if (!inserted) return false;
    }
    return true;
}

bool ChainRegistry::UndoBlock(const RegistryBlockUndo& undo)
{
    for (auto it{undo.operations.rbegin()}; it != undo.operations.rend(); ++it) {
        if (!Undo(*it)) return false;
    }
    return true;
}

RegistryBlockResult ChainRegistry::ApplyBlock(const CBlock& block,
                                              uint32_t height,
                                              const uint256& main_genesis_hash,
                                              CAmount minimum_registration_burn,
                                              size_t maximum_operations,
                                              CommitmentRequirement commitment_requirement)
{
    RegistryBlockResult result;
    if (block.vtx.empty()) {
        result.error = RegistryBlockError::EMPTY_BLOCK;
        return result;
    }
    if (!block.vtx.front()->IsCoinBase()) {
        result.error = RegistryBlockError::INVALID_COINBASE;
        result.tx_index = 0;
        return result;
    }

    const auto coinbase_operation{ExtractTransactionOperation(*block.vtx.front(), minimum_registration_burn)};
    if (!coinbase_operation.IsValid() || coinbase_operation.operation) {
        result.error = RegistryBlockError::COINBASE_OPERATION;
        result.transition.error = RegistryError::INVALID_TRANSACTION_OPERATION;
        result.transition.tx_error = coinbase_operation.error;
        result.transition.parse_error = coinbase_operation.parse_error;
        result.tx_index = 0;
        return result;
    }

    const auto commitment{ExtractRegistryCommitment(*block.vtx.front())};
    if (!commitment.IsValid()) {
        result.error = RegistryBlockError::INVALID_COINBASE_COMMITMENT;
        result.commitment_error = commitment.error;
        result.commitment_parse_error = commitment.parse_error;
        result.tx_index = 0;
        return result;
    }

    RegistryBlockUndo undo;
    const auto rollback{[&]() {
        if (!UndoBlock(undo)) result.error = RegistryBlockError::ROLLBACK_FAILED;
        result.undo.reset();
    }};

    for (size_t tx_index{1}; tx_index < block.vtx.size(); ++tx_index) {
        const auto non_coinbase_commitment{ExtractRegistryCommitment(*block.vtx[tx_index])};
        if (!non_coinbase_commitment.IsValid() || non_coinbase_commitment.root) {
            result.error = RegistryBlockError::NON_COINBASE_COMMITMENT;
            result.commitment_error = non_coinbase_commitment.error;
            result.commitment_parse_error = non_coinbase_commitment.parse_error;
            result.tx_index = tx_index;
            rollback();
            return result;
        }

        auto transition{ApplyTransaction(*block.vtx[tx_index], height, main_genesis_hash, minimum_registration_burn)};
        if (!transition.IsValid()) {
            result.error = RegistryBlockError::TRANSACTION_TRANSITION;
            result.tx_index = tx_index;
            result.transition = std::move(transition);
            rollback();
            return result;
        }
        if (!transition.HasOperation()) continue;
        if (undo.operations.size() >= maximum_operations) {
            result.error = RegistryBlockError::TOO_MANY_OPERATIONS;
            result.tx_index = tx_index;
            result.transition = std::move(transition);
            if (result.transition.undo) undo.operations.push_back(*result.transition.undo);
            rollback();
            return result;
        }
        undo.operations.push_back(*transition.undo);
    }

    result.computed_root = ComputeRoot();
    if (!commitment.root && commitment_requirement == CommitmentRequirement::REQUIRED) {
        result.error = RegistryBlockError::MISSING_COMMITMENT;
        rollback();
        return result;
    }
    if (commitment.root && *commitment.root != result.computed_root) {
        result.error = RegistryBlockError::COMMITMENT_MISMATCH;
        rollback();
        return result;
    }

    result.undo = std::move(undo);
    return result;
}

} // namespace chainregistry
