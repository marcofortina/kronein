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
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace chainregistry {
namespace {

RegistryTransitionResult TransitionError(RegistryError error,
                                         std::optional<ChainId> chain_id = std::nullopt,
                                         TxOperationError tx_error = TxOperationError::NONE,
                                         OperationParseError parse_error = OperationParseError::NONE,
                                         std::optional<DealerId> dealer_id = std::nullopt)
{
    RegistryTransitionResult result;
    result.error = error;
    result.tx_error = tx_error;
    result.parse_error = parse_error;
    result.chain_id = std::move(chain_id);
    result.dealer_id = std::move(dealer_id);
    return result;
}

uint256 FinalizeRegistryRoot(uint64_t leaf_count, const uint256& tree_root)
{
    auto hasher{TaggedHash(std::string{REGISTRY_ROOT_HASH_TAG})};
    hasher << leaf_count << tree_root;
    return hasher.GetSHA256();
}

uint256 ComputeDealerNodeHash(const uint256& left, const uint256& right)
{
    auto hasher{TaggedHash(std::string{DEALER_NODE_HASH_TAG})};
    hasher << left << right;
    return hasher.GetSHA256();
}

uint256 ComputeDealerRootFromLeaves(std::vector<uint256> ordered_leaves)
{
    const uint64_t dealer_count{ordered_leaves.size()};
    while (ordered_leaves.size() > 1) {
        if (ordered_leaves.size() % 2 != 0) ordered_leaves.push_back(ordered_leaves.back());
        for (size_t i{0}; i < ordered_leaves.size(); i += 2) {
            ordered_leaves[i / 2] = ComputeDealerNodeHash(ordered_leaves[i], ordered_leaves[i + 1]);
        }
        ordered_leaves.resize(ordered_leaves.size() / 2);
    }
    auto hasher{TaggedHash(std::string{DEALER_ROOT_HASH_TAG})};
    hasher << dealer_count << (ordered_leaves.empty() ? uint256{} : ordered_leaves.front());
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

DealerRecordValidationError ValidateDealerRecord(const DealerRecord& record)
{
    if (record.record_version != DEALER_RECORD_VERSION) {
        return DealerRecordValidationError::UNSUPPORTED_VERSION;
    }
    if (record.dealer_id.IsNull()) return DealerRecordValidationError::NULL_DEALER_ID;
    if (record.control_outpoint.IsNull()) return DealerRecordValidationError::NULL_CONTROL_OUTPOINT;
    if (!record.payout_script.IsPayToTaproot()) {
        return DealerRecordValidationError::INVALID_PAYOUT_SCRIPT;
    }
    if (record.updated_height < record.authorized_height) {
        return DealerRecordValidationError::INVALID_HEIGHTS;
    }
    if (record.status != DealerStatus::ACTIVE && record.status != DealerStatus::REVOKED) {
        return DealerRecordValidationError::UNKNOWN_STATUS;
    }
    return DealerRecordValidationError::NONE;
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

uint256 ComputeDealerLeafHash(const DealerRecord& record)
{
    auto hasher{TaggedHash(std::string{DEALER_LEAF_HASH_TAG})};
    hasher << record;
    return hasher.GetSHA256();
}

uint256 ComputeDealerRoot(const std::map<DealerId, DealerRecord>& dealers)
{
    std::vector<uint256> leaves;
    leaves.reserve(dealers.size());
    for (const auto& [_, dealer] : dealers) leaves.push_back(ComputeDealerLeafHash(dealer));
    return ComputeDealerRootFromLeaves(std::move(leaves));
}

uint256 ComputeRegistryStateRoot(const uint256& chain_root,
                                 const uint256& dealer_root,
                                 uint64_t authority_sequence,
                                 const uint256& authority_state_hash)
{
    auto hasher{TaggedHash(std::string{REGISTRY_STATE_HASH_TAG})};
    hasher << chain_root << dealer_root << authority_sequence << authority_state_hash;
    return hasher.GetSHA256();
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
    const uint256 chain_root{FinalizeRegistryRoot(proof.leaf_count, current)};
    return ComputeRegistryStateRoot(chain_root, proof.dealer_root, proof.authority_sequence, proof.authority_state_hash) == expected_root;
}

bool VerifyRegistryNonInclusion(const ChainId& chain_id,
                                const RegistryNonInclusionProof& proof,
                                const uint256& expected_root)
{
    if (proof.leaf_count == 0) {
        return !proof.has_left && !proof.has_right &&
               expected_root == ComputeRegistryStateRoot(
                   ComputeRegistryRootFromLeaves({}), proof.dealer_root, proof.authority_sequence, proof.authority_state_hash);
    }
    if (!proof.has_left && !proof.has_right) return false;

    if (proof.has_left) {
        if (proof.left.proof.leaf_count != proof.leaf_count ||
            !(proof.left.record.chain_id < chain_id) ||
            proof.left.proof.dealer_root != proof.dealer_root ||
            proof.left.proof.authority_sequence != proof.authority_sequence ||
            proof.left.proof.authority_state_hash != proof.authority_state_hash ||
            !VerifyRegistryInclusion(proof.left.record, proof.left.proof, expected_root)) {
            return false;
        }
    }
    if (proof.has_right) {
        if (proof.right.proof.leaf_count != proof.leaf_count ||
            !(chain_id < proof.right.record.chain_id) ||
            proof.right.proof.dealer_root != proof.dealer_root ||
            proof.right.proof.authority_sequence != proof.authority_sequence ||
            proof.right.proof.authority_state_hash != proof.authority_state_hash ||
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

const DealerRecord* ChainRegistry::FindDealer(const DealerId& dealer_id) const
{
    const auto it{m_dealers.find(dealer_id)};
    return it == m_dealers.end() ? nullptr : &it->second;
}

RegistryLoadResult ChainRegistry::LoadRecords(std::vector<ChainRecord> records)
{
    return LoadState(std::move(records), {}, 0);
}

RegistryLoadResult ChainRegistry::LoadState(std::vector<ChainRecord> records,
                                            std::vector<DealerRecord> dealers,
                                            uint64_t authority_sequence,
                                            DealerAuthorityTransition authority_transition)
{
    if (!authority_transition.IsValid() || (authority_transition.activation_height != 0 && authority_sequence == 0)) {
        return {.error = RegistryLoadError::INVALID_AUTHORITY_TRANSITION, .chain_id = {}, .dealer_id = {}};
    }
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

    std::map<DealerId, DealerRecord> loaded_dealers;
    std::map<COutPoint, DealerId> loaded_dealer_controls;
    for (auto& dealer : dealers) {
        const DealerRecordValidationError dealer_error{ValidateDealerRecord(dealer)};
        if (dealer_error != DealerRecordValidationError::NONE) {
            RegistryLoadResult result;
            result.error = RegistryLoadError::INVALID_DEALER_RECORD;
            result.dealer_record_error = dealer_error;
            result.dealer_id = dealer.dealer_id;
            return result;
        }
        const DealerId dealer_id{dealer.dealer_id};
        const auto [_, inserted]{loaded_dealers.emplace(dealer_id, std::move(dealer))};
        if (!inserted) {
            RegistryLoadResult result;
            result.error = RegistryLoadError::DUPLICATE_DEALER_ID;
            result.dealer_id = dealer_id;
            return result;
        }
        const DealerRecord& stored{loaded_dealers.at(dealer_id)};
        if (stored.status == DealerStatus::ACTIVE) {
            if (!loaded_dealer_controls.emplace(stored.control_outpoint, dealer_id).second) {
                RegistryLoadResult result;
                result.error = RegistryLoadError::DUPLICATE_ACTIVE_DEALER_CONTROL;
                result.dealer_id = dealer_id;
                return result;
            }
            if (loaded_controls.contains(stored.control_outpoint)) {
                RegistryLoadResult result;
                result.error = RegistryLoadError::CONTROL_NAMESPACE_COLLISION;
                result.dealer_id = dealer_id;
                return result;
            }
        }
    }

    m_records = std::move(loaded_records);
    m_control_index = std::move(loaded_controls);
    m_dealers = std::move(loaded_dealers);
    m_dealer_control_index = std::move(loaded_dealer_controls);
    m_authority_sequence = authority_sequence;
    m_authority_transition = std::move(authority_transition);
    return {};
}

uint256 ChainRegistry::ComputeRoot() const
{
    std::vector<uint256> leaves;
    leaves.reserve(m_records.size());
    for (const auto& entry : m_records) {
        leaves.push_back(ComputeRegistryLeafHash(entry.second));
    }
    return ComputeRegistryStateRoot(ComputeRegistryRootFromLeaves(std::move(leaves)),
                                    ComputeDealerRoot(m_dealers),
                                    m_authority_sequence, m_authority_transition.GetHash());
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
    RegistryInclusionProof proof{BuildRegistryInclusionProof(std::move(leaves), target_index)};
    proof.dealer_root = ComputeDealerRoot(m_dealers);
    proof.authority_sequence = m_authority_sequence;
    proof.authority_state_hash = m_authority_transition.GetHash();
    return proof;
}

std::optional<RegistryNonInclusionProof> ChainRegistry::GetNonInclusionProof(const ChainId& chain_id) const
{
    const auto right_it{m_records.lower_bound(chain_id)};
    if (right_it != m_records.end() && right_it->first == chain_id) return std::nullopt;

    RegistryNonInclusionProof proof;
    proof.leaf_count = m_records.size();
    proof.dealer_root = ComputeDealerRoot(m_dealers);
    proof.authority_sequence = m_authority_sequence;
    proof.authority_state_hash = m_authority_transition.GetHash();
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
                                                         const DealerAuthority& dealer_authority)
{
    const auto extracted{ExtractTransactionOperation(tx)};
    if (!extracted.IsValid()) {
        return TransitionError(RegistryError::INVALID_TRANSACTION_OPERATION,
                               std::nullopt,
                               extracted.error,
                               extracted.parse_error);
    }

    std::map<ChainId, size_t> spent_controls;
    std::map<DealerId, size_t> spent_dealer_controls;
    for (const auto& input : tx.vin) {
        if (const auto it{m_control_index.find(input.prevout)}; it != m_control_index.end()) {
            ++spent_controls[it->second];
        }
        if (const auto it{m_dealer_control_index.find(input.prevout)};
            it != m_dealer_control_index.end()) {
            ++spent_dealer_controls[it->second];
        }
    }

    if (!extracted.operation) {
        if (!spent_controls.empty()) return TransitionError(RegistryError::CONTROL_SPEND_WITHOUT_OPERATION);
        if (!spent_dealer_controls.empty()) {
            return TransitionError(RegistryError::CONTROL_SPEND_WITHOUT_OPERATION);
        }
        return {};
    }

    const RegistryOperation& operation{extracted.operation->operation};

    if (std::holds_alternative<AuthorizeDealer>(operation) ||
        std::holds_alternative<UpdateDealer>(operation) ||
        std::holds_alternative<RevokeDealer>(operation) ||
        std::holds_alternative<RotateAuthority>(operation)) {
        if (!spent_controls.empty() || !spent_dealer_controls.empty()) {
            return TransitionError(RegistryError::WRONG_CONTROL_OUTPOINT);
        }
        const auto& authority{Authority(height, dealer_authority)};
        if (!authority.IsValid()) {
            return TransitionError(RegistryError::INVALID_AUTHORITY_KEY);
        }
        if (m_authority_sequence == std::numeric_limits<uint64_t>::max()) {
            return TransitionError(RegistryError::INVALID_AUTHORITY_SEQUENCE);
        }

        const uint64_t sequence{std::visit([](const auto& payload) -> uint64_t {
            using Payload = std::decay_t<decltype(payload)>;
            if constexpr (std::is_same_v<Payload, AuthorizeDealer> ||
                          std::is_same_v<Payload, UpdateDealer> ||
                          std::is_same_v<Payload, RevokeDealer> ||
                          std::is_same_v<Payload, RotateAuthority>) {
                return payload.authority_sequence;
            }
            return 0;
        }, operation)};
        if (sequence != m_authority_sequence + 1) {
            return TransitionError(RegistryError::INVALID_AUTHORITY_SEQUENCE);
        }
        const auto authority_hash{ComputeDealerAuthorityHash(main_genesis_hash, operation)};
        const auto* signatures{std::visit([](const auto& payload) -> const DealerAuthoritySignatures* {
            using Payload = std::decay_t<decltype(payload)>;
            if constexpr (std::is_same_v<Payload, AuthorizeDealer> ||
                          std::is_same_v<Payload, UpdateDealer> ||
                          std::is_same_v<Payload, RevokeDealer> ||
                          std::is_same_v<Payload, RotateAuthority>) {
                return &payload.authority_signatures;
            }
            return {};
        }, operation)};
        if (!authority_hash || !signatures || !signatures->Verify(*authority_hash, authority)) {
            return TransitionError(RegistryError::INVALID_AUTHORITY_SIGNATURE);
        }

        if (const auto* rotation{std::get_if<RotateAuthority>(&operation)}) {
            if (m_authority_transition.Pending(height)) {
                return TransitionError(RegistryError::AUTHORITY_ROTATION_PENDING);
            }
            if (height == 0 || height > std::numeric_limits<uint32_t>::max() - DEALER_AUTHORITY_ROTATION_DELAY ||
                rotation->previous_policy_hash != authority.GetHash() ||
                rotation->next_authority == authority ||
                rotation->next_authority.threshold != authority.threshold ||
                rotation->next_authority.keys.size() != authority.keys.size()) {
                return TransitionError(RegistryError::INVALID_AUTHORITY_ROTATION);
            }
            if (!rotation->next_authority_signatures.Verify(*authority_hash, rotation->next_authority)) {
                return TransitionError(RegistryError::INVALID_AUTHORITY_SIGNATURE);
            }
            RegistryUndo undo;
            undo.previous_authority_sequence = m_authority_sequence;
            undo.previous_authority_transition = m_authority_transition;
            // Copy the effective policy before replacing its owning transition.
            DealerAuthorityTransition replacement{
                .activation_height = height + DEALER_AUTHORITY_ROTATION_DELAY,
                .previous = authority,
                .next = rotation->next_authority,
            };
            m_authority_transition = std::move(replacement);
            m_authority_sequence = sequence;
            return {.chain_id = {}, .dealer_id = {}, .applied = true, .undo = std::move(undo)};
        }

        if (const auto* authorization{std::get_if<AuthorizeDealer>(&operation)}) {
            const DealerId dealer_id{DeriveDealerId(main_genesis_hash,
                                                    authorization->authorization_nonce,
                                                    authorization->control_key)};
            if (m_dealers.contains(dealer_id)) {
                return TransitionError(RegistryError::DUPLICATE_DEALER_ID,
                                       std::nullopt,
                                       TxOperationError::NONE,
                                       OperationParseError::NONE,
                                       dealer_id);
            }
            const COutPoint control_outpoint{tx.GetHash(), authorization->control_output};
            if (m_control_index.contains(control_outpoint) ||
                m_dealer_control_index.contains(control_outpoint)) {
                return TransitionError(RegistryError::WRONG_DEALER_CONTROL_OUTPOINT);
            }
            DealerRecord dealer{
                .dealer_id = dealer_id,
                .control_outpoint = control_outpoint,
                .payout_script = CScript{authorization->payout_script.begin(), authorization->payout_script.end()},
                .remaining_licenses = authorization->initial_licenses,
                .status = DealerStatus::ACTIVE,
                .authorized_height = height,
                .updated_height = height,
            };
            m_dealer_control_index.emplace(control_outpoint, dealer_id);
            m_dealers.emplace(dealer_id, dealer);
            const uint64_t previous_sequence{m_authority_sequence++};
            return {
                .chain_id = std::nullopt,
                .dealer_id = dealer_id,
                .applied = true,
                .undo = RegistryUndo{
                    .has_chain = false,
                    .chain_id = {},
                    .chain_had_previous = false,
                    .previous_chain = {},
                    .has_dealer = true,
                    .dealer_id = dealer_id,
                    .dealer_had_previous = false,
                    .previous_dealer = {},
                    .previous_authority_sequence = previous_sequence,
                },
            };
        }

        const DealerId& dealer_id{std::get_if<UpdateDealer>(&operation)
                                      ? std::get<UpdateDealer>(operation).dealer_id
                                      : std::get<RevokeDealer>(operation).dealer_id};
        const auto dealer_it{m_dealers.find(dealer_id)};
        if (dealer_it == m_dealers.end()) {
            return TransitionError(RegistryError::UNKNOWN_DEALER,
                                   std::nullopt,
                                   TxOperationError::NONE,
                                   OperationParseError::NONE,
                                   dealer_id);
        }
        if (dealer_it->second.status == DealerStatus::REVOKED) {
            return TransitionError(RegistryError::REVOKED_DEALER,
                                   std::nullopt,
                                   TxOperationError::NONE,
                                   OperationParseError::NONE,
                                   dealer_id);
        }
        const DealerRecord previous{dealer_it->second};
        const uint64_t previous_sequence{m_authority_sequence};
        if (const auto* update{std::get_if<UpdateDealer>(&operation)}) {
            if (update->added_licenses > std::numeric_limits<uint32_t>::max() -
                                             dealer_it->second.remaining_licenses) {
                return TransitionError(RegistryError::LICENSE_COUNT_OVERFLOW,
                                       std::nullopt,
                                       TxOperationError::NONE,
                                       OperationParseError::NONE,
                                       dealer_id);
            }
            dealer_it->second.remaining_licenses += update->added_licenses;
            if (!update->payout_script.empty()) {
                dealer_it->second.payout_script =
                    CScript{update->payout_script.begin(), update->payout_script.end()};
            }
            dealer_it->second.updated_height = height;
        } else {
            m_dealer_control_index.erase(dealer_it->second.control_outpoint);
            dealer_it->second.status = DealerStatus::REVOKED;
            dealer_it->second.updated_height = height;
        }
        m_authority_sequence = sequence;
        return {
            .chain_id = std::nullopt,
            .dealer_id = dealer_id,
            .applied = true,
            .undo = RegistryUndo{
                .has_chain = false,
                .chain_id = {},
                .chain_had_previous = false,
                .previous_chain = {},
                .has_dealer = true,
                .dealer_id = dealer_id,
                .dealer_had_previous = true,
                .previous_dealer = previous,
                .previous_authority_sequence = previous_sequence,
            },
        };
    }

    if (const auto* registration{std::get_if<RegisterChain>(&operation)}) {
        if (!spent_controls.empty()) return TransitionError(RegistryError::WRONG_CONTROL_OUTPOINT);
        const COutPoint& anchor{tx.vin[registration->anchor_input].prevout};
        const ChainSpecHash spec_hash{ComputeChainSpecHash(registration->manifest.spec)};
        const ChainId chain_id{DeriveChainId(main_genesis_hash, anchor, spec_hash)};
        if (m_records.contains(chain_id)) {
            return TransitionError(RegistryError::DUPLICATE_CHAIN_ID, chain_id);
        }
        if (spent_dealer_controls.size() > 1 ||
            (spent_dealer_controls.size() == 1 && spent_dealer_controls.begin()->second > 1)) {
            return TransitionError(RegistryError::MULTIPLE_DEALER_CONTROL_OUTPOINTS,
                                   std::nullopt,
                                   TxOperationError::NONE,
                                   OperationParseError::NONE,
                                   registration->dealer_id);
        }
        const auto dealer_it{m_dealers.find(registration->dealer_id)};
        if (dealer_it == m_dealers.end()) {
            return TransitionError(RegistryError::UNAUTHORIZED_DEALER,
                                   std::nullopt,
                                   TxOperationError::NONE,
                                   OperationParseError::NONE,
                                   registration->dealer_id);
        }
        if (dealer_it->second.status != DealerStatus::ACTIVE) {
            return TransitionError(RegistryError::REVOKED_DEALER,
                                   std::nullopt,
                                   TxOperationError::NONE,
                                   OperationParseError::NONE,
                                   registration->dealer_id);
        }
        if (dealer_it->second.remaining_licenses == 0) {
            return TransitionError(RegistryError::DEALER_LICENSES_EXHAUSTED,
                                   std::nullopt,
                                   TxOperationError::NONE,
                                   OperationParseError::NONE,
                                   registration->dealer_id);
        }
        if (spent_dealer_controls.size() != 1 ||
            spent_dealer_controls.begin()->first != registration->dealer_id) {
            return TransitionError(RegistryError::WRONG_DEALER_CONTROL_OUTPOINT,
                                   std::nullopt,
                                   TxOperationError::NONE,
                                   OperationParseError::NONE,
                                   registration->dealer_id);
        }
        if (tx.vin[registration->anchor_input].prevout == dealer_it->second.control_outpoint) {
            return TransitionError(RegistryError::WRONG_DEALER_CONTROL_OUTPOINT,
                                   std::nullopt,
                                   TxOperationError::NONE,
                                   OperationParseError::NONE,
                                   registration->dealer_id);
        }
        if (tx.vout[registration->dealer_payment_output].scriptPubKey != dealer_it->second.payout_script) {
            return TransitionError(RegistryError::WRONG_DEALER_PAYMENT,
                                   std::nullopt,
                                   TxOperationError::NONE,
                                   OperationParseError::NONE,
                                   registration->dealer_id);
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
        const DealerRecord previous_dealer{dealer_it->second};
        m_dealer_control_index.erase(dealer_it->second.control_outpoint);
        dealer_it->second.control_outpoint =
            COutPoint{tx.GetHash(), registration->dealer_control_output};
        --dealer_it->second.remaining_licenses;
        dealer_it->second.updated_height = height;
        m_dealer_control_index.emplace(dealer_it->second.control_outpoint, registration->dealer_id);
        m_control_index.emplace(record.control_outpoint, chain_id);
        m_records.emplace(chain_id, record);
        return {
            .chain_id = chain_id,
            .dealer_id = registration->dealer_id,
            .applied = true,
            .undo = RegistryUndo{
                .has_chain = true,
                .chain_id = chain_id,
                .chain_had_previous = false,
                .previous_chain = {},
                .has_dealer = true,
                .dealer_id = registration->dealer_id,
                .dealer_had_previous = true,
                .previous_dealer = previous_dealer,
                .previous_authority_sequence = m_authority_sequence,
            },
        };
    }

    if (!spent_dealer_controls.empty()) {
        return TransitionError(RegistryError::WRONG_DEALER_CONTROL_OUTPOINT);
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
        .has_chain = true,
        .chain_id = chain_id,
        .chain_had_previous = true,
        .previous_chain = record_it->second,
        .has_dealer = false,
        .dealer_id = {},
        .dealer_had_previous = false,
        .previous_dealer = {},
        .previous_authority_sequence = m_authority_sequence,
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

    return {
        .chain_id = chain_id,
        .dealer_id = std::nullopt,
        .applied = true,
        .undo = undo,
    };
}

bool ChainRegistry::Undo(const RegistryUndo& undo)
{
    if (!undo.has_chain && !undo.has_dealer && !undo.previous_authority_transition) return false;

    // Undo data is persisted and may be corrupted. Apply it to a candidate so
    // a failed consistency check can never leave the live registry half
    // reverted.
    ChainRegistry candidate{*this};
    if (undo.has_chain) {
        const auto current{candidate.m_records.find(undo.chain_id)};
        if (current == candidate.m_records.end()) return false;
        if (undo.chain_had_previous && undo.previous_chain.chain_id != undo.chain_id) return false;
        if (current->second.status == ChainStatus::ACTIVE) {
            candidate.m_control_index.erase(current->second.control_outpoint);
        }
        if (!undo.chain_had_previous) {
            candidate.m_records.erase(current);
        } else {
            current->second = undo.previous_chain;
            if (undo.previous_chain.status == ChainStatus::ACTIVE &&
                (candidate.m_dealer_control_index.contains(undo.previous_chain.control_outpoint) ||
                 !candidate.m_control_index.emplace(
                     undo.previous_chain.control_outpoint, undo.chain_id).second)) {
                return false;
            }
        }
    }
    if (undo.has_dealer) {
        const auto current{candidate.m_dealers.find(undo.dealer_id)};
        if (current == candidate.m_dealers.end()) return false;
        if (undo.dealer_had_previous && undo.previous_dealer.dealer_id != undo.dealer_id) return false;
        if (current->second.status == DealerStatus::ACTIVE) {
            candidate.m_dealer_control_index.erase(current->second.control_outpoint);
        }
        if (!undo.dealer_had_previous) {
            candidate.m_dealers.erase(current);
        } else {
            current->second = undo.previous_dealer;
            if (undo.previous_dealer.status == DealerStatus::ACTIVE &&
                (candidate.m_control_index.contains(undo.previous_dealer.control_outpoint) ||
                 !candidate.m_dealer_control_index.emplace(
                     undo.previous_dealer.control_outpoint, undo.dealer_id).second)) {
                return false;
            }
        }
    }
    if (undo.previous_authority_transition) {
        if (undo.has_chain || undo.has_dealer || !undo.previous_authority_transition->IsValid() ||
            m_authority_transition.activation_height == 0 ||
            undo.previous_authority_sequence == std::numeric_limits<uint64_t>::max() ||
            undo.previous_authority_sequence + 1 != m_authority_sequence) return false;
        candidate.m_authority_transition = *undo.previous_authority_transition;
    }
    candidate.m_authority_sequence = undo.previous_authority_sequence;
    *this = std::move(candidate);
    return true;
}

bool ChainRegistry::UndoBlock(const RegistryBlockUndo& undo)
{
    ChainRegistry candidate{*this};
    for (auto it{undo.operations.rbegin()}; it != undo.operations.rend(); ++it) {
        if (!candidate.Undo(*it)) return false;
    }
    *this = std::move(candidate);
    return true;
}

BlockDepositsResult ValidateBlockDeposits(
    const CBlock& block,
    const ChainRegistry& final_registry,
    const uint256& main_genesis_hash,
    const DepositValidationParams& params)
{
    BlockDepositsResult result;
    std::set<DepositId> seen;

    for (size_t transaction_index{0}; transaction_index < block.vtx.size(); ++transaction_index) {
        const auto& transaction_ref{block.vtx[transaction_index]};
        const CTransaction& transaction{*transaction_ref};
        const auto transaction_funds{ExtractTransactionFunds(transaction)};
        if (!transaction_funds.IsValid()) {
            result.error = BlockDepositsError::INVALID_TRANSACTION;
            result.transaction_error = transaction_funds.error;
            result.parse_error = transaction_funds.parse_error;
            result.transaction = transaction.GetHash();
            return result;
        }

        for (const auto& output : transaction_funds.funds) {
            result.transaction = transaction.GetHash();
            result.output_index = output.output_index;
            result.chain_id = output.fund.chain_id;
            if (result.deposits.size() >= params.maximum_deposits) {
                result.error = BlockDepositsError::TOO_MANY_DEPOSITS;
                return result;
            }
            if (output.amount < params.minimum_amount) {
                result.error = BlockDepositsError::AMOUNT_BELOW_MINIMUM;
                return result;
            }
            if (output.amount > MAX_MONEY - result.total_amount) {
                result.error = BlockDepositsError::TOTAL_AMOUNT_OUT_OF_RANGE;
                return result;
            }

            const ChainRecord* record{final_registry.Find(output.fund.chain_id)};
            if (!record) {
                result.error = BlockDepositsError::UNKNOWN_CHAIN;
                return result;
            }
            if (record->status != ChainStatus::ACTIVE) {
                result.error = BlockDepositsError::INACTIVE_CHAIN;
                return result;
            }

            const COutPoint outpoint{transaction.GetHash(), output.output_index};
            const DepositId deposit_id{DeriveDepositId(main_genesis_hash, outpoint)};
            if (!seen.insert(deposit_id).second) {
                result.error = BlockDepositsError::DUPLICATE_DEPOSIT_ID;
                return result;
            }

            result.total_amount += output.amount;
            result.deposits.push_back(ValidatedDeposit{
                .deposit_id = deposit_id,
                .outpoint = outpoint,
                .transaction_index = static_cast<uint32_t>(transaction_index),
                .amount = output.amount,
                .fund = output.fund,
            });
        }
    }

    result.transaction.reset();
    result.output_index.reset();
    result.chain_id.reset();
    return result;
}

RegistryBlockResult ChainRegistry::ApplyBlock(const CBlock& block,
                                              uint32_t height,
                                              const uint256& main_genesis_hash,
                                              const DealerAuthority& dealer_authority,
                                              size_t maximum_operations,
                                              CommitmentRequirement commitment_requirement,
                                              std::optional<DepositValidationParams> deposit_params)
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

    const auto coinbase_operation{ExtractTransactionOperation(*block.vtx.front())};
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

        auto transition{ApplyTransaction(
            *block.vtx[tx_index], height, main_genesis_hash, dealer_authority)};
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

    if (deposit_params) {
        result.deposits = ValidateBlockDeposits(block, *this, main_genesis_hash, *deposit_params);
        if (!result.deposits.IsValid()) {
            result.error = RegistryBlockError::INVALID_DEPOSITS;
            rollback();
            return result;
        }
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
