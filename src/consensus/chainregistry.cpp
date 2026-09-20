// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/chainregistry.h>

#include <hash.h>

#include <cstdint>
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

} // namespace

uint256 ComputeRegistryLeafHash(const ChainRecord& record)
{
    auto hasher{TaggedHash(std::string{REGISTRY_LEAF_HASH_TAG})};
    hasher << record;
    return hasher.GetSHA256();
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
    auto hasher{TaggedHash(std::string{REGISTRY_ROOT_HASH_TAG})};
    hasher << record_count << tree_root;
    return hasher.GetSHA256();
}

const ChainRecord* ChainRegistry::Find(const ChainId& chain_id) const
{
    const auto it{m_records.find(chain_id)};
    return it == m_records.end() ? nullptr : &it->second;
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

} // namespace chainregistry
