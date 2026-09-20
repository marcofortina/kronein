// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <primitives/chainregistry.h>

#include <hash.h>
#include <primitives/transaction.h>
#include <streams.h>

#include <algorithm>
#include <ios>
#include <limits>
#include <span>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

namespace chainregistry {

ChainSpecHash ComputeChainSpecHash(std::span<const std::byte> canonical_spec)
{
    auto hasher{TaggedHash(std::string{CHAIN_SPEC_HASH_TAG})};
    hasher.write(canonical_spec);
    return ChainSpecHash::FromUint256(hasher.GetSHA256());
}

ChainSpecHash ComputeChainSpecHash(const ChainSpec& spec)
{
    auto hasher{TaggedHash(std::string{CHAIN_SPEC_HASH_TAG})};
    hasher << spec;
    return ChainSpecHash::FromUint256(hasher.GetSHA256());
}

ManifestHash ComputeManifestHash(const ChainManifest& manifest)
{
    auto hasher{TaggedHash(std::string{MANIFEST_HASH_TAG})};
    hasher << manifest;
    return ManifestHash::FromUint256(hasher.GetSHA256());
}

ManifestValidationError ValidateManifest(const ChainManifest& manifest)
{
    if (manifest.spec.protocol_version != PROTOCOL_VERSION) {
        return ManifestValidationError::UNSUPPORTED_PROTOCOL_VERSION;
    }
    if (manifest.spec.template_id == 0) return ManifestValidationError::INVALID_TEMPLATE_ID;
    if (manifest.spec.template_version == 0) return ManifestValidationError::INVALID_TEMPLATE_VERSION;
    if (manifest.spec.consensus_parameters.size() > MAX_CONSENSUS_PARAMETERS_SIZE) {
        return ManifestValidationError::CONSENSUS_PARAMETERS_TOO_LARGE;
    }
    if (manifest.spec.anchoring_policy != AnchoringPolicy::BMM_V1) {
        return ManifestValidationError::UNKNOWN_ANCHORING_POLICY;
    }
    if (manifest.child_genesis_hash.IsNull()) return ManifestValidationError::NULL_GENESIS;
    if (manifest.initial_metadata_hash.IsNull()) return ManifestValidationError::NULL_METADATA_HASH;
    return ManifestValidationError::NONE;
}

OperationType GetOperationType(const RegistryOperation& operation)
{
    return std::visit([](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, RegisterChain>) return OperationType::REGISTER;
        if constexpr (std::is_same_v<Payload, UpdateChain>) return OperationType::UPDATE;
        if constexpr (std::is_same_v<Payload, RetireChain>) return OperationType::RETIRE;
    }, operation);
}

OperationValidationError ValidateOperation(const RegistryOperation& operation)
{
    return std::visit([](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, RegisterChain>) {
            if (payload.anchor_input == std::numeric_limits<uint32_t>::max()) {
                return OperationValidationError::INVALID_ANCHOR_INPUT;
            }
            if (payload.control_output == std::numeric_limits<uint32_t>::max()) {
                return OperationValidationError::INVALID_CONTROL_OUTPUT;
            }
            if (ValidateManifest(payload.manifest) != ManifestValidationError::NONE) {
                return OperationValidationError::INVALID_MANIFEST;
            }
        } else if constexpr (std::is_same_v<Payload, UpdateChain>) {
            if (payload.chain_id.IsNull()) return OperationValidationError::NULL_CHAIN_ID;
            if (payload.control_output == std::numeric_limits<uint32_t>::max()) {
                return OperationValidationError::INVALID_CONTROL_OUTPUT;
            }
        } else if constexpr (std::is_same_v<Payload, RetireChain>) {
            if (payload.chain_id.IsNull()) return OperationValidationError::NULL_CHAIN_ID;
        }
        return OperationValidationError::NONE;
    }, operation);
}

CScript BuildOperationScript(const RegistryOperation& operation)
{
    std::vector<unsigned char> data{REGISTRY_MAGIC.begin(), REGISTRY_MAGIC.end()};
    VectorWriter writer{data, data.size()};
    writer << REGISTRY_ENVELOPE_VERSION << static_cast<uint8_t>(GetOperationType(operation));
    std::visit([&](const auto& payload) { writer << payload; }, operation);
    return CScript{} << OP_RETURN << data;
}

OperationParseResult ParseOperationScript(const CScript& script)
{
    auto cursor{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(cursor, opcode) || opcode != OP_RETURN) {
        return {OperationParseError::NOT_REGISTRY, std::nullopt};
    }
    if (!script.GetOp(cursor, opcode, data)) {
        return {OperationParseError::NOT_REGISTRY, std::nullopt};
    }
    if (data.size() < REGISTRY_MAGIC.size() ||
        !std::equal(REGISTRY_MAGIC.begin(), REGISTRY_MAGIC.end(), data.begin())) {
        return {OperationParseError::NOT_REGISTRY, std::nullopt};
    }
    if (opcode > OP_PUSHDATA4 || cursor != script.end()) {
        return {OperationParseError::MALFORMED_SCRIPT, std::nullopt};
    }
    if (data.size() > MAX_REGISTRY_DATA_SIZE) {
        return {OperationParseError::DATA_TOO_LARGE, std::nullopt};
    }
    if (script != (CScript{} << OP_RETURN << data)) {
        return {OperationParseError::NON_CANONICAL_SCRIPT, std::nullopt};
    }

    try {
        SpanReader reader{std::span{data}.subspan(REGISTRY_MAGIC.size())};
        uint8_t envelope_version;
        uint8_t operation_type;
        reader >> envelope_version >> operation_type;
        if (envelope_version != REGISTRY_ENVELOPE_VERSION) {
            return {OperationParseError::UNSUPPORTED_ENVELOPE_VERSION, std::nullopt};
        }

        RegistryOperation operation;
        switch (static_cast<OperationType>(operation_type)) {
        case OperationType::REGISTER: {
            RegisterChain payload;
            reader >> payload;
            operation = std::move(payload);
            break;
        }
        case OperationType::UPDATE: {
            UpdateChain payload;
            reader >> payload;
            operation = std::move(payload);
            break;
        }
        case OperationType::RETIRE: {
            RetireChain payload;
            reader >> payload;
            operation = std::move(payload);
            break;
        }
        default:
            return {OperationParseError::UNKNOWN_OPERATION_TYPE, std::nullopt};
        }
        if (!reader.empty()) return {OperationParseError::TRAILING_DATA, std::nullopt};
        if (ValidateOperation(operation) != OperationValidationError::NONE) {
            return {OperationParseError::INVALID_OPERATION, std::nullopt};
        }
        return {OperationParseError::NONE, std::move(operation)};
    } catch (const std::ios_base::failure&) {
        return {OperationParseError::INVALID_PAYLOAD, std::nullopt};
    }
}

TxOperationResult ExtractTransactionOperation(const CTransaction& tx, CAmount minimum_registration_burn)
{
    std::optional<TransactionOperation> found;
    for (size_t output_index{0}; output_index < tx.vout.size(); ++output_index) {
        const auto parsed{ParseOperationScript(tx.vout[output_index].scriptPubKey)};
        if (parsed.error == OperationParseError::NOT_REGISTRY) continue;
        if (!parsed) {
            return {TxOperationError::INVALID_ENVELOPE, parsed.error, std::nullopt};
        }
        if (found) {
            return {TxOperationError::MULTIPLE_OPERATIONS, OperationParseError::NONE, std::nullopt};
        }
        found = TransactionOperation{
            .registry_output = static_cast<uint32_t>(output_index),
            .operation = *parsed.operation,
        };
    }

    if (!found) return {};

    const CTxOut& registry_output{tx.vout[found->registry_output]};
    const auto validate_control_output{[&](uint32_t output_index) -> TxOperationError {
        if (output_index >= tx.vout.size()) return TxOperationError::INVALID_CONTROL_OUTPUT;
        if (output_index == found->registry_output) return TxOperationError::CONTROL_OUTPUT_COLLISION;
        if (!tx.vout[output_index].scriptPubKey.IsPayToTaproot()) {
            return TxOperationError::CONTROL_OUTPUT_NOT_P2TR;
        }
        return TxOperationError::NONE;
    }};

    const TxOperationError error{std::visit([&](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, RegisterChain>) {
            if (payload.anchor_input >= tx.vin.size()) return TxOperationError::INVALID_ANCHOR_INPUT;
            if (tx.vin[payload.anchor_input].prevout.IsNull()) return TxOperationError::NULL_ANCHOR_PREVOUT;
            if (const auto control_error{validate_control_output(payload.control_output)};
                control_error != TxOperationError::NONE) {
                return control_error;
            }
            if (registry_output.nValue < minimum_registration_burn) {
                return TxOperationError::INSUFFICIENT_REGISTRATION_BURN;
            }
        } else if constexpr (std::is_same_v<Payload, UpdateChain>) {
            if (const auto control_error{validate_control_output(payload.control_output)};
                control_error != TxOperationError::NONE) {
                return control_error;
            }
            if (registry_output.nValue != 0) return TxOperationError::UNEXPECTED_OPERATION_VALUE;
        } else if constexpr (std::is_same_v<Payload, RetireChain>) {
            if (registry_output.nValue != 0) return TxOperationError::UNEXPECTED_OPERATION_VALUE;
        }
        return TxOperationError::NONE;
    }, found->operation)};

    if (error != TxOperationError::NONE) return {error, OperationParseError::NONE, std::nullopt};
    return {TxOperationError::NONE, OperationParseError::NONE, std::move(found)};
}

ChainId DeriveChainId(const uint256& main_genesis_hash,
                      const COutPoint& registration_outpoint,
                      const ChainSpecHash& spec_hash)
{
    auto hasher{TaggedHash(std::string{CHAIN_ID_TAG})};
    hasher << main_genesis_hash << registration_outpoint << spec_hash;
    return ChainId::FromUint256(hasher.GetSHA256());
}

DepositId DeriveDepositId(const uint256& main_genesis_hash, const COutPoint& burn_outpoint)
{
    auto hasher{TaggedHash(std::string{DEPOSIT_ID_TAG})};
    hasher << main_genesis_hash << burn_outpoint;
    return DepositId::FromUint256(hasher.GetSHA256());
}

} // namespace chainregistry
