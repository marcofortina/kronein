// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <primitives/chainregistry.h>

#include <hash.h>
#include <primitives/transaction.h>
#include <pubkey.h>
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

ManifestValidationError ValidateChainSpec(const ChainSpec& spec)
{
    if (spec.protocol_version != PROTOCOL_VERSION) {
        return ManifestValidationError::UNSUPPORTED_PROTOCOL_VERSION;
    }
    if (spec.template_id == 0) return ManifestValidationError::INVALID_TEMPLATE_ID;
    if (spec.template_version == 0) return ManifestValidationError::INVALID_TEMPLATE_VERSION;
    if (spec.consensus_parameters.size() > MAX_CONSENSUS_PARAMETERS_SIZE) {
        return ManifestValidationError::CONSENSUS_PARAMETERS_TOO_LARGE;
    }
    if (spec.anchoring_policy != AnchoringPolicy::BMM_V1) {
        return ManifestValidationError::UNKNOWN_ANCHORING_POLICY;
    }
    return ManifestValidationError::NONE;
}

ManifestValidationError ValidateManifest(const ChainManifest& manifest)
{
    if (const auto error{ValidateChainSpec(manifest.spec)}; error != ManifestValidationError::NONE) {
        return error;
    }
    if (manifest.child_genesis_hash.IsNull()) return ManifestValidationError::NULL_GENESIS;
    if (manifest.initial_metadata_hash.IsNull()) return ManifestValidationError::NULL_METADATA_HASH;
    if (manifest.default_fee_recipient.recipient_type == 0) {
        return ManifestValidationError::INVALID_FEE_RECIPIENT_TYPE;
    }
    if (manifest.default_fee_recipient.recipient.empty() ||
        manifest.default_fee_recipient.recipient.size() > MAX_FEE_RECIPIENT_SIZE) {
        return ManifestValidationError::INVALID_FEE_RECIPIENT_SIZE;
    }
    return ManifestValidationError::NONE;
}

OperationType GetOperationType(const RegistryOperation& operation)
{
    return std::visit([](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, RegisterChain>) return OperationType::REGISTER;
        if constexpr (std::is_same_v<Payload, UpdateChain>) return OperationType::UPDATE;
        if constexpr (std::is_same_v<Payload, RetireChain>) return OperationType::RETIRE;
        if constexpr (std::is_same_v<Payload, AuthorizeDealer>) return OperationType::AUTHORIZE_DEALER;
        if constexpr (std::is_same_v<Payload, UpdateDealer>) return OperationType::UPDATE_DEALER;
        if constexpr (std::is_same_v<Payload, RevokeDealer>) return OperationType::REVOKE_DEALER;
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
            if (payload.dealer_id.IsNull()) return OperationValidationError::NULL_DEALER_ID;
            if (payload.dealer_control_output == std::numeric_limits<uint32_t>::max()) {
                return OperationValidationError::INVALID_DEALER_CONTROL_OUTPUT;
            }
            if (payload.dealer_payment_output == std::numeric_limits<uint32_t>::max()) {
                return OperationValidationError::INVALID_DEALER_PAYMENT_OUTPUT;
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
        } else if constexpr (std::is_same_v<Payload, AuthorizeDealer>) {
            if (payload.authority_sequence == 0) {
                return OperationValidationError::INVALID_AUTHORITY_SEQUENCE;
            }
            if (payload.authorization_nonce.IsNull()) {
                return OperationValidationError::NULL_AUTHORIZATION_NONCE;
            }
            if (!XOnlyPubKey{payload.control_key}.IsFullyValid()) {
                return OperationValidationError::INVALID_DEALER_CONTROL_KEY;
            }
            if (payload.control_output == std::numeric_limits<uint32_t>::max()) {
                return OperationValidationError::INVALID_DEALER_CONTROL_OUTPUT;
            }
            if (payload.payout_script.empty() ||
                !CScript{payload.payout_script.begin(), payload.payout_script.end()}.IsPayToTaproot()) {
                return OperationValidationError::INVALID_PAYOUT_SCRIPT;
            }
            if (payload.initial_licenses != DEALER_INITIAL_LICENSES) {
                return OperationValidationError::INVALID_LICENSE_COUNT;
            }
            if (!payload.authority_signatures.IsWellFormed() || payload.authority_signatures.signers == 0) {
                return OperationValidationError::INVALID_AUTHORITY_SIGNATURE;
            }
        } else if constexpr (std::is_same_v<Payload, UpdateDealer>) {
            if (payload.authority_sequence == 0) {
                return OperationValidationError::INVALID_AUTHORITY_SEQUENCE;
            }
            if (payload.dealer_id.IsNull()) return OperationValidationError::NULL_DEALER_ID;
            if (payload.added_licenses > DEALER_MAX_ADDED_LICENSES ||
                (payload.added_licenses == 0 && payload.payout_script.empty())) {
                return OperationValidationError::INVALID_LICENSE_COUNT;
            }
            if (!payload.payout_script.empty() &&
                !CScript{payload.payout_script.begin(), payload.payout_script.end()}.IsPayToTaproot()) {
                return OperationValidationError::INVALID_PAYOUT_SCRIPT;
            }
            if (!payload.authority_signatures.IsWellFormed() || payload.authority_signatures.signers == 0) {
                return OperationValidationError::INVALID_AUTHORITY_SIGNATURE;
            }
        } else if constexpr (std::is_same_v<Payload, RevokeDealer>) {
            if (payload.authority_sequence == 0) {
                return OperationValidationError::INVALID_AUTHORITY_SEQUENCE;
            }
            if (payload.dealer_id.IsNull()) return OperationValidationError::NULL_DEALER_ID;
            if (!payload.authority_signatures.IsWellFormed() || payload.authority_signatures.signers == 0) {
                return OperationValidationError::INVALID_AUTHORITY_SIGNATURE;
            }
        }
        return OperationValidationError::NONE;
    }, operation);
}

CScript BuildOperationScript(const RegistryOperation& operation)
{
    std::vector<unsigned char> data{REGISTRY_MAGIC.begin(), REGISTRY_MAGIC.end()};
    VectorWriter writer{data, data.size()};
    const auto type{GetOperationType(operation)};
    const uint8_t version{type >= OperationType::AUTHORIZE_DEALER ? DEALER_ENVELOPE_VERSION : REGISTRY_ENVELOPE_VERSION};
    writer << version << static_cast<uint8_t>(type);
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
        const bool dealer_operation{operation_type >= static_cast<uint8_t>(OperationType::AUTHORIZE_DEALER) &&
                                    operation_type <= static_cast<uint8_t>(OperationType::REVOKE_DEALER)};
        const uint8_t expected_version{dealer_operation ? DEALER_ENVELOPE_VERSION : REGISTRY_ENVELOPE_VERSION};
        if (envelope_version != expected_version) {
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
        case OperationType::AUTHORIZE_DEALER: {
            AuthorizeDealer payload;
            reader >> payload;
            operation = std::move(payload);
            break;
        }
        case OperationType::UPDATE_DEALER: {
            UpdateDealer payload;
            reader >> payload;
            operation = std::move(payload);
            break;
        }
        case OperationType::REVOKE_DEALER: {
            RevokeDealer payload;
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

TxOperationResult ExtractTransactionOperation(const CTransaction& tx)
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
            if (const auto control_error{validate_control_output(payload.dealer_control_output)};
                control_error != TxOperationError::NONE) {
                return control_error;
            }
            if (payload.dealer_payment_output >= tx.vout.size()) {
                return TxOperationError::INVALID_DEALER_PAYMENT;
            }
            if (payload.control_output == payload.dealer_control_output ||
                payload.control_output == payload.dealer_payment_output ||
                payload.dealer_control_output == payload.dealer_payment_output ||
                payload.dealer_payment_output == found->registry_output) {
                return TxOperationError::OUTPUT_COLLISION;
            }
            if (tx.vout[payload.dealer_payment_output].nValue <= 0) {
                return TxOperationError::INVALID_DEALER_PAYMENT;
            }
        } else if constexpr (std::is_same_v<Payload, UpdateChain>) {
            if (const auto control_error{validate_control_output(payload.control_output)};
                control_error != TxOperationError::NONE) {
                return control_error;
            }
            if (registry_output.nValue != 0) return TxOperationError::UNEXPECTED_OPERATION_VALUE;
        } else if constexpr (std::is_same_v<Payload, RetireChain>) {
            if (registry_output.nValue != 0) return TxOperationError::UNEXPECTED_OPERATION_VALUE;
        } else if constexpr (std::is_same_v<Payload, AuthorizeDealer>) {
            if (const auto control_error{validate_control_output(payload.control_output)};
                control_error != TxOperationError::NONE) {
                return control_error;
            }
            const CScript expected_script{CScript{} << OP_1 << std::vector<unsigned char>{
                payload.control_key.begin(), payload.control_key.end()}};
            if (tx.vout[payload.control_output].scriptPubKey != expected_script) {
                return TxOperationError::CONTROL_OUTPUT_NOT_P2TR;
            }
        }
        if (registry_output.nValue != 0) return TxOperationError::UNEXPECTED_OPERATION_VALUE;
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

DealerId DeriveDealerId(const uint256& main_genesis_hash,
                        const uint256& authorization_nonce,
                        std::span<const unsigned char, DEALER_CONTROL_KEY_SIZE> control_key)
{
    auto hasher{TaggedHash(std::string{DEALER_ID_TAG})};
    hasher << main_genesis_hash << authorization_nonce;
    hasher.write(std::as_bytes(control_key));
    return DealerId::FromUint256(hasher.GetSHA256());
}

std::optional<uint256> ComputeDealerAuthorityHash(const uint256& main_genesis_hash,
                                                 const RegistryOperation& operation)
{
    auto hasher{TaggedHash(std::string{DEALER_AUTHORITY_TAG})};
    hasher << main_genesis_hash << static_cast<uint8_t>(GetOperationType(operation));
    const bool is_admin{std::visit([&](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, AuthorizeDealer>) {
            hasher << payload.authority_sequence
                   << payload.authorization_nonce
                   << payload.control_key
                   << payload.control_output
                   << payload.payout_script
                   << payload.initial_licenses;
            return true;
        } else if constexpr (std::is_same_v<Payload, UpdateDealer>) {
            hasher << payload.authority_sequence
                   << payload.dealer_id
                   << payload.added_licenses
                   << payload.payout_script;
            return true;
        } else if constexpr (std::is_same_v<Payload, RevokeDealer>) {
            hasher << payload.authority_sequence << payload.dealer_id;
            return true;
        }
        return false;
    }, operation)};
    if (!is_admin) return std::nullopt;
    return hasher.GetSHA256();
}

} // namespace chainregistry
