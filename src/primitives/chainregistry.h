// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PRIMITIVES_CHAINREGISTRY_H
#define BITCOIN_PRIMITIVES_CHAINREGISTRY_H

#include <attributes.h>
#include <consensus/amount.h>
#include <primitives/dealerauthority.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

class COutPoint;
class CTransaction;

namespace chainregistry {

namespace detail {
struct ChainIdTag {};
struct ChainSpecHashTag {};
struct ManifestHashTag {};
struct MetadataHashTag {};
struct DepositIdTag {};
struct DealerIdTag {};
} // namespace detail

/** A strongly typed 256-bit protocol identifier. */
template <typename Tag>
class Identifier
{
private:
    uint256 m_value;

    explicit Identifier(const uint256& value) : m_value{value} {}

public:
    Identifier() = default;
    consteval explicit Identifier(std::string_view hex) : m_value{hex} {}

    static Identifier FromUint256(const uint256& value) { return Identifier{value}; }
    static std::optional<Identifier> FromHex(std::string_view hex)
    {
        const auto value{uint256::FromHex(hex)};
        if (!value) return std::nullopt;
        return FromUint256(*value);
    }

    const uint256& ToUint256() const LIFETIMEBOUND { return m_value; }
    bool IsNull() const { return m_value.IsNull(); }
    std::string GetHex() const { return m_value.GetHex(); }
    std::string ToString() const { return m_value.ToString(); }

    static constexpr size_t size() { return uint256::size(); }
    const std::byte* begin() const { return reinterpret_cast<const std::byte*>(m_value.begin()); }
    const std::byte* end() const { return reinterpret_cast<const std::byte*>(m_value.end()); }

    friend bool operator==(const Identifier&, const Identifier&) = default;
    friend std::strong_ordering operator<=>(const Identifier& lhs, const Identifier& rhs)
    {
        return lhs.m_value.Compare(rhs.m_value) <=> 0;
    }

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        m_value.Serialize(stream);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        m_value.Unserialize(stream);
    }
};

/** Stable identity of a registered child chain. */
using ChainId = Identifier<detail::ChainIdTag>;
/** Tagged hash of the canonical pre-genesis consensus specification. */
using ChainSpecHash = Identifier<detail::ChainSpecHashTag>;
/** Tagged hash of the final manifest, including the derived genesis hash. */
using ManifestHash = Identifier<detail::ManifestHashTag>;
/** Hash commitment to mutable, externally stored display metadata. */
using MetadataHash = Identifier<detail::MetadataHashTag>;
/** Stable identity of a main-chain burn output. */
using DepositId = Identifier<detail::DepositIdTag>;
/** Stable identity of an authorized child-chain dealer. */
using DealerId = Identifier<detail::DealerIdTag>;

inline constexpr std::string_view CHAIN_SPEC_HASH_TAG{"Kronein/ChainSpec/v1"};
inline constexpr std::string_view MANIFEST_HASH_TAG{"Kronein/ChainManifest/v1"};
inline constexpr std::string_view CHAIN_ID_TAG{"Kronein/ChainId/v1"};
inline constexpr std::string_view DEPOSIT_ID_TAG{"Kronein/DepositId/v1"};
inline constexpr std::string_view DEALER_ID_TAG{"Kronein/DealerId/v1"};
inline constexpr std::string_view DEALER_AUTHORITY_TAG{"Kronein/DealerAuthority/v2"};

inline constexpr uint16_t PROTOCOL_VERSION{1};
inline constexpr size_t MAX_CONSENSUS_PARAMETERS_SIZE{1024};
inline constexpr size_t MAX_FEE_RECIPIENT_SIZE{64};
inline constexpr size_t MAX_REGISTRY_DATA_SIZE{1400};
inline constexpr size_t DEALER_CONTROL_KEY_SIZE{32};
inline constexpr size_t DEALER_AUTHORITY_SIGNATURE_SIZE{64};
inline constexpr uint32_t DEALER_INITIAL_LICENSES{10};
inline constexpr uint32_t DEALER_MAX_ADDED_LICENSES{10};
inline constexpr std::array<unsigned char, 4> REGISTRY_MAGIC{'K', 'R', 'E', 'G'};
inline constexpr uint8_t REGISTRY_ENVELOPE_VERSION{1};
inline constexpr uint8_t DEALER_ENVELOPE_VERSION{2};

enum class AnchoringPolicy : uint8_t {
    BMM_V1 = 1,
};

/** Immutable pre-genesis parameters used to derive ChainId. */
struct ChainSpec {
    uint16_t protocol_version{PROTOCOL_VERSION};
    uint32_t template_id{0};
    uint32_t template_version{0};
    std::vector<unsigned char> consensus_parameters;
    AnchoringPolicy anchoring_policy{AnchoringPolicy::BMM_V1};

    SERIALIZE_METHODS(ChainSpec, obj)
    {
        uint8_t anchoring_policy;
        SER_WRITE(obj, anchoring_policy = static_cast<uint8_t>(obj.anchoring_policy));
        READWRITE(obj.protocol_version,
                  obj.template_id,
                  obj.template_version,
                  obj.consensus_parameters,
                  anchoring_policy);
        SER_READ(obj, obj.anchoring_policy = static_cast<AnchoringPolicy>(anchoring_policy));
    }

    friend bool operator==(const ChainSpec&, const ChainSpec&) = default;
};

/** Template-namespaced destination used when a child block producer omits one. */
struct DefaultFeeRecipient {
    uint16_t recipient_type{0};
    std::vector<unsigned char> recipient;

    SERIALIZE_METHODS(DefaultFeeRecipient, obj)
    {
        READWRITE(obj.recipient_type, obj.recipient);
    }

    friend bool operator==(const DefaultFeeRecipient&, const DefaultFeeRecipient&) = default;
};

/** Final registration manifest created after ChainId and genesis derivation. */
struct ChainManifest {
    ChainSpec spec;
    uint256 child_genesis_hash;
    MetadataHash initial_metadata_hash;
    DefaultFeeRecipient default_fee_recipient;

    SERIALIZE_METHODS(ChainManifest, obj)
    {
        READWRITE(obj.spec,
                  obj.child_genesis_hash,
                  obj.initial_metadata_hash,
                  obj.default_fee_recipient);
    }

    friend bool operator==(const ChainManifest&, const ChainManifest&) = default;
};

enum class ManifestValidationError : uint8_t {
    NONE,
    UNSUPPORTED_PROTOCOL_VERSION,
    INVALID_TEMPLATE_ID,
    INVALID_TEMPLATE_VERSION,
    CONSENSUS_PARAMETERS_TOO_LARGE,
    UNKNOWN_ANCHORING_POLICY,
    NULL_GENESIS,
    NULL_METADATA_HASH,
    INVALID_FEE_RECIPIENT_TYPE,
    INVALID_FEE_RECIPIENT_SIZE,
};

enum class OperationType : uint8_t {
    REGISTER = 1,
    UPDATE = 2,
    RETIRE = 3,
    AUTHORIZE_DEALER = 4,
    UPDATE_DEALER = 5,
    REVOKE_DEALER = 6,
};

/** Registration consumes vin[anchor_input] as its unique pre-existing anchor. */
struct RegisterChain {
    uint32_t anchor_input{std::numeric_limits<uint32_t>::max()};
    uint32_t control_output{std::numeric_limits<uint32_t>::max()};
    DealerId dealer_id;
    uint32_t dealer_control_output{std::numeric_limits<uint32_t>::max()};
    uint32_t dealer_payment_output{std::numeric_limits<uint32_t>::max()};
    ChainManifest manifest;

    SERIALIZE_METHODS(RegisterChain, obj)
    {
        READWRITE(obj.anchor_input,
                  obj.control_output,
                  obj.dealer_id,
                  obj.dealer_control_output,
                  obj.dealer_payment_output,
                  obj.manifest);
    }

    friend bool operator==(const RegisterChain&, const RegisterChain&) = default;
};

/** Update mutable metadata and rotate/recreate the control output. */
struct UpdateChain {
    ChainId chain_id;
    uint32_t control_output{std::numeric_limits<uint32_t>::max()};
    MetadataHash metadata_hash;

    SERIALIZE_METHODS(UpdateChain, obj)
    {
        READWRITE(obj.chain_id, obj.control_output, obj.metadata_hash);
    }

    friend bool operator==(const UpdateChain&, const UpdateChain&) = default;
};

/** Permanently retire a registered chain. */
struct RetireChain {
    ChainId chain_id;

    SERIALIZE_METHODS(RetireChain, obj) { READWRITE(obj.chain_id); }

    friend bool operator==(const RetireChain&, const RetireChain&) = default;
};

/** Create an authorized dealer with a bounded initial license allocation. */
struct AuthorizeDealer {
    uint64_t authority_sequence{0};
    uint256 authorization_nonce;
    std::array<unsigned char, DEALER_CONTROL_KEY_SIZE> control_key{};
    uint32_t control_output{std::numeric_limits<uint32_t>::max()};
    std::vector<unsigned char> payout_script;
    uint32_t initial_licenses{0};
    DealerAuthoritySignatures authority_signatures{};

    SERIALIZE_METHODS(AuthorizeDealer, obj)
    {
        READWRITE(obj.authority_sequence,
                  obj.authorization_nonce,
                  obj.control_key,
                  obj.control_output,
                  obj.payout_script,
                  obj.initial_licenses,
                  obj.authority_signatures);
    }

    friend bool operator==(const AuthorizeDealer&, const AuthorizeDealer&) = default;
};

/** Replenish a dealer and optionally replace its payout script. */
struct UpdateDealer {
    uint64_t authority_sequence{0};
    DealerId dealer_id;
    uint32_t added_licenses{0};
    std::vector<unsigned char> payout_script;
    DealerAuthoritySignatures authority_signatures{};

    SERIALIZE_METHODS(UpdateDealer, obj)
    {
        READWRITE(obj.authority_sequence,
                  obj.dealer_id,
                  obj.added_licenses,
                  obj.payout_script,
                  obj.authority_signatures);
    }

    friend bool operator==(const UpdateDealer&, const UpdateDealer&) = default;
};

/** Permanently prevent a dealer from selling more child-chain licenses. */
struct RevokeDealer {
    uint64_t authority_sequence{0};
    DealerId dealer_id;
    DealerAuthoritySignatures authority_signatures{};

    SERIALIZE_METHODS(RevokeDealer, obj)
    {
        READWRITE(obj.authority_sequence, obj.dealer_id, obj.authority_signatures);
    }

    friend bool operator==(const RevokeDealer&, const RevokeDealer&) = default;
};

using RegistryOperation = std::variant<RegisterChain,
                                       UpdateChain,
                                       RetireChain,
                                       AuthorizeDealer,
                                       UpdateDealer,
                                       RevokeDealer>;

enum class OperationValidationError : uint8_t {
    NONE,
    INVALID_ANCHOR_INPUT,
    INVALID_CONTROL_OUTPUT,
    INVALID_MANIFEST,
    NULL_CHAIN_ID,
    NULL_DEALER_ID,
    INVALID_DEALER_CONTROL_OUTPUT,
    INVALID_DEALER_PAYMENT_OUTPUT,
    INVALID_AUTHORITY_SEQUENCE,
    NULL_AUTHORIZATION_NONCE,
    INVALID_DEALER_CONTROL_KEY,
    INVALID_PAYOUT_SCRIPT,
    INVALID_LICENSE_COUNT,
    INVALID_AUTHORITY_SIGNATURE,
};

enum class OperationParseError : uint8_t {
    NONE,
    NOT_REGISTRY,
    MALFORMED_SCRIPT,
    DATA_TOO_LARGE,
    NON_CANONICAL_SCRIPT,
    UNSUPPORTED_ENVELOPE_VERSION,
    UNKNOWN_OPERATION_TYPE,
    INVALID_PAYLOAD,
    TRAILING_DATA,
    INVALID_OPERATION,
};

struct OperationParseResult {
    OperationParseError error{OperationParseError::NOT_REGISTRY};
    std::optional<RegistryOperation> operation;

    explicit operator bool() const { return error == OperationParseError::NONE && operation.has_value(); }
};

enum class TxOperationError : uint8_t {
    NONE,
    INVALID_ENVELOPE,
    MULTIPLE_OPERATIONS,
    INVALID_ANCHOR_INPUT,
    NULL_ANCHOR_PREVOUT,
    INVALID_CONTROL_OUTPUT,
    CONTROL_OUTPUT_COLLISION,
    CONTROL_OUTPUT_NOT_P2TR,
    OUTPUT_COLLISION,
    INVALID_DEALER_PAYMENT,
    UNEXPECTED_OPERATION_VALUE,
};

struct TransactionOperation {
    uint32_t registry_output;
    RegistryOperation operation;

    friend bool operator==(const TransactionOperation&, const TransactionOperation&) = default;
};

struct TxOperationResult {
    TxOperationError error{TxOperationError::NONE};
    OperationParseError parse_error{OperationParseError::NONE};
    std::optional<TransactionOperation> operation;

    bool IsValid() const { return error == TxOperationError::NONE; }
};

/** Hash canonical pre-genesis specification bytes. This function does not validate their schema. */
ChainSpecHash ComputeChainSpecHash(std::span<const std::byte> canonical_spec);
ChainSpecHash ComputeChainSpecHash(const ChainSpec& spec);
ManifestHash ComputeManifestHash(const ChainManifest& manifest);

ManifestValidationError ValidateChainSpec(const ChainSpec& spec);
ManifestValidationError ValidateManifest(const ChainManifest& manifest);
OperationValidationError ValidateOperation(const RegistryOperation& operation);
OperationType GetOperationType(const RegistryOperation& operation);

/** Serialize an operation without validating it. */
CScript BuildOperationScript(const RegistryOperation& operation);
/** Parse and validate the canonical OP_RETURN envelope used by registry operations. */
OperationParseResult ParseOperationScript(const CScript& script);

/**
 * Find and perform context-free transaction checks for a registry operation.
 * A valid transaction without an operation returns NONE and std::nullopt.
 * State-dependent authorization and uniqueness checks are performed by the
 * registry state transition code.
 */
TxOperationResult ExtractTransactionOperation(const CTransaction& tx);

/**
 * Derive a child-chain identity from the main network, registration outpoint,
 * and immutable pre-genesis specification hash. The registration outpoint is
 * an existing UTXO consumed by the registration transaction, so the identity
 * is known before the child genesis is generated.
 */
ChainId DeriveChainId(const uint256& main_genesis_hash,
                      const COutPoint& registration_outpoint,
                      const ChainSpecHash& spec_hash);

/** Derive the identity consumed by a one-way child-chain import. */
DepositId DeriveDepositId(const uint256& main_genesis_hash, const COutPoint& burn_outpoint);

DealerId DeriveDealerId(const uint256& main_genesis_hash,
                        const uint256& authorization_nonce,
                        std::span<const unsigned char, DEALER_CONTROL_KEY_SIZE> control_key);

/** Domain-separated digest signed by the configured dealer authority. */
std::optional<uint256> ComputeDealerAuthorityHash(const uint256& main_genesis_hash,
                                                 const RegistryOperation& operation);

} // namespace chainregistry

#endif // BITCOIN_PRIMITIVES_CHAINREGISTRY_H
