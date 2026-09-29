// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CHAINREGISTRY_CHILD_TEMPLATE_H
#define BITCOIN_CHAINREGISTRY_CHILD_TEMPLATE_H

#include <primitives/chainregistry.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace chainregistry {

inline constexpr uint32_t REFERENCE_CHILD_TEMPLATE_ID{1};
inline constexpr uint32_t REFERENCE_CHILD_TEMPLATE_VERSION{1};
inline constexpr uint8_t REFERENCE_CHILD_PARAMETERS_VERSION{1};
inline constexpr uint8_t REFERENCE_CHILD_GENESIS_VERSION{1};
inline constexpr uint16_t REFERENCE_CHILD_P2TR_RECIPIENT{1};

inline constexpr uint32_t MIN_CHILD_BLOCK_WEIGHT{400'000};
inline constexpr uint32_t MAX_CHILD_BLOCK_WEIGHT{4'000'000};
inline constexpr uint32_t CHILD_BLOCK_WEIGHT_GRANULARITY{4'000};
inline constexpr uint32_t MIN_DEPOSIT_MATURITY{100};
inline constexpr uint32_t MAX_DEPOSIT_MATURITY{2'016};
inline constexpr uint32_t DEFAULT_DEPOSIT_MATURITY{144};

inline constexpr std::string_view CHILD_INITIAL_STATE_TAG{"Kronein/ChildInitialState/v1"};
inline constexpr std::string_view CHILD_GENESIS_TAG{"Kronein/ChildGenesis/v1"};

/**
 * Closed parameter schema for the first child-chain template.
 *
 * Child blocks are secured and ordered by BMM anchors, so the template has no
 * independent PoW, difficulty adjustment, or block subsidy parameters.
 */
struct ReferenceChildParameters {
    uint8_t version{REFERENCE_CHILD_PARAMETERS_VERSION};
    uint32_t max_block_weight{MAX_CHILD_BLOCK_WEIGHT};
    uint32_t deposit_maturity{DEFAULT_DEPOSIT_MATURITY};

    SERIALIZE_METHODS(ReferenceChildParameters, obj)
    {
        READWRITE(obj.version,
                  obj.max_block_weight,
                  obj.deposit_maturity);
    }

    friend bool operator==(const ReferenceChildParameters&, const ReferenceChildParameters&) = default;
};

enum class ReferenceChildParametersError : uint8_t {
    NONE,
    MALFORMED,
    TRAILING_DATA,
    UNSUPPORTED_VERSION,
    INVALID_BLOCK_WEIGHT,
    INVALID_DEPOSIT_MATURITY,
};

struct ReferenceChildParametersResult {
    ReferenceChildParametersError error{ReferenceChildParametersError::NONE};
    std::optional<ReferenceChildParameters> parameters;

    bool IsValid() const { return error == ReferenceChildParametersError::NONE && parameters.has_value(); }
};

std::vector<unsigned char> SerializeReferenceChildParameters(
    const ReferenceChildParameters& parameters);
ReferenceChildParametersError ValidateReferenceChildParameters(
    const ReferenceChildParameters& parameters);
ReferenceChildParametersResult ParseReferenceChildParameters(
    std::span<const unsigned char> encoded);
ChainSpec MakeReferenceChildSpec(const ReferenceChildParameters& parameters);

/** Canonical descriptor whose tagged hash is the child genesis identity. */
struct ReferenceChildGenesis {
    uint8_t version{REFERENCE_CHILD_GENESIS_VERSION};
    ChainId chain_id;
    uint256 main_genesis_hash;
    COutPoint registration_anchor;
    ChainSpecHash chain_spec_hash;
    uint256 initial_state_commitment;

    SERIALIZE_METHODS(ReferenceChildGenesis, obj)
    {
        READWRITE(obj.version,
                  obj.chain_id,
                  obj.main_genesis_hash,
                  obj.registration_anchor,
                  obj.chain_spec_hash,
                  obj.initial_state_commitment);
    }

    friend bool operator==(const ReferenceChildGenesis&, const ReferenceChildGenesis&) = default;
};

struct ReferenceChildDefinition {
    ReferenceChildParameters parameters;
    ChainSpecHash chain_spec_hash;
    ChainId chain_id;
    ReferenceChildGenesis genesis;
    uint256 genesis_hash;
    ChainManifest manifest;
    ManifestHash manifest_hash;

    friend bool operator==(const ReferenceChildDefinition&, const ReferenceChildDefinition&) = default;
};

enum class ReferenceChildError : uint8_t {
    NONE,
    NULL_MAIN_GENESIS,
    NULL_REGISTRATION_ANCHOR,
    NULL_METADATA_HASH,
    UNSUPPORTED_TEMPLATE,
    INVALID_PARAMETERS,
    INVALID_MANIFEST,
    INVALID_FEE_RECIPIENT,
    GENESIS_MISMATCH,
};

struct ReferenceChildResult {
    ReferenceChildError error{ReferenceChildError::NONE};
    ReferenceChildParametersError parameters_error{ReferenceChildParametersError::NONE};
    ManifestValidationError manifest_error{ManifestValidationError::NONE};
    std::optional<ReferenceChildDefinition> definition;

    bool IsValid() const { return error == ReferenceChildError::NONE && definition.has_value(); }
};

uint256 ComputeReferenceChildInitialStateCommitment();
uint256 ComputeReferenceChildGenesisHash(const ReferenceChildGenesis& genesis);

/** Construct a canonical manifest and its deterministic genesis. */
ReferenceChildResult BuildReferenceChildDefinition(
    const uint256& main_genesis_hash,
    const COutPoint& registration_anchor,
    const ChainSpec& spec,
    const MetadataHash& initial_metadata_hash,
    std::span<const unsigned char> default_fee_recipient);

/** Recompute and verify every derived field in an externally supplied manifest. */
ReferenceChildResult ValidateReferenceChildManifest(
    const uint256& main_genesis_hash,
    const COutPoint& registration_anchor,
    const ChainManifest& manifest);

/** Template v1 accepts only 32-byte x-only Taproot output keys. */
bool IsValidReferenceChildRecipient(uint16_t recipient_type,
                                    std::span<const unsigned char> recipient);

} // namespace chainregistry

#endif // BITCOIN_CHAINREGISTRY_CHILD_TEMPLATE_H
