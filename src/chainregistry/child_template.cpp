// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_template.h>

#include <hash.h>
#include <pubkey.h>
#include <streams.h>

#include <ios>
#include <string>
#include <utility>

namespace chainregistry {
namespace {

ReferenceChildResult DefinitionError(
    ReferenceChildError error,
    ReferenceChildParametersError parameters_error = ReferenceChildParametersError::NONE,
    ManifestValidationError manifest_error = ManifestValidationError::NONE)
{
    ReferenceChildResult result;
    result.error = error;
    result.parameters_error = parameters_error;
    result.manifest_error = manifest_error;
    return result;
}

} // namespace

std::vector<unsigned char> SerializeReferenceChildParameters(
    const ReferenceChildParameters& parameters)
{
    std::vector<unsigned char> encoded;
    VectorWriter{encoded, 0} << parameters;
    return encoded;
}

ReferenceChildParametersError ValidateReferenceChildParameters(
    const ReferenceChildParameters& parameters)
{
    if (parameters.version != REFERENCE_CHILD_PARAMETERS_VERSION) {
        return ReferenceChildParametersError::UNSUPPORTED_VERSION;
    }
    if (parameters.max_block_weight < MIN_CHILD_BLOCK_WEIGHT ||
        parameters.max_block_weight > MAX_CHILD_BLOCK_WEIGHT ||
        parameters.max_block_weight % CHILD_BLOCK_WEIGHT_GRANULARITY != 0) {
        return ReferenceChildParametersError::INVALID_BLOCK_WEIGHT;
    }
    if (parameters.deposit_maturity < MIN_DEPOSIT_MATURITY ||
        parameters.deposit_maturity > MAX_DEPOSIT_MATURITY) {
        return ReferenceChildParametersError::INVALID_DEPOSIT_MATURITY;
    }
    return ReferenceChildParametersError::NONE;
}

ReferenceChildParametersResult ParseReferenceChildParameters(
    std::span<const unsigned char> encoded)
{
    try {
        SpanReader reader{encoded};
        ReferenceChildParameters parameters;
        reader >> parameters;
        if (!reader.empty()) {
            return {ReferenceChildParametersError::TRAILING_DATA, std::nullopt};
        }
        const auto error{ValidateReferenceChildParameters(parameters)};
        if (error != ReferenceChildParametersError::NONE) {
            return {error, std::nullopt};
        }
        return {ReferenceChildParametersError::NONE, std::move(parameters)};
    } catch (const std::ios_base::failure&) {
        return {ReferenceChildParametersError::MALFORMED, std::nullopt};
    }
}

ChainSpec MakeReferenceChildSpec(const ReferenceChildParameters& parameters)
{
    return ChainSpec{
        .protocol_version = PROTOCOL_VERSION,
        .template_id = REFERENCE_CHILD_TEMPLATE_ID,
        .template_version = REFERENCE_CHILD_TEMPLATE_VERSION,
        .consensus_parameters = SerializeReferenceChildParameters(parameters),
        .anchoring_policy = AnchoringPolicy::BMM_V1,
    };
}

uint256 ComputeReferenceChildInitialStateCommitment()
{
    return TaggedHash(std::string{CHILD_INITIAL_STATE_TAG}).GetSHA256();
}

uint256 ComputeReferenceChildGenesisHash(const ReferenceChildGenesis& genesis)
{
    auto hasher{TaggedHash(std::string{CHILD_GENESIS_TAG})};
    hasher << genesis;
    return hasher.GetSHA256();
}

ReferenceChildResult BuildReferenceChildDefinition(
    const uint256& main_genesis_hash,
    const COutPoint& registration_anchor,
    const ChainSpec& spec,
    const MetadataHash& initial_metadata_hash)
{
    if (main_genesis_hash.IsNull()) {
        return DefinitionError(ReferenceChildError::NULL_MAIN_GENESIS);
    }
    if (registration_anchor.IsNull()) {
        return DefinitionError(ReferenceChildError::NULL_REGISTRATION_ANCHOR);
    }
    if (initial_metadata_hash.IsNull()) {
        return DefinitionError(ReferenceChildError::NULL_METADATA_HASH);
    }
    if (spec.protocol_version != PROTOCOL_VERSION ||
        spec.template_id != REFERENCE_CHILD_TEMPLATE_ID ||
        spec.template_version != REFERENCE_CHILD_TEMPLATE_VERSION ||
        spec.anchoring_policy != AnchoringPolicy::BMM_V1) {
        return DefinitionError(ReferenceChildError::UNSUPPORTED_TEMPLATE);
    }

    const auto parsed{ParseReferenceChildParameters(spec.consensus_parameters)};
    if (!parsed.IsValid()) {
        return DefinitionError(ReferenceChildError::INVALID_PARAMETERS, parsed.error);
    }

    const ChainSpecHash spec_hash{ComputeChainSpecHash(spec)};
    const ChainId chain_id{DeriveChainId(main_genesis_hash, registration_anchor, spec_hash)};
    const ReferenceChildGenesis genesis{
        .chain_id = chain_id,
        .main_genesis_hash = main_genesis_hash,
        .registration_anchor = registration_anchor,
        .chain_spec_hash = spec_hash,
        .initial_state_commitment = ComputeReferenceChildInitialStateCommitment(),
    };
    const uint256 genesis_hash{ComputeReferenceChildGenesisHash(genesis)};
    const ChainManifest manifest{
        .spec = spec,
        .child_genesis_hash = genesis_hash,
        .initial_metadata_hash = initial_metadata_hash,
    };

    ReferenceChildResult result;
    result.definition = ReferenceChildDefinition{
        .parameters = *parsed.parameters,
        .chain_spec_hash = spec_hash,
        .chain_id = chain_id,
        .genesis = genesis,
        .genesis_hash = genesis_hash,
        .manifest = manifest,
        .manifest_hash = ComputeManifestHash(manifest),
    };
    return result;
}

ReferenceChildResult ValidateReferenceChildManifest(
    const uint256& main_genesis_hash,
    const COutPoint& registration_anchor,
    const ChainManifest& manifest)
{
    const auto manifest_error{ValidateManifest(manifest)};
    if (manifest_error != ManifestValidationError::NONE) {
        return DefinitionError(ReferenceChildError::INVALID_MANIFEST,
                               ReferenceChildParametersError::NONE,
                               manifest_error);
    }
    auto result{BuildReferenceChildDefinition(main_genesis_hash,
                                              registration_anchor,
                                              manifest.spec,
                                              manifest.initial_metadata_hash)};
    if (!result.IsValid()) return result;
    if (result.definition->genesis_hash != manifest.child_genesis_hash) {
        return DefinitionError(ReferenceChildError::GENESIS_MISMATCH);
    }
    result.definition->manifest = manifest;
    result.definition->manifest_hash = ComputeManifestHash(manifest);
    return result;
}

bool IsValidReferenceChildRecipient(uint16_t recipient_type,
                                    std::span<const unsigned char> recipient)
{
    return recipient_type == REFERENCE_CHILD_P2TR_RECIPIENT &&
           recipient.size() == XOnlyPubKey::size() &&
           XOnlyPubKey{recipient}.IsFullyValid();
}

} // namespace chainregistry
