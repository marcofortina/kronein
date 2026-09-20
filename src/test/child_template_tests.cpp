// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_template.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <vector>

BOOST_AUTO_TEST_SUITE(child_template_tests)

namespace {

const uint256 MAIN_GENESIS{"0000000000000000000000000000000000000000000000000000000000000001"};
const COutPoint REGISTRATION_ANCHOR{
    Txid::FromUint256(uint256{"0000000000000000000000000000000000000000000000000000000000000002"}),
    3,
};
const chainregistry::MetadataHash METADATA_HASH{chainregistry::MetadataHash::FromUint256(
    uint256{"0000000000000000000000000000000000000000000000000000000000000004"})};

} // namespace

BOOST_AUTO_TEST_CASE(parameters_are_closed_and_canonical)
{
    const chainregistry::ReferenceChildParameters parameters;
    const auto encoded{chainregistry::SerializeReferenceChildParameters(parameters)};
    BOOST_CHECK_EQUAL(encoded.size(), 9U);
    BOOST_CHECK_EQUAL(HexStr(encoded), "0100093d0090000000");

    const auto parsed{chainregistry::ParseReferenceChildParameters(encoded)};
    BOOST_REQUIRE(parsed.IsValid());
    BOOST_CHECK(*parsed.parameters == parameters);

    auto trailing{encoded};
    trailing.push_back(0);
    BOOST_CHECK(chainregistry::ParseReferenceChildParameters(trailing).error ==
                chainregistry::ReferenceChildParametersError::TRAILING_DATA);
    BOOST_CHECK(chainregistry::ParseReferenceChildParameters(
                    std::span<const unsigned char>{encoded}.first(encoded.size() - 1)).error ==
                chainregistry::ReferenceChildParametersError::MALFORMED);

    auto unsupported{parameters};
    unsupported.version = 2;
    BOOST_CHECK(chainregistry::ValidateReferenceChildParameters(unsupported) ==
                chainregistry::ReferenceChildParametersError::UNSUPPORTED_VERSION);

    auto invalid_weight{parameters};
    invalid_weight.max_block_weight = chainregistry::MIN_CHILD_BLOCK_WEIGHT + 1;
    BOOST_CHECK(chainregistry::ValidateReferenceChildParameters(invalid_weight) ==
                chainregistry::ReferenceChildParametersError::INVALID_BLOCK_WEIGHT);

    auto immature{parameters};
    immature.deposit_maturity = chainregistry::MIN_DEPOSIT_MATURITY - 1;
    BOOST_CHECK(chainregistry::ValidateReferenceChildParameters(immature) ==
                chainregistry::ReferenceChildParametersError::INVALID_DEPOSIT_MATURITY);

}

BOOST_AUTO_TEST_CASE(genesis_and_identity_are_deterministic)
{
    const auto spec{chainregistry::MakeReferenceChildSpec({})};
    const auto first{chainregistry::BuildReferenceChildDefinition(
        MAIN_GENESIS, REGISTRATION_ANCHOR, spec, METADATA_HASH)};
    const auto second{chainregistry::BuildReferenceChildDefinition(
        MAIN_GENESIS, REGISTRATION_ANCHOR, spec, METADATA_HASH)};
    BOOST_REQUIRE(first.IsValid());
    BOOST_REQUIRE(second.IsValid());
    BOOST_CHECK(*first.definition == *second.definition);
    BOOST_CHECK(!first.definition->chain_id.IsNull());
    BOOST_CHECK(!first.definition->genesis_hash.IsNull());
    BOOST_CHECK_EQUAL(first.definition->chain_spec_hash.GetHex(),
                      "2b3838a6f41877a1f14d9f8faab90d392990feaaa7d1e000140a1f99fdb6d0de");
    BOOST_CHECK_EQUAL(first.definition->chain_id.GetHex(),
                      "a711ee9c9407e1e4a951331e58024bc664a5dd5816c22cf36f91f7708160fbeb");
    BOOST_CHECK_EQUAL(first.definition->genesis.initial_state_commitment.GetHex(),
                      "047131d8250b2564ee43adc52ac8a2ddda45532d6a0ba1cb7b95b67f42030bdc");
    BOOST_CHECK_EQUAL(first.definition->genesis_hash.GetHex(),
                      "3f5d529fa3d5cdf81c5b97bc4a12aa193c17c40b3c1702739a7186f8a684409c");
    BOOST_CHECK_EQUAL(first.definition->manifest_hash.GetHex(),
                      "dcc1175363c84667ce09b77a56ff80ceaf754466a7adbd914bc47172b17adcd2");
    BOOST_CHECK(first.definition->manifest.child_genesis_hash ==
                first.definition->genesis_hash);
    BOOST_CHECK(first.definition->manifest_hash ==
                chainregistry::ComputeManifestHash(first.definition->manifest));

    const auto validated{chainregistry::ValidateReferenceChildManifest(
        MAIN_GENESIS, REGISTRATION_ANCHOR, first.definition->manifest)};
    BOOST_REQUIRE(validated.IsValid());
    BOOST_CHECK(*validated.definition == *first.definition);

    COutPoint other_anchor{REGISTRATION_ANCHOR};
    ++other_anchor.n;
    const auto other{chainregistry::BuildReferenceChildDefinition(
        MAIN_GENESIS, other_anchor, spec, METADATA_HASH)};
    BOOST_REQUIRE(other.IsValid());
    BOOST_CHECK(other.definition->chain_id != first.definition->chain_id);
    BOOST_CHECK(other.definition->genesis_hash != first.definition->genesis_hash);
}

BOOST_AUTO_TEST_CASE(manifest_cannot_claim_another_genesis)
{
    const auto built{chainregistry::BuildReferenceChildDefinition(
        MAIN_GENESIS,
        REGISTRATION_ANCHOR,
        chainregistry::MakeReferenceChildSpec({}),
        METADATA_HASH)};
    BOOST_REQUIRE(built.IsValid());

    auto manifest{built.definition->manifest};
    manifest.child_genesis_hash = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    const auto result{chainregistry::ValidateReferenceChildManifest(
        MAIN_GENESIS, REGISTRATION_ANCHOR, manifest)};
    BOOST_CHECK(result.error == chainregistry::ReferenceChildError::GENESIS_MISMATCH);
}

BOOST_AUTO_TEST_CASE(rejects_unsupported_or_ambiguous_definitions)
{
    auto spec{chainregistry::MakeReferenceChildSpec({})};
    ++spec.template_version;
    BOOST_CHECK(chainregistry::BuildReferenceChildDefinition(
                    MAIN_GENESIS, REGISTRATION_ANCHOR, spec, METADATA_HASH).error ==
                chainregistry::ReferenceChildError::UNSUPPORTED_TEMPLATE);

    spec = chainregistry::MakeReferenceChildSpec({});
    spec.consensus_parameters.push_back(0);
    const auto parameters_error{chainregistry::BuildReferenceChildDefinition(
        MAIN_GENESIS, REGISTRATION_ANCHOR, spec, METADATA_HASH)};
    BOOST_CHECK(parameters_error.error == chainregistry::ReferenceChildError::INVALID_PARAMETERS);
    BOOST_CHECK(parameters_error.parameters_error ==
                chainregistry::ReferenceChildParametersError::TRAILING_DATA);

    BOOST_CHECK(chainregistry::BuildReferenceChildDefinition(
                    {}, REGISTRATION_ANCHOR, chainregistry::MakeReferenceChildSpec({}), METADATA_HASH).error ==
                chainregistry::ReferenceChildError::NULL_MAIN_GENESIS);
    BOOST_CHECK(chainregistry::BuildReferenceChildDefinition(
                    MAIN_GENESIS, {}, chainregistry::MakeReferenceChildSpec({}), METADATA_HASH).error ==
                chainregistry::ReferenceChildError::NULL_REGISTRATION_ANCHOR);
    BOOST_CHECK(chainregistry::BuildReferenceChildDefinition(
                    MAIN_GENESIS,
                    REGISTRATION_ANCHOR,
                    chainregistry::MakeReferenceChildSpec({}),
                    {}).error == chainregistry::ReferenceChildError::NULL_METADATA_HASH);
}

BOOST_AUTO_TEST_CASE(recipient_namespace_is_strict)
{
    const std::array<unsigned char, 32> invalid_key{};
    constexpr std::array<unsigned char, 32> valid_key{
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
        0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
        0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
        0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    };
    BOOST_CHECK(chainregistry::IsValidReferenceChildRecipient(
        chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT, valid_key));
    BOOST_CHECK(!chainregistry::IsValidReferenceChildRecipient(
        chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT, invalid_key));
    BOOST_CHECK(!chainregistry::IsValidReferenceChildRecipient(2, valid_key));
    BOOST_CHECK(!chainregistry::IsValidReferenceChildRecipient(
        chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT,
        std::span<const unsigned char>{valid_key}.first(31)));
}

BOOST_AUTO_TEST_SUITE_END()
