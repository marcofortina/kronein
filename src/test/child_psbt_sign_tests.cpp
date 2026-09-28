// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_psbt.h>
#include <chainregistry/child_psbt_sign.h>
#include <chainregistry/child_sighash.h>

#include <addresstype.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <vector>

namespace {

const chainregistry::ChainId CHILD_A{
    "1111111111111111111111111111111111111111111111111111111111111111"};
const chainregistry::ChainId CHILD_B{
    "2222222222222222222222222222222222222222222222222222222222222222"};

CKey TestKey()
{
    constexpr std::array<unsigned char, 32> secret{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    };
    CKey key;
    key.Set(secret.begin(), secret.end(), /*fCompressedIn=*/true);
    return key;
}

chainregistry::ReferenceChildDefinition Definition(
    const chainregistry::ChainId& chain_id)
{
    chainregistry::ReferenceChildDefinition definition;
    definition.chain_id = chain_id;
    definition.genesis_hash = uint256{
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    return definition;
}

PartiallySignedTransaction UnsignedPSBT(
    const chainregistry::ReferenceChildDefinition& definition,
    const CTxOut& spent_output)
{
    CMutableTransaction transaction;
    transaction.vin.emplace_back(COutPoint{
        Txid{"3333333333333333333333333333333333333333333333333333333333333333"},
        0});
    transaction.vout.emplace_back(49'000, spent_output.scriptPubKey);
    PartiallySignedTransaction psbt{transaction};
    psbt.inputs.front().witness_utxo = spent_output;
    BOOST_REQUIRE(chainregistry::AddChildPSBTIdentity(
                      psbt,
                      chainregistry::MakeChildPSBTIdentity(definition)) ==
                  chainregistry::ChildPSBTIdentityError::NONE);
    return psbt;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(child_psbt_sign_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sign_finalize_and_extract_use_child_domain)
{
    const CKey key{TestKey()};
    const XOnlyPubKey pubkey{key.GetPubKey()};
    const CTxOut spent_output{
        50'000,
        GetScriptForDestination(WitnessV1Taproot{pubkey})};
    const auto definition{Definition(CHILD_A)};
    auto psbt{UnsignedPSBT(definition, spent_output)};
    const auto txdata{PrecomputePSBTData(psbt)};
    BOOST_REQUIRE(txdata.has_value());

    FlatSigningProvider provider;
    provider.keys.emplace(key.GetPubKey().GetID(), key);
    const auto signed_result{chainregistry::UpdateChildPSBTInput(
        provider,
        psbt,
        0,
        definition,
        *txdata,
        SIGHASH_DEFAULT,
        /*finalize=*/false)};
    BOOST_REQUIRE(signed_result.IsValid());
    BOOST_CHECK(signed_result.signature_complete);
    BOOST_CHECK(!psbt.inputs.front().m_tap_key_sig.empty());
    BOOST_CHECK(psbt.inputs.front().final_script_witness.IsNull());

    auto standard_psbt{psbt};
    CMutableTransaction standard_transaction;
    BOOST_CHECK(!FinalizeAndExtractPSBT(
        standard_psbt, standard_transaction));

    CMutableTransaction child_transaction;
    const auto finalized{chainregistry::FinalizeAndExtractChildPSBT(
        psbt, definition, child_transaction)};
    BOOST_REQUIRE(finalized.IsValid());
    BOOST_CHECK(finalized.signature_complete);
    BOOST_CHECK(!child_transaction.vin.front().scriptWitness.IsNull());

    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const CTransaction immutable{child_transaction};
    const chainregistry::ReferenceChildTransactionSignatureChecker checker{
        CHILD_A, &immutable, 0, *txdata, MissingDataBehavior::FAIL};
    BOOST_CHECK(VerifyScript(immutable.vin.front().scriptSig,
                             spent_output.scriptPubKey,
                             &immutable.vin.front().scriptWitness,
                             STANDARD_SCRIPT_VERIFY_FLAGS,
                             checker,
                             &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(signer_rejects_stripped_mismatched_and_foreign_signatures)
{
    const CKey key{TestKey()};
    const XOnlyPubKey pubkey{key.GetPubKey()};
    const CTxOut spent_output{
        50'000,
        GetScriptForDestination(WitnessV1Taproot{pubkey})};
    const auto definition_a{Definition(CHILD_A)};
    const auto definition_b{Definition(CHILD_B)};
    auto psbt{UnsignedPSBT(definition_a, spent_output)};
    const auto txdata{PrecomputePSBTData(psbt)};
    BOOST_REQUIRE(txdata.has_value());

    FlatSigningProvider provider;
    provider.keys.emplace(key.GetPubKey().GetID(), key);

    auto stripped{psbt};
    stripped.m_proprietary.clear();
    const auto stripped_result{chainregistry::UpdateChildPSBTInput(
        provider, stripped, 0, definition_a, *txdata)};
    BOOST_CHECK(stripped_result.error ==
                chainregistry::ChildPSBTSignError::INVALID_IDENTITY);
    BOOST_CHECK(stripped_result.identity_error ==
                chainregistry::ChildPSBTIdentityError::MISSING_CHAIN_ID);

    const auto mismatch_result{chainregistry::UpdateChildPSBTInput(
        provider, psbt, 0, definition_b, *txdata)};
    BOOST_CHECK(mismatch_result.error ==
                chainregistry::ChildPSBTSignError::INVALID_IDENTITY);
    BOOST_CHECK(mismatch_result.identity_error ==
                chainregistry::ChildPSBTIdentityError::CHAIN_ID_MISMATCH);

    auto main_signed{UnsignedPSBT(definition_a, spent_output)};
    BOOST_REQUIRE(SignPSBTInput(
        provider,
        main_signed,
        0,
        &*txdata,
        {.sign = true, .finalize = false})
                      .has_value());
    const auto foreign_result{chainregistry::UpdateChildPSBTInput(
        provider, main_signed, 0, definition_a, *txdata)};
    BOOST_CHECK(foreign_result.error ==
                chainregistry::ChildPSBTSignError::INVALID_SIGNATURE);
}

BOOST_AUTO_TEST_SUITE_END()
