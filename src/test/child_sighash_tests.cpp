// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_sighash.h>

#include <addresstype.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

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
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    CKey key;
    key.Set(secret.begin(), secret.end(), /*fCompressedIn=*/true);
    return key;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(child_sighash_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(tagged_hash_is_stable_and_rejects_null_chain)
{
    constexpr uint256 base_sighash{
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    const auto child_sighash{
        chainregistry::ComputeReferenceChildSignatureHash(CHILD_A, base_sighash)};
    BOOST_REQUIRE(child_sighash.has_value());
    BOOST_CHECK_EQUAL(
        child_sighash->GetHex(),
        "c2faec0af29fb306fe0daf602ba0b45b37694d046c16ffa2563beb0f06f69908");
    BOOST_CHECK(!chainregistry::ComputeReferenceChildSignatureHash(
                     chainregistry::ChainId{}, base_sighash)
                     .has_value());
}

BOOST_AUTO_TEST_CASE(signature_cannot_replay_across_chain_domains)
{
    const CKey key{TestKey()};
    const XOnlyPubKey pubkey{key.GetPubKey()};
    const CTxOut spent_output{
        50'000,
        GetScriptForDestination(WitnessV1Taproot{pubkey})};

    CMutableTransaction mutable_transaction;
    mutable_transaction.vin.emplace_back(COutPoint{
        Txid{"3333333333333333333333333333333333333333333333333333333333333333"},
        0});
    mutable_transaction.vout.emplace_back(
        49'000,
        GetScriptForDestination(WitnessV1Taproot{pubkey}));

    PrecomputedTransactionData txdata;
    txdata.Init(mutable_transaction, std::vector<CTxOut>{spent_output});

    ScriptExecutionData execution_data;
    execution_data.m_annex_init = true;
    execution_data.m_annex_present = false;
    uint256 base_sighash;
    BOOST_REQUIRE(SignatureHashSchnorr(
        base_sighash,
        execution_data,
        mutable_transaction,
        0,
        SIGHASH_DEFAULT,
        SigVersion::TAPROOT,
        txdata,
        MissingDataBehavior::FAIL));

    const auto child_sighash{
        chainregistry::ComputeReferenceChildSignatureHash(CHILD_A, base_sighash)};
    BOOST_REQUIRE(child_sighash.has_value());
    std::vector<unsigned char> signature(64);
    BOOST_REQUIRE(key.SignSchnorr(*child_sighash,
                                 signature,
                                 /*merkle_root=*/nullptr,
                                 /*aux=*/{}));
    mutable_transaction.vin.front().scriptWitness.stack = {signature};
    const CTransaction transaction{mutable_transaction};

    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const chainregistry::ReferenceChildTransactionSignatureChecker child_a_checker{
        CHILD_A, &transaction, 0, txdata, MissingDataBehavior::FAIL};
    BOOST_CHECK(VerifyScript(transaction.vin.front().scriptSig,
                             spent_output.scriptPubKey,
                             &transaction.vin.front().scriptWitness,
                             STANDARD_SCRIPT_VERIFY_FLAGS,
                             child_a_checker,
                             &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    const chainregistry::ReferenceChildTransactionSignatureChecker child_b_checker{
        CHILD_B, &transaction, 0, txdata, MissingDataBehavior::FAIL};
    BOOST_CHECK(!VerifyScript(transaction.vin.front().scriptSig,
                              spent_output.scriptPubKey,
                              &transaction.vin.front().scriptWitness,
                              STANDARD_SCRIPT_VERIFY_FLAGS,
                              child_b_checker,
                              &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_SCHNORR_SIG);

    const TransactionSignatureChecker main_checker{
        &transaction, 0, txdata, MissingDataBehavior::FAIL};
    BOOST_CHECK(!VerifyScript(transaction.vin.front().scriptSig,
                              spent_output.scriptPubKey,
                              &transaction.vin.front().scriptWitness,
                              STANDARD_SCRIPT_VERIFY_FLAGS,
                              main_checker,
                              &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_SCHNORR_SIG);
}

BOOST_AUTO_TEST_SUITE_END()
