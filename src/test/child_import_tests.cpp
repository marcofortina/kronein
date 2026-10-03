// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_import.h>

#include <consensus/chainregistry.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <primitives/deposit.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <vector>

namespace {

constexpr uint256 MAIN_GENESIS{
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
const COutPoint REGISTRATION_ANCHOR{
    Txid{"1111111111111111111111111111111111111111111111111111111111111111"}, 1};
const chainregistry::MetadataHash METADATA_HASH{
    "4444444444444444444444444444444444444444444444444444444444444444"};
constexpr std::array<unsigned char, 32> RECIPIENT{
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
};

chainregistry::ReferenceChildDefinition Definition(
    chainregistry::ReferenceChildParameters parameters = {})
{
    const auto result{chainregistry::BuildReferenceChildDefinition(
        MAIN_GENESIS,
        REGISTRATION_ANCHOR,
        chainregistry::MakeReferenceChildSpec(parameters),
        METADATA_HASH,
        RECIPIENT)};
    BOOST_REQUIRE(result.IsValid());
    return *result.definition;
}

chainregistry::ChainRecord Record(
    const chainregistry::ReferenceChildDefinition& definition)
{
    return {
        .record_version = chainregistry::CHAIN_RECORD_VERSION,
        .chain_id = definition.chain_id,
        .manifest_hash = definition.manifest_hash,
        .template_id = chainregistry::REFERENCE_CHILD_TEMPLATE_ID,
        .template_version = chainregistry::REFERENCE_CHILD_TEMPLATE_VERSION,
        .control_outpoint = COutPoint{
            Txid{"3333333333333333333333333333333333333333333333333333333333333333"}, 0},
        .metadata_hash = METADATA_HASH,
        .status = chainregistry::ChainStatus::ACTIVE,
        .registered_height = 10,
        .updated_height = 10,
    };
}

chainregistry::DepositProof Proof(
    const chainregistry::ReferenceChildDefinition& definition)
{
    const auto record{Record(definition)};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vin.front().scriptSig = CScript{} << std::vector<unsigned char>{0, 0};
    coinbase.vout.emplace_back(
        0, chainregistry::BuildRegistryCommitment(registry.ComputeRoot()));

    CMutableTransaction funding;
    funding.vin.emplace_back(COutPoint{
        Txid{"5555555555555555555555555555555555555555555555555555555555555555"}, 0});
    funding.vout.emplace_back(
        50'000,
        chainregistry::BuildFundScript({
            .chain_id = definition.chain_id,
            .recipient_type = chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT,
            .recipient = {RECIPIENT.begin(), RECIPIENT.end()},
        }));

    CBlock block;
    block.nVersion = CBlockHeader::CURRENT_VERSION;
    block.nTime = 1;
    block.nBits = 0x207fffff;
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(funding)};
    block.hashMerkleRoot = BlockMerkleRoot(block);

    return {
        .main_genesis_hash = MAIN_GENESIS,
        .block_height = 20,
        .block_header = block,
        .funding_transaction = funding,
        .funding_vout = 0,
        .transaction_index = 1,
        .transaction_merkle_branch = TransactionMerklePath(block, 1),
        .coinbase_transaction = coinbase,
        .coinbase_merkle_branch = TransactionMerklePath(block, 0),
        .chain_record = record,
        .registry_proof = *registry.GetInclusionProof(definition.chain_id),
    };
}

} // namespace

BOOST_AUTO_TEST_SUITE(child_import_tests)

BOOST_AUTO_TEST_CASE(canonical_import_reuses_native_transaction_rules)
{
    const auto definition{Definition()};
    const auto built{chainregistry::BuildReferenceChildImportTransaction(
        Proof(definition), definition)};
    BOOST_REQUIRE(built.IsValid());
    const CTransaction transaction{*built.transaction};
    BOOST_CHECK(chainregistry::IsReferenceChildImport(transaction));
    BOOST_CHECK(!transaction.IsCoinBase());
    BOOST_REQUIRE_EQUAL(transaction.vin.size(), 1U);
    BOOST_REQUIRE_EQUAL(transaction.vout.size(), 1U);
    BOOST_CHECK_EQUAL(transaction.vin.front().prevout.n,
                      chainregistry::CHILD_IMPORT_PREVOUT_INDEX);
    BOOST_CHECK(transaction.vin.front().prevout.hash.ToUint256() ==
                built.deposit_id->ToUint256());
    BOOST_CHECK_EQUAL(transaction.vout.front().nValue, 50'000);
    BOOST_CHECK_EQUAL(transaction.GetHash().GetHex(),
                      "c25edea4695f5a4d9370cf64f227babbca995bdfd105cb94fca19c258cf6d8c4");
    // KDPR v3 binds authority state inside the witness. The base transaction
    // (and deposit identity) stays unchanged across this proof-format update.
    BOOST_CHECK_EQUAL(transaction.GetWitnessHash().GetHex(),
                      "3af5373ca5485e71810bba38221be156647b801a7ba1850c0cc90acd18d1ebab");

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(transaction, state));
    BOOST_CHECK(CheckNativeTransaction(transaction, state));
    BOOST_CHECK_LE(GetTransactionWeight(transaction),
                   definition.parameters.max_block_weight);

    const auto parsed{chainregistry::ParseReferenceChildImportTransaction(
        transaction, definition)};
    BOOST_REQUIRE(parsed.IsValid());
    BOOST_CHECK(parsed.deposit_id == built.deposit_id);
    BOOST_CHECK(parsed.proof->chain_record.chain_id == definition.chain_id);
}

BOOST_AUTO_TEST_CASE(rejects_malleated_base_or_witness_fields)
{
    const auto definition{Definition()};
    const auto built{chainregistry::BuildReferenceChildImportTransaction(
        Proof(definition), definition)};
    BOOST_REQUIRE(built.IsValid());

    auto transaction{*built.transaction};
    transaction.vin.front().scriptWitness.SetNull();
    BOOST_CHECK(chainregistry::ParseReferenceChildImportTransaction(
                    CTransaction{transaction}, definition).error ==
                chainregistry::ChildImportError::INVALID_WITNESS);

    transaction = *built.transaction;
    transaction.vin.front().scriptWitness.stack.emplace_back();
    BOOST_CHECK(chainregistry::ParseReferenceChildImportTransaction(
                    CTransaction{transaction}, definition).error ==
                chainregistry::ChildImportError::INVALID_WITNESS);

    transaction = *built.transaction;
    transaction.vin.front().scriptWitness.stack.front().push_back(0);
    BOOST_CHECK(chainregistry::ParseReferenceChildImportTransaction(
                    CTransaction{transaction}, definition).error ==
                chainregistry::ChildImportError::PROOF_TRAILING_DATA);

    transaction = *built.transaction;
    transaction.vin.front().prevout.hash = Txid::FromUint256(uint256{1});
    BOOST_CHECK(chainregistry::ParseReferenceChildImportTransaction(
                    CTransaction{transaction}, definition).error ==
                chainregistry::ChildImportError::DEPOSIT_ID_MISMATCH);

    transaction = *built.transaction;
    ++transaction.vout.front().nValue;
    BOOST_CHECK(chainregistry::ParseReferenceChildImportTransaction(
                    CTransaction{transaction}, definition).error ==
                chainregistry::ChildImportError::INVALID_OUTPUT);

    transaction = *built.transaction;
    transaction.nLockTime = 1;
    BOOST_CHECK(chainregistry::ParseReferenceChildImportTransaction(
                    CTransaction{transaction}, definition).error ==
                chainregistry::ChildImportError::INVALID_SHAPE);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_recipient_and_resource_limits)
{
    const auto definition{Definition()};
    auto proof{Proof(definition)};
    proof.funding_transaction.vout.front().scriptPubKey =
        chainregistry::BuildFundScript({
            .chain_id = definition.chain_id,
            .recipient_type = chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT,
            .recipient = std::vector<unsigned char>(32),
        });
    CBlock block;
    block.nVersion = proof.block_header.nVersion;
    block.nTime = proof.block_header.nTime;
    block.nBits = proof.block_header.nBits;
    block.vtx = {MakeTransactionRef(proof.coinbase_transaction),
                 MakeTransactionRef(proof.funding_transaction)};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    proof.block_header.hashMerkleRoot = block.hashMerkleRoot;
    proof.transaction_merkle_branch = TransactionMerklePath(block, 1);
    proof.coinbase_merkle_branch = TransactionMerklePath(block, 0);

    const auto invalid_recipient{chainregistry::BuildReferenceChildImportTransaction(
        proof, definition)};
    BOOST_CHECK(invalid_recipient.error ==
                chainregistry::ChildImportError::INVALID_RECIPIENT);

    auto small{chainregistry::ReferenceChildParameters{}};
    small.max_block_weight = chainregistry::MIN_CHILD_BLOCK_WEIGHT;
    const auto small_definition{Definition(small)};
    const auto valid{chainregistry::BuildReferenceChildImportTransaction(
        Proof(small_definition), small_definition)};
    BOOST_REQUIRE(valid.IsValid());

    small.max_block_weight = chainregistry::MIN_CHILD_BLOCK_WEIGHT - 1;
    auto invalid_definition{small_definition};
    invalid_definition.parameters = small;
    BOOST_CHECK(chainregistry::BuildReferenceChildImportTransaction(
                    Proof(small_definition), invalid_definition).error ==
                chainregistry::ChildImportError::INVALID_PARAMETERS);
}

BOOST_AUTO_TEST_CASE(rejects_another_network_or_manifest)
{
    const auto definition{Definition()};
    auto proof{Proof(definition)};
    proof.main_genesis_hash = uint256{
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
    auto result{chainregistry::BuildReferenceChildImportTransaction(
        proof, definition)};
    BOOST_CHECK(result.error == chainregistry::ChildImportError::INVALID_PROOF);
    BOOST_CHECK(result.proof_error ==
                chainregistry::DepositProofValidationError::WRONG_MAIN_NETWORK);

    const chainregistry::MetadataHash other_metadata{
        "6666666666666666666666666666666666666666666666666666666666666666"};
    const auto other_result{chainregistry::BuildReferenceChildDefinition(
        MAIN_GENESIS,
        REGISTRATION_ANCHOR,
        definition.manifest.spec,
        other_metadata,
        RECIPIENT)};
    BOOST_REQUIRE(other_result.IsValid());
    BOOST_CHECK(other_result.definition->chain_id == definition.chain_id);
    BOOST_CHECK(other_result.definition->manifest_hash != definition.manifest_hash);

    result = chainregistry::BuildReferenceChildImportTransaction(
        Proof(definition), *other_result.definition);
    BOOST_CHECK(result.error == chainregistry::ChildImportError::MANIFEST_MISMATCH);

    const auto built{chainregistry::BuildReferenceChildImportTransaction(
        Proof(definition), definition)};
    BOOST_REQUIRE(built.IsValid());
    const auto parsed{chainregistry::ParseReferenceChildImportTransaction(
        CTransaction{*built.transaction}, *other_result.definition)};
    BOOST_CHECK(parsed.error == chainregistry::ChildImportError::MANIFEST_MISMATCH);
}

BOOST_AUTO_TEST_SUITE_END()
