// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/deposit_proof.h>

#include <consensus/merkle.h>
#include <primitives/deposit.h>
#include <streams.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string_view>
#include <vector>

namespace {

constexpr uint256 MAIN_GENESIS{
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
constexpr chainregistry::ChainId CHILD_CHAIN{
    "1111111111111111111111111111111111111111111111111111111111111111"};

chainregistry::ChainRecord Record()
{
    return {
        .record_version = chainregistry::CHAIN_RECORD_VERSION,
        .chain_id = CHILD_CHAIN,
        .manifest_hash = chainregistry::ManifestHash{
            "2222222222222222222222222222222222222222222222222222222222222222"},
        .template_id = 1,
        .template_version = 1,
        .control_outpoint = COutPoint{
            Txid{"3333333333333333333333333333333333333333333333333333333333333333"}, 0},
        .metadata_hash = chainregistry::MetadataHash{
            "4444444444444444444444444444444444444444444444444444444444444444"},
        .status = chainregistry::ChainStatus::ACTIVE,
        .registered_height = 10,
        .updated_height = 10,
        .retired_height = 0,
    };
}

chainregistry::DepositProof Proof()
{
    const auto record{Record()};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vout.emplace_back(
        0, chainregistry::BuildRegistryCommitment(registry.ComputeRoot()));

    CMutableTransaction funding;
    funding.vin.emplace_back(COutPoint{
        Txid{"5555555555555555555555555555555555555555555555555555555555555555"}, 0});
    funding.vout.emplace_back(
        50'000,
        chainregistry::BuildFundScript({
            .chain_id = CHILD_CHAIN,
            .recipient_type = 1,
            .recipient = std::vector<unsigned char>(32, 0x42),
        }));

    CBlock block;
    block.nVersion = 1;
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
        .registry_proof = *registry.GetInclusionProof(CHILD_CHAIN),
    };
}

} // namespace

BOOST_AUTO_TEST_SUITE(deposit_proof_tests)

BOOST_AUTO_TEST_CASE(canonical_roundtrip_and_validation)
{
    const auto proof{Proof()};
    const auto result{chainregistry::ValidateDepositProofStructure(
        proof, MAIN_GENESIS, CHILD_CHAIN)};
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.fund.has_value());
    BOOST_CHECK_EQUAL(result.fund->amount, 50'000);
    BOOST_CHECK(result.fund->fund.chain_id == CHILD_CHAIN);
    const auto commitment{chainregistry::ExtractRegistryCommitment(
        CTransaction{proof.coinbase_transaction})};
    BOOST_REQUIRE(commitment.root.has_value());
    BOOST_CHECK(result.registry_root == *commitment.root);
    BOOST_CHECK(result.deposit_id == chainregistry::DeriveDepositId(
        MAIN_GENESIS,
        COutPoint{CTransaction{proof.funding_transaction}.GetHash(), proof.funding_vout}));

    DataStream stream;
    stream << proof;
    // Independently derived from the v3 layout with Python hashlib/struct.
    constexpr std::string_view expected_proof_hex{
        "4b44505203aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1400000001000000000000"
        "0000000000000000000000000000000000000000000000000000000000db9bb002af1d4426264c2db32fd32b37fe4789"
        "023dfe92406a4822d2fd23b5e801000000ffff7f20000000000100000001555555555555555555555555555555555555"
        "55555555555555555555555555550000000000ffffffff0150c30000000000004a6a484b464e44011111111111111111"
        "111111111111111111111111111111111111111111111111010020424242424242424242424242424242424242424242"
        "4242424242424242424242000000000000000001000000019468b871833802cff0d6e60845a3fcfcd2bef3afd6aaa0bf"
        "36b8fccfc71880dc01000000010000000000000000000000000000000000000000000000000000000000000000ffffff"
        "ff00ffffffff010000000000000000276a254b5252540333036409e81c06b8f70c0b90598c6065b5f3319faf6b7fd030"
        "29485bf1564f3100000000018a2fef917bcc6c28e988135be6ccea6ae9d3f2b5d479d9520e3c581733fcb43401111111"
        "111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222"
        "222222222222222222222222220100000001000000333333333333333333333333333333333333333333333333333333"
        "3333333333000000004444444444444444444444444444444444444444444444444444444444444444010a0000000a00"
        "00000000000001000000000000000000000000000000004c26fbd550dc1fbd5a3ddc411e4451847b88fa0955bc2debae"
        "e0a5761f9b8d950000000000000000db7daf32a14c56ec8da3ebe4d66969c8b3431a798252ac173928cf7e2d929bee"};
    BOOST_CHECK_EQUAL(HexStr(stream), expected_proof_hex);
    chainregistry::DepositProof decoded;
    stream >> decoded;
    BOOST_CHECK(stream.empty());
    const auto decoded_result{chainregistry::ValidateDepositProofStructure(
        decoded, MAIN_GENESIS, CHILD_CHAIN)};
    BOOST_REQUIRE(decoded_result.IsValid());
    BOOST_CHECK(decoded_result.deposit_id == result.deposit_id);
}

BOOST_AUTO_TEST_CASE(rejects_wrong_domains_and_tampering)
{
    auto proof{Proof()};
    constexpr uint256 other_genesis{
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
    constexpr chainregistry::ChainId other_child{
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"};

    proof.version = 4;
    auto result{chainregistry::ValidateDepositProofStructure(
        proof, MAIN_GENESIS, CHILD_CHAIN)};
    BOOST_CHECK(result.error == chainregistry::DepositProofValidationError::UNSUPPORTED_VERSION);

    proof = Proof();
    result = chainregistry::ValidateDepositProofStructure(
        proof, other_genesis, CHILD_CHAIN);
    BOOST_CHECK(result.error == chainregistry::DepositProofValidationError::WRONG_MAIN_NETWORK);

    result = chainregistry::ValidateDepositProofStructure(proof, MAIN_GENESIS, other_child);
    BOOST_CHECK(result.error == chainregistry::DepositProofValidationError::WRONG_CHILD_CHAIN);

    proof.transaction_merkle_branch[0].SetNull();
    result = chainregistry::ValidateDepositProofStructure(proof, MAIN_GENESIS, CHILD_CHAIN);
    BOOST_CHECK(result.error ==
                chainregistry::DepositProofValidationError::TRANSACTION_MERKLE_ROOT_MISMATCH);

    proof = Proof();
    proof.registry_proof.leaf_index = 1;
    result = chainregistry::ValidateDepositProofStructure(proof, MAIN_GENESIS, CHILD_CHAIN);
    BOOST_CHECK(result.error == chainregistry::DepositProofValidationError::INVALID_REGISTRY_PROOF);

    proof = Proof();
    proof.coinbase_transaction.vout[0].scriptPubKey.clear();
    result = chainregistry::ValidateDepositProofStructure(proof, MAIN_GENESIS, CHILD_CHAIN);
    BOOST_CHECK(result.error ==
                chainregistry::DepositProofValidationError::COINBASE_MERKLE_ROOT_MISMATCH);

    proof = Proof();
    proof.transaction_merkle_branch.resize(
        chainregistry::MAX_DEPOSIT_PROOF_MERKLE_BRANCH + 1);
    DataStream oversized;
    BOOST_CHECK_THROW(oversized << proof, std::ios_base::failure);
}

BOOST_AUTO_TEST_SUITE_END()
