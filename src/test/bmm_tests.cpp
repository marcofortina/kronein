// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/bmm.h>

#include <consensus/merkle.h>
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
constexpr uint256 CHILD_BLOCK{
    "2222222222222222222222222222222222222222222222222222222222222222"};

chainregistry::ChainRecord Record()
{
    return {
        .record_version = chainregistry::CHAIN_RECORD_VERSION,
        .chain_id = CHILD_CHAIN,
        .manifest_hash = chainregistry::ManifestHash{
            "3333333333333333333333333333333333333333333333333333333333333333"},
        .template_id = 1,
        .template_version = 1,
        .control_outpoint = COutPoint{
            Txid{"4444444444444444444444444444444444444444444444444444444444444444"}, 0},
        .metadata_hash = chainregistry::MetadataHash{
            "5555555555555555555555555555555555555555555555555555555555555555"},
        .status = chainregistry::ChainStatus::ACTIVE,
        .registered_height = 10,
        .updated_height = 10,
    };
}

chainregistry::BmmAnchorProof Proof()
{
    const auto record{Record()};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vout.emplace_back(
        0, chainregistry::BuildRegistryCommitment(registry.ComputeRoot()));

    CMutableTransaction proposal;
    proposal.vin.emplace_back(COutPoint{
        Txid{"6666666666666666666666666666666666666666666666666666666666666666"}, 1});
    proposal.vout.emplace_back(
        0,
        chainregistry::BuildBmmAnchorScript({
            .chain_id = CHILD_CHAIN,
            .child_block_hash = CHILD_BLOCK,
        }));

    CBlock block;
    block.nVersion = 1;
    block.nTime = 1;
    block.nBits = 0x207fffff;
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(proposal)};
    block.hashMerkleRoot = BlockMerkleRoot(block);

    return {
        .main_genesis_hash = MAIN_GENESIS,
        .block_height = 20,
        .block_header = block,
        .anchor_transaction = proposal,
        .transaction_index = 1,
        .transaction_merkle_branch = TransactionMerklePath(block, 1),
        .coinbase_transaction = coinbase,
        .coinbase_merkle_branch = TransactionMerklePath(block, 0),
        .chain_record = record,
        .registry_proof = *registry.GetInclusionProof(CHILD_CHAIN),
    };
}

} // namespace

BOOST_AUTO_TEST_SUITE(bmm_tests)

BOOST_AUTO_TEST_CASE(anchor_encoding_is_minimal_and_canonical)
{
    const chainregistry::BmmAnchor anchor{
        .chain_id = CHILD_CHAIN,
        .child_block_hash = CHILD_BLOCK,
    };
    const CScript script{chainregistry::BuildBmmAnchorScript(anchor)};
    BOOST_CHECK_EQUAL(chainregistry::BMM_ANCHOR_DATA_SIZE, 69U);
    BOOST_CHECK_EQUAL(script.size(), 71U);
    BOOST_CHECK_EQUAL(
        HexStr(script),
        "6a454b424d4d0111111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222");

    const auto parsed{chainregistry::ParseBmmAnchorScript(script)};
    BOOST_REQUIRE(parsed);
    BOOST_CHECK(*parsed.anchor == anchor);

    CMutableTransaction proposal;
    proposal.vout.emplace_back(0, script);
    const auto extracted{
        chainregistry::ExtractTransactionBmmAnchor(CTransaction{proposal})};
    BOOST_REQUIRE(extracted.IsValid());
    BOOST_REQUIRE(extracted.anchor.has_value());
    BOOST_CHECK(*extracted.anchor == anchor);
    BOOST_CHECK_EQUAL(*extracted.output_index, 0U);
}

BOOST_AUTO_TEST_CASE(anchor_parser_rejects_invalid_encodings)
{
    chainregistry::BmmAnchor anchor{
        .chain_id = CHILD_CHAIN,
        .child_block_hash = CHILD_BLOCK,
    };

    anchor.chain_id = {};
    auto parsed{chainregistry::ParseBmmAnchorScript(
        chainregistry::BuildBmmAnchorScript(anchor))};
    BOOST_CHECK(parsed.error == chainregistry::BmmAnchorParseError::INVALID_ANCHOR);

    anchor = {
        .chain_id = CHILD_CHAIN,
        .child_block_hash = {},
    };
    parsed = chainregistry::ParseBmmAnchorScript(
        chainregistry::BuildBmmAnchorScript(anchor));
    BOOST_CHECK(parsed.error == chainregistry::BmmAnchorParseError::INVALID_ANCHOR);

    std::vector<unsigned char> wrong_version(
        chainregistry::BMM_ANCHOR_MAGIC.begin(),
        chainregistry::BMM_ANCHOR_MAGIC.end());
    wrong_version.resize(chainregistry::BMM_ANCHOR_DATA_SIZE);
    wrong_version[4] = 2;
    parsed = chainregistry::ParseBmmAnchorScript(
        CScript{} << OP_RETURN << wrong_version);
    BOOST_CHECK(parsed.error ==
                chainregistry::BmmAnchorParseError::UNSUPPORTED_VERSION);

    CMutableTransaction proposal;
    const auto valid_script{chainregistry::BuildBmmAnchorScript({
        .chain_id = CHILD_CHAIN,
        .child_block_hash = CHILD_BLOCK,
    })};
    proposal.vout.emplace_back(1, valid_script);
    auto extracted{
        chainregistry::ExtractTransactionBmmAnchor(CTransaction{proposal})};
    BOOST_CHECK(extracted.error == chainregistry::TxBmmAnchorError::NONZERO_VALUE);

    proposal.vout[0].nValue = 0;
    proposal.vout.emplace_back(0, valid_script);
    extracted = chainregistry::ExtractTransactionBmmAnchor(CTransaction{proposal});
    BOOST_CHECK(extracted.error ==
                chainregistry::TxBmmAnchorError::MULTIPLE_ANCHORS);
}

BOOST_AUTO_TEST_CASE(canonical_proof_roundtrip_and_validation)
{
    const auto proof{Proof()};
    const auto result{chainregistry::ValidateBmmAnchorProofStructure(
        proof, MAIN_GENESIS, CHILD_CHAIN)};
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.anchor.has_value());
    BOOST_CHECK(result.anchor->chain_id == CHILD_CHAIN);
    BOOST_CHECK(result.anchor->child_block_hash == CHILD_BLOCK);

    DataStream stream;
    stream << proof;
    chainregistry::BmmAnchorProof decoded;
    stream >> decoded;
    BOOST_CHECK(stream.empty());
    const auto decoded_result{chainregistry::ValidateBmmAnchorProofStructure(
        decoded, MAIN_GENESIS, CHILD_CHAIN)};
    BOOST_REQUIRE(decoded_result.IsValid());
    BOOST_CHECK(decoded_result.anchor == result.anchor);
    BOOST_CHECK(decoded_result.registry_root == result.registry_root);
}

BOOST_AUTO_TEST_CASE(proof_rejects_wrong_domains_and_tampering)
{
    auto proof{Proof()};
    constexpr uint256 OTHER_GENESIS{
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
    constexpr chainregistry::ChainId OTHER_CHILD{
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"};

    proof.version = 2;
    auto result{chainregistry::ValidateBmmAnchorProofStructure(
        proof, MAIN_GENESIS, CHILD_CHAIN)};
    BOOST_CHECK(result.error ==
                chainregistry::BmmProofValidationError::UNSUPPORTED_VERSION);

    proof = Proof();
    result = chainregistry::ValidateBmmAnchorProofStructure(
        proof, OTHER_GENESIS, CHILD_CHAIN);
    BOOST_CHECK(result.error ==
                chainregistry::BmmProofValidationError::WRONG_MAIN_NETWORK);

    result = chainregistry::ValidateBmmAnchorProofStructure(
        proof, MAIN_GENESIS, OTHER_CHILD);
    BOOST_CHECK(result.error ==
                chainregistry::BmmProofValidationError::WRONG_CHILD_CHAIN);

    proof.transaction_index = 0;
    result = chainregistry::ValidateBmmAnchorProofStructure(
        proof, MAIN_GENESIS, CHILD_CHAIN);
    BOOST_CHECK(result.error ==
                chainregistry::BmmProofValidationError::INVALID_TRANSACTION_POSITION);

    proof = Proof();
    proof.transaction_merkle_branch[0].SetNull();
    result = chainregistry::ValidateBmmAnchorProofStructure(
        proof, MAIN_GENESIS, CHILD_CHAIN);
    BOOST_CHECK(result.error == chainregistry::BmmProofValidationError::
                                    TRANSACTION_MERKLE_ROOT_MISMATCH);

    proof = Proof();
    proof.registry_proof.leaf_index = 1;
    result = chainregistry::ValidateBmmAnchorProofStructure(
        proof, MAIN_GENESIS, CHILD_CHAIN);
    BOOST_CHECK(result.error ==
                chainregistry::BmmProofValidationError::INVALID_REGISTRY_PROOF);

    proof = Proof();
    proof.transaction_merkle_branch.resize(
        chainregistry::MAX_BMM_PROOF_MERKLE_BRANCH + 1);
    DataStream oversized;
    BOOST_CHECK_THROW(oversized << proof, std::ios_base::failure);
}

BOOST_AUTO_TEST_SUITE_END()
