// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/deposit_import.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <pow.h>
#include <primitives/deposit.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

namespace {

constexpr chainregistry::ChainId CHILD_CHAIN{
    "1111111111111111111111111111111111111111111111111111111111111111"};

struct DepositImportSetup : BasicTestingSetup {
    DepositImportSetup()
        : BasicTestingSetup{ChainType::REGTEST}
    {
    }
};

chainregistry::ChainRecord ChildRecord()
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
        .registered_height = 0,
        .updated_height = 0,
        .retired_height = 0,
    };
}

CBlockHeader MineHeader(const CBlockIndex& parent,
                        const Consensus::Params& params,
                        uint8_t discriminator)
{
    CBlockHeader header;
    header.nVersion = CBlockHeader::CURRENT_VERSION;
    header.hashPrevBlock = parent.GetBlockHash();
    header.hashMerkleRoot = uint256{discriminator};
    header.nTime = parent.nTime + 1;
    header.nBits = GetNextWorkRequired(&parent, &header, params);

    const auto seed{GetRandomXSeed(&parent, parent.nHeight + 1, params)};
    BOOST_REQUIRE(seed.has_value());
    uint64_t max_tries{1'000'000};
    BOOST_REQUIRE(MineProofOfWork(
        header, *seed, params, max_tries, /*threads=*/1, /*use_full_memory=*/false));
    return header;
}

chainregistry::DepositProof MakeDepositProof(CBlock& block,
                                             const CBlockIndex& parent,
                                             const Consensus::Params& params)
{
    const auto record{ChildRecord()};
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

    block.nVersion = CBlockHeader::CURRENT_VERSION;
    block.hashPrevBlock = parent.GetBlockHash();
    block.nTime = parent.nTime + 1;
    block.nBits = GetNextWorkRequired(&parent, &block, params);
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(funding)};
    block.hashMerkleRoot = BlockMerkleRoot(block);

    const auto seed{GetRandomXSeed(&parent, parent.nHeight + 1, params)};
    BOOST_REQUIRE(seed.has_value());
    uint64_t max_tries{1'000'000};
    BOOST_REQUIRE(MineProofOfWork(
        block, *seed, params, max_tries, /*threads=*/1, /*use_full_memory=*/false));

    return {
        .main_genesis_hash = params.hashGenesisBlock,
        .block_height = static_cast<uint32_t>(parent.nHeight + 1),
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

BOOST_FIXTURE_TEST_SUITE(deposit_import_tests, DepositImportSetup)

BOOST_AUTO_TEST_CASE(import_is_mature_atomic_and_reversible_with_child_undo)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    chainregistry::MainHeaderChain main_headers{params};
    BOOST_REQUIRE(main_headers.Initialize(genesis).IsValid());
    const CBlockIndex* genesis_index{main_headers.Find(genesis.GetHash())};
    BOOST_REQUIRE(genesis_index);

    CBlock deposit_block;
    const auto proof{MakeDepositProof(deposit_block, *genesis_index, params)};
    BOOST_REQUIRE(main_headers.AddHeader(deposit_block, deposit_block.nTime).IsValid());

    chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
    const uint256 child_block_hash{uint256{0x51}};
    auto result{imports.ImportProof(proof, main_headers, child_block_hash, 10)};
    BOOST_CHECK(result.error == chainregistry::DepositImportError::PROOF_REJECTED);
    BOOST_CHECK(result.authentication_error ==
                chainregistry::AuthenticatedDepositError::IMMATURE);
    BOOST_CHECK_EQUAL(imports.Size(), 0U);

    const CBlockIndex* deposit_index{main_headers.Find(deposit_block.GetHash())};
    BOOST_REQUIRE(deposit_index);
    const CBlockHeader confirmation{MineHeader(*deposit_index, params, 1)};
    BOOST_REQUIRE(main_headers.AddHeader(confirmation, confirmation.nTime).IsValid());

    auto tampered{proof};
    tampered.block_height++;
    const std::vector<chainregistry::DepositProof> partially_invalid{proof, tampered};
    result = imports.ImportProofs(partially_invalid, main_headers, child_block_hash, 10);
    BOOST_CHECK(result.error == chainregistry::DepositImportError::PROOF_REJECTED);
    BOOST_CHECK(result.failed_proof == 1U);
    BOOST_CHECK_EQUAL(imports.Size(), 0U);

    const std::vector<chainregistry::DepositProof> duplicate_batch{proof, proof};
    result = imports.ImportProofs(duplicate_batch, main_headers, child_block_hash, 10);
    BOOST_CHECK(result.error == chainregistry::DepositImportError::DUPLICATE_IN_BATCH);
    BOOST_CHECK(result.failed_proof == 1U);
    BOOST_CHECK_EQUAL(imports.Size(), 0U);

    result = imports.ImportProof(proof, main_headers, child_block_hash, 10);
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE_EQUAL(result.imports.size(), 1U);
    BOOST_REQUIRE_EQUAL(result.undo.imports.size(), 1U);
    const auto& imported{result.imports.front()};
    BOOST_CHECK_EQUAL(imported.amount, 50'000);
    BOOST_CHECK(imported.fund.chain_id == CHILD_CHAIN);
    BOOST_CHECK(imported.main_block_hash == deposit_block.GetHash());
    BOOST_CHECK(imported.child_block_hash == child_block_hash);
    BOOST_CHECK_EQUAL(imported.child_block_height, 10U);
    BOOST_CHECK(imports.Find(imported.deposit_id) != nullptr);

    const auto duplicate{imports.ImportProof(proof, main_headers, child_block_hash, 10)};
    BOOST_CHECK(duplicate.error == chainregistry::DepositImportError::ALREADY_IMPORTED);
    BOOST_CHECK_EQUAL(imports.Size(), 1U);

    BOOST_CHECK(!imports.DisconnectImports(uint256{0x52}, result.undo));
    BOOST_CHECK_EQUAL(imports.Size(), 1U);
    BOOST_CHECK(imports.DisconnectImports(child_block_hash, result.undo));
    BOOST_CHECK_EQUAL(imports.Size(), 0U);
}

BOOST_AUTO_TEST_CASE(invalid_configuration_is_fail_closed)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    chainregistry::MainHeaderChain main_headers{params};
    BOOST_REQUIRE(main_headers.Initialize(genesis).IsValid());
    const CBlockIndex* genesis_index{main_headers.Find(genesis.GetHash())};
    BOOST_REQUIRE(genesis_index);
    CBlock deposit_block;
    const auto proof{MakeDepositProof(deposit_block, *genesis_index, params)};

    chainregistry::DepositImportState null_child{{}, 2};
    BOOST_CHECK(null_child.ImportProof(proof, main_headers, uint256{1}, 1).error ==
                chainregistry::DepositImportError::INVALID_CHILD_CHAIN);

    chainregistry::DepositImportState zero_confirmations{CHILD_CHAIN, 0};
    BOOST_CHECK(zero_confirmations.ImportProof(
                    proof, main_headers, uint256{1}, 1).error ==
                chainregistry::DepositImportError::INVALID_CONFIRMATION_POLICY);

    chainregistry::DepositImportState valid_config{CHILD_CHAIN, 2};
    BOOST_CHECK(valid_config.ImportProof(proof, main_headers, {}, 1).error ==
                chainregistry::DepositImportError::INVALID_CHILD_BLOCK);
}

BOOST_AUTO_TEST_CASE(main_reorg_triggers_permanent_safe_halt)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    chainregistry::MainHeaderChain main_headers{params};
    BOOST_REQUIRE(main_headers.Initialize(genesis).IsValid());
    const CBlockIndex* genesis_index{main_headers.Find(genesis.GetHash())};
    BOOST_REQUIRE(genesis_index);

    CBlock deposit_block;
    const auto proof{MakeDepositProof(deposit_block, *genesis_index, params)};
    BOOST_REQUIRE(main_headers.AddHeader(deposit_block, deposit_block.nTime).IsValid());
    const CBlockIndex* deposit_index{main_headers.Find(deposit_block.GetHash())};
    BOOST_REQUIRE(deposit_index);
    const CBlockHeader confirmation{MineHeader(*deposit_index, params, 10)};
    BOOST_REQUIRE(main_headers.AddHeader(confirmation, confirmation.nTime).IsValid());

    chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
    const uint256 child_block_hash{uint256{0x61}};
    const auto imported{imports.ImportProof(
        proof, main_headers, child_block_hash, 20)};
    BOOST_REQUIRE(imported.IsValid());
    const auto deposit_id{imported.imports.front().deposit_id};
    BOOST_CHECK(!imports.Reconcile(main_headers).safe_halt);

    const CBlockHeader fork1{MineHeader(*genesis_index, params, 20)};
    BOOST_REQUIRE(main_headers.AddHeader(fork1, fork1.nTime).IsValid());
    const CBlockIndex* fork1_index{main_headers.Find(fork1.GetHash())};
    BOOST_REQUIRE(fork1_index);
    const CBlockHeader fork2{MineHeader(*fork1_index, params, 21)};
    BOOST_REQUIRE(main_headers.AddHeader(fork2, fork2.nTime).IsValid());
    const CBlockIndex* fork2_index{main_headers.Find(fork2.GetHash())};
    BOOST_REQUIRE(fork2_index);
    const CBlockHeader fork3{MineHeader(*fork2_index, params, 22)};
    const auto reorg{main_headers.AddHeader(fork3, fork3.nTime)};
    BOOST_REQUIRE(reorg.IsValid());
    BOOST_REQUIRE(reorg.became_best);
    BOOST_CHECK_EQUAL(reorg.disconnected_headers, 2U);

    const auto reconciled{imports.Reconcile(main_headers)};
    BOOST_CHECK(reconciled.safe_halt);
    BOOST_CHECK(reconciled.newly_halted);
    BOOST_REQUIRE_EQUAL(reconciled.affected_imports.size(), 1U);
    BOOST_CHECK(reconciled.affected_imports.front() == deposit_id);
    BOOST_CHECK(imports.IsSafeHalted());
    BOOST_REQUIRE(imports.SafeHalt().has_value());
    BOOST_CHECK(imports.SafeHalt()->observed_main_tip == fork3.GetHash());

    const auto repeated{imports.Reconcile(main_headers)};
    BOOST_CHECK(repeated.safe_halt);
    BOOST_CHECK(!repeated.newly_halted);
    BOOST_CHECK(imports.ImportProof(proof, main_headers, uint256{0x62}, 21).error ==
                chainregistry::DepositImportError::SAFE_HALT);

    BOOST_CHECK(imports.DisconnectImports(child_block_hash, imported.undo));
    BOOST_CHECK_EQUAL(imports.Size(), 0U);
    BOOST_CHECK(imports.IsSafeHalted());
}

BOOST_AUTO_TEST_SUITE_END()
