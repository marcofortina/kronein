// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/mainchain_lightclient.h>

#include <chainparams.h>
#include <consensus/bmm.h>
#include <consensus/merkle.h>
#include <pow.h>
#include <primitives/deposit.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <vector>

namespace {

constexpr chainregistry::ChainId CHILD_CHAIN{
    "1111111111111111111111111111111111111111111111111111111111111111"};

struct MainchainLightClientSetup : BasicTestingSetup {
    MainchainLightClientSetup()
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
                        uint32_t discriminator,
                        int64_t block_time = 0,
                        int32_t version = CBlockHeader::CURRENT_VERSION)
{
    CBlockHeader header;
    header.nVersion = version;
    header.hashPrevBlock = parent.GetBlockHash();
    header.hashMerkleRoot = uint256{static_cast<uint8_t>(discriminator)};
    header.nTime = block_time == 0 ? parent.nTime + 1 : block_time;
    header.nBits = GetNextWorkRequired(&parent, &header, params);

    const auto seed{GetRandomXSeed(&parent, parent.nHeight + 1, params)};
    BOOST_REQUIRE(seed.has_value());
    uint64_t max_tries{1'000'000};
    BOOST_REQUIRE(MineProofOfWork(
        header, *seed, params, max_tries, /*threads=*/1, /*use_full_memory=*/false));
    return header;
}

chainregistry::DepositProof DepositBlock(CBlock& block,
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

    block.nVersion = 1;
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

chainregistry::BmmAnchorProof BmmBlock(CBlock& block,
                                       const CBlockIndex& parent,
                                       const Consensus::Params& params,
                                       const uint256& child_block_hash)
{
    const auto record{ChildRecord()};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vout.emplace_back(
        0, chainregistry::BuildRegistryCommitment(registry.ComputeRoot()));

    CMutableTransaction proposal;
    proposal.vin.emplace_back(COutPoint{
        Txid{"6666666666666666666666666666666666666666666666666666666666666666"}, 0});
    proposal.vout.emplace_back(
        0,
        chainregistry::BuildBmmAnchorScript({
            .chain_id = CHILD_CHAIN,
            .child_block_hash = child_block_hash,
        }));

    block.nVersion = CBlockHeader::CURRENT_VERSION;
    block.hashPrevBlock = parent.GetBlockHash();
    block.nTime = parent.nTime + 1;
    block.nBits = GetNextWorkRequired(&parent, &block, params);
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(proposal)};
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

BOOST_FIXTURE_TEST_SUITE(mainchain_lightclient_tests, MainchainLightClientSetup)

BOOST_AUTO_TEST_CASE(mainchain_version_namespace)
{
    const auto& params{Params().GetConsensus()};
    const auto& genesis{Params().GenesisBlock()};
    chainregistry::MainHeaderChain chain{params};
    BOOST_REQUIRE(chain.Initialize(genesis).IsValid());
    const CBlockIndex* parent{chain.Find(genesis.GetHash())};
    BOOST_REQUIRE(parent);
    for (const int32_t version : {1, 0x20000000, 0x20000001, 0x3fffffff}) {
        BOOST_CHECK(CBlockHeader::IsSupportedMainchainVersion(version));
        const auto header{MineHeader(*parent, params, 1, 0, version)};
        BOOST_REQUIRE(chain.AddHeader(header, header.nTime).IsValid());
        parent = chain.Find(header.GetHash());
        BOOST_REQUIRE(parent);
    }
    for (const int32_t version : {0, 2, 4, 0x1fffffff, 0x40000000, 0x60000000, -1, std::numeric_limits<int32_t>::min()}) {
        BOOST_CHECK(!CBlockHeader::IsSupportedMainchainVersion(version));
        auto header{MineHeader(*parent, params, 2)};
        header.nVersion = version;
        BOOST_CHECK(chain.AddHeader(header, header.nTime).error == chainregistry::MainHeaderError::INVALID_VERSION);
    }
}

BOOST_AUTO_TEST_CASE(rejects_invalid_header_context)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    chainregistry::MainHeaderChain chain{params};

    CBlockHeader orphan;
    orphan.hashPrevBlock = uint256{1};
    BOOST_CHECK(chain.AddHeader(orphan, genesis.nTime).error ==
                chainregistry::MainHeaderError::NOT_INITIALIZED);

    CBlockHeader wrong_genesis{genesis};
    wrong_genesis.nNonce++;
    BOOST_CHECK(chain.Initialize(wrong_genesis).error ==
                chainregistry::MainHeaderError::WRONG_GENESIS);

    BOOST_REQUIRE(chain.Initialize(genesis).IsValid());
    BOOST_CHECK(chain.AddHeader(orphan, genesis.nTime).error ==
                chainregistry::MainHeaderError::UNKNOWN_PARENT);

    const CBlockIndex* genesis_index{chain.Find(genesis.GetHash())};
    BOOST_REQUIRE(genesis_index);
    CBlockHeader invalid_version{MineHeader(*genesis_index, params, 3)};
    invalid_version.nVersion = CBlockHeader::CURRENT_VERSION + 1;
    BOOST_CHECK(chain.AddHeader(invalid_version, invalid_version.nTime).error ==
                chainregistry::MainHeaderError::INVALID_VERSION);

    CBlockHeader invalid_difficulty{MineHeader(*genesis_index, params, 1)};
    invalid_difficulty.nBits--;
    BOOST_CHECK(chain.AddHeader(invalid_difficulty, invalid_difficulty.nTime).error ==
                chainregistry::MainHeaderError::INVALID_DIFFICULTY);

    const int64_t future_time{genesis.nTime + MAX_FUTURE_BLOCK_TIME + 1};
    const CBlockHeader future{MineHeader(*genesis_index, params, 2, future_time)};
    BOOST_CHECK(chain.AddHeader(future, genesis.nTime).error ==
                chainregistry::MainHeaderError::TIME_TOO_NEW);
}

BOOST_AUTO_TEST_CASE(selects_most_work_chain_and_reports_reorg)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    chainregistry::MainHeaderChain chain{params};
    BOOST_REQUIRE(chain.Initialize(genesis).IsValid());
    const CBlockIndex* genesis_index{chain.Find(genesis.GetHash())};
    BOOST_REQUIRE(genesis_index);

    const CBlockHeader a1{MineHeader(*genesis_index, params, 10)};
    const auto a1_result{chain.AddHeader(a1, a1.nTime)};
    BOOST_REQUIRE(a1_result.IsValid());
    BOOST_CHECK(a1_result.became_best);
    BOOST_CHECK_EQUAL(chain.GetStatus(a1.GetHash()).confirmations, 1);

    const CBlockHeader b1{MineHeader(*genesis_index, params, 20)};
    const auto b1_result{chain.AddHeader(b1, b1.nTime)};
    BOOST_REQUIRE(b1_result.IsValid());
    BOOST_CHECK(!b1_result.became_best);
    const CBlockIndex* b1_index{chain.Find(b1.GetHash())};
    BOOST_REQUIRE(b1_index);

    const CBlockHeader b2{MineHeader(*b1_index, params, 21)};
    const auto b2_result{chain.AddHeader(b2, b2.nTime)};
    BOOST_REQUIRE(b2_result.IsValid());
    BOOST_CHECK(b2_result.became_best);
    BOOST_CHECK_EQUAL(b2_result.fork_height, 0);
    BOOST_CHECK_EQUAL(b2_result.disconnected_headers, 1U);
    BOOST_CHECK(b2_result.previous_best == a1.GetHash());
    BOOST_CHECK(!chain.GetStatus(a1.GetHash()).active);
    BOOST_CHECK(chain.GetStatus(b1.GetHash()).active);
    BOOST_CHECK_EQUAL(chain.GetStatus(b1.GetHash()).confirmations, 2);

    const auto duplicate{chain.AddHeader(b2, b2.nTime)};
    BOOST_REQUIRE(duplicate.IsValid());
    BOOST_CHECK(duplicate.already_known);
    BOOST_CHECK(!duplicate.became_best);
}

BOOST_AUTO_TEST_CASE(authenticates_only_mature_active_deposits)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    chainregistry::MainHeaderChain chain{params};
    BOOST_REQUIRE(chain.Initialize(genesis).IsValid());
    const CBlockIndex* genesis_index{chain.Find(genesis.GetHash())};
    BOOST_REQUIRE(genesis_index);

    CBlock deposit_block;
    const auto proof{DepositBlock(deposit_block, *genesis_index, params)};
    BOOST_REQUIRE(chain.AddHeader(deposit_block, deposit_block.nTime).IsValid());

    auto result{chain.AuthenticateDeposit(proof, CHILD_CHAIN, 0)};
    BOOST_CHECK(result.error ==
                chainregistry::AuthenticatedDepositError::INVALID_CONFIRMATION_POLICY);

    result = chain.AuthenticateDeposit(proof, CHILD_CHAIN, 2);
    BOOST_CHECK(result.error == chainregistry::AuthenticatedDepositError::IMMATURE);
    BOOST_CHECK_EQUAL(result.confirmations, 1);

    const CBlockIndex* deposit_index{chain.Find(deposit_block.GetHash())};
    BOOST_REQUIRE(deposit_index);
    const CBlockHeader confirmation{MineHeader(*deposit_index, params, 30)};
    BOOST_REQUIRE(chain.AddHeader(confirmation, confirmation.nTime).IsValid());
    result = chain.AuthenticateDeposit(proof, CHILD_CHAIN, 2);
    BOOST_REQUIRE(result.IsValid());
    BOOST_CHECK(result.proof.deposit_id == chainregistry::DeriveDepositId(
        params.hashGenesisBlock,
        COutPoint{CTransaction{proof.funding_transaction}.GetHash(), proof.funding_vout}));
    BOOST_CHECK_EQUAL(result.confirmations, 2);

    auto tampered{proof};
    tampered.block_height++;
    result = chain.AuthenticateDeposit(tampered, CHILD_CHAIN, 2);
    BOOST_CHECK(result.error ==
                chainregistry::AuthenticatedDepositError::HEADER_HEIGHT_MISMATCH);

    constexpr chainregistry::ChainId other_child{
        "9999999999999999999999999999999999999999999999999999999999999999"};
    result = chain.AuthenticateDeposit(proof, other_child, 2);
    BOOST_CHECK(result.error ==
                chainregistry::AuthenticatedDepositError::STRUCTURAL_PROOF_INVALID);
}

BOOST_AUTO_TEST_CASE(authenticates_only_mature_active_bmm_anchors)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    chainregistry::MainHeaderChain chain{params};
    BOOST_REQUIRE(chain.Initialize(genesis).IsValid());
    const CBlockIndex* genesis_index{chain.Find(genesis.GetHash())};
    BOOST_REQUIRE(genesis_index);

    constexpr uint256 child_block_hash{
        "7777777777777777777777777777777777777777777777777777777777777777"};
    CBlock anchor_block;
    const auto proof{BmmBlock(
        anchor_block, *genesis_index, params, child_block_hash)};
    BOOST_REQUIRE(chain.AddHeader(
        anchor_block, anchor_block.nTime).IsValid());

    auto result{chain.AuthenticateBmmAnchor(proof, CHILD_CHAIN, 0)};
    BOOST_CHECK(result.error == chainregistry::AuthenticatedBmmAnchorError::
                                    INVALID_CONFIRMATION_POLICY);

    result = chain.AuthenticateBmmAnchor(proof, CHILD_CHAIN, 2);
    BOOST_CHECK(result.error ==
                chainregistry::AuthenticatedBmmAnchorError::IMMATURE);
    BOOST_CHECK_EQUAL(result.confirmations, 1);

    const CBlockIndex* anchor_index{chain.Find(anchor_block.GetHash())};
    BOOST_REQUIRE(anchor_index);
    const CBlockHeader confirmation{MineHeader(*anchor_index, params, 70)};
    BOOST_REQUIRE(chain.AddHeader(
        confirmation, confirmation.nTime).IsValid());
    result = chain.AuthenticateBmmAnchor(proof, CHILD_CHAIN, 2);
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.proof.anchor.has_value());
    BOOST_CHECK(result.proof.anchor->chain_id == CHILD_CHAIN);
    BOOST_CHECK(result.proof.anchor->child_block_hash == child_block_hash);
    BOOST_CHECK(result.anchor_chain_work == anchor_index->nChainWork);
    BOOST_CHECK(result.tip_chain_work == chain.Tip()->nChainWork);

    auto tampered{proof};
    tampered.block_height++;
    result = chain.AuthenticateBmmAnchor(tampered, CHILD_CHAIN, 2);
    BOOST_CHECK(result.error == chainregistry::AuthenticatedBmmAnchorError::
                                    HEADER_HEIGHT_MISMATCH);

    constexpr chainregistry::ChainId other_child{
        "9999999999999999999999999999999999999999999999999999999999999999"};
    result = chain.AuthenticateBmmAnchor(proof, other_child, 2);
    BOOST_CHECK(result.error == chainregistry::AuthenticatedBmmAnchorError::
                                    STRUCTURAL_PROOF_INVALID);
}

BOOST_AUTO_TEST_CASE(restores_validated_dag_and_explicit_equal_work_tip)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    chainregistry::MainHeaderChain chain{params};
    BOOST_REQUIRE(chain.Initialize(genesis).IsValid());
    const CBlockIndex* genesis_index{chain.Find(genesis.GetHash())};
    BOOST_REQUIRE(genesis_index);
    const CBlockHeader a1{MineHeader(*genesis_index, params, 40)};
    const CBlockHeader b1{MineHeader(*genesis_index, params, 41)};
    BOOST_REQUIRE(chain.AddHeader(a1, a1.nTime).IsValid());
    BOOST_REQUIRE(chain.AddHeader(b1, b1.nTime).IsValid());
    const auto records{chain.ExportHeaders()};
    BOOST_REQUIRE_EQUAL(records.size(), 3U);

    chainregistry::MainHeaderChain restored_first{params};
    BOOST_REQUIRE(restored_first.LoadHeaders(
        records, a1.GetHash(), a1.nTime).IsValid());
    BOOST_CHECK(restored_first.Tip()->GetBlockHash() == a1.GetHash());

    chainregistry::MainHeaderChain restored_other_tie{params};
    BOOST_REQUIRE(restored_other_tie.LoadHeaders(
        records, b1.GetHash(), b1.nTime).IsValid());
    BOOST_CHECK(restored_other_tie.Tip()->GetBlockHash() == b1.GetHash());

    chainregistry::MainHeaderChain restored_local{params};
    BOOST_REQUIRE(restored_local.LoadValidatedHeaders(
        records, b1.GetHash(), b1.nTime).IsValid());
    BOOST_CHECK(restored_local.Tip()->GetBlockHash() == b1.GetHash());

    chainregistry::MainHeaderChain copied{restored_local};
    BOOST_CHECK(copied.Tip()->GetBlockHash() == b1.GetHash());
    const CBlockIndex* copied_b1{copied.Find(b1.GetHash())};
    BOOST_REQUIRE(copied_b1);
    const CBlockHeader b2{MineHeader(*copied_b1, params, 42)};
    BOOST_REQUIRE(copied.AddValidatedHeader(b2, b2.nTime).IsValid());
    BOOST_CHECK(copied.Tip()->GetBlockHash() == b2.GetHash());
    BOOST_CHECK(restored_local.Find(b2.GetHash()) == nullptr);

    CBlockHeader invalid_difficulty{b2};
    invalid_difficulty.hashMerkleRoot = uint256{43};
    invalid_difficulty.nBits--;
    BOOST_CHECK(copied.AddValidatedHeader(
                    invalid_difficulty, invalid_difficulty.nTime).error ==
                chainregistry::MainHeaderError::INVALID_DIFFICULTY);
    BOOST_REQUIRE(copied.SelectValidatedTip(genesis.GetHash()).IsValid());
    chainregistry::MainHeaderChain copied_lower_work{copied};
    BOOST_CHECK(copied_lower_work.Tip()->GetBlockHash() == genesis.GetHash());
    BOOST_REQUIRE(copied_lower_work.SelectValidatedTip(b2.GetHash()).IsValid());
    BOOST_CHECK(copied_lower_work.Tip()->GetBlockHash() == b2.GetHash());

    chainregistry::MainHeaderChain invalid_tip{params};
    BOOST_CHECK(invalid_tip.LoadHeaders(
                    records, genesis.GetHash(), b1.nTime).error ==
                chainregistry::MainHeaderLoadError::INVALID_ACTIVE_TIP);

    auto wrong_height{records};
    wrong_height.back().height++;
    chainregistry::MainHeaderChain invalid_height{params};
    BOOST_CHECK(invalid_height.LoadHeaders(
                    wrong_height, a1.GetHash(), a1.nTime).error ==
                chainregistry::MainHeaderLoadError::INVALID_HEIGHT);
}

BOOST_AUTO_TEST_SUITE_END()
