// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_net_processor.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <variant>
#include <vector>

using namespace std::chrono_literals;

namespace {

const COutPoint REGISTRATION_ANCHOR{
    Txid{"1111111111111111111111111111111111111111111111111111111111111111"},
    1};
const chainregistry::MetadataHash METADATA_HASH{
    "4444444444444444444444444444444444444444444444444444444444444444"};

struct ChildNetProcessorSetup : BasicTestingSetup {
    ChildNetProcessorSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};

chainregistry::ReferenceChildDefinition Definition()
{
    const auto result{chainregistry::BuildReferenceChildDefinition(
        Params().GetConsensus().hashGenesisBlock,
        REGISTRATION_ANCHOR,
        chainregistry::MakeReferenceChildSpec({}),
        METADATA_HASH)};
    BOOST_REQUIRE(result.IsValid());
    return *result.definition;
}

CBlock ChildBlock(const uint256& parent_hash,
                  int height,
                  uint32_t time,
                  CAmount reward = 0)
{
    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vin.front().scriptSig =
        CScript{} << static_cast<int64_t>(height) <<
        std::vector<unsigned char>{0};
    coinbase.vin.front().scriptWitness.stack = {
        std::vector<unsigned char>(32)};
    if (reward != 0) {
        coinbase.vout.emplace_back(
            reward,
            CScript{} << OP_1 << std::vector<unsigned char>(32, 1));
    }

    CBlock block;
    block.nVersion = CBlockHeader::CURRENT_VERSION;
    block.hashPrevBlock = parent_hash;
    block.nTime = time;
    block.nBits = 0;
    block.nNonce = 0;
    block.vtx = {MakeTransactionRef(std::move(coinbase))};

    const auto& reserved{
        block.vtx.front()->vin.front().scriptWitness.stack.front()};
    uint256 commitment{BlockWitnessMerkleRoot(block)};
    CHash256().Write(commitment).Write(reserved).Finalize(commitment);
    std::vector<unsigned char> payload{0xaa, 0x21, 0xa9, 0xed};
    payload.insert(payload.end(), commitment.begin(), commitment.end());
    CMutableTransaction committed_coinbase{*block.vtx.front()};
    committed_coinbase.vout.emplace_back(
        0, CScript{} << OP_RETURN << payload);
    block.vtx.front() = MakeTransactionRef(std::move(committed_coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

chainregistry::BmmAnchorProof MakeBmmProof(
    CBlock& main_block,
    const CBlockIndex& parent,
    const Consensus::Params& params,
    const chainregistry::ReferenceChildDefinition& definition,
    const uint256& child_block_hash)
{
    const chainregistry::ChainRecord record{
        .record_version = chainregistry::CHAIN_RECORD_VERSION,
        .chain_id = definition.chain_id,
        .manifest_hash = definition.manifest_hash,
        .template_id = definition.manifest.spec.template_id,
        .template_version = definition.manifest.spec.template_version,
        .control_outpoint = definition.genesis.registration_anchor,
        .metadata_hash = definition.manifest.initial_metadata_hash,
        .status = chainregistry::ChainStatus::ACTIVE,
        .registered_height = 0,
        .updated_height = 0,
    };
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vout.emplace_back(
        0, chainregistry::BuildRegistryCommitment(registry.ComputeRoot()));
    CMutableTransaction proposal;
    proposal.vin.emplace_back(COutPoint{
        Txid{"3333333333333333333333333333333333333333333333333333333333333333"},
        0});
    proposal.vout.emplace_back(
        0,
        chainregistry::BuildBmmAnchorScript({
            .chain_id = definition.chain_id,
            .child_block_hash = child_block_hash,
        }));

    main_block.nVersion = CBlockHeader::CURRENT_VERSION;
    main_block.hashPrevBlock = parent.GetBlockHash();
    main_block.nTime = parent.nTime + 1;
    main_block.nBits = GetNextWorkRequired(&parent, &main_block, params);
    main_block.vtx = {
        MakeTransactionRef(coinbase), MakeTransactionRef(proposal)};
    main_block.hashMerkleRoot = BlockMerkleRoot(main_block);
    const auto seed{GetRandomXSeed(&parent, parent.nHeight + 1, params)};
    BOOST_REQUIRE(seed.has_value());
    uint64_t max_tries{1'000'000};
    BOOST_REQUIRE(MineProofOfWork(
        main_block,
        *seed,
        params,
        max_tries,
        /*threads=*/1,
        /*use_full_memory=*/false));

    return {
        .main_genesis_hash = params.hashGenesisBlock,
        .block_height = static_cast<uint32_t>(parent.nHeight + 1),
        .block_header = main_block,
        .anchor_transaction = proposal,
        .transaction_index = 1,
        .transaction_merkle_branch = TransactionMerklePath(main_block, 1),
        .coinbase_transaction = coinbase,
        .coinbase_merkle_branch = TransactionMerklePath(main_block, 0),
        .chain_record = record,
        .registry_proof = *registry.GetInclusionProof(definition.chain_id),
    };
}

void StageBlock(node::ChainManager& manager,
                const chainregistry::ReferenceChildDefinition& definition,
                const CBlock& child_block)
{
    const auto* runtime{manager.Get(definition.chain_id)};
    BOOST_REQUIRE(runtime);
    const CBlockIndex* main_parent{runtime->MainHeaders()->Tip()};
    BOOST_REQUIRE(main_parent);
    CBlock main_block;
    const auto proof{MakeBmmProof(
        main_block,
        *main_parent,
        Params().GetConsensus(),
        definition,
        child_block.GetHash())};
    const auto update{manager.AddMainHeader(
        main_block, main_block.nTime, /*sync=*/true)};
    BOOST_REQUIRE(update.unloaded.empty());
    BOOST_REQUIRE(manager.StageBmmAnchor(
        definition.chain_id,
        proof,
        child_block.nTime,
        /*sync=*/true).IsValid());
}

const chainregistry::ChildBlockHashes& OutboundHashes(
    const node::ChildNetOutbound& outbound)
{
    BOOST_REQUIRE(
        std::holds_alternative<chainregistry::ChildBlockHashes>(
            outbound.message));
    return std::get<chainregistry::ChildBlockHashes>(outbound.message);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(
    child_net_processor_tests,
    ChildNetProcessorSetup)

BOOST_AUTO_TEST_CASE(requires_full_child_handshake)
{
    const auto definition{Definition()};
    node::ChainManager manager{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_net_handshake",
        1 << 20};
    BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());
    node::ChildNetProcessor processor{manager, definition};

    const auto connected{processor.Connected(7)};
    BOOST_REQUIRE(connected.IsValid());
    BOOST_REQUIRE_EQUAL(connected.outbound.size(), 1U);
    BOOST_CHECK(
        connected.outbound.front().command ==
        node::ChildNetCommand::HELLO);
    BOOST_REQUIRE(std::holds_alternative<chainregistry::ChildNetHello>(
        connected.outbound.front().message));
    const auto& local_hello{std::get<chainregistry::ChildNetHello>(
        connected.outbound.front().message)};
    BOOST_CHECK(local_hello.chain_id == definition.chain_id);
    BOOST_CHECK(local_hello.genesis_hash == definition.genesis_hash);

    const auto premature{processor.ReceiveInventory(
        7,
        {.chain_id = definition.chain_id,
         .block_hashes = {uint256{1}}},
        1s)};
    BOOST_CHECK(
        premature.error ==
        node::ChildNetProcessorError::HANDSHAKE_REQUIRED);
    BOOST_CHECK(premature.disconnect);

    chainregistry::ChildNetHello wrong{
        .chain_id = definition.chain_id,
        .genesis_hash = uint256{1},
    };
    const auto rejected{processor.ReceiveHello(7, wrong)};
    BOOST_CHECK(
        rejected.validation_error ==
        chainregistry::ChildNetValidationError::WRONG_GENESIS);
    BOOST_CHECK(rejected.disconnect);

    wrong.genesis_hash = definition.genesis_hash;
    const auto accepted{processor.ReceiveHello(7, wrong)};
    BOOST_REQUIRE(accepted.IsValid());
    BOOST_CHECK_EQUAL(processor.HandshakenPeerCount(), 1U);

    const auto unanchored{processor.ReceiveInventory(
        7,
        {.chain_id = definition.chain_id,
         .block_hashes = {uint256{2}}},
        2s)};
    BOOST_CHECK(
        unanchored.error ==
        node::ChildNetProcessorError::UNAUTHENTICATED_BLOCK);
    BOOST_CHECK(unanchored.disconnect);
    BOOST_CHECK_EQUAL(processor.Downloads().CandidateCount(), 0U);
}

BOOST_AUTO_TEST_CASE(downloads_parent_before_connecting_deferred_child)
{
    const auto definition{Definition()};
    node::ChainManager manager{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_net_deferred",
        1 << 20};
    BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());

    const uint32_t genesis_time{Params().GenesisBlock().nTime};
    const CBlock parent{ChildBlock(
        definition.genesis_hash, 1, genesis_time + 1)};
    const CBlock child{ChildBlock(
        parent.GetHash(), 2, genesis_time + 2)};
    StageBlock(manager, definition, parent);
    StageBlock(manager, definition, child);

    node::ChildNetProcessor processor{manager, definition};
    BOOST_REQUIRE(processor.Connected(1).IsValid());
    BOOST_REQUIRE(processor.Connected(2).IsValid());
    const chainregistry::ChildNetHello hello{
        .chain_id = definition.chain_id,
        .genesis_hash = definition.genesis_hash,
    };
    BOOST_REQUIRE(processor.ReceiveHello(1, hello).IsValid());
    BOOST_REQUIRE(processor.ReceiveHello(2, hello).IsValid());
    BOOST_CHECK_EQUAL(processor.PendingCount(), 2U);

    const auto announced{processor.ReceiveInventory(
        1,
        {.chain_id = definition.chain_id,
         .block_hashes = {child.GetHash()}},
        1s)};
    BOOST_REQUIRE(announced.IsValid());
    BOOST_REQUIRE_EQUAL(announced.outbound.size(), 1U);
    BOOST_CHECK(
        announced.outbound.front().command ==
        node::ChildNetCommand::GET_BLOCKS);
    BOOST_CHECK(
        OutboundHashes(announced.outbound.front()).block_hashes ==
        std::vector<uint256>{child.GetHash()});

    const auto deferred{processor.ReceiveBlock(
        1,
        {.chain_id = definition.chain_id, .block = child},
        2s,
        child.nTime,
        /*sync=*/true)};
    BOOST_REQUIRE(deferred.IsValid());
    BOOST_REQUIRE_EQUAL(deferred.deferred_blocks.size(), 1U);
    BOOST_CHECK(deferred.deferred_blocks.front() == child.GetHash());
    BOOST_CHECK_EQUAL(processor.DeferredCount(), 1U);
    BOOST_REQUIRE_EQUAL(deferred.outbound.size(), 1U);
    BOOST_CHECK(
        deferred.outbound.front().command ==
        node::ChildNetCommand::GET_BLOCKS);
    BOOST_CHECK(
        OutboundHashes(deferred.outbound.front()).block_hashes ==
        std::vector<uint256>{parent.GetHash()});

    const auto connected{processor.ReceiveBlock(
        1,
        {.chain_id = definition.chain_id, .block = parent},
        3s,
        child.nTime,
        /*sync=*/true)};
    BOOST_REQUIRE_MESSAGE(
        connected.IsValid(), static_cast<int>(connected.error));
    BOOST_REQUIRE_EQUAL(connected.accepted_blocks.size(), 2U);
    BOOST_CHECK(
        std::find(
            connected.accepted_blocks.begin(),
            connected.accepted_blocks.end(),
            parent.GetHash()) != connected.accepted_blocks.end());
    BOOST_CHECK(
        std::find(
            connected.accepted_blocks.begin(),
            connected.accepted_blocks.end(),
            child.GetHash()) != connected.accepted_blocks.end());
    BOOST_CHECK_EQUAL(processor.DeferredCount(), 0U);
    BOOST_CHECK_EQUAL(processor.PendingCount(), 0U);
    BOOST_REQUIRE(manager.Get(definition.chain_id)->Tip());
    BOOST_CHECK(
        manager.Get(definition.chain_id)->Tip()->GetBlockHash() ==
        child.GetHash());

    size_t announcements_to_second_peer{0};
    for (const auto& outbound : connected.outbound) {
        if (outbound.peer == 2 &&
            outbound.command == node::ChildNetCommand::INVENTORY &&
            std::holds_alternative<chainregistry::ChildBlockHashes>(
                outbound.message)) {
            ++announcements_to_second_peer;
        }
    }
    BOOST_CHECK_EQUAL(announcements_to_second_peer, 2U);
}

BOOST_AUTO_TEST_SUITE_END()
