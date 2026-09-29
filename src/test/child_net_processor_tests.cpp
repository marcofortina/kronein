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
        METADATA_HASH,
        TestChildFeeRecipient())};
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
                const CBlock& child_block,
                bool sync = true)
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
        main_block, main_block.nTime, sync)};
    BOOST_REQUIRE(update.unloaded.empty());
    BOOST_REQUIRE(manager.StageBmmAnchor(
        definition.chain_id,
        proof,
        child_block.nTime,
        sync).IsValid());
}

const chainregistry::ChildBlockHashes& OutboundHashes(
    const node::ChildNetOutbound& outbound)
{
    BOOST_REQUIRE(
        std::holds_alternative<chainregistry::ChildBlockHashes>(
            outbound.message));
    return std::get<chainregistry::ChildBlockHashes>(outbound.message);
}

chainregistry::ChildBlockHashes BlockRequest(
    const chainregistry::ChainId& chain_id,
    uint64_t first,
    size_t count)
{
    chainregistry::ChildBlockHashes request{
        .chain_id = chain_id,
        .block_hashes = {},
    };
    request.block_hashes.reserve(count);
    for (size_t index{0}; index < count; ++index) {
        request.block_hashes.emplace_back(first + index);
    }
    return request;
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

    const auto connected{processor.Connected(7, 123)};
    BOOST_REQUIRE(connected.IsValid());
    BOOST_REQUIRE_EQUAL(connected.outbound.size(), 1U);
    BOOST_CHECK(
        connected.outbound.front().command ==
        node::ChildNetCommand::HELLO);
    BOOST_REQUIRE(std::holds_alternative<chainregistry::ChildNetHello>(
        connected.outbound.front().message));
    const auto& local_hello{std::get<chainregistry::ChildNetHello>(
        connected.outbound.front().message)};
    BOOST_CHECK_EQUAL(local_hello.nonce, 123U);
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

    const auto repeated{processor.ReceiveHello(7, wrong)};
    BOOST_CHECK(
        repeated.error ==
        node::ChildNetProcessorError::HANDSHAKE_ALREADY_COMPLETED);
    BOOST_CHECK(repeated.disconnect);
    BOOST_CHECK(repeated.outbound.empty());
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

BOOST_AUTO_TEST_CASE(rate_limits_block_hash_requests_per_peer)
{
    const auto definition{Definition()};
    node::ChainManager manager{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_net_request_rate",
        1 << 20};
    BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());

    node::ChildNetProcessor processor{manager, definition};
    const chainregistry::ChildNetHello hello{
        .chain_id = definition.chain_id,
        .genesis_hash = definition.genesis_hash,
    };
    BOOST_REQUIRE(processor.Connected(7, 123).IsValid());
    BOOST_REQUIRE(processor.ReceiveHello(7, hello).IsValid());

    const node::ChildRequestTime start{0};
    const auto full_request{BlockRequest(
        definition.chain_id,
        /*first=*/1,
        chainregistry::MAX_CHILD_BLOCK_REQUEST_HASHES)};
    for (uint64_t batch{0}; batch < 4; ++batch) {
        const auto accepted{processor.ReceiveGetBlocks(
            7,
            BlockRequest(
                definition.chain_id,
                1 + batch * chainregistry::MAX_CHILD_BLOCK_REQUEST_HASHES,
                chainregistry::MAX_CHILD_BLOCK_REQUEST_HASHES),
            start)};
        BOOST_CHECK(accepted.IsValid());
        BOOST_CHECK(accepted.outbound.empty());
    }
    const auto limited{processor.ReceiveGetBlocks(7, full_request, start)};
    BOOST_CHECK(
        limited.error ==
        node::ChildNetProcessorError::REQUEST_RATE_LIMITED);
    BOOST_CHECK(limited.disconnect);

    BOOST_REQUIRE(processor.Connected(8, 456).IsValid());
    BOOST_REQUIRE(processor.ReceiveHello(8, hello).IsValid());
    for (uint64_t batch{0}; batch < 4; ++batch) {
        BOOST_REQUIRE(processor.ReceiveGetBlocks(
            8,
            BlockRequest(
                definition.chain_id,
                100 + batch * chainregistry::MAX_CHILD_BLOCK_REQUEST_HASHES,
                chainregistry::MAX_CHILD_BLOCK_REQUEST_HASHES),
            start).IsValid());
    }
    const auto refilled{processor.ReceiveGetBlocks(
        8,
        BlockRequest(definition.chain_id, 200, 1),
        start + node::CHILD_GETBLOCKS_REFILL_INTERVAL)};
    BOOST_CHECK(refilled.IsValid());
}

BOOST_AUTO_TEST_CASE(relays_only_handshaken_chain_bound_transactions)
{
    const auto definition{Definition()};
    node::ChainManager manager{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_net_transactions",
        1 << 20};
    BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());

    node::ChildNetProcessor processor{manager, definition};
    const chainregistry::ChildNetHello hello{
        .chain_id = definition.chain_id,
        .genesis_hash = definition.genesis_hash,
    };
    BOOST_REQUIRE(processor.Connected(1, 123).IsValid());
    BOOST_REQUIRE(processor.Connected(2, 456).IsValid());
    BOOST_REQUIRE(processor.Connected(3, 789).IsValid());
    BOOST_REQUIRE(processor.ReceiveHello(1, hello).IsValid());
    BOOST_REQUIRE(processor.ReceiveHello(2, hello).IsValid());

    CMutableTransaction missing_input;
    missing_input.vin.emplace_back(
        COutPoint{Txid::FromUint256(uint256{1}), 0});
    missing_input.vout.emplace_back(1, CScript{} << OP_TRUE);
    const CTransactionRef transaction{
        MakeTransactionRef(missing_input)};
    const auto relayed{processor.RelayTransaction(transaction)};
    BOOST_REQUIRE(relayed.IsValid());
    BOOST_REQUIRE_EQUAL(relayed.outbound.size(), 2U);
    for (const auto& outbound : relayed.outbound) {
        BOOST_CHECK(
            outbound.command == node::ChildNetCommand::TRANSACTION);
        BOOST_CHECK(outbound.peer == 1 || outbound.peer == 2);
        BOOST_REQUIRE(std::holds_alternative<
            chainregistry::ChildTransactionData>(outbound.message));
        const auto& payload{std::get<chainregistry::ChildTransactionData>(
            outbound.message)};
        BOOST_CHECK(payload.chain_id == definition.chain_id);
        BOOST_CHECK(payload.transaction.GetHash() == transaction->GetHash());
    }

    auto wrong_chain{chainregistry::ChildTransactionData{
        .chain_id = Definition().chain_id,
        .transaction = missing_input,
    }};
    wrong_chain.chain_id = chainregistry::ChainId{
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    const auto malformed{processor.ReceiveTransaction(
        1, wrong_chain, 1s, Params().GenesisBlock().nTime)};
    BOOST_CHECK(
        malformed.validation_error ==
        chainregistry::ChildNetValidationError::WRONG_CHAIN);
    BOOST_CHECK(malformed.disconnect);

    const auto rejected{processor.ReceiveTransaction(
        1,
        {.chain_id = definition.chain_id,
         .transaction = missing_input},
        1s,
        Params().GenesisBlock().nTime)};
    BOOST_CHECK(
        rejected.error ==
        node::ChildNetProcessorError::TRANSACTION_REJECTED);
    BOOST_CHECK(!rejected.disconnect);
    BOOST_CHECK(
        rejected.transaction_submission.runtime.error ==
        node::ReferenceChildMempoolAcceptError::CONTEXT_REJECTED);
    BOOST_CHECK(manager.GetMempool(definition.chain_id).runtime.entries.empty());

    for (uint64_t count{2}; count < node::MAX_CHILD_TRANSACTION_BURST;
         ++count) {
        const auto invalid{processor.ReceiveTransaction(
            1,
            {.chain_id = definition.chain_id,
             .transaction = missing_input},
            1s,
            Params().GenesisBlock().nTime)};
        BOOST_CHECK(
            invalid.error ==
            node::ChildNetProcessorError::TRANSACTION_REJECTED);
    }
    const auto limited{processor.ReceiveTransaction(
        1,
        {.chain_id = definition.chain_id,
         .transaction = missing_input},
        1s,
        Params().GenesisBlock().nTime)};
    BOOST_CHECK(
        limited.error ==
        node::ChildNetProcessorError::TRANSACTION_RATE_LIMITED);
    BOOST_CHECK(limited.disconnect);
    const auto refilled{processor.ReceiveTransaction(
        1,
        {.chain_id = definition.chain_id,
         .transaction = missing_input},
        1s + node::CHILD_TRANSACTION_REFILL_INTERVAL,
        Params().GenesisBlock().nTime)};
    BOOST_CHECK(
        refilled.error ==
        node::ChildNetProcessorError::TRANSACTION_REJECTED);
    BOOST_CHECK(!refilled.disconnect);
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
    BOOST_REQUIRE(processor.Connected(1, 123).IsValid());
    BOOST_REQUIRE(processor.Connected(2, 456).IsValid());
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

BOOST_AUTO_TEST_CASE(bounds_and_expires_deferred_blocks)
{
    const auto definition{Definition()};
    node::ChainManager manager{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_net_deferred_limits",
        1 << 20};
    BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());

    std::vector<CBlock> blocks;
    blocks.reserve(node::MAX_DEFERRED_CHILD_BLOCKS + 1);
    const uint32_t genesis_time{Params().GenesisBlock().nTime};
    for (size_t index{0};
         index <= node::MAX_DEFERRED_CHILD_BLOCKS;
         ++index) {
        blocks.push_back(ChildBlock(
            uint256{static_cast<uint8_t>(index + 1)},
            static_cast<int>(index + 1),
            genesis_time + static_cast<uint32_t>(index + 1)));
        StageBlock(manager, definition, blocks.back(), /*sync=*/false);
    }

    node::ChildNetProcessor processor{manager, definition};
    BOOST_REQUIRE(processor.Connected(1, 123).IsValid());
    BOOST_REQUIRE(processor.ReceiveHello(1, {
        .chain_id = definition.chain_id,
        .genesis_hash = definition.genesis_hash,
    }).IsValid());

    const node::ChildRequestTime now{1s};
    for (size_t index{0}; index < node::MAX_DEFERRED_CHILD_BLOCKS; ++index) {
        const auto announced{processor.ReceiveInventory(
            1,
            {.chain_id = definition.chain_id,
             .block_hashes = {blocks[index].GetHash()}},
            now)};
        BOOST_REQUIRE(announced.IsValid());
        const auto deferred{processor.ReceiveBlock(
            1,
            {.chain_id = definition.chain_id, .block = blocks[index]},
            now,
            blocks[index].nTime)};
        BOOST_REQUIRE(deferred.IsValid());
        BOOST_REQUIRE_EQUAL(deferred.deferred_blocks.size(), 1U);
    }
    BOOST_CHECK_EQUAL(
        processor.DeferredCount(), node::MAX_DEFERRED_CHILD_BLOCKS);
    const size_t full_bytes{processor.DeferredBytes()};

    const CBlock& overflow{blocks.back()};
    BOOST_REQUIRE(processor.ReceiveInventory(
        1,
        {.chain_id = definition.chain_id,
         .block_hashes = {overflow.GetHash()}},
        now).IsValid());
    const auto limited{processor.ReceiveBlock(
        1,
        {.chain_id = definition.chain_id, .block = overflow},
        now,
        overflow.nTime)};
    BOOST_CHECK(
        limited.error == node::ChildNetProcessorError::DEFERRED_CACHE_FULL);
    BOOST_CHECK(limited.deferred_blocks.empty());
    BOOST_CHECK_EQUAL(
        processor.DeferredCount(), node::MAX_DEFERRED_CHILD_BLOCKS);
    BOOST_CHECK_EQUAL(processor.DeferredBytes(), full_bytes);

    const auto expired{processor.Poll(
        now + node::DEFERRED_CHILD_BLOCK_TIMEOUT,
        overflow.nTime)};
    BOOST_REQUIRE_EQUAL(
        expired.expired_deferred_blocks.size(),
        node::MAX_DEFERRED_CHILD_BLOCKS);
    BOOST_CHECK_EQUAL(processor.DeferredCount(), 0U);
    BOOST_CHECK_EQUAL(processor.DeferredBytes(), 0U);

    BOOST_REQUIRE(processor.ReceiveInventory(
        1,
        {.chain_id = definition.chain_id,
         .block_hashes = {overflow.GetHash()}},
        now + node::DEFERRED_CHILD_BLOCK_TIMEOUT).IsValid());
    const auto recovered{processor.ReceiveBlock(
        1,
        {.chain_id = definition.chain_id, .block = overflow},
        now + node::DEFERRED_CHILD_BLOCK_TIMEOUT,
        overflow.nTime)};
    BOOST_REQUIRE(recovered.IsValid());
    BOOST_CHECK_EQUAL(processor.DeferredCount(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
