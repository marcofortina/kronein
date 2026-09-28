// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace {

const COutPoint REGISTRATION_ANCHOR{
    Txid{"1111111111111111111111111111111111111111111111111111111111111111"},
    1};
const chainregistry::MetadataHash METADATA_HASH{
    "4444444444444444444444444444444444444444444444444444444444444444"};

struct ChildChainSetup : BasicTestingSetup {
    ChildChainSetup()
        : BasicTestingSetup{ChainType::REGTEST}
    {
    }
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

CBlock ChildBlock(const CBlockIndex& parent, CAmount reward = 0)
{
    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vin.front().scriptSig =
        CScript{} << static_cast<int64_t>(parent.nHeight + 1) <<
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
    block.hashPrevBlock = parent.GetBlockHash();
    block.nTime = parent.nTime + 1;
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

CBlockHeader MineMainHeader(const CBlockIndex& parent,
                            const Consensus::Params& params)
{
    CBlockHeader header;
    header.nVersion = CBlockHeader::CURRENT_VERSION;
    header.hashPrevBlock = parent.GetBlockHash();
    header.hashMerkleRoot = uint256{0x42};
    header.nTime = parent.nTime + 1;
    header.nBits = GetNextWorkRequired(&parent, &header, params);
    const auto seed{GetRandomXSeed(&parent, parent.nHeight + 1, params)};
    BOOST_REQUIRE(seed.has_value());
    uint64_t max_tries{1'000'000};
    BOOST_REQUIRE(MineProofOfWork(
        header,
        *seed,
        params,
        max_tries,
        /*threads=*/1,
        /*use_full_memory=*/false));
    return header;
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
        .control_outpoint = COutPoint{
            Txid{"2222222222222222222222222222222222222222222222222222222222222222"}, 0},
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
        Txid{"3333333333333333333333333333333333333333333333333333333333333333"}, 0});
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

DBParams ChildDBParams(const fs::path& path, bool wipe)
{
    return {
        .path = path,
        .cache_bytes = 1 << 20,
        .memory_only = false,
        .wipe_data = wipe,
        .obfuscate = true,
    };
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(child_chain_tests, ChildChainSetup)

BOOST_AUTO_TEST_CASE(connect_restart_disconnect_is_atomic)
{
    const auto definition{Definition()};
    const auto& params{Params().GetConsensus()};
    const CBlock& main_genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "reference_child_runtime"};
    uint256 child_hash;

    {
        node::ReferenceChildRuntime runtime{params, definition};
        const auto initialized{runtime.Initialize(
            ChildDBParams(path, /*wipe=*/true),
            main_genesis,
            main_genesis.nTime,
            /*sync=*/true)};
        BOOST_REQUIRE(initialized.IsValid());
        BOOST_CHECK(!initialized.loaded_existing);
        BOOST_REQUIRE(runtime.Tip());
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == definition.genesis_hash);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 0U);
        const auto initially_pending{runtime.GetPendingBlocks()};
        BOOST_REQUIRE(initially_pending.has_value());
        BOOST_CHECK(initially_pending->empty());

        const CBlock block{ChildBlock(*runtime.Tip())};
        child_hash = block.GetHash();
        BOOST_CHECK(
            runtime.ConnectStagedBlock(block, block.nTime).error ==
            node::ReferenceChildRuntimeError::BMM_ANCHOR_UNAVAILABLE);
        const CBlockIndex* main_parent{runtime.MainHeaders()->Tip()};
        BOOST_REQUIRE(main_parent);
        CBlock main_anchor;
        const auto anchor_proof{MakeBmmProof(
            main_anchor, *main_parent, params, definition, child_hash)};
        const auto unknown_anchor{runtime.ConnectBlock(
            block, anchor_proof, block.nTime, /*sync=*/true)};
        BOOST_CHECK(unknown_anchor.error ==
                    node::ReferenceChildRuntimeError::BMM_ANCHOR_REJECTED);
        BOOST_CHECK(unknown_anchor.bmm_anchor.error ==
                    chainregistry::AuthenticatedBmmAnchorError::HEADER_UNKNOWN);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 0U);
        BOOST_REQUIRE(runtime.AddMainHeader(
            main_anchor, main_anchor.nTime, /*sync=*/true).IsValid());
        const auto staged{runtime.StageBmmAnchor(
            anchor_proof, block.nTime, /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(staged.IsValid(), static_cast<int>(staged.error));
        BOOST_CHECK(!staged.bmm_anchor_already_known);
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_count, 1U);
        BOOST_CHECK_GT(runtime.State().pending_anchor_bytes, 0U);
        const auto first_pending{runtime.GetPendingBlocks()};
        BOOST_REQUIRE(first_pending.has_value());
        BOOST_REQUIRE_EQUAL(first_pending->size(), 1U);
        BOOST_CHECK(first_pending->front().block_hash == child_hash);
        BOOST_CHECK_EQUAL(first_pending->front().anchor_count, 1U);
        BOOST_CHECK_EQUAL(
            first_pending->front().oldest_anchor_height,
            anchor_proof.block_height);
        BOOST_CHECK_EQUAL(
            first_pending->front().newest_anchor_height,
            anchor_proof.block_height);
        const auto duplicate_stage{runtime.StageBmmAnchor(
            anchor_proof, block.nTime, /*sync=*/true)};
        BOOST_REQUIRE(duplicate_stage.IsValid());
        BOOST_CHECK(duplicate_stage.bmm_anchor_already_known);
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_count, 1U);

        main_parent = runtime.MainHeaders()->Tip();
        BOOST_REQUIRE(main_parent);
        CBlock repeated_main_anchor;
        const auto repeated_anchor_proof{MakeBmmProof(
            repeated_main_anchor,
            *main_parent,
            params,
            definition,
            child_hash)};
        BOOST_REQUIRE(runtime.AddMainHeader(
            repeated_main_anchor,
            repeated_main_anchor.nTime,
            /*sync=*/true).IsValid());
        BOOST_REQUIRE(runtime.StageBmmAnchor(
            repeated_anchor_proof, block.nTime, /*sync=*/true).IsValid());
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_count, 2U);
        const auto repeated_pending{runtime.GetPendingBlocks()};
        BOOST_REQUIRE(repeated_pending.has_value());
        BOOST_REQUIRE_EQUAL(repeated_pending->size(), 1U);
        BOOST_CHECK_EQUAL(repeated_pending->front().anchor_count, 2U);
        BOOST_CHECK_EQUAL(
            repeated_pending->front().oldest_anchor_height,
            anchor_proof.block_height);
        BOOST_CHECK_EQUAL(
            repeated_pending->front().newest_anchor_height,
            repeated_anchor_proof.block_height);
        const auto connected{runtime.ConnectStagedBlock(
            block, block.nTime, /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(
            connected.IsValid(),
            static_cast<int>(connected.error) << ":" <<
                static_cast<int>(connected.child_block.error));
        BOOST_CHECK(connected.bmm_anchor.anchor_chain_work ==
                    runtime.MainHeaders()->Tip()->nChainWork);
        BOOST_REQUIRE(runtime.Tip());
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == child_hash);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 1U);
        BOOST_CHECK(runtime.State().child_tip == child_hash);
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_count, 0U);
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_bytes, 0U);
        const auto no_longer_pending{runtime.GetPendingBlocks()};
        BOOST_REQUIRE(no_longer_pending.has_value());
        BOOST_CHECK(no_longer_pending->empty());
        BOOST_CHECK_EQUAL(runtime.State().candidate_anchor_count, 1U);
        const auto duplicate_connected_anchor{runtime.StageBmmAnchor(
            repeated_anchor_proof, block.nTime, /*sync=*/true)};
        BOOST_REQUIRE(duplicate_connected_anchor.IsValid());
        BOOST_CHECK(duplicate_connected_anchor.bmm_anchor_already_known);
        BOOST_CHECK_EQUAL(runtime.State().candidate_anchor_count, 1U);

        main_parent = runtime.MainHeaders()->Tip();
        BOOST_REQUIRE(main_parent);
        CBlock third_main_anchor;
        const auto third_anchor_proof{MakeBmmProof(
            third_main_anchor,
            *main_parent,
            params,
            definition,
            child_hash)};
        BOOST_REQUIRE(runtime.AddMainHeader(
            third_main_anchor,
            third_main_anchor.nTime,
            /*sync=*/true).IsValid());
        const auto third_staged{runtime.StageBmmAnchor(
            third_anchor_proof, block.nTime, /*sync=*/true)};
        BOOST_REQUIRE(third_staged.IsValid());
        BOOST_CHECK(!third_staged.bmm_anchor_already_known);
        BOOST_CHECK_EQUAL(runtime.State().candidate_anchor_count, 2U);

        CBlock stored;
        BOOST_REQUIRE(runtime.ReadBlock(child_hash, stored));
        BOOST_CHECK(stored.vtx.front()->GetWitnessHash() ==
                    block.vtx.front()->GetWitnessHash());
        const auto child_view{runtime.GetBlockView(child_hash)};
        BOOST_REQUIRE(child_view);
        BOOST_REQUIRE(child_view->block);
        BOOST_REQUIRE(child_view->undo);
        BOOST_CHECK(child_view->block->GetHash() == child_hash);
        BOOST_CHECK(child_view->undo->block_hash == child_hash);
        BOOST_CHECK(child_view->undo->parent_hash == block.hashPrevBlock);
        BOOST_CHECK(child_view->active);
        BOOST_CHECK(!child_view->virtual_genesis);
        BOOST_CHECK_EQUAL(child_view->height, 1);
        BOOST_CHECK_EQUAL(child_view->confirmations, 1);
        BOOST_CHECK(child_view->fork_score.eligible);
        BOOST_CHECK(child_view->fork_score.cumulative_anchor_work > 0);
        const auto genesis_view{
            runtime.GetBlockView(definition.genesis_hash)};
        BOOST_REQUIRE(genesis_view);
        BOOST_CHECK(genesis_view->virtual_genesis);
        BOOST_CHECK(!genesis_view->block);
        BOOST_CHECK(genesis_view->active);
        BOOST_CHECK_EQUAL(genesis_view->confirmations, 2);
        BOOST_REQUIRE(genesis_view->next_block_hash);
        BOOST_CHECK(*genesis_view->next_block_hash == child_hash);
        BOOST_CHECK(!runtime.GetBlockView(uint256{42}));

        const CBlock invalid{ChildBlock(*runtime.Tip(), /*reward=*/1)};
        main_parent = runtime.MainHeaders()->Tip();
        BOOST_REQUIRE(main_parent);
        CBlock invalid_main_anchor;
        const auto invalid_anchor_proof{MakeBmmProof(
            invalid_main_anchor,
            *main_parent,
            params,
            definition,
            invalid.GetHash())};
        BOOST_REQUIRE(runtime.AddMainHeader(
            invalid_main_anchor,
            invalid_main_anchor.nTime,
            /*sync=*/true).IsValid());
        const auto rejected{runtime.ConnectBlock(
            invalid,
            invalid_anchor_proof,
            invalid.nTime,
            /*sync=*/true)};
        BOOST_CHECK(rejected.error ==
                    node::ReferenceChildRuntimeError::CHILD_BLOCK_REJECTED);
        BOOST_CHECK_MESSAGE(
            rejected.child_block.error ==
                chainregistry::ReferenceChildBlockError::COINBASE_PAYS_TOO_MUCH,
            static_cast<int>(rejected.child_block.error));
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == child_hash);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 1U);

        CBlock missing_parent_block{ChildBlock(*runtime.Tip())};
        missing_parent_block.hashPrevBlock = uint256{42};
        main_parent = runtime.MainHeaders()->Tip();
        BOOST_REQUIRE(main_parent);
        CBlock missing_parent_main_anchor;
        const auto missing_parent_proof{MakeBmmProof(
            missing_parent_main_anchor,
            *main_parent,
            params,
            definition,
            missing_parent_block.GetHash())};
        BOOST_REQUIRE(runtime.AddMainHeader(
            missing_parent_main_anchor,
            missing_parent_main_anchor.nTime,
            /*sync=*/true).IsValid());
        const auto missing_parent{runtime.ConnectBlock(
            missing_parent_block,
            missing_parent_proof,
            missing_parent_block.nTime,
            /*sync=*/true)};
        BOOST_CHECK(
            missing_parent.error ==
            node::ReferenceChildRuntimeError::CHILD_PARENT_UNAVAILABLE);
        BOOST_CHECK(runtime.VerifyDatabase(missing_parent_main_anchor.nTime));
    }

    {
        node::ReferenceChildRuntime runtime{params, definition};
        const auto loaded{runtime.Initialize(
            ChildDBParams(path, /*wipe=*/false),
            main_genesis,
            main_genesis.nTime + 2,
            /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK(loaded.loaded_existing);
        BOOST_REQUIRE(runtime.Tip());
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == child_hash);
        BOOST_CHECK_EQUAL(runtime.Tip()->nHeight, 1);
        BOOST_CHECK(runtime.VerifyDatabase(main_genesis.nTime + 2));

        const auto disconnected{runtime.DisconnectTip(/*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(
            disconnected.IsValid(), static_cast<int>(disconnected.error));
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == definition.genesis_hash);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 0U);
        BOOST_CHECK(runtime.State().child_tip == definition.genesis_hash);
        CBlock removed;
        BOOST_CHECK(!runtime.ReadBlock(child_hash, removed));
        BOOST_CHECK(runtime.DisconnectTip().error ==
                    node::ReferenceChildRuntimeError::CHILD_DISCONNECT_REJECTED);
    }

    {
        node::ReferenceChildRuntime runtime{params, definition};
        const auto loaded{runtime.Initialize(
            ChildDBParams(path, /*wipe=*/false),
            main_genesis,
            main_genesis.nTime + 2)};
        BOOST_REQUIRE(loaded.IsValid());
        BOOST_CHECK(loaded.loaded_existing);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 0U);
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == definition.genesis_hash);
    }
}

BOOST_AUTO_TEST_CASE(validates_and_restores_noncanonical_branches)
{
    const auto definition{Definition()};
    const auto& params{Params().GetConsensus()};
    const CBlock& main_genesis{Params().GenesisBlock()};
    const fs::path path{
        m_args.GetDataDirBase() / "reference_child_candidates"};
    uint256 canonical_hash;
    uint256 competing_hash;
    uint256 extension_hash;
    CBlockHeader final_main_tip;

    {
        node::ReferenceChildRuntime runtime{params, definition};
        BOOST_REQUIRE(runtime.Initialize(
            ChildDBParams(path, /*wipe=*/true),
            main_genesis,
            main_genesis.nTime,
            /*sync=*/true).IsValid());
        const CBlockIndex* child_genesis{runtime.Tip()};
        BOOST_REQUIRE(child_genesis);

        const CBlock canonical{ChildBlock(*child_genesis)};
        canonical_hash = canonical.GetHash();
        const CBlockIndex* main_parent{runtime.MainHeaders()->Tip()};
        BOOST_REQUIRE(main_parent);
        CBlock canonical_anchor_block;
        const auto canonical_anchor{MakeBmmProof(
            canonical_anchor_block,
            *main_parent,
            params,
            definition,
            canonical_hash)};
        BOOST_REQUIRE(runtime.AddMainHeader(
            canonical_anchor_block,
            canonical_anchor_block.nTime,
            /*sync=*/true).IsValid());
        BOOST_REQUIRE(runtime.ConnectBlock(
            canonical,
            canonical_anchor,
            canonical.nTime,
            /*sync=*/true).IsValid());

        CBlock competing{ChildBlock(*child_genesis)};
        do {
            ++competing.nTime;
            competing_hash = competing.GetHash();
        } while (!(canonical_hash < competing_hash));
        BOOST_REQUIRE(competing_hash != canonical_hash);
        main_parent = runtime.MainHeaders()->Tip();
        BOOST_REQUIRE(main_parent);
        CBlock competing_anchor_block;
        const auto competing_anchor{MakeBmmProof(
            competing_anchor_block,
            *main_parent,
            params,
            definition,
            competing_hash)};
        BOOST_REQUIRE(runtime.AddMainHeader(
            competing_anchor_block,
            competing_anchor_block.nTime,
            /*sync=*/true).IsValid());

        const auto stored{runtime.ConnectBlock(
            competing,
            competing_anchor,
            competing.nTime,
            /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(stored.IsValid(), static_cast<int>(stored.error));
        BOOST_CHECK(stored.candidate_stored);
        BOOST_CHECK(!stored.reorganization_required);
        BOOST_CHECK(stored.selected_child_head == canonical_hash);
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == canonical_hash);
        BOOST_CHECK_EQUAL(runtime.State().side_candidate_count, 1U);
        BOOST_CHECK_EQUAL(runtime.State().candidate_anchor_count, 1U);

        main_parent = runtime.MainHeaders()->Tip();
        BOOST_REQUIRE(main_parent);
        CBlock repeated_anchor_block;
        const auto repeated_anchor{MakeBmmProof(
            repeated_anchor_block,
            *main_parent,
            params,
            definition,
            competing_hash)};
        BOOST_REQUIRE(runtime.AddMainHeader(
            repeated_anchor_block,
            repeated_anchor_block.nTime,
            /*sync=*/true).IsValid());
        const auto activated{runtime.StageBmmAnchor(
            repeated_anchor, competing.nTime, /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(
            activated.IsValid(), static_cast<int>(activated.error));
        BOOST_CHECK(!activated.bmm_anchor_already_known);
        BOOST_CHECK(!activated.reorganization_required);
        BOOST_CHECK(activated.selected_child_head == competing_hash);
        BOOST_REQUIRE_EQUAL(
            activated.disconnected_child_blocks.size(), 1U);
        BOOST_CHECK(
            activated.disconnected_child_blocks.front() == canonical_hash);
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == competing_hash);
        BOOST_CHECK_EQUAL(runtime.State().side_candidate_count, 1U);
        BOOST_CHECK_EQUAL(runtime.State().candidate_anchor_count, 2U);
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_count, 0U);

        CBlockIndex competing_index{competing};
        competing_index.phashBlock = &competing_hash;
        competing_index.pprev = const_cast<CBlockIndex*>(child_genesis);
        competing_index.nHeight = 1;
        competing_index.nTimeMax = std::max(
            child_genesis->nTimeMax, competing_index.nTime);
        competing_index.BuildSkip();
        const CBlock extension{ChildBlock(competing_index)};
        extension_hash = extension.GetHash();
        main_parent = runtime.MainHeaders()->Tip();
        BOOST_REQUIRE(main_parent);
        CBlock extension_anchor_block;
        const auto extension_anchor{MakeBmmProof(
            extension_anchor_block,
            *main_parent,
            params,
            definition,
            extension_hash)};
        BOOST_REQUIRE(runtime.AddMainHeader(
            extension_anchor_block,
            extension_anchor_block.nTime,
            /*sync=*/true).IsValid());
        final_main_tip = extension_anchor_block;
        const auto extended{runtime.ConnectBlock(
            extension,
            extension_anchor,
            extension.nTime,
            /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(
            extended.IsValid(), static_cast<int>(extended.error));
        BOOST_CHECK(!extended.candidate_stored);
        BOOST_CHECK(!extended.reorganization_required);
        BOOST_CHECK(extended.selected_child_head == extension_hash);
        BOOST_CHECK_EQUAL(runtime.State().side_candidate_count, 1U);
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == extension_hash);
    }

    {
        node::ReferenceChildRuntime runtime{params, definition};
        const auto loaded{runtime.Initialize(
            ChildDBParams(path, /*wipe=*/false),
            main_genesis,
            final_main_tip.nTime + 1,
            /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK(loaded.loaded_existing);
        BOOST_REQUIRE(runtime.Tip());
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == extension_hash);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 2U);
        BOOST_CHECK_EQUAL(runtime.State().side_candidate_count, 1U);
        CBlock restored_competing;
        CBlock restored_extension;
        CBlock restored_demoted;
        BOOST_CHECK(runtime.ReadBlock(competing_hash, restored_competing));
        BOOST_CHECK(runtime.ReadBlock(extension_hash, restored_extension));
        BOOST_CHECK(runtime.ReadBlock(canonical_hash, restored_demoted));
        BOOST_CHECK(restored_demoted.GetHash() == canonical_hash);
    }
}

BOOST_AUTO_TEST_CASE(pending_anchor_survives_restart_and_is_pruned_by_reorg)
{
    const auto definition{Definition()};
    const auto& params{Params().GetConsensus()};
    const CBlock& main_genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "reference_child_pending"};
    chainregistry::BmmAnchorProof proof;
    CBlock anchor_block;
    CBlockHeader fork2;

    {
        node::ReferenceChildRuntime runtime{params, definition};
        BOOST_REQUIRE(runtime.Initialize(
            ChildDBParams(path, /*wipe=*/true),
            main_genesis,
            main_genesis.nTime,
            /*sync=*/true).IsValid());
        const CBlock candidate{ChildBlock(*runtime.Tip())};
        const CBlockIndex* main_parent{runtime.MainHeaders()->Tip()};
        BOOST_REQUIRE(main_parent);
        proof = MakeBmmProof(
            anchor_block,
            *main_parent,
            params,
            definition,
            candidate.GetHash());
        BOOST_REQUIRE(runtime.AddMainHeader(
            anchor_block, anchor_block.nTime, /*sync=*/true).IsValid());
        const auto staged{runtime.StageBmmAnchor(
            proof, anchor_block.nTime, /*sync=*/true)};
        BOOST_REQUIRE(staged.IsValid());
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_count, 1U);
        BOOST_CHECK_GT(runtime.State().pending_anchor_bytes, 0U);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 0U);
    }

    {
        node::ReferenceChildRuntime runtime{params, definition};
        const auto loaded{runtime.Initialize(
            ChildDBParams(path, /*wipe=*/false),
            main_genesis,
            anchor_block.nTime + 1,
            /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK(loaded.loaded_existing);
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_count, 1U);
        const auto duplicate{runtime.StageBmmAnchor(
            proof, anchor_block.nTime, /*sync=*/true)};
        BOOST_REQUIRE(duplicate.IsValid());
        BOOST_CHECK(duplicate.bmm_anchor_already_known);

        const CBlockIndex* genesis_index{
            runtime.MainHeaders()->Find(main_genesis.GetHash())};
        BOOST_REQUIRE(genesis_index);
        const CBlockHeader fork1{MineMainHeader(*genesis_index, params)};
        BOOST_REQUIRE(runtime.AddMainHeader(
            fork1, fork1.nTime, /*sync=*/true).IsValid());
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_count, 1U);
        const CBlockIndex* fork1_index{
            runtime.MainHeaders()->Find(fork1.GetHash())};
        BOOST_REQUIRE(fork1_index);
        fork2 = MineMainHeader(*fork1_index, params);
        const auto reorg{runtime.AddMainHeader(
            fork2, fork2.nTime, /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(reorg.IsValid(), static_cast<int>(reorg.error));
        BOOST_CHECK(reorg.main_header.became_best);
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_count, 0U);
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_bytes, 0U);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 0U);
    }

    {
        node::ReferenceChildRuntime runtime{params, definition};
        const auto loaded{runtime.Initialize(
            ChildDBParams(path, /*wipe=*/false),
            main_genesis,
            fork2.nTime + 1,
            /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_count, 0U);
        BOOST_CHECK_EQUAL(runtime.State().pending_anchor_bytes, 0U);
        BOOST_CHECK(runtime.MainHeaders()->Tip()->GetBlockHash() == fork2.GetHash());
    }
}

BOOST_AUTO_TEST_CASE(main_reorg_preserves_orphaned_child_candidates)
{
    const auto definition{Definition()};
    const auto& params{Params().GetConsensus()};
    const CBlock& main_genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "reference_child_reorg"};
    uint256 first_child_hash;
    uint256 second_child_hash;
    CBlockHeader fork3;

    {
        node::ReferenceChildRuntime runtime{params, definition};
        BOOST_REQUIRE(runtime.Initialize(
            ChildDBParams(path, /*wipe=*/true),
            main_genesis,
            main_genesis.nTime,
            /*sync=*/true).IsValid());

        const CBlock first_child{ChildBlock(*runtime.Tip())};
        first_child_hash = first_child.GetHash();
        const CBlockIndex* main_parent{runtime.MainHeaders()->Tip()};
        BOOST_REQUIRE(main_parent);
        CBlock first_anchor;
        const auto first_proof{MakeBmmProof(
            first_anchor,
            *main_parent,
            params,
            definition,
            first_child_hash)};
        BOOST_REQUIRE(runtime.AddMainHeader(
            first_anchor, first_anchor.nTime, /*sync=*/true).IsValid());
        BOOST_REQUIRE(runtime.ConnectBlock(
            first_child,
            first_proof,
            first_child.nTime,
            /*sync=*/true).IsValid());

        const CBlock second_child{ChildBlock(*runtime.Tip())};
        second_child_hash = second_child.GetHash();
        main_parent = runtime.MainHeaders()->Tip();
        BOOST_REQUIRE(main_parent);
        CBlock second_anchor;
        const auto second_proof{MakeBmmProof(
            second_anchor,
            *main_parent,
            params,
            definition,
            second_child_hash)};
        BOOST_REQUIRE(runtime.AddMainHeader(
            second_anchor, second_anchor.nTime, /*sync=*/true).IsValid());
        BOOST_REQUIRE(runtime.ConnectBlock(
            second_child,
            second_proof,
            second_child.nTime,
            /*sync=*/true).IsValid());
        BOOST_CHECK_EQUAL(runtime.State().child_height, 2U);

        const CBlockIndex* genesis_index{
            runtime.MainHeaders()->Find(main_genesis.GetHash())};
        BOOST_REQUIRE(genesis_index);
        const CBlockHeader fork1{MineMainHeader(*genesis_index, params)};
        const auto fork1_result{runtime.AddMainHeader(
            fork1, fork1.nTime, /*sync=*/true)};
        BOOST_REQUIRE(fork1_result.IsValid());
        BOOST_CHECK(fork1_result.disconnected_child_blocks.empty());
        const CBlockIndex* fork1_index{
            runtime.MainHeaders()->Find(fork1.GetHash())};
        BOOST_REQUIRE(fork1_index);
        const CBlockHeader fork2{MineMainHeader(*fork1_index, params)};
        const auto fork2_result{runtime.AddMainHeader(
            fork2, fork2.nTime, /*sync=*/true)};
        BOOST_REQUIRE(fork2_result.IsValid());
        BOOST_CHECK(fork2_result.disconnected_child_blocks.empty());
        BOOST_CHECK_EQUAL(runtime.State().child_height, 2U);

        const CBlockIndex* fork2_index{
            runtime.MainHeaders()->Find(fork2.GetHash())};
        BOOST_REQUIRE(fork2_index);
        fork3 = MineMainHeader(*fork2_index, params);
        const auto reorganized{runtime.AddMainHeader(
            fork3, fork3.nTime, /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(
            reorganized.IsValid(), static_cast<int>(reorganized.error));
        BOOST_CHECK(reorganized.main_header.became_best);
        BOOST_CHECK_EQUAL(reorganized.main_header.disconnected_headers, 2U);
        BOOST_REQUIRE_EQUAL(reorganized.disconnected_child_blocks.size(), 2U);
        BOOST_CHECK(reorganized.disconnected_child_blocks[0] == second_child_hash);
        BOOST_CHECK(reorganized.disconnected_child_blocks[1] == first_child_hash);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 0U);
        BOOST_CHECK_EQUAL(runtime.State().anchor_count, 0U);
        BOOST_CHECK_EQUAL(runtime.State().side_candidate_count, 2U);
        BOOST_CHECK_EQUAL(runtime.State().candidate_anchor_count, 2U);
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == definition.genesis_hash);
        BOOST_CHECK(runtime.MainHeaders()->Tip()->GetBlockHash() == fork3.GetHash());
        CBlock retained;
        BOOST_CHECK(runtime.ReadBlock(first_child_hash, retained));
        BOOST_CHECK(runtime.ReadBlock(second_child_hash, retained));
        const auto tips{runtime.GetChainTips()};
        BOOST_REQUIRE(tips);
        BOOST_REQUIRE_EQUAL(tips->size(), 2U);
        BOOST_CHECK(tips->at(0).block_hash == second_child_hash);
        BOOST_CHECK_EQUAL(tips->at(0).height, 2);
        BOOST_CHECK_EQUAL(tips->at(0).branch_length, 2);
        BOOST_CHECK(!tips->at(0).active);
        BOOST_CHECK(!tips->at(0).fork_score.eligible);
        BOOST_CHECK(tips->at(1).block_hash == definition.genesis_hash);
        BOOST_CHECK(tips->at(1).active);
        BOOST_CHECK_EQUAL(tips->at(1).branch_length, 0);
    }

    {
        node::ReferenceChildRuntime runtime{params, definition};
        const auto loaded{runtime.Initialize(
            ChildDBParams(path, /*wipe=*/false),
            main_genesis,
            fork3.nTime + 1,
            /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK(loaded.loaded_existing);
        BOOST_CHECK_EQUAL(runtime.State().header_count, 6U);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 0U);
        BOOST_CHECK_EQUAL(runtime.State().anchor_count, 0U);
        BOOST_CHECK_EQUAL(runtime.State().side_candidate_count, 2U);
        BOOST_CHECK_EQUAL(runtime.State().candidate_anchor_count, 2U);
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == definition.genesis_hash);
        BOOST_CHECK(runtime.MainHeaders()->Tip()->GetBlockHash() == fork3.GetHash());
        CBlock retained;
        BOOST_CHECK(runtime.ReadBlock(first_child_hash, retained));
        BOOST_CHECK(runtime.ReadBlock(second_child_hash, retained));
        const auto tips{runtime.GetChainTips()};
        BOOST_REQUIRE(tips);
        BOOST_REQUIRE_EQUAL(tips->size(), 2U);
        BOOST_CHECK(tips->at(0).block_hash == second_child_hash);
        BOOST_CHECK(tips->at(1).block_hash == definition.genesis_hash);
        BOOST_CHECK(tips->at(1).active);
    }
}

BOOST_AUTO_TEST_CASE(main_reorg_activates_surviving_child_fork)
{
    const auto definition{Definition()};
    const auto& params{Params().GetConsensus()};
    const CBlock& main_genesis{Params().GenesisBlock()};
    const fs::path path{
        m_args.GetDataDirBase() / "reference_child_main_reselect"};

    node::ReferenceChildRuntime runtime{params, definition};
    BOOST_REQUIRE(runtime.Initialize(
        ChildDBParams(path, /*wipe=*/true),
        main_genesis,
        main_genesis.nTime,
        /*sync=*/true).IsValid());
    const CBlockIndex* child_genesis{runtime.Tip()};
    BOOST_REQUIRE(child_genesis);

    const CBlock canonical{ChildBlock(*child_genesis)};
    const uint256 canonical_hash{canonical.GetHash()};
    CBlock surviving{ChildBlock(*child_genesis)};
    uint256 surviving_hash;
    do {
        ++surviving.nTime;
        surviving_hash = surviving.GetHash();
    } while (!(canonical_hash < surviving_hash));

    const CBlockIndex* main_parent{runtime.MainHeaders()->Tip()};
    BOOST_REQUIRE(main_parent);
    CBlock surviving_anchor_block;
    const auto surviving_anchor{MakeBmmProof(
        surviving_anchor_block,
        *main_parent,
        params,
        definition,
        surviving_hash)};
    BOOST_REQUIRE(runtime.AddMainHeader(
        surviving_anchor_block,
        surviving_anchor_block.nTime,
        /*sync=*/true).IsValid());
    BOOST_REQUIRE(runtime.StageBmmAnchor(
        surviving_anchor, surviving.nTime, /*sync=*/true).IsValid());

    main_parent = runtime.MainHeaders()->Tip();
    BOOST_REQUIRE(main_parent);
    CBlock canonical_anchor_block;
    const auto canonical_anchor{MakeBmmProof(
        canonical_anchor_block,
        *main_parent,
        params,
        definition,
        canonical_hash)};
    BOOST_REQUIRE(runtime.AddMainHeader(
        canonical_anchor_block,
        canonical_anchor_block.nTime,
        /*sync=*/true).IsValid());
    BOOST_REQUIRE(runtime.ConnectBlock(
        canonical,
        canonical_anchor,
        canonical.nTime,
        /*sync=*/true).IsValid());

    const auto stored{runtime.ConnectBlock(
        surviving,
        surviving_anchor,
        surviving.nTime,
        /*sync=*/true)};
    BOOST_REQUIRE_MESSAGE(stored.IsValid(), static_cast<int>(stored.error));
    BOOST_CHECK(stored.candidate_stored);
    BOOST_CHECK(stored.selected_child_head == canonical_hash);
    BOOST_CHECK(runtime.Tip()->GetBlockHash() == canonical_hash);

    const CBlockIndex* common_main{
        runtime.MainHeaders()->Find(surviving_anchor_block.GetHash())};
    BOOST_REQUIRE(common_main);
    const CBlockHeader fork2{MineMainHeader(*common_main, params)};
    BOOST_REQUIRE(runtime.AddMainHeader(
        fork2, fork2.nTime, /*sync=*/true).IsValid());
    const CBlockIndex* fork2_index{
        runtime.MainHeaders()->Find(fork2.GetHash())};
    BOOST_REQUIRE(fork2_index);
    const CBlockHeader fork3{MineMainHeader(*fork2_index, params)};
    const auto reorganized{runtime.AddMainHeader(
        fork3, fork3.nTime, /*sync=*/true)};
    BOOST_REQUIRE_MESSAGE(
        reorganized.IsValid(), static_cast<int>(reorganized.error));
    BOOST_REQUIRE_EQUAL(reorganized.disconnected_child_blocks.size(), 1U);
    BOOST_CHECK(
        reorganized.disconnected_child_blocks.front() == canonical_hash);
    BOOST_CHECK(reorganized.selected_child_head == surviving_hash);
    BOOST_CHECK(!reorganized.reorganization_required);
    BOOST_CHECK(runtime.Tip()->GetBlockHash() == surviving_hash);
    BOOST_CHECK_EQUAL(runtime.State().child_height, 1U);
    BOOST_CHECK_EQUAL(runtime.State().side_candidate_count, 1U);
    BOOST_CHECK_EQUAL(runtime.State().candidate_anchor_count, 1U);
    CBlock retained;
    BOOST_CHECK(runtime.ReadBlock(canonical_hash, retained));
}

BOOST_AUTO_TEST_CASE(main_headers_are_validated_and_persisted)
{
    const auto definition{Definition()};
    const auto& params{Params().GetConsensus()};
    const CBlock& main_genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "reference_child_headers"};
    CBlockHeader header;

    {
        node::ReferenceChildRuntime runtime{params, definition};
        BOOST_REQUIRE(runtime.Initialize(
            ChildDBParams(path, /*wipe=*/true),
            main_genesis,
            main_genesis.nTime,
            /*sync=*/true).IsValid());
        const CBlockIndex* genesis_index{
            runtime.MainHeaders()->Find(main_genesis.GetHash())};
        BOOST_REQUIRE(genesis_index);
        header = MineMainHeader(*genesis_index, params);
        const auto added{runtime.AddMainHeader(
            header, header.nTime, /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(added.IsValid(), static_cast<int>(added.error));
        BOOST_CHECK(added.main_header.became_best);
        BOOST_CHECK(runtime.MainHeaders()->Tip()->GetBlockHash() ==
                    header.GetHash());
        BOOST_CHECK_EQUAL(runtime.State().header_count, 2U);

        const auto duplicate{runtime.AddMainHeader(
            header, header.nTime, /*sync=*/true)};
        BOOST_REQUIRE(duplicate.IsValid());
        BOOST_CHECK(duplicate.main_header.already_known);
        BOOST_CHECK_EQUAL(runtime.State().header_count, 2U);

        CBlockHeader invalid{header};
        invalid.hashPrevBlock = header.GetHash();
        invalid.nTime += 1;
        invalid.nBits = 0;
        const auto rejected{runtime.AddMainHeader(invalid, invalid.nTime)};
        BOOST_CHECK(rejected.error ==
                    node::ReferenceChildRuntimeError::MAIN_HEADER_REJECTED);
        BOOST_CHECK(runtime.MainHeaders()->Tip()->GetBlockHash() ==
                    header.GetHash());
        BOOST_CHECK_EQUAL(runtime.State().header_count, 2U);
    }

    {
        node::ReferenceChildRuntime runtime{params, definition};
        const auto loaded{runtime.Initialize(
            ChildDBParams(path, /*wipe=*/false),
            main_genesis,
            header.nTime + 1)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK(loaded.loaded_existing);
        BOOST_CHECK(runtime.MainHeaders()->Tip()->GetBlockHash() ==
                    header.GetHash());
        BOOST_CHECK_EQUAL(runtime.State().header_count, 2U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
