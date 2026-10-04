// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chain_manager.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <dbwrapper.h>
#include <pow.h>
#include <primitives/chainregistry.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <future>
#include <thread>
#include <vector>

namespace {

const chainregistry::MetadataHash METADATA_HASH{
    "4444444444444444444444444444444444444444444444444444444444444444"};

struct ChainManagerSetup : BasicTestingSetup {
    ChainManagerSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};

chainregistry::ReferenceChildDefinition Definition(uint32_t index)
{
    const COutPoint anchor{
        Txid::FromUint256(ArithToUint256(arith_uint256{index + 1})),
        index};
    const auto result{chainregistry::BuildReferenceChildDefinition(
        Params().GetConsensus().hashGenesisBlock,
        anchor,
        chainregistry::MakeReferenceChildSpec({}),
        METADATA_HASH,
        TestChildFeeRecipient())};
    BOOST_REQUIRE(result.IsValid());
    return *result.definition;
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
        header, *seed, params, max_tries,
        /*threads=*/1, /*use_full_memory=*/false));
    return header;
}

CBlock ChildBlock(
    const CBlockIndex& parent,
    const chainregistry::ReferenceChildDefinition& definition)
{
    auto built{chainregistry::BuildReferenceChildBlock(
        parent, parent.nTime + 1, definition, {}, std::nullopt)};
    BOOST_REQUIRE(built.IsValid());
    return std::move(*built.block);
}

chainregistry::ChainRecord Record(
    const chainregistry::ReferenceChildDefinition& definition,
    chainregistry::ChainStatus status = chainregistry::ChainStatus::ACTIVE)
{
    return {
        .chain_id = definition.chain_id,
        .manifest_hash = definition.manifest_hash,
        .template_id = definition.manifest.spec.template_id,
        .template_version = definition.manifest.spec.template_version,
        .control_outpoint = definition.genesis.registration_anchor,
        .metadata_hash = definition.manifest.initial_metadata_hash,
        .status = status,
        .registered_height = 1,
        .updated_height = 1,
        .retired_height = status == chainregistry::ChainStatus::RETIRED ? 2U : 0U,
    };
}

chainregistry::BmmAnchorProof MakeBmmProof(
    CBlock& main_block,
    const CBlockIndex& parent,
    const Consensus::Params& params,
    const chainregistry::ReferenceChildDefinition& definition,
    const uint256& child_block_hash)
{
    const chainregistry::ChainRecord record{Record(definition)};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vout.emplace_back(
        0, chainregistry::BuildRegistryCommitment(registry.ComputeRoot()));
    CMutableTransaction proposal;
    proposal.vin.emplace_back(COutPoint{
        Txid::FromUint256(child_block_hash), 0});
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
    const auto seed{
        GetRandomXSeed(&parent, parent.nHeight + 1, params)};
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(chain_manager_tests, ChainManagerSetup)

BOOST_AUTO_TEST_CASE(catalog_is_opt_in_and_uses_isolated_paths)
{
    const auto first{Definition(1)};
    const auto second{Definition(2)};
    const fs::path root{m_args.GetDataDirBase() / "chains"};
    node::ChainManager manager{
        Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
    BOOST_REQUIRE(manager.IsCatalogReady());

    const auto registered{manager.RegisterChain(first)};
    BOOST_REQUIRE(registered.IsValid());
    BOOST_CHECK(!registered.already_registered);
    const auto duplicate{manager.RegisterChain(first)};
    BOOST_REQUIRE(duplicate.IsValid());
    BOOST_CHECK(duplicate.already_registered);
    BOOST_REQUIRE(manager.RegisterChain(second).IsValid());
    BOOST_CHECK_EQUAL(manager.RegisteredCount(), 2U);
    BOOST_CHECK_EQUAL(manager.LoadedCount(), 0U);
    BOOST_CHECK(!manager.IsLoaded(first.chain_id));
    BOOST_CHECK(!manager.IsLoaded(second.chain_id));

    const std::vector<CTransactionRef> no_transactions;
    BOOST_CHECK(
        manager.BuildTransactionBlock(
            chainregistry::ChainId{},
            no_transactions,
            std::nullopt,
            Params().GenesisBlock().nTime).error ==
        node::ChainManagerTransactionBlockBuildError::NULL_CHAIN_ID);
    BOOST_CHECK(
        manager.BuildTransactionBlock(
            Definition(99).chain_id,
            no_transactions,
            std::nullopt,
            Params().GenesisBlock().nTime).error ==
        node::ChainManagerTransactionBlockBuildError::UNKNOWN_CHAIN);
    BOOST_CHECK(
        manager.BuildTransactionBlock(
            first.chain_id,
            no_transactions,
            std::nullopt,
            Params().GenesisBlock().nTime).error ==
        node::ChainManagerTransactionBlockBuildError::CHAIN_NOT_LOADED);
    BOOST_CHECK(
        manager.GetMempool(chainregistry::ChainId{}).error ==
        node::ChainManagerMempoolViewError::NULL_CHAIN_ID);
    BOOST_CHECK(
        manager.GetMempool(Definition(99).chain_id).error ==
        node::ChainManagerMempoolViewError::UNKNOWN_CHAIN);
    BOOST_CHECK(
        manager.GetMempool(first.chain_id).error ==
        node::ChainManagerMempoolViewError::CHAIN_NOT_LOADED);
    BOOST_CHECK(
        manager.TestTransactions(
            chainregistry::ChainId{}, no_transactions,
            Params().GenesisBlock().nTime).error ==
        node::ChainManagerMempoolPackageError::NULL_CHAIN_ID);
    BOOST_CHECK(
        manager.TestTransactions(
            Definition(99).chain_id, no_transactions,
            Params().GenesisBlock().nTime).error ==
        node::ChainManagerMempoolPackageError::UNKNOWN_CHAIN);
    BOOST_CHECK(
        manager.TestTransactions(
            first.chain_id, no_transactions,
            Params().GenesisBlock().nTime).error ==
        node::ChainManagerMempoolPackageError::CHAIN_NOT_LOADED);
    BOOST_CHECK(
        manager.ScanWalletHistory(chainregistry::ChainId{}, {}).error ==
        node::ChainManagerWalletHistoryError::NULL_CHAIN_ID);
    BOOST_CHECK(
        manager.ScanWalletHistory(Definition(99).chain_id, {}).error ==
        node::ChainManagerWalletHistoryError::UNKNOWN_CHAIN);
    BOOST_CHECK(
        manager.ScanWalletHistory(first.chain_id, {}).error ==
        node::ChainManagerWalletHistoryError::CHAIN_NOT_LOADED);

    const auto loaded{manager.LoadChain(
        first.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true)};
    BOOST_REQUIRE_MESSAGE(
        loaded.IsValid(), static_cast<int>(loaded.runtime.error));
    BOOST_CHECK(!loaded.runtime.loaded_existing);
    BOOST_CHECK_EQUAL(manager.LoadedCount(), 1U);
    BOOST_REQUIRE(manager.Get(first.chain_id));
    BOOST_CHECK(!manager.Get(second.chain_id));
    const auto child_mempool{manager.GetMempool(first.chain_id)};
    BOOST_REQUIRE(child_mempool.IsValid());
    BOOST_CHECK(child_mempool.runtime.entries.empty());
    BOOST_CHECK_EQUAL(child_mempool.runtime.total_bytes, 0U);
    BOOST_CHECK_EQUAL(child_mempool.runtime.total_fees, 0);
    const auto empty_history{
        manager.ScanWalletHistory(first.chain_id, {})};
    BOOST_REQUIRE(empty_history.IsValid());
    BOOST_CHECK(empty_history.transactions.empty());
    BOOST_CHECK(!empty_history.next_height);
    BOOST_CHECK_EQUAL(empty_history.entry.height, 0U);
    BOOST_CHECK(
        manager.ScanWalletHistory(first.chain_id, {}, 1).error ==
        node::ChainManagerWalletHistoryError::HEIGHT_OUT_OF_RANGE);
    BOOST_CHECK(
        manager.ScanWalletHistory(
            first.chain_id, {}, std::nullopt, /*max_blocks=*/0).error ==
        node::ChainManagerWalletHistoryError::INVALID_LIMIT);
    BOOST_CHECK(
        manager.ScanWalletHistory(
            first.chain_id,
            {},
            std::nullopt,
            node::MAX_CHILD_WALLET_HISTORY_BLOCKS_PER_SCAN + 1)
            .error == node::ChainManagerWalletHistoryError::INVALID_LIMIT);

    const std::vector<chainregistry::DepositProof> oversized_import_batch(
        node::MAX_CHILD_IMPORTS_PER_BLOCK + 1);
    BOOST_CHECK(
        manager.BuildImportBlock(
            first.chain_id,
            oversized_import_batch,
            Params().GenesisBlock().nTime)
            .error ==
        node::ChainManagerImportBlockBuildError::TOO_MANY_PROOFS);
    const std::vector<chainregistry::DepositProof> maximum_import_batch(
        node::MAX_CHILD_IMPORTS_PER_BLOCK);
    const auto invalid_import{manager.BuildImportBlock(
        first.chain_id,
        maximum_import_batch,
        Params().GenesisBlock().nTime)};
    BOOST_CHECK(
        invalid_import.error ==
        node::ChainManagerImportBlockBuildError::IMPORT_REJECTED);
    BOOST_REQUIRE(invalid_import.failed_proof);
    BOOST_CHECK_EQUAL(*invalid_import.failed_proof, 0U);

    CMutableTransaction missing_input;
    missing_input.vin.emplace_back(
        COutPoint{Txid::FromUint256(uint256{1}), 0});
    missing_input.vout.emplace_back(1, CScript{} << OP_TRUE);
    const CTransactionRef missing_input_ref{
        MakeTransactionRef(std::move(missing_input))};
    const std::array<CTransactionRef, 1> missing_package{
        missing_input_ref};
    const auto tested{manager.TestTransactions(
        first.chain_id,
        missing_package,
        Params().GenesisBlock().nTime)};
    BOOST_REQUIRE(tested.IsValid());
    BOOST_REQUIRE_EQUAL(tested.transactions.size(), 1U);
    BOOST_CHECK(
        tested.transactions[0].error ==
        node::ReferenceChildMempoolAcceptError::CONTEXT_REJECTED);
    BOOST_CHECK(manager.GetMempool(first.chain_id).runtime.entries.empty());
    const std::array<std::optional<CAmount>, 1> no_fee_limits{
        std::nullopt};
    const auto package_rejected{manager.SubmitTransactions(
        first.chain_id,
        missing_package,
        no_fee_limits,
        Params().GenesisBlock().nTime)};
    BOOST_REQUIRE(package_rejected.IsValid());
    BOOST_CHECK(!package_rejected.submitted);
    BOOST_REQUIRE_EQUAL(package_rejected.transactions.size(), 1U);
    BOOST_CHECK(manager.GetMempool(first.chain_id).runtime.entries.empty());
    const auto rejected{manager.SubmitTransaction(
        first.chain_id,
        missing_input_ref,
        Params().GenesisBlock().nTime)};
    BOOST_CHECK(
        rejected.error ==
        node::ChainManagerMempoolAcceptError::RUNTIME_REJECTED);
    BOOST_CHECK(
        rejected.runtime.error ==
        node::ReferenceChildMempoolAcceptError::CONTEXT_REJECTED);
    BOOST_CHECK(
        manager.BuildTransactionBlock(
            first.chain_id,
            no_transactions,
            std::nullopt,
            Params().GenesisBlock().nTime).error ==
        node::ChainManagerTransactionBlockBuildError::EMPTY_TRANSACTIONS);
    BOOST_CHECK(manager.DataPath(first.chain_id) ==
                root / fs::PathFromString(first.chain_id.GetHex()));

    const auto entries{manager.List()};
    BOOST_REQUIRE_EQUAL(entries.size(), 2U);
    BOOST_CHECK(entries[0].chain_id < entries[1].chain_id);
    size_t loaded_entries{0};
    for (const auto& entry : entries) {
        if (entry.loaded) {
            ++loaded_entries;
            BOOST_CHECK(entry.chain_id == first.chain_id);
            BOOST_CHECK_EQUAL(entry.height, 0U);
            BOOST_CHECK(!entry.failed);
            BOOST_CHECK(!entry.safe_halt);
        }
    }
    BOOST_CHECK_EQUAL(loaded_entries, 1U);

    const auto view{manager.GetChainView(first.chain_id)};
    BOOST_REQUIRE(view.IsValid());
    BOOST_CHECK_EQUAL(view.entry.height, 0U);
    BOOST_CHECK(view.entry.tip == first.genesis_hash);
    const auto bmm_status{manager.GetBmmStatusView(first.chain_id)};
    BOOST_REQUIRE(bmm_status.IsValid());
    BOOST_CHECK_EQUAL(bmm_status.entry.height, 0U);
    BOOST_CHECK(bmm_status.entry.tip == first.genesis_hash);
    BOOST_CHECK(!bmm_status.safe_halt);
    BOOST_CHECK(!bmm_status.tip_anchor);
    BOOST_CHECK(bmm_status.pending_blocks.empty());
    BOOST_CHECK(bmm_status.proposals.empty());
    const auto genesis_view{manager.GetChainView(first.chain_id, 0)};
    BOOST_REQUIRE(genesis_view.IsValid());
    BOOST_REQUIRE(genesis_view.block_hash);
    BOOST_CHECK(*genesis_view.block_hash == first.genesis_hash);
    const auto genesis_block_view{
        manager.GetBlockView(first.chain_id, first.genesis_hash)};
    BOOST_REQUIRE(genesis_block_view.IsValid());
    BOOST_CHECK(genesis_block_view.block.virtual_genesis);
    BOOST_CHECK(!genesis_block_view.block.block);
    BOOST_CHECK(genesis_block_view.block.active);
    BOOST_CHECK_EQUAL(genesis_block_view.block.height, 0);
    BOOST_CHECK_EQUAL(genesis_block_view.block.confirmations, 1);
    const auto genesis_block_by_height{
        manager.GetBlockViewByHeight(first.chain_id, 0)};
    BOOST_REQUIRE(genesis_block_by_height.IsValid());
    BOOST_CHECK(genesis_block_by_height.block.block_hash ==
                first.genesis_hash);
    BOOST_CHECK(
        manager.GetBlockViewByHeight(first.chain_id, 1).error ==
        node::ChainManagerBlockViewError::HEIGHT_OUT_OF_RANGE);
    const auto tip_block_view{manager.GetTipBlockView(first.chain_id)};
    BOOST_REQUIRE(tip_block_view.IsValid());
    BOOST_CHECK(tip_block_view.block.block_hash == first.genesis_hash);
    BOOST_CHECK(tip_block_view.block.virtual_genesis);
    const auto empty_active_blocks{
        manager.GetActiveBlockViews(first.chain_id, {})};
    BOOST_REQUIRE(empty_active_blocks.IsValid());
    BOOST_CHECK(empty_active_blocks.blocks.empty());
    BOOST_CHECK(empty_active_blocks.entry.chain_id == first.chain_id);
    const std::array<uint256, 1> genesis_hashes{first.genesis_hash};
    BOOST_CHECK(
        manager.GetActiveBlockViews(first.chain_id, genesis_hashes).error ==
        node::ChainManagerActiveBlocksViewError::VIRTUAL_GENESIS);
    const std::array<uint256, 1> unknown_hashes{uint256{42}};
    BOOST_CHECK(
        manager.GetActiveBlockViews(first.chain_id, unknown_hashes).error ==
        node::ChainManagerActiveBlocksViewError::BLOCK_NOT_FOUND);
    const auto chain_tips{manager.GetChainTipsView(first.chain_id)};
    BOOST_REQUIRE(chain_tips.IsValid());
    BOOST_REQUIRE_EQUAL(chain_tips.tips.size(), 1U);
    BOOST_CHECK(chain_tips.tips.front().active);
    BOOST_CHECK(chain_tips.tips.front().block_hash == first.genesis_hash);
    BOOST_CHECK_EQUAL(chain_tips.tips.front().branch_length, 0);
    const auto utxo_stats{manager.GetUTXOStatsView(
        first.chain_id, kernel::CoinStatsHashType::MUHASH)};
    BOOST_REQUIRE(utxo_stats.IsValid());
    BOOST_CHECK_EQUAL(utxo_stats.stats.nHeight, 0);
    BOOST_CHECK(utxo_stats.stats.hashBlock == first.genesis_hash);
    BOOST_CHECK_EQUAL(utxo_stats.stats.nTransactionOutputs, 0U);
    BOOST_CHECK_EQUAL(utxo_stats.stats.nTransactions, 0U);
    BOOST_REQUIRE(utxo_stats.stats.total_amount);
    BOOST_CHECK_EQUAL(*utxo_stats.stats.total_amount, 0);
    BOOST_CHECK(!utxo_stats.stats.muhash.IsNull());
    const auto verified{manager.VerifyChain(
        first.chain_id, Params().GenesisBlock().nTime)};
    BOOST_REQUIRE(verified.IsValid());
    BOOST_CHECK(verified.verified);
    BOOST_CHECK(
        manager.GetBlockView(first.chain_id, uint256{42}).error ==
        node::ChainManagerBlockViewError::BLOCK_NOT_FOUND);
    const auto missing_coin{manager.GetCoinView(
        first.chain_id, COutPoint{Txid::FromUint256(uint256{42}), 0})};
    BOOST_REQUIRE(missing_coin.IsValid());
    BOOST_CHECK(!missing_coin.coin);
    BOOST_CHECK(missing_coin.entry.tip == first.genesis_hash);
    BOOST_CHECK(manager.GetChainView(first.chain_id, 1).error ==
                node::ChainManagerViewError::HEIGHT_OUT_OF_RANGE);
    BOOST_CHECK(manager.GetChainView(second.chain_id).error ==
                node::ChainManagerViewError::CHAIN_NOT_LOADED);
    BOOST_CHECK(manager.GetBmmStatusView(second.chain_id).error ==
                node::ChainManagerBmmStatusViewError::CHAIN_NOT_LOADED);
    BOOST_CHECK(manager.GetBmmStatusView(Definition(100).chain_id).error ==
                node::ChainManagerBmmStatusViewError::UNKNOWN_CHAIN);
    BOOST_CHECK(manager.GetBmmStatusView(chainregistry::ChainId{}).error ==
                node::ChainManagerBmmStatusViewError::NULL_CHAIN_ID);
    BOOST_CHECK(manager.GetChainView(chainregistry::ChainId{}).error ==
                node::ChainManagerViewError::NULL_CHAIN_ID);
    BOOST_CHECK(manager.GetCoinView(
        second.chain_id, COutPoint{}).error ==
        node::ChainManagerCoinViewError::CHAIN_NOT_LOADED);
    BOOST_CHECK(manager.GetTipBlockView(second.chain_id).error ==
                node::ChainManagerBlockViewError::CHAIN_NOT_LOADED);
    BOOST_CHECK(manager.GetBlockViewByHeight(second.chain_id, 0).error ==
                node::ChainManagerBlockViewError::CHAIN_NOT_LOADED);
    BOOST_CHECK(
        manager.GetBlockViewByHeight(chainregistry::ChainId{}, 0).error ==
        node::ChainManagerBlockViewError::NULL_CHAIN_ID);
    BOOST_CHECK(
        manager.GetBlockViewByHeight(Definition(100).chain_id, 0).error ==
        node::ChainManagerBlockViewError::UNKNOWN_CHAIN);
    BOOST_CHECK(manager.GetActiveBlockViews(second.chain_id, {}).error ==
                node::ChainManagerActiveBlocksViewError::CHAIN_NOT_LOADED);
    BOOST_CHECK(
        manager.GetActiveBlockViews(chainregistry::ChainId{}, {}).error ==
        node::ChainManagerActiveBlocksViewError::NULL_CHAIN_ID);
    BOOST_CHECK(manager.GetChainTipsView(second.chain_id).error ==
                node::ChainManagerTipsViewError::CHAIN_NOT_LOADED);
    BOOST_CHECK(manager.GetUTXOStatsView(
        second.chain_id, kernel::CoinStatsHashType::NONE).error ==
        node::ChainManagerUTXOStatsViewError::CHAIN_NOT_LOADED);
    BOOST_CHECK(manager.VerifyChain(
        second.chain_id, Params().GenesisBlock().nTime).error ==
        node::ChainManagerVerifyError::CHAIN_NOT_LOADED);
    BOOST_CHECK(manager.GetCoinView(
        chainregistry::ChainId{}, COutPoint{}).error ==
        node::ChainManagerCoinViewError::NULL_CHAIN_ID);
    BOOST_CHECK(manager.GetUTXOStatsView(
        chainregistry::ChainId{}, kernel::CoinStatsHashType::NONE).error ==
        node::ChainManagerUTXOStatsViewError::NULL_CHAIN_ID);
    BOOST_CHECK(manager.VerifyChain(
        chainregistry::ChainId{}, Params().GenesisBlock().nTime).error ==
        node::ChainManagerVerifyError::NULL_CHAIN_ID);

    const auto already_loaded{manager.LoadChain(
        first.chain_id, Params().GenesisBlock().nTime)};
    BOOST_REQUIRE(already_loaded.IsValid());
    BOOST_CHECK(already_loaded.already_loaded);
    BOOST_CHECK(
        manager.ForgetChain(first.chain_id).error ==
        node::ChainManagerError::CHAIN_LOADED);
    BOOST_REQUIRE(manager.UnloadChain(first.chain_id).IsValid());
    BOOST_CHECK_EQUAL(manager.LoadedCount(), 0U);
    BOOST_REQUIRE(manager.ForgetChain(second.chain_id).IsValid());
    BOOST_CHECK_EQUAL(manager.RegisteredCount(), 1U);
}

BOOST_AUTO_TEST_CASE(isolates_concurrent_child_block_submission)
{
    const auto first{Definition(3)};
    const auto second{Definition(4)};
    const auto& params{Params().GetConsensus()};
    const fs::path root{
        m_args.GetDataDirBase() / "chains_concurrent_submission"};
    std::vector<CBlockHeader> main_headers;
    uint256 first_tip;
    uint256 second_tip;

    {
        node::ChainManager manager{
            params, Params().GenesisBlock(), root, 1 << 20};
        BOOST_REQUIRE(manager.RegisterChain(first).IsValid());
        BOOST_REQUIRE(manager.RegisterChain(second).IsValid());
        BOOST_REQUIRE(manager.LoadChain(
            first.chain_id,
            Params().GenesisBlock().nTime,
            /*wipe_data=*/true,
            /*sync=*/true).IsValid());
        BOOST_REQUIRE(manager.LoadChain(
            second.chain_id,
            Params().GenesisBlock().nTime,
            /*wipe_data=*/true,
            /*sync=*/true).IsValid());

        auto* first_runtime{manager.Get(first.chain_id)};
        auto* second_runtime{manager.Get(second.chain_id)};
        BOOST_REQUIRE(first_runtime);
        BOOST_REQUIRE(second_runtime);
        const CBlock first_block{ChildBlock(*first_runtime->Tip(), first)};
        const CBlock second_block{ChildBlock(*second_runtime->Tip(), second)};

        CBlock first_main_block;
        const auto first_proof{MakeBmmProof(
            first_main_block,
            *first_runtime->MainHeaders()->Tip(),
            params,
            first,
            first_block.GetHash())};
        const auto first_header_update{manager.AddMainHeader(
            first_main_block, first_main_block.nTime, /*sync=*/true)};
        BOOST_REQUIRE(first_header_update.unloaded.empty());
        BOOST_REQUIRE_EQUAL(first_header_update.advanced.size(), 2U);
        main_headers.push_back(first_main_block);

        CBlock second_main_block;
        const auto second_proof{MakeBmmProof(
            second_main_block,
            *first_runtime->MainHeaders()->Tip(),
            params,
            second,
            second_block.GetHash())};
        const auto second_header_update{manager.AddMainHeader(
            second_main_block, second_main_block.nTime, /*sync=*/true)};
        BOOST_REQUIRE(second_header_update.unloaded.empty());
        BOOST_REQUIRE_EQUAL(second_header_update.advanced.size(), 2U);
        main_headers.push_back(second_main_block);

        const auto second_before{
            manager.GetBmmStatusView(second.chain_id)};
        BOOST_REQUIRE(second_before.IsValid());
        const auto first_connected{manager.SubmitBlock(
            first.chain_id,
            first_block,
            first_proof,
            second_main_block.nTime,
            /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(
            first_connected.IsValid(),
            static_cast<int>(first_connected.runtime.error));

        // A single-transaction block must visit index zero without decrementing
        // an unsigned counter past zero at the end of the reverse scan.
        BOOST_REQUIRE_EQUAL(first_block.vtx.size(), 1U);
        BOOST_REQUIRE(!first_block.vtx.front()->vout.empty());
        const auto history{manager.ScanWalletHistory(
            first.chain_id, {first_block.vtx.front()->vout.front().scriptPubKey})};
        BOOST_REQUIRE(history.IsValid());
        BOOST_REQUIRE_EQUAL(history.transactions.size(), 1U);
        BOOST_CHECK(history.transactions.front().transaction->GetHash() ==
                    first_block.vtx.front()->GetHash());
        BOOST_CHECK_EQUAL(history.transactions.front().block_index, 0U);
        BOOST_CHECK(!history.next_height);

        const auto first_view{manager.GetChainView(first.chain_id)};
        const auto second_after_first{
            manager.GetBmmStatusView(second.chain_id)};
        BOOST_REQUIRE(first_view.IsValid());
        BOOST_REQUIRE(second_after_first.IsValid());
        BOOST_CHECK_EQUAL(first_view.entry.height, 1U);
        BOOST_CHECK(first_view.entry.tip == first_block.GetHash());
        BOOST_CHECK_EQUAL(second_after_first.entry.height, 0U);
        BOOST_CHECK(second_after_first.entry.tip == second.genesis_hash);
        BOOST_CHECK_EQUAL(
            second_after_first.entry.anchor_count,
            second_before.entry.anchor_count);
        BOOST_CHECK_EQUAL(
            second_after_first.entry.pending_anchor_count,
            second_before.entry.pending_anchor_count);
        BOOST_CHECK_EQUAL(
            second_after_first.entry.local_proposal_count,
            second_before.entry.local_proposal_count);
        BOOST_CHECK_EQUAL(
            second_after_first.entry.side_candidate_count,
            second_before.entry.side_candidate_count);
        BOOST_CHECK_EQUAL(
            second_after_first.entry.candidate_anchor_count,
            second_before.entry.candidate_anchor_count);
        BOOST_CHECK(
            second_after_first.entry.main_tip == second_before.entry.main_tip);

        const auto second_connected{manager.SubmitBlock(
            second.chain_id,
            second_block,
            second_proof,
            second_main_block.nTime,
            /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(
            second_connected.IsValid(),
            static_cast<int>(second_connected.runtime.error));

        first_runtime = manager.Get(first.chain_id);
        second_runtime = manager.Get(second.chain_id);
        BOOST_REQUIRE(first_runtime);
        BOOST_REQUIRE(second_runtime);
        const CBlock next_first_block{
            ChildBlock(*first_runtime->Tip(), first)};
        const CBlock next_second_block{
            ChildBlock(*second_runtime->Tip(), second)};

        CBlock next_first_main_block;
        const auto next_first_proof{MakeBmmProof(
            next_first_main_block,
            *first_runtime->MainHeaders()->Tip(),
            params,
            first,
            next_first_block.GetHash())};
        BOOST_REQUIRE(manager.AddMainHeader(
            next_first_main_block,
            next_first_main_block.nTime,
            /*sync=*/true).unloaded.empty());
        main_headers.push_back(next_first_main_block);
        CBlock next_second_main_block;
        const auto next_second_proof{MakeBmmProof(
            next_second_main_block,
            *first_runtime->MainHeaders()->Tip(),
            params,
            second,
            next_second_block.GetHash())};
        BOOST_REQUIRE(manager.AddMainHeader(
            next_second_main_block,
            next_second_main_block.nTime,
            /*sync=*/true).unloaded.empty());
        main_headers.push_back(next_second_main_block);

        auto first_submission{std::async(std::launch::async, [&] {
            return manager.SubmitBlock(
                first.chain_id,
                next_first_block,
                next_first_proof,
                next_second_main_block.nTime,
                /*sync=*/true);
        })};
        auto second_submission{std::async(std::launch::async, [&] {
            return manager.SubmitBlock(
                second.chain_id,
                next_second_block,
                next_second_proof,
                next_second_main_block.nTime,
                /*sync=*/true);
        })};
        BOOST_REQUIRE(first_submission.get().IsValid());
        BOOST_REQUIRE(second_submission.get().IsValid());

        const auto final_first{manager.GetChainView(first.chain_id)};
        const auto final_second{manager.GetChainView(second.chain_id)};
        BOOST_REQUIRE(final_first.IsValid());
        BOOST_REQUIRE(final_second.IsValid());
        BOOST_CHECK_EQUAL(final_first.entry.height, 2U);
        BOOST_CHECK_EQUAL(final_second.entry.height, 2U);
        first_tip = final_first.entry.tip;
        second_tip = final_second.entry.tip;
        BOOST_CHECK(first_tip == next_first_block.GetHash());
        BOOST_CHECK(second_tip == next_second_block.GetHash());
        BOOST_CHECK(first_tip != second_tip);
    }

    node::ChainManager restarted{
        params, Params().GenesisBlock(), root, 1 << 20};
    BOOST_REQUIRE(restarted.IsCatalogReady());
    const auto reopened_first{restarted.LoadChain(
        first.chain_id,
        Params().GenesisBlock().nTime + 4,
        /*wipe_data=*/false,
        /*sync=*/true,
        main_headers)};
    const auto reopened_second{restarted.LoadChain(
        second.chain_id,
        Params().GenesisBlock().nTime + 4,
        /*wipe_data=*/false,
        /*sync=*/true,
        main_headers)};
    BOOST_REQUIRE(reopened_first.IsValid());
    BOOST_REQUIRE(reopened_second.IsValid());
    BOOST_CHECK(reopened_first.runtime.loaded_existing);
    BOOST_CHECK(reopened_second.runtime.loaded_existing);
    const auto persisted_first{restarted.GetChainView(first.chain_id)};
    const auto persisted_second{restarted.GetChainView(second.chain_id)};
    BOOST_REQUIRE(persisted_first.IsValid());
    BOOST_REQUIRE(persisted_second.IsValid());
    BOOST_CHECK_EQUAL(persisted_first.entry.height, 2U);
    BOOST_CHECK_EQUAL(persisted_second.entry.height, 2U);
    BOOST_CHECK(persisted_first.entry.tip == first_tip);
    BOOST_CHECK(persisted_second.entry.tip == second_tip);
}

BOOST_AUTO_TEST_CASE(reopens_only_an_explicitly_selected_chain)
{
    const auto first{Definition(10)};
    const auto second{Definition(11)};
    const fs::path root{m_args.GetDataDirBase() / "chains_restart"};
    {
        node::ChainManager manager{
            Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
        BOOST_REQUIRE(manager.RegisterChain(first).IsValid());
        BOOST_REQUIRE(manager.RegisterChain(second).IsValid());
        BOOST_REQUIRE(manager.LoadChain(
            first.chain_id,
            Params().GenesisBlock().nTime,
            /*wipe_data=*/true,
            /*sync=*/true).IsValid());
    }

    {
        node::ChainManager restarted{
            Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
        BOOST_REQUIRE(restarted.IsCatalogReady());
        BOOST_CHECK(restarted.IsRegistered(first.chain_id));
        BOOST_CHECK(restarted.IsRegistered(second.chain_id));
        BOOST_CHECK_EQUAL(restarted.RegisteredCount(), 2U);
        BOOST_CHECK_EQUAL(restarted.LoadedCount(), 0U);
        const auto loaded{restarted.LoadChain(
            first.chain_id,
            Params().GenesisBlock().nTime + 1,
            /*wipe_data=*/false,
            /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(
            loaded.IsValid(), static_cast<int>(loaded.runtime.error));
        BOOST_CHECK(loaded.runtime.loaded_existing);
        BOOST_CHECK(restarted.IsLoaded(first.chain_id));
        BOOST_CHECK(!restarted.IsLoaded(second.chain_id));

        const chainregistry::ChainId null_id;
        BOOST_CHECK(
            restarted.LoadChain(null_id, Params().GenesisBlock().nTime).error ==
            node::ChainManagerError::NULL_CHAIN_ID);
        BOOST_CHECK(
            restarted.LoadChain(Definition(12).chain_id,
                                Params().GenesisBlock().nTime).error ==
            node::ChainManagerError::UNKNOWN_CHAIN);
        BOOST_REQUIRE(restarted.ForgetChain(second.chain_id).IsValid());
    }

    node::ChainManager after_forget{
        Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
    BOOST_REQUIRE(after_forget.IsCatalogReady());
    BOOST_CHECK(after_forget.IsRegistered(first.chain_id));
    BOOST_CHECK(!after_forget.IsRegistered(second.chain_id));
    BOOST_CHECK_EQUAL(after_forget.RegisteredCount(), 1U);
    BOOST_CHECK_EQUAL(after_forget.LoadedCount(), 0U);
}

BOOST_AUTO_TEST_CASE(serializes_child_submission_through_loaded_runtime)
{
    const auto definition{Definition(13)};
    const auto unknown{Definition(14)};
    const fs::path root{m_args.GetDataDirBase() / "chains_submission"};
    node::ChainManager manager{
        Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
    BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());

    const chainregistry::ChainId null_id;
    const chainregistry::BmmAnchorProof proof;
    const CBlock block;
    BOOST_CHECK(
        manager.GetPendingBlocksView(null_id).error ==
        node::ChainManagerPendingBlocksViewError::NULL_CHAIN_ID);
    BOOST_CHECK(
        manager.GetPendingBlocksView(unknown.chain_id).error ==
        node::ChainManagerPendingBlocksViewError::UNKNOWN_CHAIN);
    BOOST_CHECK(
        manager.GetPendingBlocksView(definition.chain_id).error ==
        node::ChainManagerPendingBlocksViewError::CHAIN_NOT_LOADED);
    BOOST_CHECK(
        manager.StageBmmAnchor(
            null_id, proof, Params().GenesisBlock().nTime).error ==
        node::ChainManagerError::NULL_CHAIN_ID);
    BOOST_CHECK(
        manager.SubmitBlock(
            unknown.chain_id,
            block,
            proof,
            Params().GenesisBlock().nTime).error ==
        node::ChainManagerError::UNKNOWN_CHAIN);
    BOOST_CHECK(
        manager.StageBmmAnchor(
            definition.chain_id,
            proof,
            Params().GenesisBlock().nTime).error ==
        node::ChainManagerError::CHAIN_NOT_LOADED);

    BOOST_REQUIRE(manager.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());
    const auto pending{manager.GetPendingBlocksView(definition.chain_id)};
    BOOST_REQUIRE(pending.IsValid());
    BOOST_CHECK(pending.blocks.empty());
    const auto rejected_anchor{manager.StageBmmAnchor(
        definition.chain_id,
        proof,
        Params().GenesisBlock().nTime,
        /*sync=*/true)};
    BOOST_CHECK(rejected_anchor.error ==
                node::ChainManagerError::RUNTIME_REJECTED);
    BOOST_CHECK(rejected_anchor.runtime.error ==
                node::ReferenceChildRuntimeError::BMM_ANCHOR_REJECTED);
    const auto rejected_block{manager.SubmitBlock(
        definition.chain_id,
        block,
        proof,
        Params().GenesisBlock().nTime,
        /*sync=*/true)};
    BOOST_CHECK(rejected_block.error ==
                node::ChainManagerError::RUNTIME_REJECTED);
    BOOST_CHECK(rejected_block.runtime.error ==
                node::ReferenceChildRuntimeError::BMM_ANCHOR_REJECTED);
    const auto unavailable_block{manager.SubmitBlockData(
        definition.chain_id,
        block,
        Params().GenesisBlock().nTime,
        /*sync=*/true)};
    BOOST_CHECK(unavailable_block.error ==
                node::ChainManagerError::RUNTIME_REJECTED);
    BOOST_CHECK(unavailable_block.runtime.error ==
                node::ReferenceChildRuntimeError::BMM_ANCHOR_UNAVAILABLE);

    BOOST_CHECK(
        manager.WaitForTipChanged(
            unknown.chain_id,
            std::nullopt,
            std::chrono::milliseconds{1}).view.error ==
        node::ChainManagerViewError::UNKNOWN_CHAIN);
    std::promise<void> waiter_started;
    auto waiter_ready{waiter_started.get_future()};
    auto waiter{std::async(std::launch::async, [&] {
        waiter_started.set_value();
        return manager.WaitForTipChanged(
            definition.chain_id,
            definition.genesis_hash,
            std::nullopt);
    })};
    waiter_ready.wait();
    manager.InterruptWaits();
    BOOST_REQUIRE(
        waiter.wait_for(std::chrono::seconds{5}) ==
        std::future_status::ready);
    const auto interrupted{waiter.get()};
    BOOST_REQUIRE(interrupted.IsValid());
    BOOST_CHECK(interrupted.interrupted);
    BOOST_CHECK(interrupted.view.entry.tip == definition.genesis_hash);
}

BOOST_AUTO_TEST_CASE(rejects_catalog_from_another_main_network)
{
    const auto definition{Definition(20)};
    const fs::path root{m_args.GetDataDirBase() / "chains_wrong_main"};
    {
        node::ChainManager manager{
            Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
        BOOST_REQUIRE(manager.IsCatalogReady());
        BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    }

    auto wrong_params{Params().GetConsensus()};
    wrong_params.hashGenesisBlock = ArithToUint256(arith_uint256{42});
    node::ChainManager wrong_network{
        std::move(wrong_params), Params().GenesisBlock(), root, 1 << 20};
    BOOST_CHECK(!wrong_network.IsCatalogReady());
    BOOST_CHECK(wrong_network.CatalogError() ==
                node::ChildChainCatalogLoadError::WRONG_MAIN_GENESIS);
    BOOST_CHECK(
        wrong_network.RegisterChain(definition).error ==
        node::ChainManagerError::CATALOG_UNAVAILABLE);
}

BOOST_AUTO_TEST_CASE(rejects_corrupt_persisted_definition)
{
    const auto definition{Definition(30)};
    const fs::path root{m_args.GetDataDirBase() / "chains_corrupt_catalog"};
    {
        node::ChainManager manager{
            Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
        BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    }
    {
        CDBWrapper db{
            DBParams{
                .path = root / "catalog",
                .cache_bytes = 1 << 20,
                .obfuscate = true,
            }};
        node::ChildChainCatalogEntry corrupt{
            .version = node::CHILD_CHAIN_CATALOG_ENTRY_VERSION + 1,
            .chain_id = definition.chain_id,
            .registration_anchor = definition.genesis.registration_anchor,
            .manifest = definition.manifest,
        };
        db.Write(std::pair{uint8_t{'R'}, definition.chain_id},
                 corrupt,
                 /*fSync=*/true);
    }

    node::ChainManager corrupted{
        Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
    BOOST_CHECK(!corrupted.IsCatalogReady());
    BOOST_CHECK(corrupted.CatalogError() ==
                node::ChildChainCatalogLoadError::INVALID_RECORD);
    BOOST_CHECK_EQUAL(corrupted.RegisteredCount(), 0U);
}

BOOST_AUTO_TEST_CASE(serializes_concurrent_catalog_updates)
{
    const fs::path root{m_args.GetDataDirBase() / "chains_concurrent"};
    node::ChainManager manager{
        Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
    BOOST_REQUIRE(manager.IsCatalogReady());

    constexpr size_t count{8};
    std::vector<chainregistry::ReferenceChildDefinition> definitions;
    definitions.reserve(count);
    for (size_t index{0}; index < count; ++index) {
        definitions.push_back(Definition(100 + index));
    }
    std::vector<node::ChainManagerResult> results(count);
    std::vector<std::thread> workers;
    workers.reserve(count);
    for (size_t index{0}; index < count; ++index) {
        workers.emplace_back([&, index] {
            results[index] = manager.RegisterChain(definitions[index]);
        });
    }
    for (auto& worker : workers) worker.join();

    for (const auto& result : results) BOOST_CHECK(result.IsValid());
    BOOST_CHECK_EQUAL(manager.RegisteredCount(), count);
    BOOST_CHECK_EQUAL(manager.List().size(), count);
}

BOOST_AUTO_TEST_CASE(synchronizes_main_headers_and_reconciles_registry)
{
    const auto first{Definition(200)};
    const auto second{Definition(201)};
    const fs::path root{m_args.GetDataDirBase() / "chains_main_updates"};
    node::ChainManager manager{
        Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
    BOOST_REQUIRE(manager.RegisterChain(first).IsValid());
    BOOST_REQUIRE(manager.RegisterChain(second).IsValid());

    CBlockIndex genesis{Params().GenesisBlock()};
    genesis.phashBlock = &Params().GetConsensus().hashGenesisBlock;
    genesis.nHeight = 0;
    genesis.nChainWork = GetBlockProof(genesis);
    genesis.nTimeMax = genesis.nTime;
    const CBlockHeader header{MineHeader(genesis, Params().GetConsensus(), 1)};

    const std::array<CBlockHeader, 1> headers{header};
    BOOST_REQUIRE(manager.LoadChain(
        first.chain_id,
        header.nTime,
        /*wipe_data=*/true,
        /*sync=*/true,
        headers).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        second.chain_id,
        header.nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());

    const auto advanced{manager.AddMainHeader(
        header, header.nTime, /*sync=*/true)};
    BOOST_REQUIRE_EQUAL(advanced.unloaded.size(), 0U);
    BOOST_REQUIRE_EQUAL(advanced.advanced.size(), 1U);
    BOOST_CHECK(advanced.advanced.front() == second.chain_id);
    for (const auto& entry : manager.List()) {
        BOOST_CHECK(entry.loaded);
        BOOST_CHECK_EQUAL(entry.main_height, 1U);
        BOOST_CHECK(entry.main_tip == header.GetHash());
    }

    const auto disconnected{manager.SynchronizeMainChain(
        {},
        Params().GetConsensus().hashGenesisBlock,
        header.nTime,
        /*sync=*/true)};
    BOOST_REQUIRE_EQUAL(disconnected.unloaded.size(), 0U);
    BOOST_REQUIRE_EQUAL(disconnected.advanced.size(), 2U);
    for (const auto& entry : manager.List()) {
        BOOST_CHECK_EQUAL(entry.main_height, 0U);
        BOOST_CHECK(entry.main_tip == Params().GetConsensus().hashGenesisBlock);
    }

    BOOST_REQUIRE(manager.UnloadChain(second.chain_id).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        second.chain_id,
        header.nTime,
        /*wipe_data=*/false,
        /*sync=*/true,
        headers).IsValid());
    for (const auto& entry : manager.List()) {
        BOOST_CHECK_EQUAL(
            entry.main_height,
            entry.chain_id == second.chain_id ? 1U : 0U);
    }
    const auto reconnected{manager.SynchronizeMainChain(
        headers,
        header.GetHash(),
        header.nTime,
        /*sync=*/true)};
    BOOST_REQUIRE_EQUAL(reconnected.unloaded.size(), 0U);
    BOOST_REQUIRE_EQUAL(reconnected.advanced.size(), 1U);
    BOOST_CHECK(reconnected.advanced.front() == first.chain_id);
    for (const auto& entry : manager.List()) {
        BOOST_CHECK_EQUAL(entry.main_height, 1U);
        BOOST_CHECK(entry.main_tip == header.GetHash());
    }

    std::map<chainregistry::ChainId, chainregistry::ChainRecord> registry{
        {first.chain_id, Record(first)},
    };
    const auto missing{manager.ReconcileRegistry(registry)};
    BOOST_REQUIRE_EQUAL(missing.unloaded.size(), 1U);
    BOOST_CHECK(missing.unloaded.front().chain_id == second.chain_id);
    BOOST_CHECK(missing.unloaded.front().reason ==
                node::ChainManagerUnloadReason::REGISTRY_MISSING);
    BOOST_CHECK(manager.IsLoaded(first.chain_id));
    BOOST_CHECK(!manager.IsLoaded(second.chain_id));

    registry.at(first.chain_id) =
        Record(first, chainregistry::ChainStatus::RETIRED);
    const auto retired{manager.ReconcileRegistry(registry)};
    BOOST_REQUIRE_EQUAL(retired.unloaded.size(), 1U);
    BOOST_CHECK(retired.unloaded.front().chain_id == first.chain_id);
    BOOST_CHECK(retired.unloaded.front().reason ==
                node::ChainManagerUnloadReason::REGISTRY_RETIRED);
    BOOST_CHECK_EQUAL(manager.LoadedCount(), 0U);
}

BOOST_AUTO_TEST_CASE(bounds_loaded_child_runtimes)
{
    const fs::path root{m_args.GetDataDirBase() / "chains_loaded_limit"};
    node::ChainManager manager{
        Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
    std::vector<chainregistry::ReferenceChildDefinition> definitions;
    definitions.reserve(node::MAX_LOADED_CHILD_CHAINS + 1);
    for (size_t index{0}; index <= node::MAX_LOADED_CHILD_CHAINS; ++index) {
        definitions.push_back(Definition(static_cast<uint32_t>(100 + index)));
        BOOST_REQUIRE(manager.RegisterChain(definitions.back()).IsValid());
    }
    for (size_t index{0}; index < node::MAX_LOADED_CHILD_CHAINS; ++index) {
        BOOST_REQUIRE(manager.LoadChain(
            definitions[index].chain_id,
            Params().GenesisBlock().nTime,
            /*wipe_data=*/true,
            /*sync=*/true).IsValid());
    }
    BOOST_CHECK_EQUAL(
        manager.LoadedCount(), node::MAX_LOADED_CHILD_CHAINS);
    BOOST_CHECK(
        manager.LoadChain(
            definitions.back().chain_id,
            Params().GenesisBlock().nTime,
            /*wipe_data=*/true,
            /*sync=*/true).error ==
        node::ChainManagerError::TOO_MANY_LOADED_CHAINS);

    BOOST_REQUIRE(manager.UnloadChain(definitions.front().chain_id).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        definitions.back().chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());
    BOOST_CHECK_EQUAL(
        manager.LoadedCount(), node::MAX_LOADED_CHILD_CHAINS);
}

BOOST_AUTO_TEST_SUITE_END()
