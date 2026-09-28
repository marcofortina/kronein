// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain_db.h>

#include <blockfilter.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <pow.h>
#include <primitives/deposit.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

namespace {

constexpr chainregistry::ChainId CHILD_CHAIN{
    "1111111111111111111111111111111111111111111111111111111111111111"};
constexpr chainregistry::ChainId OTHER_CHILD{
    "9999999999999999999999999999999999999999999999999999999999999999"};
constexpr uint256 CHILD_GENESIS{
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"};

struct ChildChainDBSetup : BasicTestingSetup {
    ChildChainDBSetup()
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

chainregistry::BmmAnchorProof MakeBmmProof(
    CBlock& block,
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

CBlock MakeChildBlock(
    const uint256& parent,
    uint32_t height,
    const std::optional<chainregistry::DepositId>& imported = std::nullopt)
{
    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vin.front().scriptSig = CScript{} << static_cast<int64_t>(height);
    coinbase.vout.emplace_back(7'500, CScript{} << OP_TRUE);

    CBlock block;
    block.nVersion = CBlockHeader::CURRENT_VERSION;
    block.hashPrevBlock = parent;
    block.nTime = Params().GenesisBlock().nTime + height;
    block.nBits = 0;
    block.nNonce = 0;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    if (imported) {
        CMutableTransaction import;
        import.vin.emplace_back(COutPoint{
            Txid::FromUint256(imported->ToUint256()),
            chainregistry::CHILD_IMPORT_PREVOUT_INDEX});
        import.vout.emplace_back(50'000, CScript{} << OP_TRUE);
        block.vtx.push_back(MakeTransactionRef(std::move(import)));
    }
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

chainregistry::DepositId ProofDepositId(
    const chainregistry::DepositProof& proof,
    const uint256& main_genesis)
{
    return chainregistry::DeriveDepositId(
        main_genesis,
        COutPoint{proof.funding_transaction.GetHash(), proof.funding_vout});
}

void AddAndPersist(node::ChildChainDB& db,
                   chainregistry::MainHeaderChain& headers,
                   const chainregistry::DepositImportState& imports,
                   const CBlockHeader& header)
{
    BOOST_REQUIRE(headers.AddHeader(header, header.nTime).IsValid());
    BOOST_REQUIRE(db.WriteMainHeader(headers, imports, header, /*sync=*/true));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(child_chain_db_tests, ChildChainDBSetup)

BOOST_AUTO_TEST_CASE(persists_bounded_local_proposals)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "child_chain_proposals"};
    const CBlock first{MakeChildBlock(CHILD_GENESIS, 1)};
    CBlock second{MakeChildBlock(CHILD_GENESIS, 2)};
    second.hashPrevBlock = CHILD_GENESIS;

    {
        chainregistry::MainHeaderChain headers{params};
        BOOST_REQUIRE(headers.Initialize(genesis).IsValid());
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .wipe_data = true,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        BOOST_REQUIRE(db.WriteInitialState(headers, imports, /*sync=*/true));
        BOOST_REQUIRE(db.WriteLocalProposal(first, 100, /*sync=*/true));
        BOOST_REQUIRE(db.WriteLocalProposal(first, 200, /*sync=*/true));
        BOOST_REQUIRE(db.WriteLocalProposal(second, 200, /*sync=*/true));
        const auto proposals{db.ReadLocalProposals()};
        BOOST_REQUIRE(proposals.has_value());
        BOOST_REQUIRE_EQUAL(proposals->size(), 2U);
        BOOST_CHECK_EQUAL(proposals->front().created_time, 100);
        BOOST_CHECK(proposals->front().block.GetHash() == first.GetHash());
        BOOST_CHECK(proposals->back().block.GetHash() == second.GetHash());
    }

    {
        chainregistry::MainHeaderChain headers{params};
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        node::ChildChainDBState state;
        const auto loaded{db.Load(headers, imports, state, genesis.nTime)};
        BOOST_REQUIRE(loaded.IsValid());
        BOOST_REQUIRE(loaded.initialized);
        const auto stored{db.ReadLocalProposal(first.GetHash())};
        BOOST_REQUIRE(stored.has_value());
        BOOST_CHECK_EQUAL(stored->created_time, 100);
        BOOST_CHECK(stored->block.GetHash() == first.GetHash());
        const uint256 missing{
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        const std::vector<uint256> incomplete{first.GetHash(), missing};
        BOOST_CHECK(!db.EraseLocalProposals(incomplete, /*sync=*/true));
        const auto retained{db.ReadLocalProposals()};
        BOOST_REQUIRE(retained.has_value());
        BOOST_REQUIRE_EQUAL(retained->size(), 2U);

        const std::vector<uint256> duplicate{
            first.GetHash(), first.GetHash()};
        BOOST_CHECK(!db.EraseLocalProposals(duplicate, /*sync=*/true));
        const std::vector<uint256> all{first.GetHash(), second.GetHash()};
        BOOST_REQUIRE(db.EraseLocalProposals(all, /*sync=*/true));
        BOOST_CHECK(!db.EraseLocalProposal(first.GetHash(), /*sync=*/true));
        const auto proposals{db.ReadLocalProposals()};
        BOOST_REQUIRE(proposals.has_value());
        BOOST_CHECK(proposals->empty());
    }
}

BOOST_AUTO_TEST_CASE(persists_headers_imports_and_child_undo)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "child_chain_state"};

    CBlock child_block;
    chainregistry::DepositId deposit_id;
    chainregistry::ReferenceChildBlockUndo child_undo;
    CBlockHeader main_tip;
    {
        chainregistry::MainHeaderChain headers{params};
        BOOST_REQUIRE(headers.Initialize(genesis).IsValid());
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .wipe_data = true,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        node::ChildChainDBState fresh_state;
        const auto fresh{db.Load(headers, imports, fresh_state, genesis.nTime)};
        BOOST_REQUIRE(fresh.IsValid());
        BOOST_CHECK(!fresh.initialized);
        BOOST_REQUIRE(db.WriteInitialState(headers, imports, /*sync=*/true));

        const CBlockIndex* genesis_index{headers.Find(genesis.GetHash())};
        BOOST_REQUIRE(genesis_index);
        CBlock deposit_block;
        const auto proof{MakeDepositProof(deposit_block, *genesis_index, params)};
        AddAndPersist(db, headers, imports, deposit_block);
        const CBlockIndex* deposit_index{headers.Find(deposit_block.GetHash())};
        BOOST_REQUIRE(deposit_index);
        const CBlockHeader confirmation{MineHeader(*deposit_index, params, 1)};
        AddAndPersist(db, headers, imports, confirmation);

        deposit_id = ProofDepositId(proof, params.hashGenesisBlock);
        child_block = MakeChildBlock(CHILD_GENESIS, 1, deposit_id);
        const CBlockIndex* confirmation_index{
            headers.Find(confirmation.GetHash())};
        BOOST_REQUIRE(confirmation_index);
        CBlock anchor_block;
        const auto anchor_proof{MakeBmmProof(
            anchor_block, *confirmation_index, params, child_block.GetHash())};
        AddAndPersist(db, headers, imports, anchor_block);
        main_tip = anchor_block;
        const auto imported{
            imports.ImportProof(proof, headers, child_block.GetHash(), 1)};
        BOOST_REQUIRE(imported.IsValid());
        BOOST_CHECK(imported.imports.front().deposit_id == deposit_id);
        child_undo = {
            .block_hash = child_block.GetHash(),
            .parent_hash = CHILD_GENESIS,
            .block_height = 1,
            .coins = CBlockUndo{{CTxUndo{}}},
            .imports = imported.undo,
        };
        CCoinsViewCache coin_cache{&db, /*deterministic=*/true};
        BOOST_CHECK(coin_cache.GetBestBlock() == CHILD_GENESIS);
        for (const auto& transaction : child_block.vtx) {
            AddCoins(coin_cache, *transaction, 1);
        }
        coin_cache.SetBestBlock(child_block.GetHash());
        BOOST_REQUIRE(db.WriteLocalProposal(
            child_block, child_block.nTime, /*sync=*/true));
        BOOST_REQUIRE(db.WriteConnectedChildBlock(
            headers,
            imports,
            child_block,
            child_undo,
            anchor_proof,
            /*sync=*/true));
        BOOST_CHECK(!db.ReadLocalProposal(child_block.GetHash()).has_value());
        const BlockFilter expected_filter{
            BlockFilterType::BASIC, child_block, child_undo.coins};
        const auto stored_filter{db.ReadBlockFilter(child_block.GetHash())};
        BOOST_REQUIRE(stored_filter.has_value());
        BOOST_CHECK(stored_filter->encoded_filter ==
                    expected_filter.GetEncodedFilter());
        BOOST_CHECK(stored_filter->filter_header ==
                    expected_filter.ComputeHeader({}));
        coin_cache.Flush();
        const auto stored{db.ReadImport(deposit_id)};
        BOOST_REQUIRE(stored.has_value());
        BOOST_CHECK(stored->deposit_id == deposit_id);
    }

    {
        chainregistry::MainHeaderChain headers{params};
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        node::ChildChainDBState state;
        const auto loaded{db.Load(headers, imports, state, main_tip.nTime + 1)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK(loaded.initialized);
        BOOST_CHECK_EQUAL(state.header_count, 4U);
        BOOST_CHECK_EQUAL(state.anchor_count, 1U);
        BOOST_CHECK_EQUAL(state.import_count, 1U);
        BOOST_CHECK_EQUAL(state.coin_count, 2U);
        BOOST_CHECK(state.child_tip == child_block.GetHash());
        BOOST_CHECK_EQUAL(state.child_height, 1U);
        BOOST_CHECK(headers.Tip()->GetBlockHash() == main_tip.GetHash());
        BOOST_CHECK(imports.Find(deposit_id) != nullptr);
        chainregistry::ReferenceChildBlockUndo stored_undo;
        BOOST_REQUIRE(db.ReadUndo(child_block.GetHash(), stored_undo));
        BOOST_CHECK(stored_undo == child_undo);
        CBlock stored_block;
        BOOST_REQUIRE(db.ReadBlock(child_block.GetHash(), stored_block));
        BOOST_CHECK(stored_block.vtx.size() == child_block.vtx.size());
        const auto stored_filter{db.ReadBlockFilter(child_block.GetHash())};
        BOOST_REQUIRE(stored_filter.has_value());
        BOOST_CHECK(stored_filter->block_hash == child_block.GetHash());
        const auto stored_anchor{db.ReadBmmAnchor(child_block.GetHash())};
        BOOST_REQUIRE(stored_anchor.has_value());
        BOOST_CHECK(stored_anchor->child_block_hash == child_block.GetHash());
        BOOST_CHECK(db.HaveCoin(COutPoint{child_block.vtx.front()->GetHash(), 0}));
        BOOST_CHECK(db.HaveCoin(COutPoint{child_block.vtx.back()->GetHash(), 0}));

        auto cursor{db.Cursor()};
        BOOST_REQUIRE(cursor);
        BOOST_CHECK(cursor->GetBestBlock() == child_block.GetHash());
        std::map<COutPoint, Coin> cursor_coins;
        while (cursor->Valid()) {
            COutPoint outpoint;
            Coin coin;
            BOOST_REQUIRE(cursor->GetKey(outpoint));
            BOOST_REQUIRE(cursor->GetValue(coin));
            BOOST_REQUIRE(cursor_coins.emplace(outpoint, coin).second);
            cursor->Next();
        }
        BOOST_CHECK_EQUAL(cursor_coins.size(), state.coin_count);
        BOOST_CHECK(cursor_coins.contains(
            COutPoint{child_block.vtx.front()->GetHash(), 0}));
        BOOST_CHECK(cursor_coins.contains(
            COutPoint{child_block.vtx.back()->GetHash(), 0}));

        CCoinsViewCache coin_cache{&db, /*deterministic=*/true};
        for (const auto& transaction : child_block.vtx) {
            for (size_t output{0}; output < transaction->vout.size(); ++output) {
                if (transaction->vout[output].scriptPubKey.IsUnspendable()) continue;
                BOOST_REQUIRE(coin_cache.SpendCoin(
                    COutPoint{transaction->GetHash(),
                              static_cast<uint32_t>(output)}));
            }
        }
        coin_cache.SetBestBlock(CHILD_GENESIS);
        BOOST_REQUIRE(imports.DisconnectImports(
            child_block.GetHash(), child_undo.imports));
        BOOST_REQUIRE(db.WriteDisconnectedChildBlock(
            headers,
            imports,
            child_block,
            child_undo,
            /*sync=*/true));
        coin_cache.Flush();
        BOOST_CHECK(!db.ReadImport(deposit_id).has_value());
        BOOST_CHECK(!db.ReadBmmAnchor(child_block.GetHash()).has_value());
        BOOST_CHECK(!db.ReadBlockFilter(child_block.GetHash()).has_value());
        BOOST_CHECK(!db.HaveCoin(COutPoint{child_block.vtx.front()->GetHash(), 0}));
    }

    {
        chainregistry::MainHeaderChain headers{params};
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        node::ChildChainDBState state;
        BOOST_REQUIRE(db.Load(headers, imports, state, main_tip.nTime + 1).IsValid());
        BOOST_CHECK_EQUAL(imports.Size(), 0U);
        BOOST_CHECK_EQUAL(state.import_count, 0U);
        BOOST_CHECK_EQUAL(state.coin_count, 0U);
        BOOST_CHECK(state.child_tip == CHILD_GENESIS);
    }

    {
        chainregistry::MainHeaderChain headers{params};
        chainregistry::DepositImportState imports{OTHER_CHILD, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .obfuscate = true,
                              },
                              OTHER_CHILD,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        node::ChildChainDBState state;
        BOOST_CHECK(db.Load(headers, imports, state, main_tip.nTime + 1).error ==
                    node::ChildChainDBLoadError::CONFIGURATION_MISMATCH);
    }
}

BOOST_AUTO_TEST_CASE(persists_safe_halt_across_restart)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "child_chain_safe_halt"};

    CBlock child_block;
    CBlockHeader fork4;
    chainregistry::DepositId deposit_id;
    chainregistry::BmmAnchorProof anchor_proof;
    {
        chainregistry::MainHeaderChain headers{params};
        BOOST_REQUIRE(headers.Initialize(genesis).IsValid());
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .wipe_data = true,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        BOOST_REQUIRE(db.WriteInitialState(headers, imports, /*sync=*/true));

        const CBlockIndex* genesis_index{headers.Find(genesis.GetHash())};
        BOOST_REQUIRE(genesis_index);
        CBlock deposit_block;
        const auto proof{MakeDepositProof(deposit_block, *genesis_index, params)};
        AddAndPersist(db, headers, imports, deposit_block);
        const CBlockIndex* deposit_index{headers.Find(deposit_block.GetHash())};
        BOOST_REQUIRE(deposit_index);
        const CBlockHeader confirmation{MineHeader(*deposit_index, params, 10)};
        AddAndPersist(db, headers, imports, confirmation);

        deposit_id = ProofDepositId(proof, params.hashGenesisBlock);
        child_block = MakeChildBlock(CHILD_GENESIS, 1, deposit_id);
        const CBlockIndex* confirmation_index{
            headers.Find(confirmation.GetHash())};
        BOOST_REQUIRE(confirmation_index);
        CBlock anchor_block;
        anchor_proof = MakeBmmProof(
            anchor_block, *confirmation_index, params, child_block.GetHash());
        AddAndPersist(db, headers, imports, anchor_block);
        const auto imported{
            imports.ImportProof(proof, headers, child_block.GetHash(), 1)};
        BOOST_REQUIRE(imported.IsValid());
        const chainregistry::ReferenceChildBlockUndo child_undo{
            .block_hash = child_block.GetHash(),
            .parent_hash = CHILD_GENESIS,
            .block_height = 1,
            .coins = CBlockUndo{{CTxUndo{}}},
            .imports = imported.undo,
        };
        BOOST_REQUIRE(db.WriteConnectedChildBlock(
            headers,
            imports,
            child_block,
            child_undo,
            anchor_proof,
            /*sync=*/true));

        const CBlockHeader fork1{MineHeader(*genesis_index, params, 20)};
        AddAndPersist(db, headers, imports, fork1);
        const CBlockIndex* fork1_index{headers.Find(fork1.GetHash())};
        BOOST_REQUIRE(fork1_index);
        const CBlockHeader fork2{MineHeader(*fork1_index, params, 21)};
        AddAndPersist(db, headers, imports, fork2);
        const CBlockIndex* fork2_index{headers.Find(fork2.GetHash())};
        BOOST_REQUIRE(fork2_index);
        const CBlockHeader fork3{MineHeader(*fork2_index, params, 22)};
        AddAndPersist(db, headers, imports, fork3);
        const CBlockIndex* fork3_index{headers.Find(fork3.GetHash())};
        BOOST_REQUIRE(fork3_index);
        fork4 = MineHeader(*fork3_index, params, 23);
        BOOST_REQUIRE(headers.AddHeader(fork4, fork4.nTime).IsValid());
        BOOST_CHECK(!db.WriteMainHeader(headers, imports, fork4));
        const auto halted{imports.Reconcile(headers)};
        BOOST_REQUIRE(halted.newly_halted);
        BOOST_REQUIRE(db.WriteMainHeader(headers, imports, fork4, /*sync=*/true));
    }

    {
        chainregistry::MainHeaderChain headers{params};
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        node::ChildChainDBState state;
        const auto loaded{db.Load(headers, imports, state, fork4.nTime + 1)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK(state.safe_halt);
        BOOST_CHECK(imports.IsSafeHalted());
        BOOST_REQUIRE(imports.SafeHalt().has_value());
        BOOST_CHECK(imports.SafeHalt()->observed_main_tip == fork4.GetHash());
        BOOST_REQUIRE_EQUAL(imports.SafeHalt()->affected_imports.size(), 1U);
        BOOST_CHECK(imports.SafeHalt()->affected_imports.front() == deposit_id);
        BOOST_CHECK(headers.Tip()->GetBlockHash() == fork4.GetHash());
        const CBlock next{MakeChildBlock(child_block.GetHash(), 2)};
        const chainregistry::ReferenceChildBlockUndo next_undo{
            .block_hash = next.GetHash(),
            .parent_hash = child_block.GetHash(),
            .block_height = 2,
            .coins = {},
            .imports = {},
        };
        BOOST_CHECK(!db.WriteConnectedChildBlock(
            headers,
            imports,
            next,
            next_undo,
            anchor_proof,
            /*sync=*/true));
    }
}

BOOST_AUTO_TEST_CASE(rejects_main_reorg_that_orphans_a_child_anchor)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "child_chain_anchor_reorg"};
    chainregistry::MainHeaderChain headers{params};
    BOOST_REQUIRE(headers.Initialize(genesis).IsValid());
    chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
    node::ChildChainDB db{{
                              .path = path,
                              .cache_bytes = 1 << 20,
                              .wipe_data = true,
                              .obfuscate = true,
                          },
                          CHILD_CHAIN,
                          params.hashGenesisBlock,
                          2,
                          CHILD_GENESIS};
    BOOST_REQUIRE(db.WriteInitialState(headers, imports, /*sync=*/true));

    const CBlock child_block{MakeChildBlock(CHILD_GENESIS, 1)};
    const CBlockIndex* genesis_index{headers.Find(genesis.GetHash())};
    BOOST_REQUIRE(genesis_index);
    CBlock anchor_block;
    const auto anchor_proof{MakeBmmProof(
        anchor_block, *genesis_index, params, child_block.GetHash())};
    AddAndPersist(db, headers, imports, anchor_block);
    const chainregistry::ReferenceChildBlockUndo undo{
        .block_hash = child_block.GetHash(),
        .parent_hash = CHILD_GENESIS,
        .block_height = 1,
        .coins = {},
        .imports = {},
    };
    BOOST_REQUIRE(db.WriteConnectedChildBlock(
        headers, imports, child_block, undo, anchor_proof, /*sync=*/true));

    const CBlockHeader fork1{MineHeader(*genesis_index, params, 0x70)};
    AddAndPersist(db, headers, imports, fork1);
    const CBlockIndex* fork1_index{headers.Find(fork1.GetHash())};
    BOOST_REQUIRE(fork1_index);
    const CBlockHeader fork2{MineHeader(*fork1_index, params, 0x71)};
    BOOST_REQUIRE(headers.AddHeader(fork2, fork2.nTime).IsValid());
    BOOST_CHECK(headers.Tip()->GetBlockHash() == fork2.GetHash());
    BOOST_CHECK(!db.WriteMainHeader(headers, imports, fork2, /*sync=*/true));

    node::ChildChainDBState state;
    BOOST_REQUIRE(db.ReadState(state));
    BOOST_CHECK_EQUAL(state.header_count, 3U);
    BOOST_CHECK(state.main_tip == anchor_block.GetHash());
    BOOST_CHECK(state.child_tip == child_block.GetHash());
    BOOST_CHECK_EQUAL(state.anchor_count, 1U);
}

BOOST_AUTO_TEST_CASE(main_reorg_atomically_disconnects_child_import_and_utxo)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "child_chain_atomic_reorg"};
    CBlockHeader fork2;

    {
        chainregistry::MainHeaderChain headers{params};
        BOOST_REQUIRE(headers.Initialize(genesis).IsValid());
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .wipe_data = true,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        BOOST_REQUIRE(db.WriteInitialState(headers, imports, /*sync=*/true));

        const CBlockIndex* genesis_index{headers.Find(genesis.GetHash())};
        BOOST_REQUIRE(genesis_index);
        CBlock deposit_block;
        const auto deposit_proof{
            MakeDepositProof(deposit_block, *genesis_index, params)};
        AddAndPersist(db, headers, imports, deposit_block);
        const CBlockIndex* deposit_index{headers.Find(deposit_block.GetHash())};
        BOOST_REQUIRE(deposit_index);
        const CBlockHeader confirmation{MineHeader(*deposit_index, params, 0x72)};
        AddAndPersist(db, headers, imports, confirmation);
        const CBlockIndex* confirmation_index{
            headers.Find(confirmation.GetHash())};
        BOOST_REQUIRE(confirmation_index);

        const chainregistry::DepositId deposit_id{
            ProofDepositId(deposit_proof, params.hashGenesisBlock)};
        const CBlock child_block{
            MakeChildBlock(CHILD_GENESIS, 1, deposit_id)};
        CBlock anchor_block;
        const auto anchor_proof{MakeBmmProof(
            anchor_block,
            *confirmation_index,
            params,
            child_block.GetHash())};
        AddAndPersist(db, headers, imports, anchor_block);
        const auto imported{imports.ImportProof(
            deposit_proof, headers, child_block.GetHash(), 1)};
        BOOST_REQUIRE(imported.IsValid());
        const chainregistry::ReferenceChildBlockUndo undo{
            .block_hash = child_block.GetHash(),
            .parent_hash = CHILD_GENESIS,
            .block_height = 1,
            .coins = CBlockUndo{{CTxUndo{}}},
            .imports = imported.undo,
        };
        CCoinsViewCache connected_coins{&db, /*deterministic=*/true};
        for (const auto& transaction : child_block.vtx) {
            AddCoins(connected_coins, *transaction, 1);
        }
        connected_coins.SetBestBlock(child_block.GetHash());
        BOOST_REQUIRE(db.WriteConnectedChildBlock(
            headers,
            imports,
            child_block,
            undo,
            anchor_proof,
            /*sync=*/true));
        connected_coins.Flush();
        const COutPoint imported_outpoint{child_block.vtx.back()->GetHash(), 0};
        BOOST_REQUIRE(db.HaveCoin(imported_outpoint));

        const CBlockHeader fork1{
            MineHeader(*confirmation_index, params, 0x73)};
        AddAndPersist(db, headers, imports, fork1);
        const CBlockIndex* fork1_index{headers.Find(fork1.GetHash())};
        BOOST_REQUIRE(fork1_index);
        fork2 = MineHeader(*fork1_index, params, 0x74);
        BOOST_REQUIRE(headers.AddHeader(fork2, fork2.nTime).IsValid());
        BOOST_CHECK(headers.Tip()->GetBlockHash() == fork2.GetHash());
        BOOST_CHECK(!db.WriteMainHeader(headers, imports, fork2));

        CCoinsViewCache disconnected_coins{&db, /*deterministic=*/true};
        BOOST_REQUIRE(chainregistry::DisconnectReferenceChildBlock(
            child_block, undo, disconnected_coins, imports).IsValid());
        const std::vector<node::ChildChainDBDisconnect> disconnected{{
            .block = child_block,
            .undo = undo,
        }};
        BOOST_REQUIRE(db.WriteMainHeaderAndDisconnect(
            headers,
            imports,
            fork2,
            disconnected,
            /*sync=*/true));
        disconnected_coins.Flush();

        node::ChildChainDBState state;
        BOOST_REQUIRE(db.ReadState(state));
        BOOST_CHECK(state.main_tip == fork2.GetHash());
        BOOST_CHECK_EQUAL(state.header_count, 6U);
        BOOST_CHECK(state.child_tip == CHILD_GENESIS);
        BOOST_CHECK_EQUAL(state.child_height, 0U);
        BOOST_CHECK_EQUAL(state.anchor_count, 0U);
        BOOST_CHECK_EQUAL(state.import_count, 0U);
        BOOST_CHECK_EQUAL(state.coin_count, 0U);
        BOOST_CHECK(!db.ReadImport(deposit_id).has_value());
        BOOST_CHECK(!db.ReadBmmAnchor(child_block.GetHash()).has_value());
        BOOST_CHECK(!db.HaveCoin(imported_outpoint));
    }

    {
        chainregistry::MainHeaderChain headers{params};
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        node::ChildChainDBState state;
        const auto loaded{db.Load(headers, imports, state, fork2.nTime + 1)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK(headers.Tip()->GetBlockHash() == fork2.GetHash());
        BOOST_CHECK(state.child_tip == CHILD_GENESIS);
        BOOST_CHECK_EQUAL(state.child_height, 0U);
        BOOST_CHECK_EQUAL(imports.Size(), 0U);
    }
}

BOOST_AUTO_TEST_CASE(persists_bounded_candidate_dag_and_repeated_anchors)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "child_chain_candidates"};
    CBlock first{MakeChildBlock(CHILD_GENESIS, 1)};
    CBlock second{MakeChildBlock(CHILD_GENESIS, 1)};
    second.nNonce = 1;
    BOOST_REQUIRE(first.GetHash() != second.GetHash());

    CBlockHeader final_main_tip;
    chainregistry::BmmAnchorProof first_anchor;
    chainregistry::BmmAnchorProof second_anchor;
    chainregistry::BmmAnchorProof repeated_first_anchor;
    {
        chainregistry::MainHeaderChain headers{params};
        BOOST_REQUIRE(headers.Initialize(genesis).IsValid());
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .wipe_data = true,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        BOOST_REQUIRE(db.WriteInitialState(headers, imports, /*sync=*/true));

        const CBlockIndex* parent{headers.Find(genesis.GetHash())};
        BOOST_REQUIRE(parent);
        CBlock first_anchor_block;
        first_anchor = MakeBmmProof(
            first_anchor_block, *parent, params, first.GetHash());
        AddAndPersist(db, headers, imports, first_anchor_block);
        BOOST_REQUIRE(db.WritePendingBmmAnchor(
            headers, first_anchor, /*sync=*/true));
        const chainregistry::ReferenceChildBlockUndo first_undo{
            .block_hash = first.GetHash(),
            .parent_hash = CHILD_GENESIS,
            .block_height = 1,
            .coins = {},
            .imports = {},
        };
        BOOST_REQUIRE(db.WriteValidatedChildCandidate(
            headers,
            first,
            first_undo,
            first_anchor,
            /*sync=*/true));
        BOOST_REQUIRE(db.ReadBlockFilter(first.GetHash()).has_value());

        parent = headers.Find(first_anchor_block.GetHash());
        BOOST_REQUIRE(parent);
        CBlock second_anchor_block;
        second_anchor = MakeBmmProof(
            second_anchor_block, *parent, params, second.GetHash());
        AddAndPersist(db, headers, imports, second_anchor_block);
        const chainregistry::ReferenceChildBlockUndo second_undo{
            .block_hash = second.GetHash(),
            .parent_hash = CHILD_GENESIS,
            .block_height = 1,
            .coins = {},
            .imports = {},
        };
        BOOST_REQUIRE(db.WriteValidatedChildCandidate(
            headers,
            second,
            second_undo,
            second_anchor,
            /*sync=*/true));
        BOOST_REQUIRE(db.ReadBlockFilter(second.GetHash()).has_value());

        parent = headers.Find(second_anchor_block.GetHash());
        BOOST_REQUIRE(parent);
        CBlock repeated_anchor_block;
        repeated_first_anchor = MakeBmmProof(
            repeated_anchor_block, *parent, params, first.GetHash());
        AddAndPersist(db, headers, imports, repeated_anchor_block);
        final_main_tip = repeated_anchor_block;
        BOOST_REQUIRE(db.WriteCandidateBmmAnchor(
            headers, repeated_first_anchor, /*sync=*/true));

        node::ChildChainDBState state;
        BOOST_REQUIRE(db.ReadState(state));
        BOOST_CHECK_EQUAL(state.side_candidate_count, 2U);
        BOOST_CHECK_GT(state.side_candidate_bytes, 0U);
        BOOST_CHECK_EQUAL(state.candidate_anchor_count, 3U);
        BOOST_CHECK_GT(state.candidate_anchor_bytes, 0U);
        BOOST_CHECK_EQUAL(state.pending_anchor_count, 0U);

        const auto fork_candidates{db.ReadForkCandidates(headers)};
        BOOST_REQUIRE(fork_candidates.has_value());
        const auto selected{chainregistry::SelectChildFork(
            CHILD_GENESIS, *fork_candidates)};
        BOOST_REQUIRE(selected.IsValid());
        BOOST_CHECK(selected.head == first.GetHash());
        BOOST_CHECK(
            selected.scores.at(first.GetHash()).own_anchor_work ==
            selected.scores.at(second.GetHash()).own_anchor_work * 2);

        CCoinsViewCache coins{&db, /*deterministic=*/true};
        AddCoins(coins, *first.vtx.front(), 1);
        coins.SetBestBlock(first.GetHash());
        BOOST_REQUIRE(db.WriteConnectedChildBlock(
            headers,
            imports,
            first,
            first_undo,
            first_anchor,
            /*sync=*/true));
        coins.Flush();

        BOOST_REQUIRE(db.ReadState(state));
        BOOST_CHECK_EQUAL(state.child_height, 1U);
        BOOST_CHECK(state.child_tip == first.GetHash());
        BOOST_CHECK_EQUAL(state.side_candidate_count, 1U);
        BOOST_CHECK_EQUAL(state.anchor_count, 1U);
        BOOST_CHECK_EQUAL(state.candidate_anchor_count, 2U);
        BOOST_CHECK(!db.ReadSideCandidate(first.GetHash()).has_value());
        BOOST_CHECK(db.ReadSideCandidate(second.GetHash()).has_value());
        BOOST_REQUIRE(db.ReadBlockFilter(first.GetHash()).has_value());
        BOOST_REQUIRE(db.ReadBlockFilter(second.GetHash()).has_value());

        const auto promoted_candidates{db.ReadForkCandidates(headers)};
        BOOST_REQUIRE(promoted_candidates.has_value());
        const auto promoted{chainregistry::SelectChildFork(
            CHILD_GENESIS, *promoted_candidates)};
        BOOST_REQUIRE(promoted.IsValid());
        BOOST_CHECK(promoted.head == first.GetHash());
    }

    {
        chainregistry::MainHeaderChain headers{params};
        chainregistry::DepositImportState imports{CHILD_CHAIN, 2};
        node::ChildChainDB db{{
                                  .path = path,
                                  .cache_bytes = 1 << 20,
                                  .obfuscate = true,
                              },
                              CHILD_CHAIN,
                              params.hashGenesisBlock,
                              2,
                              CHILD_GENESIS};
        node::ChildChainDBState state;
        const auto loaded{
            db.Load(headers, imports, state, final_main_tip.nTime + 1)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK_EQUAL(state.child_height, 1U);
        BOOST_CHECK_EQUAL(state.side_candidate_count, 1U);
        BOOST_CHECK_EQUAL(state.candidate_anchor_count, 2U);
        BOOST_REQUIRE(db.ReadBlockFilter(first.GetHash()).has_value());
        BOOST_REQUIRE(db.ReadBlockFilter(second.GetHash()).has_value());
        const auto candidates{db.ReadForkCandidates(headers)};
        BOOST_REQUIRE(candidates.has_value());
        const auto selected{
            chainregistry::SelectChildFork(CHILD_GENESIS, *candidates)};
        BOOST_REQUIRE(selected.IsValid());
        BOOST_CHECK(selected.head == first.GetHash());
    }
}

BOOST_AUTO_TEST_SUITE_END()
