// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_chain_db.h>

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

BOOST_AUTO_TEST_CASE(persists_headers_imports_and_child_undo)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "child_chain_state"};
    constexpr uint256 child_block{
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};

    chainregistry::DepositId deposit_id;
    chainregistry::DepositImportUndo import_undo;
    CBlockHeader confirmation;
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
        confirmation = MineHeader(*deposit_index, params, 1);
        AddAndPersist(db, headers, imports, confirmation);

        const auto imported{imports.ImportProof(proof, headers, child_block, 1)};
        BOOST_REQUIRE(imported.IsValid());
        deposit_id = imported.imports.front().deposit_id;
        import_undo = imported.undo;
        BOOST_REQUIRE(db.WriteConnectedChildBlock(
            imports, child_block, 1, import_undo, /*sync=*/true));
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
        const auto loaded{db.Load(headers, imports, state, confirmation.nTime + 1)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK(loaded.initialized);
        BOOST_CHECK_EQUAL(state.header_count, 3U);
        BOOST_CHECK_EQUAL(state.import_count, 1U);
        BOOST_CHECK(state.child_tip == child_block);
        BOOST_CHECK_EQUAL(state.child_height, 1U);
        BOOST_CHECK(headers.Tip()->GetBlockHash() == confirmation.GetHash());
        BOOST_CHECK(imports.Find(deposit_id) != nullptr);
        chainregistry::DepositImportUndo stored_undo;
        BOOST_REQUIRE(db.ReadUndo(child_block, stored_undo));
        BOOST_CHECK(stored_undo == import_undo);

        BOOST_REQUIRE(imports.DisconnectImports(child_block, import_undo));
        BOOST_REQUIRE(db.WriteDisconnectedChildBlock(
            imports,
            child_block,
            CHILD_GENESIS,
            0,
            import_undo,
            /*sync=*/true));
        BOOST_CHECK(!db.ReadImport(deposit_id).has_value());
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
        BOOST_REQUIRE(db.Load(headers, imports, state, confirmation.nTime + 1).IsValid());
        BOOST_CHECK_EQUAL(imports.Size(), 0U);
        BOOST_CHECK_EQUAL(state.import_count, 0U);
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
        BOOST_CHECK(db.Load(headers, imports, state, confirmation.nTime + 1).error ==
                    node::ChildChainDBLoadError::CONFIGURATION_MISMATCH);
    }
}

BOOST_AUTO_TEST_CASE(persists_safe_halt_across_restart)
{
    const auto& params{Params().GetConsensus()};
    const CBlock& genesis{Params().GenesisBlock()};
    const fs::path path{m_args.GetDataDirBase() / "child_chain_safe_halt"};
    constexpr uint256 child_block{
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"};

    CBlockHeader fork3;
    chainregistry::DepositId deposit_id;
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

        const auto imported{imports.ImportProof(proof, headers, child_block, 1)};
        BOOST_REQUIRE(imported.IsValid());
        deposit_id = imported.imports.front().deposit_id;
        BOOST_REQUIRE(db.WriteConnectedChildBlock(
            imports, child_block, 1, imported.undo, /*sync=*/true));

        const CBlockHeader fork1{MineHeader(*genesis_index, params, 20)};
        AddAndPersist(db, headers, imports, fork1);
        const CBlockIndex* fork1_index{headers.Find(fork1.GetHash())};
        BOOST_REQUIRE(fork1_index);
        const CBlockHeader fork2{MineHeader(*fork1_index, params, 21)};
        AddAndPersist(db, headers, imports, fork2);
        const CBlockIndex* fork2_index{headers.Find(fork2.GetHash())};
        BOOST_REQUIRE(fork2_index);
        fork3 = MineHeader(*fork2_index, params, 22);
        BOOST_REQUIRE(headers.AddHeader(fork3, fork3.nTime).IsValid());
        BOOST_CHECK(!db.WriteMainHeader(headers, imports, fork3));
        const auto halted{imports.Reconcile(headers)};
        BOOST_REQUIRE(halted.newly_halted);
        BOOST_REQUIRE(db.WriteMainHeader(headers, imports, fork3, /*sync=*/true));
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
        const auto loaded{db.Load(headers, imports, state, fork3.nTime + 1)};
        BOOST_REQUIRE_MESSAGE(loaded.IsValid(), static_cast<int>(loaded.error));
        BOOST_CHECK(state.safe_halt);
        BOOST_CHECK(imports.IsSafeHalted());
        BOOST_REQUIRE(imports.SafeHalt().has_value());
        BOOST_CHECK(imports.SafeHalt()->observed_main_tip == fork3.GetHash());
        BOOST_REQUIRE_EQUAL(imports.SafeHalt()->affected_imports.size(), 1U);
        BOOST_CHECK(imports.SafeHalt()->affected_imports.front() == deposit_id);
        BOOST_CHECK(headers.Tip()->GetBlockHash() == fork3.GetHash());
        BOOST_CHECK(!db.WriteConnectedChildBlock(
            imports, uint256{0x44}, 2, {}, /*sync=*/true));
    }
}

BOOST_AUTO_TEST_SUITE_END()
