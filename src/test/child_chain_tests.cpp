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

        const CBlock block{ChildBlock(*runtime.Tip())};
        child_hash = block.GetHash();
        const auto connected{runtime.ConnectBlock(
            block, block.nTime, /*sync=*/true)};
        BOOST_REQUIRE_MESSAGE(
            connected.IsValid(),
            static_cast<int>(connected.error) << ":" <<
                static_cast<int>(connected.child_block.error));
        BOOST_REQUIRE(runtime.Tip());
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == child_hash);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 1U);
        BOOST_CHECK(runtime.State().child_tip == child_hash);

        CBlock stored;
        BOOST_REQUIRE(runtime.ReadBlock(child_hash, stored));
        BOOST_CHECK(stored.vtx.front()->GetWitnessHash() ==
                    block.vtx.front()->GetWitnessHash());

        const CBlock invalid{ChildBlock(*runtime.Tip(), /*reward=*/1)};
        const auto rejected{runtime.ConnectBlock(
            invalid, invalid.nTime, /*sync=*/true)};
        BOOST_CHECK(rejected.error ==
                    node::ReferenceChildRuntimeError::CHILD_BLOCK_REJECTED);
        BOOST_CHECK_MESSAGE(
            rejected.child_block.error ==
                chainregistry::ReferenceChildBlockError::COINBASE_PAYS_TOO_MUCH,
            static_cast<int>(rejected.child_block.error));
        BOOST_CHECK(runtime.Tip()->GetBlockHash() == child_hash);
        BOOST_CHECK_EQUAL(runtime.State().child_height, 1U);
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
