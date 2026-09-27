// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chain_manager.h>

#include <chainparams.h>
#include <primitives/chainregistry.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

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
        METADATA_HASH)};
    BOOST_REQUIRE(result.IsValid());
    return *result.definition;
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

    node::ChainManager restarted{
        Params().GetConsensus(), Params().GenesisBlock(), root, 1 << 20};
    BOOST_REQUIRE(restarted.RegisterChain(first).IsValid());
    BOOST_REQUIRE(restarted.RegisterChain(second).IsValid());
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
}

BOOST_AUTO_TEST_SUITE_END()
