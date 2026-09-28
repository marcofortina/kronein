// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_network_manager.h>

#include <chainparams.h>
#include <chainregistry/child_template.h>
#include <node/chain_manager.h>
#include <scheduler.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

namespace {

const COutPoint REGISTRATION_ANCHOR{
    Txid{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    1};
const chainregistry::MetadataHash METADATA_HASH{
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};

struct ChildNetworkManagerSetup : BasicTestingSetup {
    ChildNetworkManagerSetup() : BasicTestingSetup{ChainType::REGTEST} {}
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(
    child_network_manager_tests,
    ChildNetworkManagerSetup)

BOOST_AUTO_TEST_CASE(owns_an_isolated_network_per_loaded_child)
{
    const auto definition{Definition()};
    node::ChainManager chains{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_network_manager",
        1 << 20};
    BOOST_REQUIRE(chains.RegisterChain(definition).IsValid());
    BOOST_REQUIRE(chains.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());

    CScheduler scheduler;
    node::ChildNetworkManager networks{chains, Params(), scheduler};
    const auto invalid{networks.Start(
        definition.chain_id,
        {.connect = {"127.0.0.1"}, .network_active = false})};
    BOOST_CHECK(
        invalid.error == node::ChildNetworkError::INVALID_ENDPOINT);

    BOOST_REQUIRE(networks.Start(
        definition.chain_id,
        {.connect = {}, .network_active = false}).IsValid());
    BOOST_CHECK(networks.IsRunning(definition.chain_id));
    const auto running{networks.GetStats(definition.chain_id)};
    BOOST_CHECK(running.running);
    BOOST_CHECK(!running.network_active);
    BOOST_CHECK_EQUAL(running.connections, 0U);
    BOOST_CHECK_EQUAL(running.handshaken, 0U);
    BOOST_CHECK(fs::exists(
        chains.DataPath(definition.chain_id) / "network" / "peers.dat"));

    BOOST_CHECK(
        networks.Start(definition.chain_id).error ==
        node::ChildNetworkError::ALREADY_RUNNING);
    BOOST_REQUIRE(networks.AddNode(
        definition.chain_id, "127.0.0.1:19843").IsValid());
    BOOST_CHECK(
        networks.AddNode(definition.chain_id, "127.0.0.1:19843").error ==
        node::ChildNetworkError::NODE_ALREADY_ADDED);
    const auto with_node{networks.GetStats(definition.chain_id)};
    BOOST_REQUIRE_EQUAL(with_node.added_nodes.size(), 1U);
    BOOST_CHECK_EQUAL(with_node.added_nodes.front(), "127.0.0.1:19843");

    BOOST_REQUIRE(networks.RemoveNode(
        definition.chain_id, "127.0.0.1:19843").IsValid());
    BOOST_CHECK(
        networks.RemoveNode(definition.chain_id, "127.0.0.1:19843").error ==
        node::ChildNetworkError::NODE_NOT_ADDED);
    BOOST_REQUIRE(networks.Stop(definition.chain_id).IsValid());
    BOOST_CHECK(!networks.IsRunning(definition.chain_id));
    BOOST_CHECK(
        networks.Stop(definition.chain_id).error ==
        node::ChildNetworkError::NOT_RUNNING);

    // The peer-store directory is durable state, not a one-shot startup path.
    BOOST_REQUIRE(networks.Start(
        definition.chain_id,
        {.connect = {}, .network_active = false}).IsValid());
    BOOST_REQUIRE(networks.Stop(definition.chain_id).IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
