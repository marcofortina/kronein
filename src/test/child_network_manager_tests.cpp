// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_network_manager.h>

#include <chainparams.h>
#include <chainregistry/child_template.h>
#include <node/chain_manager.h>
#include <scheduler.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/readwritefile.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

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
        METADATA_HASH,
        TestChildFeeRecipient())};
    BOOST_REQUIRE(result.IsValid());
    return *result.definition;
}

std::vector<std::string> Endpoints(size_t count, uint16_t first_port)
{
    std::vector<std::string> endpoints;
    endpoints.reserve(count);
    for (size_t index{0}; index < count; ++index) {
        endpoints.push_back(strprintf("127.0.0.1:%u", first_port + index));
    }
    return endpoints;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(child_network_manager_tests, ChildNetworkManagerSetup)

BOOST_AUTO_TEST_CASE(enforces_process_wide_child_upload_budget)
{
    node::ChildBandwidthLimiter limiter{/*target=*/100};
    const std::chrono::seconds start{1'000};

    auto stats{limiter.GetStats(start)};
    BOOST_CHECK_EQUAL(stats.target, 100U);
    BOOST_CHECK_EQUAL(stats.bytes_sent, 0U);
    BOOST_CHECK_EQUAL(stats.bytes_left, 100U);
    BOOST_CHECK_EQUAL(stats.time_left.count(),
                      node::CHILD_UPLOAD_TIMEFRAME.count());
    BOOST_CHECK(!stats.target_reached);

    BOOST_CHECK(limiter.TryReserve(60, start));
    BOOST_CHECK(!limiter.TryReserve(41, start + std::chrono::seconds{1}));
    BOOST_CHECK(limiter.TryReserve(40, start + std::chrono::seconds{2}));
    stats = limiter.GetStats(start + std::chrono::seconds{3});
    BOOST_CHECK_EQUAL(stats.bytes_sent, 100U);
    BOOST_CHECK_EQUAL(stats.bytes_left, 0U);
    BOOST_CHECK(stats.target_reached);

    const auto next_cycle{start + node::CHILD_UPLOAD_TIMEFRAME};
    stats = limiter.GetStats(next_cycle);
    BOOST_CHECK_EQUAL(stats.bytes_sent, 0U);
    BOOST_CHECK_EQUAL(stats.bytes_left, 100U);
    BOOST_CHECK(!stats.target_reached);
    BOOST_CHECK(limiter.TryReserve(100, next_cycle));

    node::ChildBandwidthLimiter unlimited{/*target=*/0};
    BOOST_CHECK(unlimited.TryReserve(101, start));
    stats = unlimited.GetStats(start);
    BOOST_CHECK_EQUAL(stats.target, 0U);
    BOOST_CHECK_EQUAL(stats.bytes_sent, 101U);
    BOOST_CHECK_EQUAL(stats.bytes_left, 0U);
    BOOST_CHECK(!stats.target_reached);
}

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
        node::ChildNetworkConfig{
            .connect = {"127.0.0.1"},
            .bind = {},
            .bootstrap = {},
            .discovery = false,
            .network_active = false})};
    BOOST_CHECK(
        invalid.error == node::ChildNetworkError::INVALID_ENDPOINT);

    BOOST_REQUIRE(networks.Start(
        definition.chain_id,
        node::ChildNetworkConfig{
            .connect = {},
            .bind = {},
            .bootstrap = {},
            .discovery = false,
            .network_active = false}).IsValid());
    BOOST_CHECK(networks.IsRunning(definition.chain_id));
    const auto running{networks.GetStats(definition.chain_id)};
    BOOST_CHECK(running.running);
    BOOST_CHECK(!running.network_active);
    BOOST_CHECK_EQUAL(running.connections, 0U);
    BOOST_CHECK_EQUAL(running.handshaken, 0U);
    BOOST_CHECK(running.bind_endpoints.empty());
    BOOST_CHECK(fs::exists(
        chains.DataPath(definition.chain_id) / "network" / "peers.dat"));

    BOOST_REQUIRE(networks.SetNetworkActive(
        definition.chain_id, true).IsValid());
    BOOST_CHECK(networks.GetStats(definition.chain_id).network_active);
    BOOST_REQUIRE(networks.SetNetworkActive(
        definition.chain_id, false).IsValid());
    BOOST_CHECK(!networks.GetStats(definition.chain_id).network_active);

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
        node::ChildNetworkConfig{
            .connect = {},
            .bind = {},
            .bootstrap = {},
            .discovery = false,
            .network_active = false}).IsValid());
    BOOST_REQUIRE(networks.AddNode(
        definition.chain_id, "127.0.0.1:19844").IsValid());
    BOOST_REQUIRE(networks.Stop(definition.chain_id).IsValid());

    BOOST_REQUIRE(networks.Start(definition.chain_id).IsValid());
    const auto restored{networks.GetStats(definition.chain_id)};
    BOOST_CHECK(!restored.network_active);
    BOOST_REQUIRE_EQUAL(restored.added_nodes.size(), 1U);
    BOOST_CHECK_EQUAL(restored.added_nodes.front(), "127.0.0.1:19844");
    BOOST_CHECK(restored.bind_endpoints.empty());
    BOOST_CHECK(!restored.discovery);
    BOOST_CHECK(restored.bootstrap_nodes.empty());

    BOOST_REQUIRE(networks.SetDiscovery(
        definition.chain_id,
        /*enabled=*/true,
        {"127.0.0.1:19846"}).IsValid());
    const auto discovery{networks.GetStats(definition.chain_id)};
    BOOST_CHECK(discovery.discovery);
    BOOST_REQUIRE_EQUAL(discovery.bootstrap_nodes.size(), 1U);
    BOOST_CHECK_EQUAL(discovery.bootstrap_nodes.front(), "127.0.0.1:19846");
    BOOST_CHECK(
        networks.SetDiscovery(
            definition.chain_id,
            /*enabled=*/true,
            {"seed.example:19846"}).error ==
        node::ChildNetworkError::INVALID_BOOTSTRAP_ENDPOINT);
    BOOST_REQUIRE(networks.Stop(definition.chain_id).IsValid());

    BOOST_REQUIRE(networks.Start(definition.chain_id).IsValid());
    const auto persisted_discovery{networks.GetStats(definition.chain_id)};
    BOOST_CHECK(persisted_discovery.discovery);
    BOOST_REQUIRE_EQUAL(persisted_discovery.bootstrap_nodes.size(), 1U);
    BOOST_CHECK_EQUAL(
        persisted_discovery.bootstrap_nodes.front(), "127.0.0.1:19846");
    BOOST_REQUIRE(networks.SetDiscovery(
        definition.chain_id,
        /*enabled=*/false,
        {}).IsValid());
    BOOST_REQUIRE(networks.Stop(definition.chain_id).IsValid());

    const fs::path config_path{
        chains.DataPath(definition.chain_id) / "network" / "config.json"};
    BOOST_REQUIRE(WriteBinaryFile(config_path, "{}"));
    BOOST_CHECK(
        networks.Start(definition.chain_id).error ==
        node::ChildNetworkError::CONFIG_INVALID);

    // An explicit replacement is the recovery path for invalid local config.
    BOOST_REQUIRE(networks.Start(
        definition.chain_id,
        node::ChildNetworkConfig{
            .connect = {},
            .bind = {},
            .bootstrap = {},
            .discovery = false,
            .network_active = false}).IsValid());
    BOOST_REQUIRE(networks.Stop(definition.chain_id).IsValid());

    const auto invalid_bind{networks.Start(
        definition.chain_id,
        node::ChildNetworkConfig{
            .connect = {},
            .bind = {"localhost:19845"},
            .bootstrap = {},
            .discovery = false,
            .network_active = false})};
    BOOST_CHECK(
        invalid_bind.error ==
        node::ChildNetworkError::INVALID_BIND_ENDPOINT);

    const auto invalid_bootstrap{networks.Start(
        definition.chain_id,
        node::ChildNetworkConfig{
            .connect = {},
            .bind = {},
            .bootstrap = {"seed.example:19846"},
            .discovery = true,
            .network_active = false})};
    BOOST_CHECK(
        invalid_bootstrap.error ==
        node::ChildNetworkError::INVALID_BOOTSTRAP_ENDPOINT);
}

BOOST_AUTO_TEST_CASE(bounds_child_network_configuration)
{
    const auto definition{Definition()};
    node::ChainManager chains{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_network_limits",
        1 << 20};
    BOOST_REQUIRE(chains.RegisterChain(definition).IsValid());
    BOOST_REQUIRE(chains.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());

    CScheduler scheduler;
    node::ChildNetworkManager networks{chains, Params(), scheduler};
    BOOST_CHECK(
        networks.Start(
            definition.chain_id,
            node::ChildNetworkConfig{
                .connect = Endpoints(
                    node::MAX_CHILD_CONNECT_NODES + 1, 20'000),
                .bind = {},
                .bootstrap = {},
                .discovery = false,
                .network_active = false})
            .error == node::ChildNetworkError::TOO_MANY_ENDPOINTS);
    BOOST_CHECK(
        networks.Start(
            definition.chain_id,
            node::ChildNetworkConfig{
                .connect = {},
                .bind = Endpoints(
                    node::MAX_CHILD_BIND_ENDPOINTS + 1, 21'000),
                .bootstrap = {},
                .discovery = false,
                .network_active = false})
            .error == node::ChildNetworkError::TOO_MANY_BIND_ENDPOINTS);
    BOOST_CHECK(
        networks.Start(
            definition.chain_id,
            node::ChildNetworkConfig{
                .connect = {},
                .bind = {},
                .bootstrap = Endpoints(
                    node::MAX_CHILD_BOOTSTRAP_NODES + 1, 22'000),
                .discovery = true,
                .network_active = false})
            .error ==
        node::ChildNetworkError::TOO_MANY_BOOTSTRAP_ENDPOINTS);
    BOOST_CHECK(!networks.IsRunning(definition.chain_id));

    BOOST_REQUIRE(networks.Start(
        definition.chain_id,
        node::ChildNetworkConfig{
            .connect = {},
            .bind = {},
            .bootstrap = {},
            .discovery = false,
            .network_active = false}).IsValid());
    const auto connect{Endpoints(node::MAX_CHILD_CONNECT_NODES + 1, 23'000)};
    for (size_t index{0}; index < node::MAX_CHILD_CONNECT_NODES; ++index) {
        BOOST_REQUIRE(networks.AddNode(
            definition.chain_id, connect[index]).IsValid());
    }
    BOOST_CHECK(
        networks.AddNode(definition.chain_id, connect.back()).error ==
        node::ChildNetworkError::TOO_MANY_ENDPOINTS);
    BOOST_CHECK_EQUAL(
        networks.GetStats(definition.chain_id).added_nodes.size(),
        node::MAX_CHILD_CONNECT_NODES);

    BOOST_CHECK(
        networks.SetBindEndpoints(
            definition.chain_id,
            Endpoints(node::MAX_CHILD_BIND_ENDPOINTS + 1, 24'000))
            .error == node::ChildNetworkError::TOO_MANY_BIND_ENDPOINTS);
    BOOST_CHECK(
        networks.SetDiscovery(
            definition.chain_id,
            /*enabled=*/true,
            Endpoints(node::MAX_CHILD_BOOTSTRAP_NODES + 1, 25'000))
            .error ==
        node::ChildNetworkError::TOO_MANY_BOOTSTRAP_ENDPOINTS);
    const auto stats{networks.GetStats(definition.chain_id)};
    BOOST_CHECK(stats.running);
    BOOST_CHECK(stats.bind_endpoints.empty());
    BOOST_CHECK(!stats.discovery);
    BOOST_CHECK(stats.bootstrap_nodes.empty());
}

BOOST_AUTO_TEST_SUITE_END()
