// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_net_events.h>
#include <node/child_network_manager.h>

#include <addrman.h>
#include <chainparams.h>
#include <netgroup.h>
#include <netmessagemaker.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

namespace {

const COutPoint REGISTRATION_ANCHOR{
    Txid{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    1};
const chainregistry::MetadataHash METADATA_HASH{
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};

struct ChildNetEventsSetup : BasicTestingSetup {
    ChildNetEventsSetup() : BasicTestingSetup{ChainType::REGTEST} {}
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

BOOST_FIXTURE_TEST_SUITE(child_net_events_tests, ChildNetEventsSetup)

BOOST_AUTO_TEST_CASE(adapts_only_the_isolated_child_protocol)
{
    const auto definition{Definition()};
    node::ChainManager manager{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_net_events",
        1 << 20};
    BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());

    NetGroupManager netgroup{NetGroupManager::NoAsmap()};
    AddrMan addrman{
        netgroup, /*deterministic=*/true,
        /*consistency_check_ratio=*/0};
    ConnmanTestMsg connman{
        1, 2, addrman, netgroup, Params()};
    node::ChildBandwidthLimiter bandwidth{
        node::DEFAULT_CHILD_UPLOAD_TARGET_BYTES};
    node::ChildNetEvents events{
        connman, manager, bandwidth, definition};
    connman.SetMsgProc(&events);

    CNode peer{
        /*id=*/7,
        /*sock=*/nullptr,
        CAddress{},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/0,
        CService{},
        /*addrNameIn=*/"",
        ConnectionType::INBOUND,
        /*inbound_onion=*/false,
        /*network_key=*/0};
    events.InitializeNode(peer, NODE_NONE);
    BOOST_CHECK_EQUAL(events.PeerCount(), 1U);
    {
        LOCK(peer.cs_vSend);
        BOOST_REQUIRE_EQUAL(peer.vSendMsg.size(), 1U);
        BOOST_CHECK(
            peer.vSendMsg.front().m_type ==
            chainregistry::ChildNetMsgType::HELLO);
        DataStream payload{peer.vSendMsg.front().data};
        chainregistry::ChildNetHello hello;
        payload >> hello;
        BOOST_CHECK(payload.empty());
        BOOST_CHECK_EQUAL(hello.nonce, peer.GetLocalNonce());
        BOOST_CHECK(hello.chain_id == definition.chain_id);
        BOOST_CHECK(hello.genesis_hash == definition.genesis_hash);
    }
    connman.FlushSendBuffer(peer);

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer,
        NetMsg::Make(
            std::string{chainregistry::ChildNetMsgType::HELLO},
            chainregistry::ChildNetHello{
                .nonce = 123,
                .chain_id = definition.chain_id,
                .genesis_hash = definition.genesis_hash,
            })));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(peer);
    }
    BOOST_CHECK(peer.fSuccessfullyConnected);
    BOOST_CHECK(!peer.fDisconnect);

    chainregistry::ChildBlockHashes block_request{
        .chain_id = definition.chain_id,
        .block_hashes = {},
    };
    for (uint64_t value{1};
         value <= chainregistry::MAX_CHILD_BLOCK_REQUEST_HASHES;
         ++value) {
        block_request.block_hashes.emplace_back(value);
    }
    for (int request{0}; request < 4; ++request) {
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer,
            NetMsg::Make(
                std::string{chainregistry::ChildNetMsgType::GET_BLOCKS},
                block_request)));
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(peer);
        BOOST_CHECK(!peer.fDisconnect);
    }
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer,
        NetMsg::Make(
            std::string{chainregistry::ChildNetMsgType::GET_BLOCKS},
            block_request)));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(peer);
    }
    BOOST_CHECK(peer.fDisconnect);
    BOOST_CHECK_EQUAL(events.RateLimitedRequests(), 1U);
    peer.fDisconnect = false;

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        peer, NetMsg::Make("main-only-message", uint8_t{0})));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(peer);
    }
    BOOST_CHECK(peer.fDisconnect);

    events.FinalizeNode(peer);
    BOOST_CHECK_EQUAL(events.PeerCount(), 0U);
}

BOOST_AUTO_TEST_CASE(rejects_child_connections_to_self)
{
    const auto definition{Definition()};
    node::ChainManager manager{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_net_self_connection",
        1 << 20};
    BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());

    NetGroupManager netgroup{NetGroupManager::NoAsmap()};
    AddrMan addrman{
        netgroup, /*deterministic=*/true,
        /*consistency_check_ratio=*/0};
    ConnmanTestMsg connman{
        1, 2, addrman, netgroup, Params()};
    node::ChildBandwidthLimiter bandwidth{
        node::DEFAULT_CHILD_UPLOAD_TARGET_BYTES};
    node::ChildNetEvents events{
        connman, manager, bandwidth, definition};
    connman.SetMsgProc(&events);

    constexpr uint64_t SELF_NONCE{77};
    auto* outbound = new CNode{
        /*id=*/7,
        /*sock=*/nullptr,
        CAddress{},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/SELF_NONCE,
        CService{},
        /*addrNameIn=*/"",
        ConnectionType::MANUAL,
        /*inbound_onion=*/false,
        /*network_key=*/0};
    connman.AddTestNode(*outbound);

    CNode inbound{
        /*id=*/8,
        /*sock=*/nullptr,
        CAddress{},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/88,
        CService{},
        /*addrNameIn=*/"",
        ConnectionType::INBOUND,
        /*inbound_onion=*/false,
        /*network_key=*/0};
    events.InitializeNode(inbound, NODE_NONE);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        inbound,
        NetMsg::Make(
            std::string{chainregistry::ChildNetMsgType::HELLO},
            chainregistry::ChildNetHello{
                .nonce = SELF_NONCE,
                .chain_id = definition.chain_id,
                .genesis_hash = definition.genesis_hash,
            })));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(inbound);
    }
    BOOST_CHECK(inbound.fDisconnect);
    BOOST_CHECK(!inbound.fSuccessfullyConnected);

    events.FinalizeNode(inbound);
    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_SUITE_END()
