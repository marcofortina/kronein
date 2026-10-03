// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_net_events.h>
#include <node/child_network_manager.h>

#include <addrman.h>
#include <chainparams.h>
#include <netbase.h>
#include <netgroup.h>
#include <netmessagemaker.h>
#include <protocol.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <memory>

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
        METADATA_HASH,
        TestChildFeeRecipient())};
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
        connman,
        addrman,
        manager,
        bandwidth,
        definition,
        /*discovery=*/false};
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
        peer, NetMsg::Make(NetMsgType::PING, uint64_t{0})));
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
        connman,
        addrman,
        manager,
        bandwidth,
        definition,
        /*discovery=*/false};
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

BOOST_AUTO_TEST_CASE(limits_inbound_peers_per_netgroup_before_handshake)
{
    const auto definition{Definition()};
    node::ChainManager manager{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_net_inbound_netgroup",
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
        connman,
        addrman,
        manager,
        bandwidth,
        definition,
        /*discovery=*/false,
        node::MAX_CHILD_KNOWN_ADDRESSES,
        /*max_inbound_per_netgroup=*/1};
    connman.SetMsgProc(&events);

    constexpr uint64_t NETGROUP{77};
    const auto make_peer{[=](NodeId id, uint64_t nonce) {
        return std::make_unique<CNode>(
            id,
            /*sock=*/nullptr,
            CAddress{},
            /*nKeyedNetGroupIn=*/NETGROUP,
            /*nLocalHostNonceIn=*/nonce,
            CService{},
            /*addrNameIn=*/"",
            ConnectionType::INBOUND,
            /*inbound_onion=*/false,
            /*network_key=*/0);
    }};
    auto first{make_peer(20, 200)};
    auto second{make_peer(21, 210)};
    auto replacement{make_peer(22, 220)};
    const auto authenticate{[&](CNode& peer, uint64_t nonce) {
        events.InitializeNode(peer, NODE_NONE);
        connman.FlushSendBuffer(peer);
        BOOST_REQUIRE(connman.ReceiveMsgFrom(
            peer,
            NetMsg::Make(
                std::string{chainregistry::ChildNetMsgType::HELLO},
                chainregistry::ChildNetHello{
                    .nonce = nonce,
                    .chain_id = definition.chain_id,
                    .genesis_hash = definition.genesis_hash,
                })));
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(peer);
    }};

    authenticate(*first, 201);
    BOOST_REQUIRE(first->fSuccessfullyConnected);
    BOOST_CHECK(!first->fDisconnect);
    BOOST_CHECK_EQUAL(events.HandshakenPeerCount(), 1U);

    events.InitializeNode(*second, NODE_NONE);
    BOOST_CHECK(!second->fSuccessfullyConnected);
    BOOST_CHECK(second->fDisconnect);
    BOOST_CHECK_EQUAL(events.PeerCount(), 1U);
    BOOST_CHECK_EQUAL(events.HandshakenPeerCount(), 1U);
    BOOST_CHECK_EQUAL(events.InboundNetgroupRejections(), 1U);

    events.FinalizeNode(*first);
    BOOST_CHECK_EQUAL(events.HandshakenPeerCount(), 0U);
    authenticate(*replacement, 221);
    BOOST_CHECK(replacement->fSuccessfullyConnected);
    BOOST_CHECK(!replacement->fDisconnect);
    BOOST_CHECK_EQUAL(events.HandshakenPeerCount(), 1U);

    events.FinalizeNode(*second);
    events.FinalizeNode(*replacement);
    BOOST_CHECK_EQUAL(events.PeerCount(), 0U);
}

BOOST_AUTO_TEST_CASE(relays_bounded_addresses_only_after_handshake)
{
    const auto definition{Definition()};
    node::ChainManager manager{
        Params().GetConsensus(),
        Params().GenesisBlock(),
        m_args.GetDataDirBase() / "child_net_address_relay",
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
        connman,
        addrman,
        manager,
        bandwidth,
        definition,
        /*discovery=*/true,
        /*max_known_addresses=*/1};
    connman.SetMsgProc(&events);

    CNode outbound{
        /*id=*/9,
        /*sock=*/nullptr,
        CAddress{LookupNumeric("8.8.8.8", 19846), NODE_NETWORK},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/91,
        CService{},
        /*addrNameIn=*/"8.8.8.8:19846",
        ConnectionType::OUTBOUND_FULL_RELAY,
        /*inbound_onion=*/false,
        /*network_key=*/0};
    events.InitializeNode(outbound, NODE_NONE);
    connman.FlushSendBuffer(outbound);

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        outbound,
        NetMsg::Make(
            std::string{chainregistry::ChildNetMsgType::HELLO},
            chainregistry::ChildNetHello{
                .nonce = 92,
                .chain_id = definition.chain_id,
                .genesis_hash = definition.genesis_hash,
            })));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(outbound);
    }
    BOOST_REQUIRE(outbound.fSuccessfullyConnected);
    // Receiving the response below proves that this outbound peer entered the
    // requested state. CConnman may optimistically move the request from
    // vSendMsg into the encrypted transport before the test can inspect it.
    connman.FlushSendBuffer(outbound);

    const chainregistry::ChildAddresses learned{
        .chain_id = definition.chain_id,
        .addresses = {{
            .time = 1'700'000'000,
            .endpoint = LookupNumeric("9.9.9.9", 19846),
        }, {
            .time = 1'700'000'000,
            .endpoint = LookupNumeric("1.1.1.1", 19846),
        }},
    };
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        outbound,
        NetMsg::Make(
            std::string{chainregistry::ChildNetMsgType::ADDRESSES},
            learned)));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(outbound);
    }
    BOOST_CHECK(!outbound.fDisconnect);
    BOOST_CHECK_EQUAL(events.KnownAddressCount(), 1U);
    BOOST_CHECK(addrman.FindAddressEntry(CAddress{
        LookupNumeric("9.9.9.9", 19846), NODE_NETWORK}));

    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        outbound,
        NetMsg::Make(
            std::string{chainregistry::ChildNetMsgType::ADDRESSES},
            learned)));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(outbound);
    }
    BOOST_CHECK(outbound.fDisconnect);
    events.FinalizeNode(outbound);

    CNode inbound{
        /*id=*/10,
        /*sock=*/nullptr,
        CAddress{LookupNumeric("8.8.4.4", 19846), NODE_NETWORK},
        /*nKeyedNetGroupIn=*/0,
        /*nLocalHostNonceIn=*/101,
        CService{},
        /*addrNameIn=*/"8.8.4.4:19846",
        ConnectionType::INBOUND,
        /*inbound_onion=*/false,
        /*network_key=*/0};
    events.InitializeNode(inbound, NODE_NONE);
    connman.FlushSendBuffer(inbound);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        inbound,
        NetMsg::Make(
            std::string{chainregistry::ChildNetMsgType::HELLO},
            chainregistry::ChildNetHello{
                .nonce = 102,
                .chain_id = definition.chain_id,
                .genesis_hash = definition.genesis_hash,
            })));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(inbound);
    }
    BOOST_CHECK(inbound.fSuccessfullyConnected);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        inbound,
        NetMsg::Make(
            std::string{chainregistry::ChildNetMsgType::GET_ADDRESSES},
            chainregistry::ChildAddressRequest{
                .chain_id = definition.chain_id,
            })));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(inbound);
    }
    BOOST_CHECK(!inbound.fDisconnect);
    // The one-shot served state is asserted by the repeated request below;
    // wire encoding and bounds are covered independently in child_net_tests.
    connman.FlushSendBuffer(inbound);
    BOOST_REQUIRE(connman.ReceiveMsgFrom(
        inbound,
        NetMsg::Make(
            std::string{chainregistry::ChildNetMsgType::GET_ADDRESSES},
            chainregistry::ChildAddressRequest{
                .chain_id = definition.chain_id,
            })));
    {
        LOCK(NetEventsInterface::g_msgproc_mutex);
        connman.ProcessMessagesOnce(inbound);
    }
    BOOST_CHECK(inbound.fDisconnect);
    events.FinalizeNode(inbound);
}

BOOST_AUTO_TEST_SUITE_END()
