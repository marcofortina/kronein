// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init.h>
#include <interfaces/init.h>
#include <kernel/mempool_entry.h>
#include <policy/fees/block_policy_estimator_args.h>
#include <rpc/server.h>
#include <scheduler.h>
#include <streams.h>
#include <util/fs.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>
#include <test/util/common.h>
#include <test/util/setup_common.h>

using node::NodeContext;

//! Like BasicTestingSetup, but using regtest network instead of mainnet.
struct InitTestSetup : BasicTestingSetup {
    InitTestSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};

BOOST_FIXTURE_TEST_SUITE(node_init_tests, InitTestSetup)

//! Custom implementation of interfaces::Init for testing.
class TestInit : public interfaces::Init
{
public:
    TestInit(NodeContext& node) : m_node(node)
    {
        InitContext(m_node);
        m_node.init = this;
    }
    std::unique_ptr<interfaces::Chain> makeChain() override { return interfaces::MakeChain(m_node); }
    std::unique_ptr<interfaces::WalletLoader> makeWalletLoader(interfaces::Chain& chain) override
    {
        return MakeWalletLoader(chain, *Assert(m_node.args));
    }
    NodeContext& m_node;
};

BOOST_AUTO_TEST_CASE(init_test)
{
    // Clear state set by BasicTestingSetup that AppInitMain assumes is unset.
    LogInstance().DisconnectTestLogger();
    m_node.args->SetConfigFilePath({});

    // Prevent the test from trying to listen on ports 8332 and 8333.
    m_node.args->ForceSetArg("-server", "0");
    m_node.args->ForceSetArg("-listen", "0");

    // Run through initialization and shutdown code.
    TestInit init{m_node};
    BOOST_CHECK(AppInitInterfaces(m_node));
    BOOST_CHECK(AppInitMain(m_node));
    BOOST_REQUIRE(m_node.child_chainman);
    BOOST_REQUIRE(m_node.child_chain_notifications);
    Interrupt(m_node);
    // Leave a block update queued after the scheduler stops, as at shutdown.
    m_node.scheduler->stop();
    constexpr unsigned int queued_height{123};
    m_node.validation_signals->MempoolTransactionsRemovedForBlock({}, queued_height);
    BOOST_REQUIRE_GT(m_node.validation_signals->CallbacksPending(), 0);
    Shutdown(m_node);
    AutoFile estimates_file{fsbridge::fopen(FeeestPath(*m_node.args), "rb")};
    unsigned int best_seen_height;
    estimates_file >> best_seen_height;
    BOOST_CHECK_EQUAL(best_seen_height, queued_height);
    BOOST_CHECK(!m_node.child_chain_notifications);
    BOOST_CHECK(!m_node.child_chainman);
}

BOOST_AUTO_TEST_SUITE_END()
