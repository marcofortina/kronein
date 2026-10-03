// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockfilter.h>
#include <index/base.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <index/txindex.h>
#include <index/txospenderindex.h>
#include <interfaces/chain.h>
#include <node/context.h>
#include <primitives/block.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <util/byte_units.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

BOOST_AUTO_TEST_SUITE(baseindex_tests)

BOOST_FIXTURE_TEST_CASE(baseindex_no_commit_ahead_of_flush, TestChain100Setup)
{
    using Factory = std::function<std::unique_ptr<BaseIndex>()>;
    const std::vector<std::pair<std::string, Factory>> factories{
        {"coinstats", [&] { return std::make_unique<CoinStatsIndex>(interfaces::MakeChain(m_node), 1_MiB); }},
        {"tx", [&] { return std::make_unique<TxIndex>(interfaces::MakeChain(m_node), 1_MiB); }},
        {"txospender", [&] { return std::make_unique<TxoSpenderIndex>(interfaces::MakeChain(m_node), 1_MiB); }},
        {"blockfilter", [&] { return std::make_unique<BlockFilterIndex>(interfaces::MakeChain(m_node), BlockFilterType::BASIC, 1_MiB); }},
    };
    auto& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    for (const auto& [name, make_index] : factories) {
        BOOST_TEST_INFO_SCOPE(name);
        const int height = WITH_LOCK(cs_main, return chainstate.m_chain.Height());
        auto sync_index = [&](bool flush, int sync_height, int committed_height) {
            auto index = make_index();
            BOOST_REQUIRE(index->Init());
            index->Sync();
            if (flush) chainstate.ForceFlushStateToDisk();
            m_node.validation_signals->SyncWithValidationInterfaceQueue();
            BOOST_CHECK_EQUAL(index->GetSummary().best_block_height, sync_height);
            index->Stop();
            BOOST_REQUIRE(index->Init());
            BOOST_CHECK_EQUAL(index->GetSummary().best_block_height, committed_height);
            // Unregister only after queued callbacks finish using the object.
            m_node.validation_signals->SyncWithValidationInterfaceQueue();
            index->Stop();
        };

        // Catching up without a durable chainstate must not create a checkpoint.
        sync_index(false, height, 0);
        sync_index(true, height, height);
        CreateAndProcessBlock({}, m_coinbase_txns.front()->vout[0].scriptPubKey);
        // A later unflushed block must not move the persisted index checkpoint.
        sync_index(false, height + 1, height);
    }
}

BOOST_AUTO_TEST_SUITE_END()
