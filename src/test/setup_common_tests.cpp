// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <core_io.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <sync.h>
#include <test/data/regtest_chain100.json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string_view>

using namespace std::chrono_literals;

BOOST_AUTO_TEST_SUITE(setup_common_tests)

BOOST_AUTO_TEST_CASE(premined_profiles)
{
    UniValue data;
    BOOST_REQUIRE(data.read(json_tests::regtest_chain100));
    for (const bool registry_active : {true, false}) {
        TestOpts opts;
        opts.setup_net = false;
        if (!registry_active) {
            opts.extra_args = {
                "-chainregistryactivationheight=101",
                "-chaindealerauthoritykey=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "-chainregistrymaxoperations=4",
            };
        }
        TestChain100Setup setup{ChainType::REGTEST, opts};
        auto& chainman{*Assert(setup.m_node.chainman)};
        const auto& profile{data[registry_active ? "registry_active" : "registry_inactive"]};
        BOOST_REQUIRE_EQUAL(setup.m_coinbase_txns.size(), COINBASE_MATURITY);
        BOOST_CHECK(Now<NodeSeconds>() == Params().GenesisBlock().Time() + (COINBASE_MATURITY + 1) * 1s);
        {
            LOCK(cs_main);
            BOOST_REQUIRE_EQUAL(chainman.ActiveHeight(), COINBASE_MATURITY);
            BOOST_CHECK_EQUAL(chainman.ActiveChain().Tip()->GetBlockHash().GetHex(), profile["tip_hash"].get_str());
            for (int height{1}; height <= COINBASE_MATURITY; ++height) {
                const auto& tx{setup.m_coinbase_txns[height - 1]};
                const auto& coin{chainman.ActiveChainstate().CoinsTip().AccessCoin(COutPoint{tx->GetHash(), 0})};
                BOOST_REQUIRE(!coin.IsSpent());
                BOOST_CHECK(coin.IsCoinBase());
                BOOST_CHECK_EQUAL(coin.nHeight, height);
                BOOST_CHECK(coin.out == tx->vout[0]);
                CBlock block;
                BOOST_REQUIRE(chainman.m_blockman.ReadBlock(block, *chainman.ActiveChain()[height]));
                DataStream stream;
                stream << TX_WITH_WITNESS(block);
                BOOST_CHECK_EQUAL(HexStr(stream), profile["blocks"][height - 1].get_str());
            }
        }
        // Only the common setup is premined; subsequent blocks still use mining.
        setup.mineBlocks(1);
        BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveHeight()), COINBASE_MATURITY + 1);
    }
}

BOOST_FIXTURE_TEST_CASE(premined_blocks_require_validation, RegTestingSetup)
{
    UniValue data;
    BOOST_REQUIRE(data.read(json_tests::regtest_chain100));
    const auto& hex{data["registry_active"]["blocks"][0].get_str()};
    auto block{std::make_shared<CBlock>()};
    BOOST_REQUIRE(DecodeHexBlk(*block, hex));
    const auto& consensus{Params().GetConsensus()};
    BOOST_REQUIRE(CheckProofOfWorkImpl(*block, consensus.randomx.bootstrap_key, consensus));

    // A genuine block with an invalid nonce must fail through the exact loader path.
    do {
        ++block->nNonce;
    } while (CheckProofOfWorkImpl(*block, consensus.randomx.bootstrap_key, consensus));
    auto& chainman{*Assert(m_node.chainman)};
    BOOST_CHECK(!chainman.ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveHeight()), 0);

    // The authentic header does not allow tampered transactions to pass either.
    block = std::make_shared<CBlock>();
    BOOST_REQUIRE(DecodeHexBlk(*block, hex));
    CMutableTransaction coinbase{*block->vtx[0]};
    ++coinbase.vout[0].nValue;
    block->vtx[0] = MakeTransactionRef(coinbase);
    BOOST_CHECK(!chainman.ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveHeight()), 0);

    // Decode again: do not reuse any cached validation state from earlier checks.
    block = std::make_shared<CBlock>();
    BOOST_REQUIRE(DecodeHexBlk(*block, hex));
    BOOST_REQUIRE(chainman.ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    BOOST_CHECK_EQUAL(WITH_LOCK(cs_main, return chainman.ActiveHeight()), 1);
}

BOOST_AUTO_TEST_CASE(premined_profiles_reject_unsupported_activation)
{
    TestOpts opts;
    opts.setup_net = false;
    opts.extra_args = {
        "-chainregistryactivationheight=50",
        "-chaindealerauthoritykey=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "-chainregistrymaxoperations=4",
    };
    BOOST_CHECK_EXCEPTION((TestChain100Setup{ChainType::REGTEST, opts}), std::runtime_error,
                         [](const std::runtime_error& error) {
                             return std::string_view{error.what()}.find("registry activation within the first 100 blocks") != std::string_view::npos;
                         });
}

BOOST_AUTO_TEST_SUITE_END()
