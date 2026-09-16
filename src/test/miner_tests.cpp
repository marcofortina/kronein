// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/tx_check.h>
#include <node/miner.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

using node::BlockAssembler;

BOOST_FIXTURE_TEST_SUITE(miner_tests, TestChain100Setup)

static CScript NativeMiningScript(const CKey& key)
{
    return GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{key.GetPubKey()}});
}

BOOST_AUTO_TEST_CASE(create_native_block_template)
{
    BlockAssembler::Options options;
    options.coinbase_output_script = NativeMiningScript(coinbaseKey);
    options.include_dummy_extranonce = true;

    const auto block_template{BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock()};
    BOOST_REQUIRE(block_template);
    const CBlock& block{block_template->block};

    BOOST_REQUIRE_EQUAL(block.nVersion, CBlockHeader::CURRENT_VERSION);
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 1U);
    BOOST_REQUIRE(block.vtx[0]->IsCoinBase());
    BOOST_REQUIRE(IsNativeOutputScript(block.vtx[0]->vout[0].scriptPubKey));
    BOOST_REQUIRE(block.vtx[0]->HasWitness());

    const BlockValidationState state{TestBlockValidity(m_node.chainman->ActiveChainstate(), block, /*check_pow=*/false, /*check_merkle_root=*/false)};
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(reject_non_native_coinbase_output)
{
    BlockAssembler::Options options;
    options.coinbase_output_script = CScript{} << OP_TRUE;
    options.include_dummy_extranonce = true;

    BOOST_CHECK_THROW(
        BlockAssembler(m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options).CreateNewBlock(),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(select_native_parent_child_package)
{
    const CScript output_script{NativeMiningScript(coinbaseKey)};
    constexpr CAmount parent_value{50 * COIN - 1'000};
    constexpr CAmount child_value{parent_value - 50'000};

    const CMutableTransaction parent{CreateValidMempoolTransaction(
        m_coinbase_txns[0], 0, /*input_height=*/1, coinbaseKey, output_script, parent_value)};
    const CMutableTransaction child{CreateValidMempoolTransaction(
        MakeTransactionRef(parent), 0, /*input_height=*/101, coinbaseKey, output_script, child_value)};

    BlockAssembler::Options options;
    options.coinbase_output_script = output_script;
    options.include_dummy_extranonce = true;
    const auto block_template{BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock()};
    BOOST_REQUIRE(block_template);

    const CBlock& block{block_template->block};
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 3U);
    BOOST_CHECK(block.vtx[1]->GetHash() == parent.GetHash());
    BOOST_CHECK(block.vtx[2]->GetHash() == child.GetHash());
}

BOOST_AUTO_TEST_SUITE_END()
