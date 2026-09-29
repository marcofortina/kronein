// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/chainregistry.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <node/miner.h>
#include <script/solver.h>
#include <test/util/mining.h>
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

    {
        LOCK(cs_main);
        const BlockValidationState state{TestBlockValidity(m_node.chainman->ActiveChainstate(), block, /*check_pow=*/false, /*check_merkle_root=*/false)};
        BOOST_CHECK(state.IsValid());
    }
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

namespace {

struct RegistryMinerSetup : public TestingSetup {
    RegistryMinerSetup()
        : TestingSetup{ChainType::REGTEST, TestOpts{.extra_args = {
              "-chainregistryactivationheight=1",
              "-chaindealerauthoritykey=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
              "-chainregistrymaxoperations=4",
          }}}
    {
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(miner_tests_chainregistry, RegistryMinerSetup)

BOOST_AUTO_TEST_CASE(create_active_registry_commitment)
{
    CKey key;
    key.MakeNewKey(true);
    BlockAssembler::Options options;
    options.coinbase_output_script = GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{key.GetPubKey()}});
    options.include_dummy_extranonce = true;

    auto block_template{BlockAssembler{
        m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock()};
    BOOST_REQUIRE(block_template);
    CBlock& block{block_template->block};

    const auto commitment{chainregistry::ExtractRegistryCommitment(*block.vtx[0])};
    BOOST_REQUIRE(commitment.IsValid());
    BOOST_REQUIRE(commitment.root.has_value());
    {
        LOCK(cs_main);
        BOOST_CHECK(*commitment.root ==
                    m_node.chainman->ActiveChainstate().ChainRegistryState().Registry().ComputeRoot());
    }
    BOOST_CHECK_EQUAL(block_template->m_coinbase_tx.required_outputs.size(), 2U);

    {
        LOCK(cs_main);
        const BlockValidationState valid{TestBlockValidity(
            m_node.chainman->ActiveChainstate(), block, /*check_pow=*/false, /*check_merkle_root=*/false)};
        BOOST_CHECK(valid.IsValid());
    }

    CBlock missing{block};
    CMutableTransaction coinbase{*missing.vtx[0]};
    coinbase.vout.erase(coinbase.vout.begin() + *commitment.output_index);
    missing.vtx[0] = MakeTransactionRef(std::move(coinbase));
    {
        LOCK(cs_main);
        const BlockValidationState invalid{TestBlockValidity(
            m_node.chainman->ActiveChainstate(), missing, /*check_pow=*/false, /*check_merkle_root=*/false)};
        BOOST_CHECK(invalid.IsInvalid());
        BOOST_CHECK_EQUAL(invalid.GetRejectReason(), "bad-chain-registry");
    }

    auto processed{std::make_shared<CBlock>(block)};
    processed->hashMerkleRoot = BlockMerkleRoot(*processed);
    BOOST_CHECK(!MineBlock(m_node, processed).IsNull());
    LOCK(cs_main);
    BOOST_CHECK_EQUAL(m_node.chainman->ActiveHeight(), 1);
    BOOST_CHECK(m_node.chainman->ActiveChainstate().ChainRegistryState().State().best_block ==
                processed->GetHash());
}

BOOST_AUTO_TEST_SUITE_END()
