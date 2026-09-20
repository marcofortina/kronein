// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/chainregistry.h>
#include <consensus/merkle.h>
#include <key.h>
#include <node/miner.h>
#include <primitives/chainregistry.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <vector>

namespace {

chainregistry::ChainManifest TestManifest()
{
    chainregistry::ChainSpec spec;
    spec.template_id = 1;
    spec.template_version = 1;
    spec.consensus_parameters = {0x01, 0x02};
    return {
        .spec = std::move(spec),
        .child_genesis_hash = uint256{"1111111111111111111111111111111111111111111111111111111111111111"},
        .initial_metadata_hash = chainregistry::MetadataHash{"2222222222222222222222222222222222222222222222222222222222222222"},
    };
}

CScript TaprootScript(const CKey& key)
{
    return GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{key.GetPubKey()}});
}

struct RegistryMempoolSetup : public TestChain100Setup {
    RegistryMempoolSetup()
        : TestChain100Setup{ChainType::REGTEST, TestOpts{.extra_args = {
              "-chainregistryactivationheight=101",
              "-chainregistryminregistrationburn=1",
              "-chainregistrymaxoperations=4",
          }}}
    {
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(chainregistry_mempool_tests, RegistryMempoolSetup)

BOOST_AUTO_TEST_CASE(validate_unconfirmed_registry_transition_chain)
{
    CKey control_key;
    control_key.MakeNewKey(true);
    const chainregistry::ChainManifest manifest{TestManifest()};
    const chainregistry::RegisterChain registration{
        .anchor_input = 0,
        .control_output = 1,
        .manifest = manifest,
    };

    const COutPoint anchor{m_coinbase_txns[0]->GetHash(), 0};
    const std::vector<CTxOut> registration_outputs{
        {COIN, chainregistry::BuildOperationScript(registration)},
        {5 * COIN, TaprootScript(control_key)},
        {43 * COIN, TaprootScript(coinbaseKey)},
    };
    const CMutableTransaction registration_tx{CreateValidTransaction(
        {m_coinbase_txns[0]}, {anchor}, /*input_height=*/1, {coinbaseKey},
        registration_outputs, std::nullopt, std::nullopt).first};

    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(MakeTransactionRef(registration_tx))};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }

    const chainregistry::ChainId chain_id{chainregistry::DeriveChainId(
        Params().GetConsensus().hashGenesisBlock,
        anchor,
        chainregistry::ComputeChainSpecHash(manifest.spec))};

    const std::vector<unsigned char> malformed_data{'K', 'R', 'E', 'G', 1};
    const CMutableTransaction malformed_tx{CreateValidTransaction(
        {MakeTransactionRef(registration_tx)},
        {COutPoint{registration_tx.GetHash(), 1}},
        /*input_height=*/101,
        {control_key},
        {{0, CScript{} << OP_RETURN << malformed_data},
         {4 * COIN, TaprootScript(control_key)}},
        std::nullopt,
        std::nullopt).first};
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(
            MakeTransactionRef(malformed_tx), /*test_accept=*/true)};
        BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-chain-registry");
    }

    const CMutableTransaction silent_control_spend{CreateValidTransaction(
        {MakeTransactionRef(registration_tx)},
        {COutPoint{registration_tx.GetHash(), 1}},
        /*input_height=*/101,
        {control_key},
        {{4 * COIN, TaprootScript(control_key)}},
        std::nullopt,
        std::nullopt).first};
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(
            MakeTransactionRef(silent_control_spend), /*test_accept=*/true)};
        BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-chain-registry");
    }

    CKey next_control_key;
    next_control_key.MakeNewKey(true);
    const chainregistry::MetadataHash next_metadata{
        "3333333333333333333333333333333333333333333333333333333333333333"};
    const CMutableTransaction update_tx{CreateValidTransaction(
        {MakeTransactionRef(registration_tx)},
        {COutPoint{registration_tx.GetHash(), 1}},
        /*input_height=*/101,
        {control_key},
        {{0, chainregistry::BuildOperationScript(chainregistry::UpdateChain{
                 .chain_id = chain_id,
                 .control_output = 1,
                 .metadata_hash = next_metadata,
             })},
         {4 * COIN, TaprootScript(next_control_key)}},
        std::nullopt,
        std::nullopt).first};
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(MakeTransactionRef(update_tx))};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 2U);

    node::BlockAssembler::Options options;
    options.coinbase_output_script = TaprootScript(coinbaseKey);
    options.include_dummy_extranonce = true;
    auto block{std::make_shared<CBlock>(node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock()->block)};
    const auto commitment{chainregistry::ExtractRegistryCommitment(*block->vtx[0])};
    BOOST_REQUIRE(commitment.IsValid());
    BOOST_REQUIRE(commitment.root.has_value());

    chainregistry::ChainRegistry expected;
    BOOST_REQUIRE(expected.ApplyTransaction(
        CTransaction{registration_tx}, 101, Params().GetConsensus().hashGenesisBlock, COIN).IsValid());
    BOOST_REQUIRE(expected.ApplyTransaction(
        CTransaction{update_tx}, 101, Params().GetConsensus().hashGenesisBlock, COIN).IsValid());
    BOOST_CHECK(*commitment.root == expected.ComputeRoot());

    block->hashMerkleRoot = BlockMerkleRoot(*block);
    BOOST_CHECK(!MineBlock(m_node, block).IsNull());
    LOCK(cs_main);
    const auto* record{m_node.chainman->ActiveChainstate().ChainRegistryState().Registry().Find(chain_id)};
    BOOST_REQUIRE(record);
    BOOST_CHECK(record->metadata_hash == next_metadata);
    BOOST_CHECK(record->control_outpoint == COutPoint(update_tx.GetHash(), 1));
}

BOOST_AUTO_TEST_SUITE_END()
