// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/bmm.h>
#include <consensus/chainregistry.h>
#include <consensus/merkle.h>
#include <key.h>
#include <node/miner.h>
#include <primitives/chainregistry.h>
#include <primitives/deposit.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
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
        .default_fee_recipient = {
            .recipient_type = 1,
            .recipient = std::vector<unsigned char>(32, 2),
        },
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
              "-chaindealerauthoritykey=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
              "-chainregistrymaxoperations=4",
              "-chaindepositactivationheight=101",
              "-chaindepositminimumamount=0.01",
              "-chaindepositmaxperblock=2",
              "-chainbmmactivationheight=101",
              "-chainbmmmaxanchorsperblock=1",
          }}}
    {
    }

    struct AuthorizedDealer {
        CTransactionRef transaction;
        chainregistry::DealerId dealer_id;
        COutPoint control_outpoint;
        CScript payout_script;
    };

    AuthorizedDealer AuthorizeDealer()
    {
        std::array<unsigned char, 32> secret{};
        secret.back() = 1;
        CKey authority_key;
        authority_key.Set(secret.begin(), secret.end(), true);

        const XOnlyPubKey dealer_control_key{coinbaseKey.GetPubKey()};
        const CScript payout_script{TaprootScript(coinbaseKey)};
        chainregistry::AuthorizeDealer authorization{
            .authority_sequence = 1,
            .authorization_nonce = uint256{
                "1111111111111111111111111111111111111111111111111111111111111111"},
            .control_output = 1,
            .payout_script = std::vector<unsigned char>{
                payout_script.begin(), payout_script.end()},
            .initial_licenses = 1,
        };
        std::copy(dealer_control_key.begin(), dealer_control_key.end(),
                  authorization.control_key.begin());
        const auto authority_hash{chainregistry::ComputeDealerAuthorityHash(
            Params().GetConsensus().hashGenesisBlock, authorization)};
        BOOST_REQUIRE(authority_hash.has_value());
        BOOST_REQUIRE(authority_key.SignSchnorr(
            *authority_hash, authorization.authority_signature, nullptr, uint256{}));

        const COutPoint funding{m_coinbase_txns[0]->GetHash(), 0};
        const CMutableTransaction transaction{CreateValidTransaction(
            {m_coinbase_txns[0]},
            {funding},
            /*input_height=*/1,
            {coinbaseKey},
            {
                {0, chainregistry::BuildOperationScript(authorization)},
                {COIN, TaprootScript(coinbaseKey)},
                {48 * COIN, TaprootScript(coinbaseKey)},
            },
            std::nullopt,
            std::nullopt).first};
        const CTransactionRef transaction_ref{MakeTransactionRef(transaction)};
        {
            LOCK(cs_main);
            const auto result{m_node.chainman->ProcessTransaction(transaction_ref)};
            BOOST_REQUIRE_MESSAGE(
                result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                result.m_state.ToString());
        }
        return {
            .transaction = transaction_ref,
            .dealer_id = chainregistry::DeriveDealerId(
                Params().GetConsensus().hashGenesisBlock,
                authorization.authorization_nonce,
                authorization.control_key),
            .control_outpoint = COutPoint{transaction.GetHash(), 1},
            .payout_script = payout_script,
        };
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(chainregistry_mempool_tests, RegistryMempoolSetup)

BOOST_AUTO_TEST_CASE(validate_unconfirmed_registry_transition_chain)
{
    const auto dealer{AuthorizeDealer()};
    CKey control_key;
    control_key.MakeNewKey(true);
    const chainregistry::ChainManifest manifest{TestManifest()};
    const chainregistry::RegisterChain registration{
        .anchor_input = 0,
        .control_output = 1,
        .dealer_id = dealer.dealer_id,
        .dealer_control_output = 2,
        .dealer_payment_output = 3,
        .manifest = manifest,
    };

    const COutPoint anchor{dealer.transaction->GetHash(), 2};
    const std::vector<CTxOut> registration_outputs{
        {0, chainregistry::BuildOperationScript(registration)},
        {5 * COIN, TaprootScript(control_key)},
        {COIN, TaprootScript(coinbaseKey)},
        {COIN, dealer.payout_script},
        {41 * COIN, TaprootScript(coinbaseKey)},
    };
    const CMutableTransaction registration_tx{CreateValidTransaction(
        {dealer.transaction}, {anchor, dealer.control_outpoint},
        /*input_height=*/101, {coinbaseKey, coinbaseKey},
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
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 3U);

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
        *dealer.transaction, 101, Params().GetConsensus().hashGenesisBlock,
        XOnlyPubKey{Params().GetConsensus().chain_registry.dealer_authority_key}).IsValid());
    BOOST_REQUIRE(expected.ApplyTransaction(
        CTransaction{registration_tx}, 101, Params().GetConsensus().hashGenesisBlock,
        XOnlyPubKey{Params().GetConsensus().chain_registry.dealer_authority_key}).IsValid());
    BOOST_REQUIRE(expected.ApplyTransaction(
        CTransaction{update_tx}, 101, Params().GetConsensus().hashGenesisBlock,
        XOnlyPubKey{Params().GetConsensus().chain_registry.dealer_authority_key}).IsValid());
    BOOST_CHECK(*commitment.root == expected.ComputeRoot());

    block->hashMerkleRoot = BlockMerkleRoot(*block);
    BOOST_CHECK(!MineBlock(m_node, block).IsNull());
    LOCK(cs_main);
    const auto* record{m_node.chainman->ActiveChainstate().ChainRegistryState().Registry().Find(chain_id)};
    BOOST_REQUIRE(record);
    BOOST_CHECK(record->metadata_hash == next_metadata);
    BOOST_CHECK(record->control_outpoint == COutPoint(update_tx.GetHash(), 1));
}

BOOST_AUTO_TEST_CASE(validate_deposit_against_unconfirmed_registration)
{
    const auto dealer{AuthorizeDealer()};
    CKey control_key;
    control_key.MakeNewKey(true);
    const chainregistry::ChainManifest manifest{TestManifest()};
    const COutPoint anchor{dealer.transaction->GetHash(), 2};
    const CMutableTransaction registration_tx{CreateValidTransaction(
        {dealer.transaction},
        {anchor, dealer.control_outpoint},
        /*input_height=*/101,
        {coinbaseKey, coinbaseKey},
        {
            {0, chainregistry::BuildOperationScript(chainregistry::RegisterChain{
                       .anchor_input = 0,
                       .control_output = 1,
                       .dealer_id = dealer.dealer_id,
                       .dealer_control_output = 2,
                       .dealer_payment_output = 3,
                       .manifest = manifest,
                   })},
            {5 * COIN, TaprootScript(control_key)},
            {COIN, TaprootScript(coinbaseKey)},
            {COIN, dealer.payout_script},
            {41 * COIN, TaprootScript(coinbaseKey)},
        },
        std::nullopt,
        std::nullopt).first};
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(MakeTransactionRef(registration_tx))};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }

    const chainregistry::ChainId chain_id{chainregistry::DeriveChainId(
        Params().GetConsensus().hashGenesisBlock,
        anchor,
        chainregistry::ComputeChainSpecHash(manifest.spec))};
    const chainregistry::FundChain fund{
        .chain_id = chain_id,
        .recipient_type = 1,
        .recipient = std::vector<unsigned char>(32, 0x42),
    };
    const CMutableTransaction fund_tx{CreateValidTransaction(
        {MakeTransactionRef(registration_tx)},
        {COutPoint{registration_tx.GetHash(), 4}},
        /*input_height=*/101,
        {coinbaseKey},
        {
            {COIN / 100, chainregistry::BuildFundScript(fund)},
            {40 * COIN, TaprootScript(coinbaseKey)},
        },
        std::nullopt,
        std::nullopt).first};
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(MakeTransactionRef(fund_tx))};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }

    auto unknown_fund{fund};
    unknown_fund.chain_id = chainregistry::ChainId{
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    const CMutableTransaction unknown_tx{CreateValidTransaction(
        {MakeTransactionRef(fund_tx)},
        {COutPoint{fund_tx.GetHash(), 1}},
        /*input_height=*/101,
        {coinbaseKey},
        {
            {COIN, chainregistry::BuildFundScript(unknown_fund)},
            {38 * COIN, TaprootScript(coinbaseKey)},
        },
        std::nullopt,
        std::nullopt).first};
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(
            MakeTransactionRef(unknown_tx), /*test_accept=*/true)};
        BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-chain-deposit");
    }

    node::BlockAssembler::Options options;
    options.coinbase_output_script = TaprootScript(coinbaseKey);
    options.include_dummy_extranonce = true;
    auto block{std::make_shared<CBlock>(node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock()->block)};
    block->hashMerkleRoot = BlockMerkleRoot(*block);
    BOOST_CHECK(!MineBlock(m_node, block).IsNull());

    LOCK(cs_main);
    const auto* record{m_node.chainman->ActiveChainstate().ChainRegistryState().Registry().Find(chain_id)};
    BOOST_REQUIRE(record);
    BOOST_CHECK(record->status == chainregistry::ChainStatus::ACTIVE);
}

BOOST_AUTO_TEST_CASE(validate_and_select_competing_bmm_proposals)
{
    const auto dealer{AuthorizeDealer()};
    CKey control_key;
    control_key.MakeNewKey(true);
    const chainregistry::ChainManifest manifest{TestManifest()};
    const COutPoint registration_anchor{dealer.transaction->GetHash(), 2};
    const CMutableTransaction registration_tx{CreateValidTransaction(
        {dealer.transaction},
        {registration_anchor, dealer.control_outpoint},
        /*input_height=*/101,
        {coinbaseKey, coinbaseKey},
        {
            {0, chainregistry::BuildOperationScript(chainregistry::RegisterChain{
                       .anchor_input = 0,
                       .control_output = 1,
                       .dealer_id = dealer.dealer_id,
                       .dealer_control_output = 2,
                       .dealer_payment_output = 3,
                       .manifest = manifest,
                   })},
            {5 * COIN, TaprootScript(control_key)},
            {COIN, TaprootScript(coinbaseKey)},
            {COIN, dealer.payout_script},
            {8 * COIN, TaprootScript(coinbaseKey)},
            {8 * COIN, TaprootScript(coinbaseKey)},
            {8 * COIN, TaprootScript(coinbaseKey)},
            {8 * COIN, TaprootScript(coinbaseKey)},
        },
        std::nullopt,
        std::nullopt).first};
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(
            MakeTransactionRef(registration_tx))};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }

    node::BlockAssembler::Options options;
    options.coinbase_output_script = TaprootScript(coinbaseKey);
    options.include_dummy_extranonce = true;
    auto registration_block{std::make_shared<CBlock>(node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock()->block)};
    registration_block->hashMerkleRoot = BlockMerkleRoot(*registration_block);
    BOOST_CHECK(!MineBlock(m_node, registration_block).IsNull());

    const chainregistry::ChainId chain_id{chainregistry::DeriveChainId(
        Params().GetConsensus().hashGenesisBlock,
        registration_anchor,
        chainregistry::ComputeChainSpecHash(manifest.spec))};
    const auto proposal = [&](uint32_t output_index,
                              CAmount change,
                              const chainregistry::ChainId& proposed_chain,
                              const uint256& child_hash) {
        return CreateValidTransaction(
            {MakeTransactionRef(registration_tx)},
            {COutPoint{registration_tx.GetHash(), output_index}},
            /*input_height=*/101,
            {coinbaseKey},
            {
                {0, chainregistry::BuildBmmAnchorScript({
                        .chain_id = proposed_chain,
                        .child_block_hash = child_hash,
                    })},
                {change, TaprootScript(coinbaseKey)},
            },
            std::nullopt,
            std::nullopt).first;
    };

    constexpr uint256 child_one{
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    constexpr uint256 child_two{
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
    const CMutableTransaction proposal_one{
        proposal(4, 7 * COIN, chain_id, child_one)};
    const CMutableTransaction proposal_two{
        proposal(5, 6 * COIN, chain_id, child_two)};
    {
        LOCK(cs_main);
        const auto first{m_node.chainman->ProcessTransaction(
            MakeTransactionRef(proposal_one))};
        const auto second{m_node.chainman->ProcessTransaction(
            MakeTransactionRef(proposal_two))};
        BOOST_REQUIRE(first.m_result_type == MempoolAcceptResult::ResultType::VALID);
        BOOST_REQUIRE(second.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }

    constexpr chainregistry::ChainId unknown_chain{
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    const CMutableTransaction unknown_proposal{
        proposal(6, 7 * COIN, unknown_chain, child_one)};
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(
            MakeTransactionRef(unknown_proposal), /*test_accept=*/true)};
        BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-chain-bmm");
    }

    const std::vector<unsigned char> malformed_data{'K', 'B', 'M', 'M', 1};
    const CMutableTransaction malformed_proposal{CreateValidTransaction(
        {MakeTransactionRef(registration_tx)},
        {COutPoint{registration_tx.GetHash(), 7}},
        /*input_height=*/101,
        {coinbaseKey},
        {
            {0, CScript{} << OP_RETURN << malformed_data},
            {7 * COIN, TaprootScript(coinbaseKey)},
        },
        std::nullopt,
        std::nullopt).first};
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(
            MakeTransactionRef(malformed_proposal), /*test_accept=*/true)};
        BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "bad-chain-bmm");
    }

    auto anchor_block{std::make_shared<CBlock>(node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock()->block)};
    {
        LOCK(cs_main);
        const auto anchors{chainregistry::ValidateBlockBmmAnchors(
            *anchor_block,
            m_node.chainman->ActiveChainstate().ChainRegistryState().Registry(),
            1)};
        BOOST_REQUIRE(anchors.IsValid());
        BOOST_REQUIRE_EQUAL(anchors.anchors.size(), 1U);
        BOOST_CHECK(anchors.anchors.front().anchor.chain_id == chain_id);
        BOOST_CHECK(anchors.anchors.front().anchor.child_block_hash == child_two);
    }

    anchor_block->hashMerkleRoot = BlockMerkleRoot(*anchor_block);
    BOOST_REQUIRE(!MineBlock(m_node, anchor_block).IsNull());
    const uint256 anchor_block_hash{anchor_block->GetHash()};
    {
        LOCK(cs_main);
        const auto indexed{m_node.chainman->ActiveChainstate().ChainRegistryState().FindAnchor({
            .chain_id = chain_id,
            .main_block_hash = anchor_block_hash,
        })};
        BOOST_REQUIRE(indexed.has_value());
        BOOST_CHECK(indexed->anchor.child_block_hash == child_two);
    }

    const CMutableTransaction retirement{CreateValidTransaction(
        {MakeTransactionRef(registration_tx)},
        {COutPoint{registration_tx.GetHash(), 1}},
        /*input_height=*/101,
        {control_key},
        {{0, chainregistry::BuildOperationScript(chainregistry::RetireChain{
                 .chain_id = chain_id,
             })}},
        std::nullopt,
        std::nullopt).first};
    {
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(
            MakeTransactionRef(retirement))};
        BOOST_REQUIRE(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }

    auto retirement_block{std::make_shared<CBlock>(node::BlockAssembler{
        m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock()->block)};
    BOOST_CHECK(std::ranges::any_of(
        retirement_block->vtx,
        [&retirement](const CTransactionRef& tx) {
            return tx->GetHash() == retirement.GetHash();
        }));
    {
        LOCK(cs_main);
        const auto retirement_anchors{chainregistry::ValidateBlockBmmAnchors(
            *retirement_block,
            m_node.chainman->ActiveChainstate().ChainRegistryState().Registry(),
            1)};
        BOOST_REQUIRE(retirement_anchors.IsValid());
        BOOST_CHECK(retirement_anchors.anchors.empty());
    }

    retirement_block->hashMerkleRoot = BlockMerkleRoot(*retirement_block);
    BOOST_REQUIRE(!MineBlock(m_node, retirement_block).IsNull());
    {
        LOCK(cs_main);
        const auto* retired{m_node.chainman->ActiveChainstate().ChainRegistryState().Registry().Find(chain_id)};
        BOOST_REQUIRE(retired);
        BOOST_CHECK(retired->status == chainregistry::ChainStatus::RETIRED);
    }
}

BOOST_AUTO_TEST_SUITE_END()
