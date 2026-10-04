// Copyright (c) 2021-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <key.h>
#include <policy/fees/block_policy_estimator.h>
#include <script/solver.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

BOOST_FIXTURE_TEST_CASE(input_size_uses_matching_outpoint_weight, BasicTestingSetup)
{
    const CTxOut output{COIN, GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey::NUMS_H})};
    constexpr Txid txid{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    const COutPoint first{txid, 0};
    const COutPoint second{txid, 1};
    const COutPoint unknown{txid, 2};
    const FlatSigningProvider provider;
    CCoinControl control;
    control.SetInputWeight(first, 401);
    control.SetInputWeight(second, 800);
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(output, first, &provider, false, &control), 101);
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(output, second, &provider, false, &control), 200);
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(output, first, nullptr, false, &control), 101);
    const auto inferred{CalculateMaximumSignedInputSize(output, unknown, &provider, false, nullptr)};
    BOOST_REQUIRE_GT(inferred, 0);
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(output, unknown, &provider, false, &control), inferred);
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(output, unknown, nullptr, false, &control), -1);
}

static CScript TaprootScript(const CKey& key)
{
    TaprootBuilder builder;
    builder.Finalize(XOnlyPubKey{key.GetPubKey()});
    return GetScriptForDestination(builder.GetOutput());
}

static void FundTaprootWallet(TestChain100Setup& setup, int count)
{
    for (int i = 0; i < count; ++i) {
        const auto funding{setup.CreateValidMempoolTransaction(
            setup.m_coinbase_txns.at(i), 0, i + 1, setup.coinbaseKey,
            TaprootScript(setup.coinbaseKey), 50 * COIN, /*submit=*/false)};
        setup.CreateAndProcessBlock({funding}, GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{setup.coinbaseKey.GetPubKey()}}));
    }
}

BOOST_FIXTURE_TEST_CASE(SubtractFee, TestChain100Setup)
{
    FundTaprootWallet(*this, 1);
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    // Check that a subtract-from-recipient transaction slightly less than the
    // coinbase input amount does not create a change output (because it would
    // be uneconomical to add and spend the output), and make sure it pays the
    // leftover input amount which would have been change to the recipient
    // instead of the miner.
    auto check_tx = [&wallet](CAmount leftover_input_amount) {
        CRecipient recipient{WitnessV1Taproot{XOnlyPubKey::NUMS_H}, 50 * COIN - leftover_input_amount, /*subtract_fee=*/true};
        CCoinControl coin_control;
        coin_control.m_feerate.emplace(10000);
        coin_control.fOverrideFeeRate = true;
        auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
        BOOST_CHECK(res);
        const auto& txr = *res;
        BOOST_CHECK_EQUAL(txr.tx->vout.size(), 1);
        BOOST_CHECK_EQUAL(txr.tx->vout[0].nValue, recipient.nAmount + leftover_input_amount - txr.fee);
        BOOST_CHECK_GT(txr.fee, 0);
        return txr.fee;
    };

    // Send full input amount to recipient, check that only nonzero fee is
    // subtracted (to_reduce == fee).
    const CAmount fee{check_tx(0)};

    // Send slightly less than full input amount to recipient, check leftover
    // input amount is paid to recipient not the miner (to_reduce == fee - 123)
    BOOST_CHECK_EQUAL(fee, check_tx(123));

}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, TestChain100Setup)
{
    // Verify that the wallet's Coin Selection process does not include pre-selected inputs twice in a transaction.

    // Add 4 spendable Taproot UTXOs, 50 KNE each, to the wallet (total balance 200 KNE)
    FundTaprootWallet(*this, 4);
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    LOCK(wallet->cs_wallet);
    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();
    BOOST_REQUIRE_EQUAL(coins.size(), 4U);
    // Preselect the first 3 UTXO (150 KNE total)
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    // Try to create a tx that spends more than what preset inputs + wallet selected inputs are covering for.
    // The wallet can cover up to 200 KNE, and the tx target is 299 KNE.
    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination("dummy")),
                                           /*nAmount=*/299 * COIN, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    // Attempt to send 299 KNE from a wallet that only has 200 KNE. The wallet should exclude
    // the preset inputs from the pool of available coins, realize that there is not enough
    // money to fund the 299 KNE payment, and fail with "Insufficient funds".
    //
    // Even with SFFO, the wallet can only afford to send 200 KNE.
    // If the wallet does not properly exclude preset inputs from the pool of available coins
    // prior to coin selection, it may create a transaction that does not fund the full payment
    // amount or, through SFFO, incorrectly reduce the recipient's amount by the difference
    // between the original target and the wrongly counted inputs (in this case 99 KNE)
    // so that the recipient's amount is no longer equal to the user's selected target of 299 KNE.

    // First case, use 'subtract_fee_from_outputs=true'
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));

    // Second case, don't use 'subtract_fee_from_outputs'.
    recipients[0].fSubtractFeeFromAmount = false;
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
