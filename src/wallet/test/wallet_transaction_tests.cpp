// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/transaction.h>

#include <streams.h>
#include <test/util/common.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(wallet_transaction_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(roundtrip)
{
    const uint256 block_hash{2};
    BOOST_CHECK(std::holds_alternative<TxStateInactive>(TxStateInterpretSerialized(uint256::ZERO, 0)));
    const TxState abandoned{TxStateInterpretSerialized(uint256::ONE, -1)};
    const auto* inactive{std::get_if<TxStateInactive>(&abandoned)};
    BOOST_REQUIRE(inactive);
    BOOST_CHECK(inactive->abandoned);
    BOOST_CHECK(std::holds_alternative<TxStateConfirmed>(TxStateInterpretSerialized(block_hash, 0)));
    BOOST_CHECK(std::holds_alternative<TxStateBlockConflicted>(TxStateInterpretSerialized(block_hash, -1)));

    BOOST_CHECK_THROW(TxStateInterpretSerialized(uint256::ZERO, -1), std::ios_base::failure);
    BOOST_CHECK_THROW(TxStateInterpretSerialized(uint256::ONE, 0), std::ios_base::failure);
    BOOST_CHECK_THROW(TxStateInterpretSerialized(block_hash, -2), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(native_wallet_tx_serialization)
{
    CMutableTransaction tx;
    tx.vin.emplace_back();
    tx.vin[0].scriptSig = CScript{} << OP_1;
    tx.vin[0].scriptWitness.stack = {{0x01}};
    tx.vout.emplace_back(42, CScript{} << OP_1 << std::vector<unsigned char>(32, 0x02));

    const uint256 block_hash{3};
    CWalletTx original{MakeTransactionRef(tx), TxStateConfirmed{block_hash, /*height=*/100, /*index=*/2}};
    original.mapValue = {{"comment", "native record"}, {"to", "recipient"}};
    original.vOrderForm = {{"note", "value"}};
    original.nTimeReceived = 123;
    original.nTimeSmart = 456;
    original.nOrderPos = 7;

    DataStream stream;
    stream << original;

    CWalletTx decoded{MakeTransactionRef(CMutableTransaction{}), TxStateInactive{}};
    stream >> decoded;

    BOOST_CHECK(stream.empty());
    BOOST_CHECK(*decoded.tx == *original.tx);
    const auto* confirmed{decoded.state<TxStateConfirmed>()};
    BOOST_REQUIRE(confirmed);
    BOOST_CHECK_EQUAL(confirmed->confirmed_block_hash, block_hash);
    BOOST_CHECK_EQUAL(confirmed->confirmed_block_height, -1);
    BOOST_CHECK_EQUAL(confirmed->position_in_block, 2);
    BOOST_CHECK(decoded.mapValue == original.mapValue);
    BOOST_CHECK(decoded.vOrderForm == original.vOrderForm);
    BOOST_CHECK_EQUAL(decoded.nTimeReceived, original.nTimeReceived);
    BOOST_CHECK_EQUAL(decoded.nTimeSmart, original.nTimeSmart);
    BOOST_CHECK_EQUAL(decoded.nOrderPos, original.nOrderPos);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
