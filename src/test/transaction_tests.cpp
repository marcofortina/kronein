// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(transaction_tests)

static CScript TaprootOutput()
{
    return CScript{} << OP_1 << std::vector<unsigned char>(32);
}

static CMutableTransaction NativeTransaction()
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vout.emplace_back(COIN, TaprootOutput());
    return tx;
}

BOOST_AUTO_TEST_CASE(fixed_transaction_version)
{
    CMutableTransaction tx{NativeTransaction()};
    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction{tx}, state));

    for (const uint32_t version : {0U, 2U, std::numeric_limits<uint32_t>::max()}) {
        tx.version = version;
        state = {};
        BOOST_CHECK(!CheckTransaction(CTransaction{tx}, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-tx-version");
    }
}

BOOST_AUTO_TEST_CASE(native_output_forms)
{
    CMutableTransaction tx{NativeTransaction()};
    TxValidationState state;
    BOOST_CHECK(CheckNativeTransaction(CTransaction{tx}, state));

    tx.vout[0].scriptPubKey = GetScriptForDestination(PayToAnchor{});
    state = {};
    BOOST_CHECK(CheckNativeTransaction(CTransaction{tx}, state));

    tx.vout[0].scriptPubKey = CScript{} << OP_RETURN << std::vector<unsigned char>{0x01, 0x02};
    state = {};
    BOOST_CHECK(CheckNativeTransaction(CTransaction{tx}, state));

    const std::vector<CScript> removed_outputs{
        CScript{} << std::vector<unsigned char>(33, 0x02) << OP_CHECKSIG,
        CScript{} << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20) << OP_EQUALVERIFY << OP_CHECKSIG,
        CScript{} << OP_HASH160 << std::vector<unsigned char>(20) << OP_EQUAL,
        CScript{} << OP_0 << std::vector<unsigned char>(20),
        CScript{} << OP_0 << std::vector<unsigned char>(32),
        CScript{} << OP_TRUE,
        CScript{} << std::vector<unsigned char>(MAX_SCRIPT_SIZE + 1, 0x01),
    };
    for (const CScript& script : removed_outputs) {
        tx.vout[0].scriptPubKey = script;
        state = {};
        BOOST_CHECK(!CheckNativeTransaction(CTransaction{tx}, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-non-native-output");
    }
}

BOOST_AUTO_TEST_CASE(native_input_form)
{
    CMutableTransaction tx{NativeTransaction()};
    tx.vin[0].scriptSig = CScript{} << OP_TRUE;
    TxValidationState state;
    BOOST_CHECK(!CheckNativeTransaction(CTransaction{tx}, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-scriptsig-not-empty");

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{}, CScript{} << OP_0 << OP_0);
    coinbase.vout.emplace_back(50 * COIN, TaprootOutput());
    state = {};
    BOOST_CHECK(CheckTransaction(CTransaction{coinbase}, state));
    BOOST_CHECK(CheckNativeTransaction(CTransaction{coinbase}, state));
}

BOOST_AUTO_TEST_CASE(native_standardness)
{
    const CFeeRate dust_fee{DUST_RELAY_TX_FEE};
    CMutableTransaction tx{NativeTransaction()};
    std::string reason;
    BOOST_CHECK(IsStandardTx(CTransaction{tx}, MAX_OP_RETURN_RELAY, dust_fee, reason));

    tx.vin[0].scriptSig = CScript{} << OP_TRUE;
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{tx}, MAX_OP_RETURN_RELAY, dust_fee, reason));
    BOOST_CHECK_EQUAL(reason, "scriptsig-not-empty");
    tx.vin[0].scriptSig.clear();

    tx.vout[0].scriptPubKey = CScript{} << OP_0 << std::vector<unsigned char>(32);
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{tx}, MAX_OP_RETURN_RELAY, dust_fee, reason));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");

    tx.vout[0].scriptPubKey = TaprootOutput();
    tx.vout[0].nValue = GetDustThreshold(tx.vout[0], dust_fee) - 1;
    tx.vout.push_back(tx.vout[0]);
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{tx}, MAX_OP_RETURN_RELAY, dust_fee, reason));
    BOOST_CHECK_EQUAL(reason, "dust");

    tx.vout.resize(1);
    tx.vout[0] = CTxOut{0, CScript{} << OP_RETURN << std::vector<unsigned char>(64)};
    reason.clear();
    BOOST_CHECK(!IsStandardTx(CTransaction{tx}, tx.vout[0].scriptPubKey.size() - 1, dust_fee, reason));
    BOOST_CHECK_EQUAL(reason, "datacarrier");
    reason.clear();
    BOOST_CHECK(IsStandardTx(CTransaction{tx}, tx.vout[0].scriptPubKey.size(), dust_fee, reason));
}

BOOST_AUTO_TEST_CASE(duplicate_inputs_rejected)
{
    CMutableTransaction tx{NativeTransaction()};
    tx.vin.push_back(tx.vin[0]);
    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction{tx}, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-inputs-duplicate");
}

BOOST_AUTO_TEST_SUITE_END()
