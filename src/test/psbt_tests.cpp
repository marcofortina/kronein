// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <psbt.h>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

BOOST_FIXTURE_TEST_SUITE(psbt_tests, BasicTestingSetup)

static PSBTProprietary MakeProprietary(uint64_t subtype, uint8_t key_data, uint8_t value)
{
    return PSBTProprietary{
        .subtype = subtype,
        .identifier = {'p', 's', 'b', 't'},
        .key = {key_data},
        .value = {value},
    };
}

BOOST_AUTO_TEST_CASE(psbt2_timelock_test)
{
    CMutableTransaction tx;
    tx.nLockTime = 42;
    PartiallySignedTransaction psbt(tx);
    BOOST_CHECK_EQUAL(*psbt.ComputeTimeLock(), 42);

    PSBTInput time_locked{Txid{}, 0};
    time_locked.time_locktime = LOCKTIME_THRESHOLD;
    psbt.inputs = {time_locked};
    BOOST_CHECK_EQUAL(*psbt.ComputeTimeLock(), LOCKTIME_THRESHOLD);

    PSBTInput height_locked{Txid{}, 1};
    height_locked.height_locktime = 100;
    psbt.inputs = {height_locked};
    BOOST_CHECK_EQUAL(*psbt.ComputeTimeLock(), 100);

    psbt.inputs = {time_locked, height_locked};
    BOOST_CHECK(!psbt.ComputeTimeLock());
    BOOST_CHECK(!psbt.GetUnsignedTx());
}

BOOST_AUTO_TEST_CASE(psbt2_addinput)
{
    FastRandomContext rng(/*fDeterministic=*/true);

    CMutableTransaction mtx;
    PartiallySignedTransaction psbt(mtx);
    psbt.m_tx_modifiable.emplace();
    psbt.m_tx_modifiable->set(0, true);
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 0);

    uint256 txid;
    rng.fillrand(MakeWritableByteSpan(txid));
    PSBTInput psbtin(Txid::FromUint256(txid), /*prev_out=*/0);
    BOOST_CHECK(psbt.AddInput(psbtin));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 1);

    // Duplicates are not allowed
    BOOST_CHECK(!psbt.AddInput(psbtin));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 1);

    // Input with a unique txid is allowed
    rng.fillrand(MakeWritableByteSpan(txid));
    PSBTInput psbtin2(Txid::FromUint256(txid), /*prev_out=*/0);
    BOOST_CHECK(psbt.AddInput(psbtin2));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 2);

    // Disabling inputs modifiable flag prevents adding new inputs
    psbt.m_tx_modifiable->set(0, false);
    rng.fillrand(MakeWritableByteSpan(txid));
    PSBTInput psbtin3(Txid::FromUint256(txid), /*prev_out=*/0);
    BOOST_CHECK(!psbt.AddInput(psbtin3));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 2);
    psbt.m_tx_modifiable->set(0, true);

    // Make sure that timelock compatibility checks are working
    // No previous required timelocks, new input with both height and time timelocks is allowed
    rng.fillrand(MakeWritableByteSpan(txid));
    PSBTInput psbtin4(Txid::FromUint256(txid), /*prev_out=*/0);
    psbtin4.time_locktime = LOCKTIME_THRESHOLD;
    psbtin4.height_locktime = 100;
    BOOST_CHECK(psbt.AddInput(psbtin4));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 3);

    // Input with only a time timelock is allowed
    rng.fillrand(MakeWritableByteSpan(txid));
    PSBTInput psbtin5(Txid::FromUint256(txid), /*prev_out=*/0);
    psbtin5.time_locktime = LOCKTIME_THRESHOLD + 1;
    BOOST_CHECK(psbt.AddInput(psbtin5));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 4);

    // Input with only a height timelock is not allowed because of previous
    rng.fillrand(MakeWritableByteSpan(txid));
    PSBTInput psbtin6(Txid::FromUint256(txid), /*prev_out=*/0);
    psbtin6.height_locktime = 100;
    BOOST_CHECK(!psbt.AddInput(psbtin6));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 4);

    // Adding an input that already has a finalized witness is allowed
    rng.fillrand(MakeWritableByteSpan(txid));
    PSBTInput psbtin7(Txid::FromUint256(txid), /*prev_out=*/0);
    psbtin7.final_script_witness.stack.emplace_back();
    BOOST_CHECK(psbt.AddInput(psbtin7));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 5);

    // An input with the same outpoint is never added twice.
    BOOST_CHECK(!psbt.AddInput(psbtin7));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 5);
    psbtin7.final_script_witness.SetNull();
    psbtin7.m_tap_key_sig.push_back(0);
    BOOST_CHECK(!psbt.AddInput(psbtin7));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 5);
    psbtin7.m_tap_key_sig.clear();
    psbtin7.m_tap_script_sigs.emplace();
    BOOST_CHECK(!psbt.AddInput(psbtin7));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 5);
    psbtin7.m_tap_script_sigs.clear();
    psbtin7.m_musig2_partial_sigs.emplace();
    BOOST_CHECK(!psbt.AddInput(psbtin7));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 5);

    // Adding an input that changes the timelock is no longer allowed
    rng.fillrand(MakeWritableByteSpan(txid));
    PSBTInput psbtin8(Txid::FromUint256(txid), /*prev_out=*/0);
    psbtin8.time_locktime = LOCKTIME_THRESHOLD + 2;
    BOOST_CHECK(!psbt.AddInput(psbtin8));
    BOOST_CHECK_EQUAL(psbt.inputs.size(), 5);
}

BOOST_AUTO_TEST_CASE(psbt2_addoutput)
{
    CMutableTransaction mtx;
    PartiallySignedTransaction psbt(mtx);
    psbt.m_tx_modifiable.emplace();
    psbt.m_tx_modifiable->set(1, true);
    BOOST_CHECK_EQUAL(psbt.outputs.size(), 0);

    PSBTOutput psbtout(/*amount=*/1, CScript());
    BOOST_CHECK(psbt.AddOutput(psbtout));
    BOOST_CHECK_EQUAL(psbt.outputs.size(), 1);

    // Disabling outputs modifiable flag prevents adding new outputs
    psbt.m_tx_modifiable->set(1, false);
    PSBTOutput psbtout2(/*amount=*/1, CScript());
    BOOST_CHECK(!psbt.AddOutput(psbtout2));
    BOOST_CHECK_EQUAL(psbt.outputs.size(), 1);
    psbt.m_tx_modifiable->set(1, true);
    PSBTOutput psbtout3(/*amount=*/1, CScript());
    BOOST_CHECK(psbt.AddOutput(psbtout3));
    BOOST_CHECK_EQUAL(psbt.outputs.size(), 2);
}

BOOST_AUTO_TEST_CASE(merge_proprietary_fields)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{});
    tx.vout.emplace_back(0, CScript{});

    PartiallySignedTransaction left(tx);
    PartiallySignedTransaction right(tx);

    const auto left_prop = MakeProprietary(/*subtype=*/1, /*key_data=*/0x01, /*value=*/0xaa);
    const auto right_prop = MakeProprietary(/*subtype=*/2, /*key_data=*/0x02, /*value=*/0xbb);

    left.m_proprietary.insert(left_prop);
    left.inputs[0].m_proprietary.insert(left_prop);
    left.outputs[0].m_proprietary.insert(left_prop);

    right.m_proprietary.insert(right_prop);
    right.inputs[0].m_proprietary.insert(right_prop);
    right.outputs[0].m_proprietary.insert(right_prop);

    BOOST_REQUIRE(left.Merge(right));

    BOOST_REQUIRE_EQUAL(left.m_proprietary.size(), 2U);
    BOOST_REQUIRE_EQUAL(left.inputs[0].m_proprietary.size(), 2U);
    BOOST_REQUIRE_EQUAL(left.outputs[0].m_proprietary.size(), 2U);

    const auto global_it = left.m_proprietary.find(right_prop);
    BOOST_REQUIRE(global_it != left.m_proprietary.end());
    BOOST_CHECK(global_it->value == right_prop.value);

    const auto input_it = left.inputs[0].m_proprietary.find(right_prop);
    BOOST_REQUIRE(input_it != left.inputs[0].m_proprietary.end());
    BOOST_CHECK(input_it->value == right_prop.value);

    const auto output_it = left.outputs[0].m_proprietary.find(right_prop);
    BOOST_REQUIRE(output_it != left.outputs[0].m_proprietary.end());
    BOOST_CHECK(output_it->value == right_prop.value);
}

BOOST_AUTO_TEST_SUITE_END()
