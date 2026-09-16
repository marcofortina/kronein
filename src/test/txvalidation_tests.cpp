// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <key_io.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/ephemeral_policy.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>


BOOST_AUTO_TEST_SUITE(txvalidation_tests)

/**
 * Ensure that the mempool won't accept coinbase transactions.
 */
BOOST_FIXTURE_TEST_CASE(tx_mempool_reject_coinbase, TestChain100Setup)
{
    CScript scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 1);
    CMutableTransaction coinbaseTx;

    coinbaseTx.version = 1;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vout.resize(1);
    coinbaseTx.vin[0].scriptSig = CScript() << OP_11 << OP_EQUAL;
    coinbaseTx.vout[0].nValue = 1 * CENT;
    coinbaseTx.vout[0].scriptPubKey = scriptPubKey;

    BOOST_CHECK(CTransaction(coinbaseTx).IsCoinBase());

    LOCK(cs_main);

    unsigned int initialPoolSize = m_node.mempool->size();
    const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(coinbaseTx));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);

    // Check that the transaction hasn't been added to mempool.
    BOOST_CHECK_EQUAL(m_node.mempool->size(), initialPoolSize);

    // Check that the validation state reflects the unsuccessful attempt.
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "coinbase");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

// Generate a number of random, nonexistent outpoints.
static inline std::vector<COutPoint> random_outpoints(size_t num_outpoints) {
    std::vector<COutPoint> outpoints;
    for (size_t i{0}; i < num_outpoints; ++i) {
        outpoints.emplace_back(Txid::FromUint256(GetRandHash()), 0);
    }
    return outpoints;
}

static inline std::vector<CPubKey> random_keys(size_t num_keys) {
    std::vector<CPubKey> keys;
    keys.reserve(num_keys);
    for (size_t i{0}; i < num_keys; ++i) {
        CKey key;
        key.MakeNewKey(true);
        keys.emplace_back(key.GetPubKey());
    }
    return keys;
}

// Creates a placeholder tx (not valid) with 25 outputs. Specify the version and the inputs.
static inline CTransactionRef make_tx(const std::vector<COutPoint>& inputs)
{
    CMutableTransaction mtx = CMutableTransaction{};
    mtx.vin.resize(inputs.size());
    mtx.vout.resize(25);
    for (size_t i{0}; i < inputs.size(); ++i) {
        mtx.vin[i].prevout = inputs[i];
    }
    for (auto i{0}; i < 25; ++i) {
        mtx.vout[i].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 1);
        mtx.vout[i].nValue = 10000;
    }
    return MakeTransactionRef(mtx);
}

static constexpr auto NUM_EPHEMERAL_TX_OUTPUTS = 3;
static constexpr auto EPHEMERAL_DUST_INDEX = NUM_EPHEMERAL_TX_OUTPUTS - 1;

// Same as make_tx but adds 2 normal outputs and 0-value dust to end of vout
static inline CTransactionRef make_ephemeral_tx(const std::vector<COutPoint>& inputs)
{
    CMutableTransaction mtx = CMutableTransaction{};
    mtx.vin.resize(inputs.size());
    for (size_t i{0}; i < inputs.size(); ++i) {
        mtx.vin[i].prevout = inputs[i];
    }
    mtx.vout.resize(NUM_EPHEMERAL_TX_OUTPUTS);
    for (auto i{0}; i < NUM_EPHEMERAL_TX_OUTPUTS; ++i) {
        mtx.vout[i].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 1);
        mtx.vout[i].nValue = (i == EPHEMERAL_DUST_INDEX) ? 0 : 10000;
    }
    return MakeTransactionRef(mtx);
}

BOOST_FIXTURE_TEST_CASE(ephemeral_tests, RegTestingSetup)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(cs_main, pool.cs);
    TestMemPoolEntryHelper entry;

    TxValidationState child_state;
    Wtxid child_wtxid;

    // Arbitrary non-0 feerate for these tests
    CFeeRate dustrelay(DUST_RELAY_TX_FEE);

    // Basic transaction with dust
    auto grandparent_tx_1 = make_ephemeral_tx(random_outpoints(1));
    const auto dust_txid = grandparent_tx_1->GetHash();

    // Child transaction spending dust
    auto dust_spend = make_tx({COutPoint{dust_txid, EPHEMERAL_DUST_INDEX}});

    // We first start with nothing "in the mempool", using package checks

    // Trivial single transaction with no dust
    BOOST_CHECK(CheckEphemeralSpends({dust_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Now with dust, ok because the tx has no dusty parents
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Dust checks pass
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, dust_spend}, CFeeRate(0), pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, dust_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    auto dust_non_spend = make_tx({COutPoint{dust_txid, EPHEMERAL_DUST_INDEX - 1}});

    // Child spending non-dust only from parent should be disallowed even if dust otherwise spent
    const auto dust_non_spend_wtxid{dust_non_spend->GetWitnessHash()};
    BOOST_CHECK(!CheckEphemeralSpends({grandparent_tx_1, dust_non_spend, dust_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(!child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, dust_non_spend_wtxid);
    child_state = TxValidationState();
    child_wtxid = Wtxid();

    BOOST_CHECK(!CheckEphemeralSpends({grandparent_tx_1, dust_spend, dust_non_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(!child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, dust_non_spend_wtxid);
    child_state = TxValidationState();
    child_wtxid = Wtxid();

    BOOST_CHECK(!CheckEphemeralSpends({grandparent_tx_1, dust_non_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(!child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, dust_non_spend_wtxid);
    child_state = TxValidationState();
    child_wtxid = Wtxid();

    auto grandparent_tx_2 = make_ephemeral_tx(random_outpoints(1));
    const auto dust_txid_2 = grandparent_tx_2->GetHash();

    // Spend dust from one but not another is ok, as long as second grandparent has no child
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, dust_spend}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    auto dust_non_spend_both_parents = make_tx({COutPoint{dust_txid, EPHEMERAL_DUST_INDEX}, COutPoint{dust_txid_2, EPHEMERAL_DUST_INDEX - 1}});
    // But if we spend from the parent, it must spend dust
    BOOST_CHECK(!CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, dust_non_spend_both_parents}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(!child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, dust_non_spend_both_parents->GetWitnessHash());
    child_state = TxValidationState();
    child_wtxid = Wtxid();

    auto dust_spend_both_parents = make_tx({COutPoint{dust_txid, EPHEMERAL_DUST_INDEX}, COutPoint{dust_txid_2, EPHEMERAL_DUST_INDEX}});
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, dust_spend_both_parents}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Spending other outputs is also correct, as long as the dusty one is spent
    const std::vector<COutPoint> all_outpoints{COutPoint(dust_txid, 0), COutPoint(dust_txid, 1), COutPoint(dust_txid, 2),
        COutPoint(dust_txid_2, 0), COutPoint(dust_txid_2, 1), COutPoint(dust_txid_2, 2)};
    auto dust_spend_all_outpoints = make_tx(all_outpoints);
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, dust_spend_all_outpoints}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // 2 grandparents with dust <- 1 dust-spending parent with dust <- child with no dust
    auto parent_with_dust = make_ephemeral_tx({COutPoint{dust_txid, EPHEMERAL_DUST_INDEX}, COutPoint{dust_txid_2, EPHEMERAL_DUST_INDEX}});
    // Ok for parent to have dust
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, parent_with_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());
    auto child_no_dust = make_tx({COutPoint{parent_with_dust->GetHash(), EPHEMERAL_DUST_INDEX}});
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, parent_with_dust, child_no_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // 2 grandparents with dust <- 1 dust-spending parent with dust <- child with dust
    auto child_with_dust = make_ephemeral_tx({COutPoint{parent_with_dust->GetHash(), EPHEMERAL_DUST_INDEX}});
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1, grandparent_tx_2, parent_with_dust, child_with_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Tests with parents in mempool

    // Nothing in mempool, this should pass for any transaction
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_1}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Add first grandparent to mempool and fetch entry
    TryAddToMempool(pool, entry.FromTx(grandparent_tx_1));

    // Ignores ancestors that aren't direct parents
    BOOST_CHECK(CheckEphemeralSpends({child_no_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Valid spend of dust with grandparent in mempool
    BOOST_CHECK(CheckEphemeralSpends({parent_with_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Second grandparent in same package
    BOOST_CHECK(CheckEphemeralSpends({parent_with_dust, grandparent_tx_2}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Order in package doesn't matter
    BOOST_CHECK(CheckEphemeralSpends({grandparent_tx_2, parent_with_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Add second grandparent to mempool
    TryAddToMempool(pool, entry.FromTx(grandparent_tx_2));

    // Only spends single dust out of two direct parents
    BOOST_CHECK(!CheckEphemeralSpends({dust_non_spend_both_parents}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(!child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, dust_non_spend_both_parents->GetWitnessHash());
    child_state = TxValidationState();
    child_wtxid = Wtxid();

    // Spends both parents' dust
    BOOST_CHECK(CheckEphemeralSpends({parent_with_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());

    // Now add dusty parent to mempool
    TryAddToMempool(pool, entry.FromTx(parent_with_dust));

    // Passes dust checks even with non-parent ancestors
    BOOST_CHECK(CheckEphemeralSpends({child_no_dust}, dustrelay, pool, child_state, child_wtxid));
    BOOST_CHECK(child_state.IsValid());
    BOOST_CHECK_EQUAL(child_wtxid, Wtxid());
}


BOOST_AUTO_TEST_SUITE_END()
