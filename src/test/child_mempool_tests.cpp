// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_mempool.h>

#include <primitives/transaction.h>

#include <boost/test/unit_test.hpp>

namespace {

CTransactionRef TestTransaction(uint32_t lock_time)
{
    CMutableTransaction transaction;
    transaction.nLockTime = lock_time;
    transaction.vin.resize(1);
    transaction.vout.emplace_back(1, CScript{} << OP_TRUE);
    return MakeTransactionRef(std::move(transaction));
}

} // namespace

BOOST_AUTO_TEST_SUITE(child_mempool_tests)

BOOST_AUTO_TEST_CASE(bounded_accounting)
{
    node::ChildMempool mempool;
    const auto first{TestTransaction(1)};
    const auto second{TestTransaction(2)};

    const auto added_first{mempool.Add(first, 10, 100)};
    BOOST_REQUIRE(added_first.IsValid());
    BOOST_CHECK(mempool.Contains(first->GetHash()));
    BOOST_CHECK_EQUAL(mempool.Size(), 1U);
    BOOST_CHECK_EQUAL(mempool.TotalBytes(), added_first.serialized_size);
    BOOST_CHECK_EQUAL(mempool.TotalFees(), 10);

    const auto duplicate{mempool.Add(first, 10, 101)};
    BOOST_CHECK(
        duplicate.error == node::ChildMempoolError::DUPLICATE_TRANSACTION);
    BOOST_CHECK_EQUAL(mempool.Size(), 1U);

    const auto invalid_fee{mempool.Add(second, -1, 102)};
    BOOST_CHECK(
        invalid_fee.error == node::ChildMempoolError::FEE_OUT_OF_RANGE);
    BOOST_CHECK_EQUAL(mempool.Size(), 1U);

    const auto added_second{mempool.Add(second, 25, 103)};
    BOOST_REQUIRE(added_second.IsValid());
    BOOST_CHECK_EQUAL(mempool.Size(), 2U);
    BOOST_CHECK_EQUAL(
        mempool.TotalBytes(),
        added_first.serialized_size + added_second.serialized_size);
    BOOST_CHECK_EQUAL(mempool.TotalFees(), 35);

    const auto removed{mempool.Clear()};
    BOOST_REQUIRE_EQUAL(removed.size(), 2U);
    BOOST_CHECK(removed[0] == first->GetHash());
    BOOST_CHECK(removed[1] == second->GetHash());
    BOOST_CHECK(mempool.Entries().empty());
    BOOST_CHECK_EQUAL(mempool.TotalBytes(), 0U);
    BOOST_CHECK_EQUAL(mempool.TotalFees(), 0);
}

BOOST_AUTO_TEST_CASE(rejects_null_transaction)
{
    node::ChildMempool mempool;
    const auto result{mempool.Add({}, 0, 0)};
    BOOST_CHECK(result.error == node::ChildMempoolError::NULL_TRANSACTION);
}

BOOST_AUTO_TEST_SUITE_END()
