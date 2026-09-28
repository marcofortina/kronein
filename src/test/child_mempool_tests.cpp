// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_mempool.h>

#include <primitives/transaction.h>

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

CTransactionRef TestTransaction(uint32_t lock_time)
{
    CMutableTransaction transaction;
    transaction.nLockTime = lock_time;
    transaction.vin.resize(1);
    transaction.vout.emplace_back(1, CScript{} << OP_TRUE);
    return MakeTransactionRef(std::move(transaction));
}

CTransactionRef LargeTestTransaction(
    uint32_t lock_time,
    const std::vector<unsigned char>& payload)
{
    CMutableTransaction transaction;
    transaction.nLockTime = lock_time;
    transaction.vin.resize(1);
    transaction.vout.emplace_back(
        1, CScript{payload.begin(), payload.end()});
    return MakeTransactionRef(std::move(transaction));
}

} // namespace

BOOST_AUTO_TEST_SUITE(child_mempool_tests)

BOOST_AUTO_TEST_CASE(bounded_accounting)
{
    node::ChildMempool mempool;
    const auto first{TestTransaction(1)};
    const auto second{TestTransaction(2)};

    const auto added_first{mempool.Add(first, 10, 100, 7)};
    BOOST_REQUIRE(added_first.IsValid());
    BOOST_CHECK(mempool.Contains(first->GetHash()));
    BOOST_CHECK_EQUAL(mempool.Size(), 1U);
    BOOST_CHECK_EQUAL(mempool.TotalBytes(), added_first.serialized_size);
    BOOST_CHECK_EQUAL(mempool.TotalFees(), 10);

    BOOST_CHECK_EQUAL(mempool.Entries().front().entry_height, 7U);
    BOOST_CHECK_EQUAL(mempool.Sequence(), 1U);

    const auto duplicate{mempool.Add(first, 10, 101, 7)};
    BOOST_CHECK(
        duplicate.error == node::ChildMempoolError::DUPLICATE_TRANSACTION);
    BOOST_CHECK_EQUAL(mempool.Size(), 1U);

    const auto invalid_fee{mempool.Add(second, -1, 102, 7)};
    BOOST_CHECK(
        invalid_fee.error == node::ChildMempoolError::FEE_OUT_OF_RANGE);
    BOOST_CHECK_EQUAL(mempool.Size(), 1U);

    const auto added_second{mempool.Add(second, 25, 103, 8)};
    BOOST_REQUIRE(added_second.IsValid());
    BOOST_CHECK_EQUAL(mempool.Size(), 2U);
    BOOST_CHECK_EQUAL(
        mempool.TotalBytes(),
        added_first.serialized_size + added_second.serialized_size);
    BOOST_CHECK_EQUAL(mempool.TotalFees(), 35);
    BOOST_CHECK_EQUAL(mempool.Sequence(), 2U);

    const auto removed{mempool.Clear()};
    BOOST_REQUIRE_EQUAL(removed.size(), 2U);
    BOOST_CHECK(removed[0] == first->GetHash());
    BOOST_CHECK(removed[1] == second->GetHash());
    BOOST_CHECK(mempool.Entries().empty());
    BOOST_CHECK_EQUAL(mempool.TotalBytes(), 0U);
    BOOST_CHECK_EQUAL(mempool.TotalFees(), 0);
    BOOST_CHECK_EQUAL(mempool.Sequence(), 3U);
}

BOOST_AUTO_TEST_CASE(rejects_null_transaction)
{
    node::ChildMempool mempool;
    const auto result{mempool.Add({}, 0, 0, 0)};
    BOOST_CHECK(result.error == node::ChildMempoolError::NULL_TRANSACTION);
}

BOOST_AUTO_TEST_CASE(enforces_transaction_count_limit)
{
    node::ChildMempool mempool;
    for (size_t index{0};
         index < node::MAX_CHILD_MEMPOOL_TRANSACTIONS;
         ++index) {
        BOOST_REQUIRE(mempool.Add(
            TestTransaction(static_cast<uint32_t>(index + 1)),
            1,
            static_cast<int64_t>(index),
            1).IsValid());
    }
    const size_t full_bytes{mempool.TotalBytes()};
    const auto rejected{mempool.Add(
        TestTransaction(
            static_cast<uint32_t>(node::MAX_CHILD_MEMPOOL_TRANSACTIONS + 1)),
        1,
        0,
        1)};
    BOOST_CHECK(
        rejected.error == node::ChildMempoolError::TOO_MANY_TRANSACTIONS);
    BOOST_CHECK_EQUAL(
        mempool.Size(), node::MAX_CHILD_MEMPOOL_TRANSACTIONS);
    BOOST_CHECK_EQUAL(mempool.TotalBytes(), full_bytes);
    BOOST_CHECK_EQUAL(
        mempool.Sequence(), node::MAX_CHILD_MEMPOOL_TRANSACTIONS);
}

BOOST_AUTO_TEST_CASE(enforces_serialized_byte_limit)
{
    node::ChildMempool mempool;
    const std::vector<unsigned char> payload(1 << 20, OP_TRUE);
    node::ChildMempoolAddResult result;
    uint32_t lock_time{1};
    do {
        result = mempool.Add(
            LargeTestTransaction(lock_time++, payload), 1, 0, 1);
    } while (result.IsValid());

    BOOST_CHECK(
        result.error == node::ChildMempoolError::SIZE_LIMIT_EXCEEDED);
    BOOST_CHECK(mempool.Size() < node::MAX_CHILD_MEMPOOL_TRANSACTIONS);
    BOOST_CHECK(mempool.TotalBytes() <= node::MAX_CHILD_MEMPOOL_BYTES);
    BOOST_CHECK(
        result.serialized_size >
        node::MAX_CHILD_MEMPOOL_BYTES - mempool.TotalBytes());
    BOOST_CHECK_EQUAL(mempool.Sequence(), mempool.Size());
}

BOOST_AUTO_TEST_SUITE_END()
