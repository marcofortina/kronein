// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_mempool.h>

#include <consensus/consensus.h>

#include <algorithm>
#include <utility>

namespace node {

bool ChildMempool::Contains(const Txid& txid) const
{
    return std::any_of(
        m_entries.begin(), m_entries.end(), [&](const auto& entry) {
            return entry.transaction->GetHash() == txid;
        });
}

ChildMempoolAddResult ChildMempool::Add(CTransactionRef transaction,
                                        CAmount fee,
                                        int64_t entry_time,
                                        uint32_t entry_height)
{
    ChildMempoolAddResult result;
    if (!transaction) {
        result.error = ChildMempoolError::NULL_TRANSACTION;
        return result;
    }
    if (Contains(transaction->GetHash())) {
        result.error = ChildMempoolError::DUPLICATE_TRANSACTION;
        return result;
    }
    if (m_entries.size() >= MAX_CHILD_MEMPOOL_TRANSACTIONS) {
        result.error = ChildMempoolError::TOO_MANY_TRANSACTIONS;
        return result;
    }
    result.serialized_size = GetSerializeSize(TX_WITH_WITNESS(*transaction));
    if (result.serialized_size > MAX_CHILD_MEMPOOL_BYTES - m_total_bytes) {
        result.error = ChildMempoolError::SIZE_LIMIT_EXCEEDED;
        return result;
    }
    if (fee < 0 || !MoneyRange(fee) ||
        fee > MAX_MONEY - m_total_fees) {
        result.error = ChildMempoolError::FEE_OUT_OF_RANGE;
        return result;
    }

    m_total_bytes += result.serialized_size;
    m_total_fees += fee;
    ++m_sequence;
    m_entries.push_back({
        .transaction = std::move(transaction),
        .fee = fee,
        .entry_time = entry_time,
        .entry_height = entry_height,
        .serialized_size = result.serialized_size,
    });
    return result;
}

std::vector<Txid> ChildMempool::Clear()
{
    std::vector<Txid> removed;
    removed.reserve(m_entries.size());
    for (const auto& entry : m_entries) {
        removed.push_back(entry.transaction->GetHash());
    }
    if (!m_entries.empty()) ++m_sequence;
    m_entries.clear();
    m_total_bytes = 0;
    m_total_fees = 0;
    return removed;
}

} // namespace node
