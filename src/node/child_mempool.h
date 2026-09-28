// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHILD_MEMPOOL_H
#define KRONEIN_NODE_CHILD_MEMPOOL_H

#include <consensus/amount.h>
#include <primitives/transaction.h>

#include <cstddef>
#include <cstdint>
#include <set>
#include <vector>

namespace node {

inline constexpr size_t MAX_CHILD_MEMPOOL_TRANSACTIONS{10'000};
inline constexpr size_t MAX_CHILD_MEMPOOL_BYTES{16 << 20};

enum class ChildMempoolError : uint8_t {
    NONE,
    NULL_TRANSACTION,
    DUPLICATE_TRANSACTION,
    TOO_MANY_TRANSACTIONS,
    SIZE_LIMIT_EXCEEDED,
    FEE_OUT_OF_RANGE,
};

struct ChildMempoolEntry {
    CTransactionRef transaction;
    CAmount fee{0};
    int64_t entry_time{0};
    uint32_t entry_height{0};
    size_t serialized_size{0};
};

struct ChildMempoolAddResult {
    ChildMempoolError error{ChildMempoolError::NONE};
    size_t serialized_size{0};

    bool IsValid() const { return error == ChildMempoolError::NONE; }
};

/**
 * Bounded insertion-ordered transaction storage for one child runtime.
 *
 * Consensus and contextual validation deliberately remain in
 * ReferenceChildRuntime. This class only owns deterministic bookkeeping.
 */
class ChildMempool
{
private:
    std::vector<ChildMempoolEntry> m_entries;
    std::set<Txid> m_txids;
    size_t m_total_bytes{0};
    CAmount m_total_fees{0};
    uint64_t m_sequence{0};

public:
    bool Contains(const Txid& txid) const;
    ChildMempoolAddResult Add(CTransactionRef transaction,
                              CAmount fee,
                              int64_t entry_time,
                              uint32_t entry_height);
    std::vector<Txid> Clear();

    const std::vector<ChildMempoolEntry>& Entries() const { return m_entries; }
    size_t Size() const { return m_entries.size(); }
    size_t TotalBytes() const { return m_total_bytes; }
    CAmount TotalFees() const { return m_total_fees; }
    uint64_t Sequence() const { return m_sequence; }
};

} // namespace node

#endif // KRONEIN_NODE_CHILD_MEMPOOL_H
