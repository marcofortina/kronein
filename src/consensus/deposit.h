// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_CONSENSUS_DEPOSIT_H
#define KRONEIN_CONSENSUS_DEPOSIT_H

#include <consensus/amount.h>
#include <primitives/chainregistry.h>
#include <primitives/deposit.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <vector>

class CBlock;

namespace chainregistry {

class ChainRegistry;

struct DepositValidationParams {
    CAmount minimum_amount{0};
    uint32_t maximum_deposits{0};
};

struct ValidatedDeposit {
    DepositId deposit_id;
    COutPoint outpoint;
    CAmount amount{0};
    FundChain fund;

    friend bool operator==(const ValidatedDeposit&, const ValidatedDeposit&) = default;
};

enum class BlockDepositsError : uint8_t {
    NONE,
    INVALID_TRANSACTION,
    TOO_MANY_DEPOSITS,
    AMOUNT_BELOW_MINIMUM,
    TOTAL_AMOUNT_OUT_OF_RANGE,
    UNKNOWN_CHAIN,
    INACTIVE_CHAIN,
    DUPLICATE_DEPOSIT_ID,
};

struct BlockDepositsResult {
    BlockDepositsError error{BlockDepositsError::NONE};
    TxFundsError transaction_error{TxFundsError::NONE};
    FundParseError parse_error{FundParseError::NONE};
    std::optional<Txid> transaction;
    std::optional<uint32_t> output_index;
    std::optional<ChainId> chain_id;
    CAmount total_amount{0};
    std::vector<ValidatedDeposit> deposits;

    bool IsValid() const { return error == BlockDepositsError::NONE; }
};

/**
 * Validate every FUND_CHAIN output against the final registry state committed
 * by the containing block. This makes same-block REGISTER usable and makes a
 * same-block RETIRE reject all deposits for that child independent of
 * transaction ordering.
 */
BlockDepositsResult ValidateBlockDeposits(
    const CBlock& block,
    const ChainRegistry& final_registry,
    const uint256& main_genesis_hash,
    const DepositValidationParams& params);

} // namespace chainregistry

#endif // KRONEIN_CONSENSUS_DEPOSIT_H
