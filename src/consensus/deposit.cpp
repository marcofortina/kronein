// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/deposit.h>

#include <consensus/chainregistry.h>
#include <primitives/block.h>
#include <primitives/transaction.h>

#include <set>
#include <utility>

namespace chainregistry {

BlockDepositsResult ValidateBlockDeposits(
    const CBlock& block,
    const ChainRegistry& final_registry,
    const uint256& main_genesis_hash,
    const DepositValidationParams& params)
{
    BlockDepositsResult result;
    std::set<DepositId> seen;

    for (size_t transaction_index{0}; transaction_index < block.vtx.size(); ++transaction_index) {
        const auto& transaction_ref{block.vtx[transaction_index]};
        const CTransaction& transaction{*transaction_ref};
        const auto transaction_funds{ExtractTransactionFunds(transaction)};
        if (!transaction_funds.IsValid()) {
            result.error = BlockDepositsError::INVALID_TRANSACTION;
            result.transaction_error = transaction_funds.error;
            result.parse_error = transaction_funds.parse_error;
            result.transaction = transaction.GetHash();
            return result;
        }

        for (const auto& output : transaction_funds.funds) {
            result.transaction = transaction.GetHash();
            result.output_index = output.output_index;
            result.chain_id = output.fund.chain_id;
            if (result.deposits.size() >= params.maximum_deposits) {
                result.error = BlockDepositsError::TOO_MANY_DEPOSITS;
                return result;
            }
            if (output.amount < params.minimum_amount) {
                result.error = BlockDepositsError::AMOUNT_BELOW_MINIMUM;
                return result;
            }
            if (output.amount > MAX_MONEY - result.total_amount) {
                result.error = BlockDepositsError::TOTAL_AMOUNT_OUT_OF_RANGE;
                return result;
            }

            const ChainRecord* record{final_registry.Find(output.fund.chain_id)};
            if (!record) {
                result.error = BlockDepositsError::UNKNOWN_CHAIN;
                return result;
            }
            if (record->status != ChainStatus::ACTIVE) {
                result.error = BlockDepositsError::INACTIVE_CHAIN;
                return result;
            }

            const COutPoint outpoint{transaction.GetHash(), output.output_index};
            const DepositId deposit_id{DeriveDepositId(main_genesis_hash, outpoint)};
            if (!seen.insert(deposit_id).second) {
                result.error = BlockDepositsError::DUPLICATE_DEPOSIT_ID;
                return result;
            }

            result.total_amount += output.amount;
            result.deposits.push_back(ValidatedDeposit{
                .deposit_id = deposit_id,
                .outpoint = outpoint,
                .transaction_index = static_cast<uint32_t>(transaction_index),
                .amount = output.amount,
                .fund = output.fund,
            });
        }
    }

    result.transaction.reset();
    result.output_index.reset();
    result.chain_id.reset();
    return result;
}

} // namespace chainregistry
