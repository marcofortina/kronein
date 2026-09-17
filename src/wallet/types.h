// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! @file wallet/types.h is a home for public enum and struct type definitions
//! that are used by internally by wallet code, but also used externally by node
//! or GUI code.
//!
//! This file is intended to define only simple types that do not have external
//! dependencies. More complicated public wallet types like CCoinControl should
//! be defined in dedicated header files.

#ifndef BITCOIN_WALLET_TYPES_H
#define BITCOIN_WALLET_TYPES_H

#include <policy/fees/block_policy_estimator.h>

namespace wallet {
/** Address purpose exposed by wallet RPC and GUI interfaces. */
enum class AddressPurpose {
    RECEIVE,
    SEND,
};

struct CreatedTransactionResult
{
    CTransactionRef tx;
    CAmount fee;
    FeeCalculation fee_calc;
    std::optional<unsigned int> change_pos;

    CreatedTransactionResult(CTransactionRef _tx, CAmount _fee, std::optional<unsigned int> _change_pos, const FeeCalculation& _fee_calc)
            : tx(_tx), fee(_fee), fee_calc(_fee_calc), change_pos(_change_pos) {}
};

} // namespace wallet

#endif // BITCOIN_WALLET_TYPES_H
