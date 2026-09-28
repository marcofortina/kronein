// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_WALLET_RPC_CHILD_H
#define KRONEIN_WALLET_RPC_CHILD_H

#include <addresstype.h>
#include <consensus/amount.h>
#include <primitives/chainregistry.h>
#include <primitives/transaction.h>

#include <vector>

namespace wallet {

class CWallet;

struct ChildWalletSendResult {
    CTransactionRef transaction;
    CAmount fee{0};
};

struct ChildWalletPayment {
    WitnessV1Taproot recipient;
    CAmount amount{0};
    bool subtract_fee{false};
};

ChildWalletSendResult CreateSignedChildPayments(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::vector<ChildWalletPayment>& payments,
    CAmount fee,
    int minconf = 1);

ChildWalletSendResult CreateSignedChildPayment(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const WitnessV1Taproot& recipient,
    CAmount amount,
    CAmount fee,
    bool subtract_fee_from_amount,
    int minconf = 1);

} // namespace wallet

#endif // KRONEIN_WALLET_RPC_CHILD_H
