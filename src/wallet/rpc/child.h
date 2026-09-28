// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_WALLET_RPC_CHILD_H
#define KRONEIN_WALLET_RPC_CHILD_H

#include <addresstype.h>
#include <consensus/amount.h>
#include <primitives/chainregistry.h>
#include <primitives/transaction.h>

#include <optional>
#include <string>
#include <vector>

namespace wallet {

class CWallet;

struct ChildWalletSendResult {
    CTransactionRef transaction;
    CAmount fee{0};
    std::string psbt;
};

struct ChildWalletPayment {
    WitnessV1Taproot recipient;
    CAmount amount{0};
    bool subtract_fee{false};
};

struct ChildWalletSweepRecipient {
    WitnessV1Taproot recipient;
    std::optional<CAmount> amount;
};

struct ChildWalletFundResult {
    std::string psbt;
    CAmount fee{0};
    int change_position{-1};
    std::vector<COutPoint> inputs;
};

ChildWalletFundResult CreateFundedChildPayments(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::vector<ChildWalletPayment>& payments,
    CAmount fee,
    int minconf = 1,
    bool bip32_derivs = true);

ChildWalletSendResult CreateSignedChildPayments(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::vector<ChildWalletPayment>& payments,
    CAmount fee,
    int minconf = 1);

ChildWalletSendResult CreateSignedChildSweep(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::vector<ChildWalletSweepRecipient>& recipients,
    CAmount fee,
    int minconf = 0);

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
