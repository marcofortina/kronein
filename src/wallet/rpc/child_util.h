// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_WALLET_RPC_CHILD_UTIL_H
#define KRONEIN_WALLET_RPC_CHILD_UTIL_H

#include <interfaces/chain.h>
#include <primitives/chainregistry.h>

#include <optional>
#include <set>

class UniValue;

namespace wallet {

class CWallet;

chainregistry::ChainId ParseChildChainId(const UniValue& value);

std::set<CScript> ChildWalletScripts(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id);

interfaces::ChildWalletScan ScanChildWallet(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id);

interfaces::ChildWalletHistoryPage ScanChildWalletHistory(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    std::optional<int> start_height = std::nullopt,
    bool include_mempool = true);

} // namespace wallet

#endif // KRONEIN_WALLET_RPC_CHILD_UTIL_H
