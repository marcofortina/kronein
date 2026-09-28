// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/rpc/child_util.h>

#include <key_io.h>
#include <rpc/util.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <set>

namespace wallet {

chainregistry::ChainId ParseChildChainId(const UniValue& value)
{
    const auto chain_id{chainregistry::ChainId::FromHex(value.get_str())};
    if (!chain_id || chain_id->IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "chain_id must be exactly 32 non-null bytes encoded as hexadecimal");
    }
    return *chain_id;
}

interfaces::ChildWalletScan ScanChildWallet(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id)
{
    std::set<CScript> scripts;
    {
        LOCK(wallet.cs_wallet);
        for (const auto& [destination, _] :
             wallet.ListChildRecipients(chain_id)) {
            const CScript script{GetScriptForDestination(destination)};
            if (wallet.IsMine(script)) scripts.insert(script);
        }
    }

    auto scan{wallet.chain().scanChildWalletUTXOs(chain_id, scripts)};
    switch (scan.error) {
    case interfaces::ChildWalletScanError::NONE:
        return scan;
    case interfaces::ChildWalletScanError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "chain_id must not be null");
    case interfaces::ChildWalletScanError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case interfaces::ChildWalletScanError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    case interfaces::ChildWalletScanError::DATA_UNAVAILABLE:
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "child chain UTXO data is unavailable");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child wallet scan error");
}

} // namespace wallet
