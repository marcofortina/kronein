// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/rpc/child_util.h>

#include <chainregistry/child_template.h>
#include <consensus/consensus.h>
#include <key_io.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <algorithm>
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

WitnessV1Taproot ParseChildRecipient(const UniValue& value)
{
    const std::vector<unsigned char> recipient{
        ParseHexV(value, "recipient")};
    if (!chainregistry::IsValidReferenceChildRecipient(
            chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT,
            recipient)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "recipient must be a valid 32-byte reference-child P2TR output key");
    }
    return WitnessV1Taproot{XOnlyPubKey{recipient}};
}

ChildReceivedTallies TallyChildReceived(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::set<CScript>& scripts,
    int min_depth,
    bool include_immature_coinbase)
{
    ChildReceivedTallies tallies;
    std::optional<uint256> best_block;
    uint32_t best_height{0};
    std::optional<int> start_height;
    bool include_mempool{true};
    do {
        const auto page{ScanChildWalletHistory(
            wallet, chain_id, scripts, start_height, include_mempool)};
        if (!best_block) {
            best_block = page.best_block;
            best_height = page.height;
        } else if (*best_block != page.best_block ||
                   best_height != page.height) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "child chain changed while received amounts were scanned; retry");
        }
        for (const auto& wallet_tx : page.transactions) {
            if (wallet_tx.confirmations < min_depth ||
                (wallet_tx.transaction->IsCoinBase() &&
                 (wallet_tx.confirmations < 1 ||
                  (!include_immature_coinbase &&
                   wallet_tx.confirmations < COINBASE_MATURITY)))) {
                continue;
            }
            for (const CTxOut& output : wallet_tx.transaction->vout) {
                if (!scripts.contains(output.scriptPubKey)) continue;
                auto& tally{tallies[output.scriptPubKey]};
                if (!MoneyRange(output.nValue) ||
                    output.nValue < 0 ||
                    !MoneyRange(tally.amount + output.nValue)) {
                    throw JSONRPCError(
                        RPC_INTERNAL_ERROR,
                        "child received amount is out of range");
                }
                tally.amount += output.nValue;
                tally.confirmations = std::min(
                    tally.confirmations, wallet_tx.confirmations);
                tally.txids.push_back(wallet_tx.transaction->GetHash());
            }
        }
        start_height = page.next_height;
        include_mempool = false;
    } while (start_height);
    return tallies;
}

interfaces::ChildWalletScan ScanChildWallet(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id)
{
    auto scan{wallet.chain().scanChildWalletUTXOs(
        chain_id, ChildWalletScripts(wallet, chain_id))};
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

std::set<CScript> ChildWalletScripts(
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
    return scripts;
}

interfaces::ChildWalletHistoryPage ScanChildWalletHistory(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::set<CScript>& scripts,
    std::optional<int> start_height,
    bool include_mempool)
{
    auto scan{wallet.chain().scanChildWalletHistory(
        chain_id,
        scripts,
        start_height,
        include_mempool)};
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
                           "child wallet history data is unavailable");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child wallet history error");
}

interfaces::ChildWalletHistoryPage ScanChildWalletHistory(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    std::optional<int> start_height,
    bool include_mempool)
{
    return ScanChildWalletHistory(
        wallet,
        chain_id,
        ChildWalletScripts(wallet, chain_id),
        start_height,
        include_mempool);
}

static interfaces::ChildBlockData CheckedChildBlockData(
    interfaces::ChildBlockData result)
{
    switch (result.error) {
    case interfaces::ChildBlockDataError::NONE:
        return result;
    case interfaces::ChildBlockDataError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "chain_id must not be null");
    case interfaces::ChildBlockDataError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case interfaces::ChildBlockDataError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    case interfaces::ChildBlockDataError::BLOCK_NOT_FOUND:
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Child block not found");
    case interfaces::ChildBlockDataError::HEIGHT_OUT_OF_RANGE:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Child block height out of range");
    case interfaces::ChildBlockDataError::DATA_UNAVAILABLE:
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "child block data is unavailable");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child block data error");
}

interfaces::ChildBlockData GetChildBlockData(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const uint256& block_hash)
{
    return CheckedChildBlockData(
        wallet.chain().getChildBlockData(chain_id, block_hash));
}

interfaces::ChildBlockData GetChildBlockDataByHeight(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    int height)
{
    return CheckedChildBlockData(
        wallet.chain().getChildBlockDataByHeight(chain_id, height));
}

} // namespace wallet
