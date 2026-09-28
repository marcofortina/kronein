// Copyright (c) 2011-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <chainregistry/child_template.h>
#include <consensus/consensus.h>
#include <key_io.h>
#include <primitives/deposit.h>
#include <primitives/block.h>
#include <primitives/transaction_identifier.h>
#include <rpc/util.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/blockchain.h>
#include <undo.h>
#include <util/vector.h>
#include <wallet/receive.h>
#include <wallet/rpc/child_util.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <map>
#include <optional>

using interfaces::FoundBlock;

namespace wallet {
static void WalletTxToJSON(const CWallet& wallet, const CWalletTx& wtx, UniValue& entry)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    interfaces::Chain& chain = wallet.chain();
    int confirms = wallet.GetTxDepthInMainChain(wtx);
    entry.pushKV("confirmations", confirms);
    if (wtx.IsCoinBase())
        entry.pushKV("generated", true);
    if (auto* conf = wtx.state<TxStateConfirmed>())
    {
        entry.pushKV("blockhash", conf->confirmed_block_hash.GetHex());
        entry.pushKV("blockheight", conf->confirmed_block_height);
        entry.pushKV("blockindex", conf->position_in_block);
        int64_t block_time;
        CHECK_NONFATAL(chain.findBlock(conf->confirmed_block_hash, FoundBlock().time(block_time)));
        entry.pushKV("blocktime", block_time);
    } else {
        entry.pushKV("trusted", CachedTxIsTrusted(wallet, wtx));
    }
    entry.pushKV("txid", wtx.GetHash().GetHex());
    entry.pushKV("wtxid", wtx.GetWitnessHash().GetHex());
    UniValue conflicts(UniValue::VARR);
    for (const Txid& conflict : wallet.GetTxConflicts(wtx))
        conflicts.push_back(conflict.GetHex());
    entry.pushKV("walletconflicts", std::move(conflicts));
    UniValue mempool_conflicts(UniValue::VARR);
    for (const Txid& mempool_conflict : wtx.mempool_conflicts)
        mempool_conflicts.push_back(mempool_conflict.GetHex());
    entry.pushKV("mempoolconflicts", std::move(mempool_conflicts));
    entry.pushKV("time", wtx.GetTxTime());
    entry.pushKV("timereceived", wtx.nTimeReceived);

    for (const std::pair<const std::string, std::string>& item : wtx.mapValue) {
        if (item.first.starts_with("__")) continue;
        entry.pushKV(item.first, item.second);
    }
}

struct tallyitem
{
    CAmount nAmount{0};
    int nConf{std::numeric_limits<int>::max()};
    std::vector<Txid> txids;
    tallyitem() = default;
};

struct ChildReceivingEntry {
    CScript script;
    WitnessV1Taproot recipient;
    std::string label;
};

static std::vector<ChildReceivingEntry> GetChildReceivingEntries(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::optional<WitnessV1Taproot>& filter)
{
    std::vector<ChildReceivingEntry> entries;
    LOCK(wallet.cs_wallet);
    for (const auto& [destination, label] :
         wallet.ListChildRecipients(chain_id)) {
        const auto* recipient{
            std::get_if<WitnessV1Taproot>(&destination)};
        if (!recipient) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "wallet contains an invalid child recipient context");
        }
        const auto* address_book{wallet.FindAddressBookEntry(
            destination, /*allow_change=*/true)};
        if (!address_book) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "wallet child recipient is missing its address-book record");
        }
        if (address_book->IsChange() || !wallet.IsMine(destination) ||
            (filter && *filter != *recipient)) {
            continue;
        }
        entries.push_back(ChildReceivingEntry{
            .script = GetScriptForDestination(destination),
            .recipient = *recipient,
            .label = label,
        });
    }
    return entries;
}

static UniValue ListChildReceived(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const UniValue& params,
    bool by_label,
    bool include_immature_coinbase)
{
    const int min_depth{params[0].isNull()
        ? 1 : params[0].getInt<int>()};
    const bool include_empty{
        !params[1].isNull() && params[1].get_bool()};
    std::optional<WitnessV1Taproot> filter;
    if (!by_label && !params[2].isNull() &&
        !params[2].get_str().empty()) {
        filter = ParseChildRecipient(params[2]);
    }
    const auto entries{
        GetChildReceivingEntries(wallet, chain_id, filter)};
    std::set<CScript> scripts;
    for (const auto& entry : entries) scripts.insert(entry.script);
    const auto tallies{TallyChildReceived(
        wallet, chain_id, scripts, min_depth,
        include_immature_coinbase)};

    UniValue result{UniValue::VARR};
    std::map<std::string, ChildReceivedTally> label_tallies;
    for (const auto& entry : entries) {
        const auto found{tallies.find(entry.script)};
        if (found == tallies.end() && !include_empty) continue;
        const ChildReceivedTally empty;
        const ChildReceivedTally& tally{
            found == tallies.end() ? empty : found->second};
        if (by_label) {
            auto& label_tally{label_tallies[entry.label]};
            if (!MoneyRange(label_tally.amount + tally.amount)) {
                throw JSONRPCError(
                    RPC_INTERNAL_ERROR,
                    "child received amount is out of range");
            }
            label_tally.amount += tally.amount;
            label_tally.confirmations = std::min(
                label_tally.confirmations, tally.confirmations);
            continue;
        }

        UniValue object{UniValue::VOBJ};
        object.pushKV("chain_id", chain_id.GetHex());
        object.pushKV("recipient_type",
                      chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT);
        object.pushKV("recipient", HexStr(entry.recipient));
        object.pushKV("amount", ValueFromAmount(tally.amount));
        object.pushKV(
            "confirmations",
            tally.confirmations == std::numeric_limits<int>::max()
                ? 0 : tally.confirmations);
        object.pushKV("label", entry.label);
        UniValue txids{UniValue::VARR};
        for (const Txid& txid : tally.txids) {
            txids.push_back(txid.GetHex());
        }
        object.pushKV("txids", std::move(txids));
        result.push_back(std::move(object));
    }

    if (by_label) {
        for (const auto& [label, tally] : label_tallies) {
            UniValue object{UniValue::VOBJ};
            object.pushKV("chain_id", chain_id.GetHex());
            object.pushKV("amount", ValueFromAmount(tally.amount));
            object.pushKV(
                "confirmations",
                tally.confirmations == std::numeric_limits<int>::max()
                    ? 0 : tally.confirmations);
            object.pushKV("label", label);
            result.push_back(std::move(object));
        }
    }
    return result;
}

static UniValue ListReceived(const CWallet& wallet, const UniValue& params, const bool by_label, const bool include_immature_coinbase) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (!params[0].isNull())
        nMinDepth = params[0].getInt<int>();

    // Whether to include empty labels
    bool fIncludeEmpty = false;
    if (!params[1].isNull())
        fIncludeEmpty = params[1].get_bool();

    std::optional<CTxDestination> filtered_address{std::nullopt};
    if (!by_label && !params[2].isNull() && !params[2].get_str().empty()) {
        if (!IsValidDestinationString(params[2].get_str())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "address_filter parameter was invalid");
        }
        filtered_address = DecodeDestination(params[2].get_str());
    }

    // Tally
    std::map<CTxDestination, tallyitem> mapTally;
    for (const auto& [_, wtx] : wallet.mapWallet) {

        int nDepth = wallet.GetTxDepthInMainChain(wtx);
        if (nDepth < nMinDepth)
            continue;

        // Coinbase with less than 1 confirmation is no longer in the main chain
        if ((wtx.IsCoinBase() && (nDepth < 1))
            || (wallet.IsTxImmatureCoinBase(wtx) && !include_immature_coinbase)) {
            continue;
        }

        for (const CTxOut& txout : wtx.tx->vout) {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            if (filtered_address && !(filtered_address == address)) {
                continue;
            }

            if (!wallet.IsMine(address))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    std::map<std::string, tallyitem> label_tally;

    const auto& func = [&](const CTxDestination& address, const std::string& label, bool is_change, const std::optional<AddressPurpose>& purpose) {
        if (is_change) return; // no change addresses

        auto it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            return;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        if (it != mapTally.end()) {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
        }

        if (by_label) {
            tallyitem& _item = label_tally[label];
            _item.nAmount += nAmount;
            _item.nConf = std::min(_item.nConf, nConf);
        } else {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("address",       EncodeDestination(address));
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            obj.pushKV("label", label);
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end()) {
                for (const Txid& _item : (*it).second.txids) {
                    transactions.push_back(_item.GetHex());
                }
            }
            obj.pushKV("txids", std::move(transactions));
            ret.push_back(std::move(obj));
        }
    };

    if (filtered_address) {
        const auto& entry = wallet.FindAddressBookEntry(*filtered_address, /*allow_change=*/false);
        if (entry) func(*filtered_address, entry->GetLabel(), entry->IsChange(), entry->purpose);
    } else {
        // No filtered addr, walk-through the addressbook entry
        wallet.ForEachAddrBookEntry(func);
    }

    if (by_label) {
        for (const auto& entry : label_tally) {
            CAmount nAmount = entry.second.nAmount;
            int nConf = entry.second.nConf;
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            obj.pushKV("label",         entry.first);
            ret.push_back(std::move(obj));
        }
    }

    return ret;
}

RPCHelpMan listreceivedbyaddress()
{
    return RPCHelpMan{
        "listreceivedbyaddress",
        "List balances by receiving address. When chain_id is present, list wallet-owned non-change recipients of that child.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum number of confirmations before payments are included."},
                    {"include_empty", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether to include addresses that haven't received any payments."},
                    {"address_filter", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If present and non-empty, only return information on this address."},
                    {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase transactions."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR, "address", /*optional=*/true, "The main-chain receiving address; omitted for child results"},
                            {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for main-chain results"},
                            {RPCResult::Type::NUM, "recipient_type", /*optional=*/true, "Reference child recipient namespace; present for child results"},
                            {RPCResult::Type::STR_HEX, "recipient", /*optional=*/true, "32-byte child recipient; present for child results"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received by the address"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations of the most recent transaction included"},
                            {RPCResult::Type::STR, "label", "The label of the receiving address. The default label is \"\""},
                            {RPCResult::Type::ARR, "txids", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The ids of transactions received with the address"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listreceivedbyaddress", "")
            + HelpExampleCli("listreceivedbyaddress", "6 true")
            + HelpExampleCli("listreceivedbyaddress", "6 true \"\" true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, \"" + EXAMPLE_ADDRESS[0] + "\", true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const bool include_immature_coinbase{request.params[3].isNull() ? false : request.params[3].get_bool()};

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        return ListChildReceived(
            *pwallet, ParseChildChainId(*chain_arg), request.params,
            /*by_label=*/false, include_immature_coinbase);
    }

    LOCK(pwallet->cs_wallet);

    return ListReceived(*pwallet, request.params, false, include_immature_coinbase);
},
    };
}

RPCHelpMan listreceivedbylabel()
{
    return RPCHelpMan{
        "listreceivedbylabel",
        "List received transactions by label. When chain_id is present, group wallet-owned non-change recipients of that child.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum number of confirmations before payments are included."},
                    {"include_empty", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether to include labels that haven't received any payments."},
                    {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase transactions."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_AMOUNT, "amount", "The total amount received by addresses with this label"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations of the most recent transaction included"},
                            {RPCResult::Type::STR, "label", "The label of the receiving address. The default label is \"\""},
                            {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for main-chain results"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listreceivedbylabel", "")
            + HelpExampleCli("listreceivedbylabel", "6 true")
            + HelpExampleRpc("listreceivedbylabel", "6, true, true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const bool include_immature_coinbase{request.params[2].isNull() ? false : request.params[2].get_bool()};

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        return ListChildReceived(
            *pwallet, ParseChildChainId(*chain_arg), request.params,
            /*by_label=*/true, include_immature_coinbase);
    }

    LOCK(pwallet->cs_wallet);

    return ListReceived(*pwallet, request.params, true, include_immature_coinbase);
},
    };
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    if (IsValidDestination(dest)) {
        entry.pushKV("address", EncodeDestination(dest));
    }
}

struct ChildRecipientRecord {
    std::string label;
    bool change{false};
};

using ChildRecipientMap = std::map<CScript, ChildRecipientRecord>;

static ChildRecipientMap GetChildRecipientMap(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id)
{
    ChildRecipientMap recipients;
    LOCK(wallet.cs_wallet);
    for (const auto& [destination, label] :
         wallet.ListChildRecipients(chain_id)) {
        const CScript script{GetScriptForDestination(destination)};
        if (!wallet.IsMine(script)) continue;
        const auto* address_book{
            wallet.FindAddressBookEntry(destination, /*allow_change=*/true)};
        if (!address_book) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "wallet child recipient is missing its address-book record");
        }
        recipients.emplace(script, ChildRecipientRecord{
            .label = label,
            .change = address_book->IsChange(),
        });
    }
    return recipients;
}

static void MaybePushChildRecipient(UniValue& entry, const CScript& script)
{
    CTxDestination destination;
    if (!ExtractDestination(script, destination)) return;
    const auto* recipient{std::get_if<WitnessV1Taproot>(&destination)};
    if (!recipient) return;
    entry.pushKV("recipient_type",
                 chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT);
    entry.pushKV("recipient", HexStr(*recipient));
}

struct ChildTransactionAmounts {
    CAmount credit{0};
    CAmount debit{0};
    CAmount fee{0};
    bool from_wallet{false};
};

static void AddChildAmount(CAmount& total, CAmount amount)
{
    if (amount < 0 || !MoneyRange(amount) || amount > MAX_MONEY - total) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "child wallet transaction amount is invalid");
    }
    total += amount;
}

static ChildTransactionAmounts GetChildTransactionAmounts(
    const interfaces::ChildWalletTransaction& wallet_tx,
    const ChildRecipientMap& recipients)
{
    ChildTransactionAmounts amounts;
    for (const CTxOut& spent : wallet_tx.spent_outputs) {
        if (recipients.contains(spent.scriptPubKey)) {
            AddChildAmount(amounts.debit, spent.nValue);
        }
    }
    for (const CTxOut& output : wallet_tx.transaction->vout) {
        if (recipients.contains(output.scriptPubKey)) {
            AddChildAmount(amounts.credit, output.nValue);
        }
    }
    amounts.from_wallet = amounts.debit > 0;
    if (amounts.from_wallet) {
        amounts.fee = amounts.debit - wallet_tx.transaction->GetValueOut();
        if (amounts.fee < 0 || !MoneyRange(amounts.fee)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child wallet transaction fee is invalid");
        }
    }
    return amounts;
}

static void ChildWalletTxToJSON(
    const interfaces::ChildWalletTransaction& wallet_tx,
    bool from_wallet,
    UniValue& entry)
{
    entry.pushKV("confirmations", wallet_tx.confirmations);
    if (wallet_tx.transaction->IsCoinBase()) {
        entry.pushKV("generated", true);
    }
    if (wallet_tx.mempool) {
        entry.pushKV("trusted", from_wallet);
    } else {
        entry.pushKV("blockhash", wallet_tx.block_hash.GetHex());
        entry.pushKV("blockheight", wallet_tx.height);
        entry.pushKV("blockindex", wallet_tx.block_index);
        entry.pushKV("blocktime", wallet_tx.block_time);
    }
    entry.pushKV("txid", wallet_tx.transaction->GetHash().GetHex());
    entry.pushKV("wtxid", wallet_tx.transaction->GetWitnessHash().GetHex());
    entry.pushKV("walletconflicts", UniValue{UniValue::VARR});
    entry.pushKV("mempoolconflicts", UniValue{UniValue::VARR});
    const int64_t time{wallet_tx.mempool
                           ? wallet_tx.entry_time
                           : static_cast<int64_t>(wallet_tx.block_time)};
    entry.pushKV("time", time);
    entry.pushKV("timereceived", time);
}

template <class Vec>
static void ListChildTransactions(
    const interfaces::ChildWalletTransaction& wallet_tx,
    const chainregistry::ChainId& chain_id,
    const ChildRecipientMap& recipients,
    Vec& result,
    const std::optional<std::string>& filter_label,
    bool verbose,
    bool include_change = false)
{
    const ChildTransactionAmounts amounts{
        GetChildTransactionAmounts(wallet_tx, recipients)};
    for (size_t index{0}; index < wallet_tx.transaction->vout.size();
         ++index) {
        const CTxOut& output{wallet_tx.transaction->vout[index]};
        const auto owned{recipients.find(output.scriptPubKey)};
        const bool change{amounts.from_wallet && owned != recipients.end() &&
                          owned->second.change};
        if (change && !include_change) continue;

        if (amounts.from_wallet && !filter_label) {
            UniValue entry{UniValue::VOBJ};
            MaybePushChildRecipient(entry, output.scriptPubKey);
            entry.pushKV("chain_id", chain_id.GetHex());
            entry.pushKV("category", "send");
            entry.pushKV("amount", ValueFromAmount(-output.nValue));
            if (owned != recipients.end()) {
                entry.pushKV("label", owned->second.label);
            }
            entry.pushKV("vout", index);
            entry.pushKV("fee", ValueFromAmount(-amounts.fee));
            if (verbose) {
                ChildWalletTxToJSON(
                    wallet_tx, amounts.from_wallet, entry);
            }
            entry.pushKV("abandoned", false);
            result.push_back(std::move(entry));
        }

        if (owned == recipients.end() ||
            (filter_label && owned->second.label != *filter_label)) {
            continue;
        }
        UniValue entry{UniValue::VOBJ};
        MaybePushChildRecipient(entry, output.scriptPubKey);
        entry.pushKV("chain_id", chain_id.GetHex());
        if (wallet_tx.transaction->IsCoinBase()) {
            entry.pushKV(
                "category",
                wallet_tx.confirmations < 1
                    ? "orphan"
                    : wallet_tx.confirmations < COINBASE_MATURITY
                    ? "immature"
                    : "generate");
        } else {
            entry.pushKV("category", "receive");
        }
        entry.pushKV("amount", ValueFromAmount(output.nValue));
        entry.pushKV("label", owned->second.label);
        entry.pushKV("vout", index);
        entry.pushKV("abandoned", false);
        if (verbose) {
            ChildWalletTxToJSON(
                wallet_tx, amounts.from_wallet, entry);
        }
        result.push_back(std::move(entry));
    }
}

static void PushChildLastProcessedBlock(
    UniValue& entry,
    const interfaces::ChildWalletHistoryPage& page)
{
    UniValue block{UniValue::VOBJ};
    block.pushKV("hash", page.best_block.GetHex());
    block.pushKV("height", page.height);
    entry.pushKV("lastprocessedblock", std::move(block));
}

static UniValue ListChildTransactionsSinceBlock(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::optional<uint256>& block_hash,
    int target_confirmations,
    bool include_removed,
    bool include_change,
    const std::optional<std::string>& filter_label)
{
    const ChildRecipientMap recipients{
        GetChildRecipientMap(wallet, chain_id)};
    const auto genesis{GetChildBlockDataByHeight(wallet, chain_id, 0)};
    const uint256 best_block{genesis.best_block};
    const uint32_t best_height{genesis.best_height};
    const auto check_tip{[&](const interfaces::ChildBlockData& block) {
        if (block.best_block != best_block ||
            block.best_height != best_height) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "child chain changed while wallet history was scanned; retry");
        }
    }};

    int since_height{-1};
    UniValue removed{UniValue::VARR};
    if (block_hash) {
        auto cursor{GetChildBlockData(wallet, chain_id, *block_hash)};
        check_tip(cursor);
        while (!cursor.active) {
            if (cursor.virtual_genesis || !cursor.block || !cursor.undo) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                   "detached child block data is unavailable");
            }
            const CBlock& block{*cursor.block};
            const CBlockUndo& undo{*cursor.undo};
            if (undo.vtxundo.size() + 1 != block.vtx.size()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                   "detached child block undo is inconsistent");
            }
            if (include_removed) {
                for (size_t index{0}; index < block.vtx.size(); ++index) {
                    interfaces::ChildWalletTransaction wallet_tx{
                        .transaction = block.vtx[index],
                        .spent_outputs = {},
                        .block_hash = cursor.block_hash,
                        .height = static_cast<uint32_t>(cursor.height),
                        .block_index = static_cast<uint32_t>(index),
                        .block_time = block.nTime,
                        .confirmations = -std::max(
                            1,
                            static_cast<int>(best_height) - cursor.height + 1),
                        .mempool = false,
                        .entry_time = 0,
                    };
                    if (index > 0) {
                        for (const Coin& coin :
                             undo.vtxundo[index - 1].vprevout) {
                            wallet_tx.spent_outputs.push_back(coin.out);
                        }
                    }
                    ListChildTransactions(
                        wallet_tx, chain_id, recipients, removed,
                        filter_label, /*verbose=*/true, include_change);
                }
            }
            cursor = GetChildBlockData(
                wallet, chain_id, block.hashPrevBlock);
            check_tip(cursor);
        }
        since_height = cursor.height;
    }

    UniValue transactions{UniValue::VARR};
    if (!recipients.empty()) {
        std::optional<int> start_height{static_cast<int>(best_height)};
        bool include_mempool{true};
        while (true) {
            const auto page{ScanChildWalletHistory(
                wallet, chain_id, start_height, include_mempool)};
            if (page.best_block != best_block || page.height != best_height) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "child chain changed while wallet history was scanned; retry");
            }
            for (const auto& wallet_tx : page.transactions) {
                if (!wallet_tx.mempool &&
                    static_cast<int>(wallet_tx.height) <= since_height) {
                    continue;
                }
                ListChildTransactions(
                    wallet_tx, chain_id, recipients, transactions,
                    filter_label, /*verbose=*/true, include_change);
            }
            if (!page.next_height || *page.next_height <= since_height) {
                break;
            }
            start_height = page.next_height;
            include_mempool = false;
        }
    }

    const int last_height{static_cast<int>(best_height) + 1 -
        std::min(target_confirmations, static_cast<int>(best_height) + 1)};
    const auto last_block{
        GetChildBlockDataByHeight(wallet, chain_id, last_height)};
    check_tip(last_block);

    UniValue result{UniValue::VOBJ};
    result.pushKV("transactions", std::move(transactions));
    if (include_removed) result.pushKV("removed", std::move(removed));
    result.pushKV("lastblock", last_block.block_hash.GetHex());
    result.pushKV("chain_id", chain_id.GetHex());
    return result;
}

/**
 * List transactions based on the given criteria.
 *
 * @param  wallet         The wallet.
 * @param  wtx            The wallet transaction.
 * @param  nMinDepth      The minimum confirmation depth.
 * @param  fLong          Whether to include the JSON version of the transaction.
 * @param  ret            The vector into which the result is stored.
 * @param  filter_label   Optional label string to filter incoming transactions.
 */
template <class Vec>
static void ListTransactions(const CWallet& wallet, const CWalletTx& wtx, int nMinDepth, bool fLong,
                             Vec& ret, const std::optional<std::string>& filter_label,
                             bool include_change = false)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CAmount nFee;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;

    CachedTxGetAmounts(wallet, wtx, listReceived, listSent, nFee, include_change);

    // Sent
    if (!filter_label.has_value())
    {
        for (const COutputEntry& s : listSent)
        {
            UniValue entry(UniValue::VOBJ);
            MaybePushAddress(entry, s.destination);
            entry.pushKV("category", "send");
            entry.pushKV("amount", ValueFromAmount(-s.amount));
            const auto* address_book_entry = wallet.FindAddressBookEntry(s.destination);
            if (address_book_entry) {
                entry.pushKV("label", address_book_entry->GetLabel());
            }
            entry.pushKV("vout", s.vout);
            entry.pushKV("fee", ValueFromAmount(-nFee));
            if (fLong)
                WalletTxToJSON(wallet, wtx, entry);
            entry.pushKV("abandoned", wtx.isAbandoned());
            ret.push_back(std::move(entry));
        }
    }

    // Received
    if (listReceived.size() > 0 && wallet.GetTxDepthInMainChain(wtx) >= nMinDepth) {
        for (const COutputEntry& r : listReceived)
        {
            std::string label;
            const auto* address_book_entry = wallet.FindAddressBookEntry(r.destination);
            if (address_book_entry) {
                label = address_book_entry->GetLabel();
            }
            if (filter_label.has_value() && label != filter_label.value()) {
                continue;
            }
            UniValue entry(UniValue::VOBJ);
            MaybePushAddress(entry, r.destination);
            PushParentDescriptors(wallet, wtx.tx->vout.at(r.vout).scriptPubKey, entry);
            if (wtx.IsCoinBase())
            {
                if (wallet.GetTxDepthInMainChain(wtx) < 1)
                    entry.pushKV("category", "orphan");
                else if (wallet.IsTxImmatureCoinBase(wtx))
                    entry.pushKV("category", "immature");
                else
                    entry.pushKV("category", "generate");
            }
            else
            {
                entry.pushKV("category", "receive");
            }
            entry.pushKV("amount", ValueFromAmount(r.amount));
            if (address_book_entry) {
                entry.pushKV("label", label);
            }
            entry.pushKV("vout", r.vout);
            entry.pushKV("abandoned", wtx.isAbandoned());
            if (fLong)
                WalletTxToJSON(wallet, wtx, entry);
            ret.push_back(std::move(entry));
        }
    }
}


static std::vector<RPCResult> TransactionDescriptionString()
{
    return{{RPCResult::Type::NUM, "confirmations", "The number of confirmations for the transaction. Negative confirmations means the\n"
               "transaction conflicted that many blocks ago."},
           {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for main-chain results."},
           {RPCResult::Type::NUM, "recipient_type", /*optional=*/true, "Child recipient namespace; present when the output has a supported child recipient."},
           {RPCResult::Type::STR_HEX, "recipient", /*optional=*/true, "Canonical child recipient bytes; present instead of a main-chain address for child results."},
           {RPCResult::Type::BOOL, "generated", /*optional=*/true, "Only present if the transaction's only input is a coinbase one."},
           {RPCResult::Type::BOOL, "trusted", /*optional=*/true, "Whether we consider the transaction to be trusted and safe to spend from.\n"
                "Only present when the transaction has 0 confirmations (or negative confirmations, if conflicted)."},
           {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash containing the transaction."},
           {RPCResult::Type::NUM, "blockheight", /*optional=*/true, "The block height containing the transaction."},
           {RPCResult::Type::NUM, "blockindex", /*optional=*/true, "The index of the transaction in the block that includes it."},
           {RPCResult::Type::NUM_TIME, "blocktime", /*optional=*/true, "The block time expressed in " + UNIX_EPOCH_TIME + "."},
           {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           {RPCResult::Type::STR_HEX, "wtxid", "The hash of serialized transaction, including witness data."},
           {RPCResult::Type::ARR, "walletconflicts", "Confirmed transactions that have been detected by the wallet to conflict with this transaction.",
           {
               {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           }},
           {RPCResult::Type::STR_HEX, "replaced_by_txid", /*optional=*/true, "Only if 'category' is 'send'. The txid if this tx was replaced."},
           {RPCResult::Type::STR_HEX, "replaces_txid", /*optional=*/true, "Only if 'category' is 'send'. The txid if this tx replaces another."},
           {RPCResult::Type::ARR, "mempoolconflicts", "Transactions in the mempool that directly conflict with either this transaction or an ancestor transaction",
           {
               {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
           }},
           {RPCResult::Type::STR, "to", /*optional=*/true, "If a comment to is associated with the transaction."},
           {RPCResult::Type::NUM_TIME, "time", "The transaction time expressed in " + UNIX_EPOCH_TIME + "."},
           {RPCResult::Type::NUM_TIME, "timereceived", "The time received expressed in " + UNIX_EPOCH_TIME + "."},
           {RPCResult::Type::STR, "comment", /*optional=*/true, "If a comment is associated with the transaction, only present if not empty."},
           {RPCResult::Type::ARR, "parent_descs", /*optional=*/true, "Only if 'category' is 'received'. List of parent descriptors for the output script of this coin.", {
               {RPCResult::Type::STR, "desc", "The descriptor string."},
           }},
           };
}

RPCHelpMan listwalletchaindeposits()
{
    return RPCHelpMan{
        "listwalletchaindeposits",
        "List one-way child-chain deposits created by this wallet. Results are ordered newest first.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Only deposits targeting this exact non-null child-chain identifier"},
            {"count", RPCArg::Type::NUM, RPCArg::Default{100}, "Maximum entries to return (1-1000)"},
            {"skip", RPCArg::Type::NUM, RPCArg::Default{0}, "Number of newest matching entries to skip"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Wallet child-deposit view", {
            {RPCResult::Type::NUM, "total", "Total matching wallet deposits before pagination"},
            {RPCResult::Type::NUM, "returned", "Number of returned entries"},
            {RPCResult::Type::ARR, "deposits", "Wallet deposits", {
                {RPCResult::Type::OBJ, "", "One irreversible main-chain deposit", {
                    {RPCResult::Type::STR_HEX, "deposit_id", "Network-bound deposit identifier"},
                    {RPCResult::Type::STR_HEX, "txid", "Funding transaction identifier"},
                    {RPCResult::Type::NUM, "vout", "Funding output index"},
                    {RPCResult::Type::STR_HEX, "chain_id", "Destination child-chain identifier"},
                    {RPCResult::Type::NUM, "recipient_type", "Child-template recipient namespace"},
                    {RPCResult::Type::STR_HEX, "recipient", "Canonical child recipient bytes"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "Amount irreversibly destroyed on the main chain"},
                    {RPCResult::Type::STR, "status", "confirmed, mempool, inactive, abandoned, or conflicted"},
                    {RPCResult::Type::NUM, "confirmations", "Active-main-chain confirmations; negative when conflicted"},
                    {RPCResult::Type::BOOL, "in_mempool", "Whether the transaction is currently in the main mempool"},
                    {RPCResult::Type::BOOL, "abandoned", "Whether the wallet marked the transaction abandoned"},
                    {RPCResult::Type::NUM_TIME, "time", "Wallet transaction time"},
                    {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "Containing active-main-chain block"},
                    {RPCResult::Type::NUM, "blockheight", /*optional=*/true, "Containing active-main-chain height"},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("listwalletchaindeposits", "")
            + HelpExampleCli("listwalletchaindeposits", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> wallet_ptr{GetWalletForJSONRPCRequest(request)};
    if (!wallet_ptr) return UniValue::VNULL;
    const CWallet& wallet{*wallet_ptr};
    wallet.BlockUntilSyncedToCurrentChain();

    std::optional<chainregistry::ChainId> chain_filter;
    if (const auto chain_arg{self.MaybeArg<std::string_view>("chain_id")}) {
        chain_filter = chainregistry::ChainId::FromHex(*chain_arg);
        if (!chain_filter || chain_filter->IsNull()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "chain_id must be exactly 32 non-null bytes encoded as hexadecimal");
        }
    }
    const int count{self.Arg<int>("count")};
    const int skip{self.Arg<int>("skip")};
    if (count < 1 || count > 1000) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be between 1 and 1000");
    }
    if (skip < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "skip must be non-negative");
    }

    const auto registry_snapshot{wallet.chain().getChainRegistrySnapshot()};
    struct ListedDeposit {
        int64_t time;
        std::string txid;
        uint32_t vout;
        UniValue value;
    };
    std::vector<ListedDeposit> listed;
    {
        LOCK(wallet.cs_wallet);
        for (const auto& [txid, wallet_tx] : wallet.mapWallet) {
            const auto funds{chainregistry::ExtractTransactionFunds(*wallet_tx.tx)};
            if (!funds.IsValid()) continue;

            const int confirmations{wallet.GetTxDepthInMainChain(wallet_tx)};
            const bool in_mempool{wallet_tx.InMempool()};
            const bool abandoned{wallet_tx.isAbandoned()};
            const char* status{confirmations > 0 ? "confirmed"
                               : confirmations < 0 ? "conflicted"
                               : abandoned ? "abandoned"
                               : in_mempool ? "mempool"
                               : "inactive"};
            for (const auto& fund : funds.funds) {
                if (chain_filter && fund.fund.chain_id != *chain_filter) continue;
                const COutPoint outpoint{txid, fund.output_index};
                UniValue entry{UniValue::VOBJ};
                entry.pushKV("deposit_id", chainregistry::DeriveDepositId(
                    registry_snapshot.main_genesis_hash, outpoint).GetHex());
                entry.pushKV("txid", txid.GetHex());
                entry.pushKV("vout", fund.output_index);
                entry.pushKV("chain_id", fund.fund.chain_id.GetHex());
                entry.pushKV("recipient_type", fund.fund.recipient_type);
                entry.pushKV("recipient", HexStr(fund.fund.recipient));
                entry.pushKV("amount", ValueFromAmount(fund.amount));
                entry.pushKV("status", status);
                entry.pushKV("confirmations", confirmations);
                entry.pushKV("in_mempool", in_mempool);
                entry.pushKV("abandoned", abandoned);
                entry.pushKV("time", wallet_tx.GetTxTime());
                if (const auto* confirmed{wallet_tx.state<TxStateConfirmed>()}) {
                    entry.pushKV("blockhash", confirmed->confirmed_block_hash.GetHex());
                    entry.pushKV("blockheight", confirmed->confirmed_block_height);
                }
                listed.push_back(ListedDeposit{
                    wallet_tx.GetTxTime(), txid.GetHex(), fund.output_index,
                    std::move(entry)});
            }
        }
    }

    std::sort(listed.begin(), listed.end(), [](const auto& left, const auto& right) {
        if (left.time != right.time) return left.time > right.time;
        if (left.txid != right.txid) return left.txid < right.txid;
        return left.vout < right.vout;
    });
    const size_t begin{std::min<size_t>(skip, listed.size())};
    const size_t end{std::min(listed.size(), begin + static_cast<size_t>(count))};
    UniValue deposits{UniValue::VARR};
    for (size_t index{begin}; index < end; ++index) {
        deposits.push_back(std::move(listed[index].value));
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("total", listed.size());
    result.pushKV("returned", end - begin);
    result.pushKV("deposits", std::move(deposits));
    return result;
},
    };
}

RPCHelpMan listtransactions()
{
    return RPCHelpMan{
        "listtransactions",
        "If a label name is provided, this will return only incoming transactions paying to addresses with the specified label.\n"
                "Returns up to 'count' most recent transactions ordered from oldest to newest while skipping the first number of \n"
                "transactions specified in the 'skip' argument. A transaction can have multiple entries in this RPC response. \n"
                "For instance, a wallet transaction that pays three addresses — one wallet-owned and two external — will produce \n"
                "four entries. The payment to the wallet-owned address appears both as a send entry and as a receive entry. \n"
                "As a result, the RPC response will contain one entry in the receive category and three entries in the send category.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If set, should be a valid label name to return only incoming transactions\n"
                          "with the specified label, or \"*\" to disable filtering and return all transactions."},
                    {"count", RPCArg::Type::NUM, RPCArg::Default{10}, "The number of transactions to return"},
                    {"skip", RPCArg::Type::NUM, RPCArg::Default{0}, "The number of transactions to skip"},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                        {
                            {RPCResult::Type::STR, "address",  /*optional=*/true, "The Kronein address of the transaction (not returned if the output does not have an address, e.g. OP_RETURN null data)."},
                            {RPCResult::Type::STR, "category", "The transaction category.\n"
                                "\"send\"                  Transactions sent.\n"
                                "\"receive\"               Non-coinbase transactions received.\n"
                                "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                "\"orphan\"                Orphaned coinbase transactions received."},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and is positive\n"
                                "for all other categories"},
                            {RPCResult::Type::STR, "label", /*optional=*/true, "A comment for the address/transaction, if any"},
                            {RPCResult::Type::NUM, "vout", "the vout value"},
                            {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                 "'send' category of transactions."},
                        },
                        TransactionDescriptionString()),
                        {
                            {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable)."},
                        })},
                    }
                },
                RPCExamples{
            "\nList the most recent 10 transactions in the systems\n"
            + HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n"
            + HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listtransactions", "\"*\", 20, 100")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    std::optional<std::string> filter_label;
    if (!request.params[0].isNull() && request.params[0].get_str() != "*") {
        filter_label.emplace(LabelFromValue(request.params[0]));
        if (filter_label.value().empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Label argument must be a valid label name or \"*\".");
        }
    }
    int nCount = 10;
    if (!request.params[1].isNull())
        nCount = request.params[1].getInt<int>();
    int nFrom = 0;
    if (!request.params[2].isNull())
        nFrom = request.params[2].getInt<int>();

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        const auto chain_id{ParseChildChainId(*chain_arg)};
        const ChildRecipientMap recipients{
            GetChildRecipientMap(*pwallet, chain_id)};
        std::vector<UniValue> ret;
        std::optional<int> start_height;
        bool include_mempool{true};
        std::optional<uint256> best_block;
        uint32_t best_height{0};
        const size_t target{static_cast<size_t>(nCount) +
                            static_cast<size_t>(nFrom)};
        do {
            auto page{ScanChildWalletHistory(
                *pwallet, chain_id, start_height, include_mempool)};
            if (!best_block) {
                best_block = page.best_block;
                best_height = page.height;
            } else if (*best_block != page.best_block ||
                       best_height != page.height) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "child chain changed while wallet history was scanned; retry");
            }
            for (const auto& wallet_tx : page.transactions) {
                ListChildTransactions(
                    wallet_tx, chain_id, recipients, ret, filter_label,
                    /*verbose=*/true);
                if (ret.size() >= target) break;
            }
            if (ret.size() >= target || !page.next_height ||
                recipients.empty()) {
                break;
            }
            start_height = page.next_height;
            include_mempool = false;
        } while (true);

        if (nFrom > static_cast<int>(ret.size())) nFrom = ret.size();
        if (nFrom + nCount > static_cast<int>(ret.size())) {
            nCount = ret.size() - nFrom;
        }
        auto txs_rev_it{std::make_move_iterator(ret.rend())};
        UniValue result{UniValue::VARR};
        result.push_backV(txs_rev_it - nFrom - nCount,
                          txs_rev_it - nFrom);
        return result;
    }

    std::vector<UniValue> ret;
    {
        LOCK(pwallet->cs_wallet);

        const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

        // iterate backwards until we have nCount items to return:
        for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
        {
            CWalletTx *const pwtx = (*it).second;
            ListTransactions(*pwallet, *pwtx, 0, true, ret, filter_label);
            if ((int)ret.size() >= (nCount+nFrom)) break;
        }
    }

    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    auto txs_rev_it{std::make_move_iterator(ret.rend())};
    UniValue result{UniValue::VARR};
    result.push_backV(txs_rev_it - nFrom - nCount, txs_rev_it - nFrom); // Return oldest to newest
    return result;
},
    };
}

RPCHelpMan listsinceblock()
{
    return RPCHelpMan{
        "listsinceblock",
        "Get all transactions in blocks since block [blockhash], or all transactions if omitted.\n"
                "If \"blockhash\" is no longer part of the selected active chain, transactions from the fork point onward are included.\n"
                "Additionally, if include_removed is set, transactions affecting the wallet which were removed are returned in the \"removed\" array.\n"
                "When chain_id is omitted, the main-chain wallet is queried as before.\n",
                {
                    {"blockhash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If set, the block hash to list transactions since, otherwise list all transactions."},
                    {"target_confirmations", RPCArg::Type::NUM, RPCArg::Default{1}, "Return the nth block hash from the selected chain. e.g. 1 would mean the best block hash. Note: this is not used as a filter, but only affects [lastblock] in the return value"},
                    {"include_removed", RPCArg::Type::BOOL, RPCArg::Default{true}, "Show transactions that were removed due to a reorg in the \"removed\" array\n"
                                                                       "(not guaranteed to work on pruned nodes)"},
                    {"include_change", RPCArg::Type::BOOL, RPCArg::Default{false}, "Also add entries for change outputs.\n"},
                    {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Return only incoming transactions paying to addresses with the specified label.\n"},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ARR, "transactions", "",
                        {
                            {RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                            {
                                {RPCResult::Type::STR, "address",  /*optional=*/true, "The Kronein address of the transaction (not returned if the output does not have an address, e.g. OP_RETURN null data)."},
                                {RPCResult::Type::STR, "category", "The transaction category.\n"
                                    "\"send\"                  Transactions sent.\n"
                                    "\"receive\"               Non-coinbase transactions received.\n"
                                    "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                    "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                    "\"orphan\"                Orphaned coinbase transactions received."},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and is positive\n"
                                    "for all other categories"},
                                {RPCResult::Type::NUM, "vout", "the vout value"},
                                {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                     "'send' category of transactions."},
                            },
                            TransactionDescriptionString()),
                            {
                                {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable)."},
                                {RPCResult::Type::STR, "label", /*optional=*/true, "A comment for the address/transaction, if any"},
                            })},
                        }},
                        {RPCResult::Type::ARR, "removed", /*optional=*/true, "<structure is the same as \"transactions\" above, only present if include_removed=true>\n"
                            "Note: transactions that were re-added in the active chain will appear as-is in this array, and may thus have a positive confirmation count."
                        , {{RPCResult::Type::ELISION, "", ""},}},
                        {RPCResult::Type::STR_HEX, "lastblock", "The hash of the block (target_confirmations-1) from the best block on the selected chain, or the genesis hash if the referenced block does not exist yet. This is typically used to feed back into listsinceblock the next time you call it. So you would generally use a target_confirmations of say 6, so you will be continually re-notified of transactions until they've reached 6 confirmations plus any new ones"},
                        {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for the main chain"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listsinceblock", "")
            + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
            + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const CWallet& wallet = *pwallet;
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();
    int target_confirms = 1;

    if (!request.params[1].isNull()) {
        target_confirms = request.params[1].getInt<int>();

        if (target_confirms < 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
    }

    bool include_removed = (request.params[2].isNull() || request.params[2].get_bool());
    bool include_change = (!request.params[3].isNull() && request.params[3].get_bool());

    // Only set it if 'label' was provided.
    std::optional<std::string> filter_label;
    if (!request.params[4].isNull()) filter_label.emplace(LabelFromValue(request.params[4]));

    std::optional<uint256> requested_block;
    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        requested_block = ParseHashV(request.params[0], "blockhash");
    }

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        return ListChildTransactionsSinceBlock(
            wallet, ParseChildChainId(*chain_arg), requested_block,
            target_confirms, include_removed, include_change, filter_label);
    }

    LOCK(wallet.cs_wallet);

    std::optional<int> height;    // Height of the specified block or the common ancestor, if the block provided was in a deactivated chain.
    std::optional<int> altheight; // Height of the specified block, even if it's in a deactivated chain.
    uint256 blockId;
    if (requested_block) {
        blockId = *requested_block;
        height = int{};
        altheight = int{};
        if (!wallet.chain().findCommonAncestor(blockId, wallet.GetLastBlockHash(), /*ancestor_out=*/FoundBlock().height(*height), /*block1_out=*/FoundBlock().height(*altheight))) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    int depth = height ? wallet.GetLastBlockHeight() + 1 - *height : -1;

    UniValue transactions(UniValue::VARR);

    for (const auto& [_, tx] : wallet.mapWallet) {

        if (depth == -1 || abs(wallet.GetTxDepthInMainChain(tx)) < depth) {
            ListTransactions(wallet, tx, 0, true, transactions, filter_label, include_change);
        }
    }

    // when a reorg'd block is requested, we also list any relevant transactions
    // in the blocks of the chain that was detached
    UniValue removed(UniValue::VARR);
    while (include_removed && altheight && *altheight > *height) {
        CBlock block;
        if (!wallet.chain().findBlock(blockId, FoundBlock().data(block)) || block.IsNull()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
        }
        for (const CTransactionRef& tx : block.vtx) {
            auto it = wallet.mapWallet.find(tx->GetHash());
            if (it != wallet.mapWallet.end()) {
                // We want all transactions regardless of confirmation count to appear here,
                // even negative confirmation ones, hence the big negative.
                ListTransactions(wallet, it->second, -100000000, true, removed, filter_label, include_change);
            }
        }
        blockId = block.hashPrevBlock;
        --*altheight;
    }

    uint256 lastblock;
    target_confirms = std::min(target_confirms, wallet.GetLastBlockHeight() + 1);
    CHECK_NONFATAL(wallet.chain().findAncestorByHeight(wallet.GetLastBlockHash(), wallet.GetLastBlockHeight() + 1 - target_confirms, FoundBlock().hash(lastblock)));

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("transactions", std::move(transactions));
    if (include_removed) ret.pushKV("removed", std::move(removed));
    ret.pushKV("lastblock", lastblock.GetHex());

    return ret;
},
    };
}

RPCHelpMan gettransaction()
{
    return RPCHelpMan{
        "gettransaction",
        "Get detailed information about in-wallet transaction <txid>. When chain_id is omitted, the main-chain wallet is queried as before.\n",
                {
                    {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false},
                            "Whether to include a `decoded` field containing the decoded transaction (equivalent to RPC decoderawtransaction)"},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "", Cat(Cat<std::vector<RPCResult>>(
                    {
                        {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                        {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                     "'send' category of transactions."},
                    },
                    TransactionDescriptionString()),
                    {
                        {RPCResult::Type::ARR, "details", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "address", /*optional=*/true, "The Kronein address involved in the transaction."},
                                {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for main-chain results."},
                                {RPCResult::Type::NUM, "recipient_type", /*optional=*/true, "Child recipient namespace."},
                                {RPCResult::Type::STR_HEX, "recipient", /*optional=*/true, "Canonical child recipient bytes."},
                                {RPCResult::Type::STR, "category", "The transaction category.\n"
                                    "\"send\"                  Transactions sent.\n"
                                    "\"receive\"               Non-coinbase transactions received.\n"
                                    "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                    "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                    "\"orphan\"                Orphaned coinbase transactions received."},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                                {RPCResult::Type::STR, "label", /*optional=*/true, "A comment for the address/transaction, if any"},
                                {RPCResult::Type::NUM, "vout", "the vout value"},
                                {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
                                    "'send' category of transactions."},
                                {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable)."},
                                {RPCResult::Type::ARR, "parent_descs", /*optional=*/true, "Only if 'category' is 'received'. List of parent descriptors for the output script of this coin.", {
                                    {RPCResult::Type::STR, "desc", "The descriptor string."},
                                }},
                            }},
                        }},
                        {RPCResult::Type::STR_HEX, "hex", "Raw data for transaction"},
                        {RPCResult::Type::OBJ, "decoded", /*optional=*/true, "The decoded transaction (only present when `verbose` is passed)",
                        {
                            DecodeTxDoc(/*txid_field_doc=*/"The transaction id", /*wallet=*/true),
                        }},
                        RESULT_LAST_PROCESSED_BLOCK,
                    })
                },
                RPCExamples{
                    HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            + HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    Txid hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};

    bool verbose = request.params[1].isNull() ? false : request.params[1].get_bool();

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        const auto chain_id{ParseChildChainId(*chain_arg)};
        const ChildRecipientMap recipients{
            GetChildRecipientMap(*pwallet, chain_id)};
        std::optional<interfaces::ChildWalletTransaction> found;
        std::optional<interfaces::ChildWalletHistoryPage> first_page;
        std::optional<int> start_height;
        bool include_mempool{true};
        do {
            auto page{ScanChildWalletHistory(
                *pwallet, chain_id, start_height, include_mempool)};
            if (!first_page) {
                first_page = page;
            } else if (first_page->best_block != page.best_block ||
                       first_page->height != page.height) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "child chain changed while wallet history was scanned; retry");
            }
            for (auto& wallet_tx : page.transactions) {
                if (wallet_tx.transaction->GetHash() == hash) {
                    found = std::move(wallet_tx);
                    break;
                }
            }
            if (found || !page.next_height || recipients.empty()) break;
            start_height = page.next_height;
            include_mempool = false;
        } while (true);
        if (!found) {
            throw JSONRPCError(
                RPC_INVALID_ADDRESS_OR_KEY,
                "Invalid or non-wallet child transaction id");
        }

        const ChildTransactionAmounts amounts{
            GetChildTransactionAmounts(*found, recipients)};
        CAmount credit{amounts.credit};
        if (found->transaction->IsCoinBase() &&
            found->confirmations < COINBASE_MATURITY) {
            credit = 0;
        }
        UniValue entry{UniValue::VOBJ};
        entry.pushKV("chain_id", chain_id.GetHex());
        entry.pushKV(
            "amount",
            ValueFromAmount(credit - amounts.debit + amounts.fee));
        if (amounts.from_wallet) {
            entry.pushKV("fee", ValueFromAmount(-amounts.fee));
        }
        ChildWalletTxToJSON(
            *found, amounts.from_wallet, entry);

        UniValue details{UniValue::VARR};
        ListChildTransactions(
            *found, chain_id, recipients, details,
            /*filter_label=*/std::nullopt,
            /*verbose=*/false);
        entry.pushKV("details", std::move(details));
        entry.pushKV("hex", EncodeHexTx(*found->transaction));

        if (verbose) {
            UniValue decoded{UniValue::VOBJ};
            TxToUniv(
                *found->transaction,
                /*block_hash=*/uint256(),
                /*entry=*/decoded,
                /*include_hex=*/false,
                /*txundo=*/nullptr,
                /*verbosity=*/TxVerbosity::SHOW_DETAILS,
                /*is_change_func=*/[&recipients](const CTxOut& output) {
                    const auto owned{recipients.find(output.scriptPubKey)};
                    return owned != recipients.end() &&
                           owned->second.change;
                });
            entry.pushKV("decoded", std::move(decoded));
        }
        Assume(first_page);
        PushChildLastProcessedBlock(entry, *first_page);
        return entry;
    }

    LOCK(pwallet->cs_wallet);

    UniValue entry(UniValue::VOBJ);
    auto it = pwallet->mapWallet.find(hash);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    const CWalletTx& wtx = it->second;

    CAmount nCredit = CachedTxGetCredit(*pwallet, wtx, /*avoid_reuse=*/false);
    CAmount nDebit = CachedTxGetDebit(*pwallet, wtx, /*avoid_reuse=*/false);
    CAmount nNet = nCredit - nDebit;
    CAmount nFee = (CachedTxIsFromMe(*pwallet, wtx) ? wtx.tx->GetValueOut() - nDebit : 0);

    entry.pushKV("amount", ValueFromAmount(nNet - nFee));
    if (CachedTxIsFromMe(*pwallet, wtx))
        entry.pushKV("fee", ValueFromAmount(nFee));

    WalletTxToJSON(*pwallet, wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(*pwallet, wtx, 0, false, details, /*filter_label=*/std::nullopt);
    entry.pushKV("details", std::move(details));

    entry.pushKV("hex", EncodeHexTx(*wtx.tx));

    if (verbose) {
        UniValue decoded(UniValue::VOBJ);
        TxToUniv(*wtx.tx,
                /*block_hash=*/uint256(),
                /*entry=*/decoded,
                /*include_hex=*/false,
                /*txundo=*/nullptr,
                /*verbosity=*/TxVerbosity::SHOW_DETAILS,
                /*is_change_func=*/[&pwallet](const CTxOut& txout) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
                                        AssertLockHeld(pwallet->cs_wallet);
                                        return OutputIsChange(*pwallet, txout);
                                    });
        entry.pushKV("decoded", std::move(decoded));
    }

    AppendLastProcessedBlock(entry, *pwallet);
    return entry;
},
    };
}

RPCHelpMan abandontransaction()
{
    return RPCHelpMan{
        "abandontransaction",
        "Mark in-wallet transaction <txid> as abandoned\n"
                "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
                "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
                "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
                "It has no effect on transactions which are already abandoned.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    Txid hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};

    if (!pwallet->mapWallet.contains(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    if (!pwallet->AbandonTransaction(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");
    }

    return UniValue::VNULL;
},
    };
}

RPCHelpMan rescanblockchain()
{
    return RPCHelpMan{
        "rescanblockchain",
        "Rescan the local blockchain for wallet related transactions.\n"
                "Note: Use \"getwalletinfo\" to query the scanning progress.\n"
                "The rescan is significantly faster if block filters are available\n"
                "(using startup option \"-blockfilterindex=1\").\n",
                {
                    {"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "block height where the rescan should start"},
                    {"stop_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "the last block height that should be scanned. If none is provided it will rescan up to the tip at return time of this call."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "start_height", "The block height where the rescan started (the requested height or 0)"},
                        {RPCResult::Type::NUM, "stop_height", "The height of the last rescanned block. May be null in rare cases if there was a reorg and the call didn't scan any blocks because they were already scanned in the background."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("rescanblockchain", "100000 120000")
            + HelpExampleRpc("rescanblockchain", "100000, 120000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;
    CWallet& wallet{*pwallet};

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    WalletRescanReserver reserver(*pwallet);
    if (!reserver.reserve(/*with_passphrase=*/true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    int start_height = 0;
    std::optional<int> stop_height;
    uint256 start_block;

    LOCK(pwallet->m_relock_mutex);
    {
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(*pwallet);
        int tip_height = pwallet->GetLastBlockHeight();

        if (!request.params[0].isNull()) {
            start_height = request.params[0].getInt<int>();
            if (start_height < 0 || start_height > tip_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid start_height");
            }
        }

        if (!request.params[1].isNull()) {
            stop_height = request.params[1].getInt<int>();
            if (*stop_height < 0 || *stop_height > tip_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid stop_height");
            } else if (*stop_height < start_height) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "stop_height must be greater than start_height");
            }
        }

        // We can't rescan unavailable blocks, stop and throw an error
        if (!pwallet->chain().hasBlocks(pwallet->GetLastBlockHash(), start_height, stop_height)) {
            if (pwallet->chain().havePruned() && pwallet->chain().getPruneHeight() >= start_height) {
                throw JSONRPCError(RPC_MISC_ERROR, "Can't rescan beyond pruned data. Use RPC call getblockchaininfo to determine your pruned height.");
            }
            if (pwallet->chain().hasAssumedValidChain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Failed to rescan unavailable blocks likely due to an in-progress assumeutxo background sync. Check logs or getchainstates RPC for assumeutxo background sync progress and try again later.");
            }
            throw JSONRPCError(RPC_MISC_ERROR, "Failed to rescan unavailable blocks, potentially caused by data corruption. If the issue persists you may want to reindex (see -reindex option).");
        }

        CHECK_NONFATAL(pwallet->chain().findAncestorByHeight(pwallet->GetLastBlockHash(), start_height, FoundBlock().hash(start_block)));
    }

    CWallet::ScanResult result =
        pwallet->ScanForWalletTransactions(start_block, start_height, stop_height, reserver, /*fUpdate=*/true, /*save_progress=*/false);
    switch (result.status) {
    case CWallet::ScanResult::SUCCESS:
        break;
    case CWallet::ScanResult::FAILURE:
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan failed. Potentially corrupted data files.");
    case CWallet::ScanResult::USER_ABORT:
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted.");
        // no default case, so the compiler can warn about missing cases
    }
    UniValue response(UniValue::VOBJ);
    response.pushKV("start_height", start_height);
    response.pushKV("stop_height", result.last_scanned_height ? *result.last_scanned_height : UniValue());
    return response;
},
    };
}

RPCHelpMan abortrescan()
{
    return RPCHelpMan{"abortrescan",
                "Stops current wallet rescan triggered by an RPC call, e.g. by a rescanblockchain call.\n"
                "Note: Use \"getwalletinfo\" to query the scanning progress.\n",
                {},
                RPCResult{RPCResult::Type::BOOL, "", "Whether the abort was successful"},
                RPCExamples{
            "\nImport a private key\n"
            + HelpExampleCli("rescanblockchain", "") +
            "\nAbort the running wallet rescan\n"
            + HelpExampleCli("abortrescan", "") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("abortrescan", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (!pwallet->IsScanning() || pwallet->IsAbortingRescan()) return false;
    pwallet->AbortRescan();
    return true;
},
    };
}
} // namespace wallet
