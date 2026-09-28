// Copyright (c) 2011-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainregistry/child_template.h>
#include <consensus/consensus.h>
#include <core_io.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <rpc/util.h>
#include <script/script.h>
#include <util/moneystr.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/rpc/child_util.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <algorithm>

namespace wallet {
namespace {

struct ChildBalances {
    CAmount trusted{0};
    CAmount untrusted_pending{0};
    CAmount immature{0};
    CAmount used{0};
    uint32_t height{0};
    uint256 best_block;
};

ChildBalances CalculateChildBalances(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    int min_depth = 0,
    bool avoid_reuse = false)
{
    const interfaces::ChildWalletScan scan{
        ScanChildWallet(wallet, chain_id)};
    std::set<CScript> used_scripts;
    if (avoid_reuse) {
        std::optional<int> start_height;
        bool include_mempool{true};
        do {
            const auto page{ScanChildWalletHistory(
                wallet, chain_id, start_height, include_mempool)};
            if (page.best_block != scan.best_block ||
                page.height != scan.height) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "child chain changed while wallet history was scanned; retry");
            }
            for (const auto& transaction : page.transactions) {
                for (const CTxOut& spent : transaction.spent_outputs) {
                    used_scripts.insert(spent.scriptPubKey);
                }
            }
            start_height = page.next_height;
            include_mempool = false;
        } while (start_height);
    }

    ChildBalances balances{
        .height = scan.height,
        .best_block = scan.best_block,
    };
    for (const interfaces::ChildWalletCoin& coin : scan.coins) {
        if ((!coin.mempool && coin.height > scan.height) ||
            !MoneyRange(coin.output.nValue)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child wallet UTXO data is inconsistent");
        }
        const uint64_t confirmations{coin.mempool ? 0 :
            uint64_t{scan.height} - coin.height + 1};
        if (confirmations < static_cast<uint64_t>(std::max(min_depth, 0))) {
            continue;
        }
        CAmount& balance{
            coin.coinbase && confirmations < COINBASE_MATURITY
                ? balances.immature
                : avoid_reuse && used_scripts.contains(coin.output.scriptPubKey)
                ? balances.used
                : coin.mempool && !coin.trusted
                ? balances.untrusted_pending
                : balances.trusted};
        if (!MoneyRange(balance + coin.output.nValue)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child wallet balance is out of range");
        }
        balance += coin.output.nValue;
    }
    return balances;
}

UniValue GetChildBalances(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id)
{
    const bool avoid_reuse{wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)};
    const ChildBalances child_balances{
        CalculateChildBalances(wallet, chain_id, 0, avoid_reuse)};

    UniValue mine{UniValue::VOBJ};
    mine.pushKV("trusted", ValueFromAmount(child_balances.trusted));
    mine.pushKV("untrusted_pending",
                ValueFromAmount(child_balances.untrusted_pending));
    mine.pushKV("immature", ValueFromAmount(child_balances.immature));
    if (avoid_reuse) {
        mine.pushKV("used", ValueFromAmount(child_balances.used));
    }

    UniValue last_processed{UniValue::VOBJ};
    last_processed.pushKV("hash", child_balances.best_block.GetHex());
    last_processed.pushKV("height", child_balances.height);

    UniValue balances{UniValue::VOBJ};
    balances.pushKV("mine", std::move(mine));
    balances.pushKV("lastprocessedblock", std::move(last_processed));
    balances.pushKV("chain_id", chain_id.GetHex());
    return balances;
}

UniValue ListChildUnspent(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    int min_depth,
    int max_depth,
    const CoinFilterParams& filter,
    bool include_unsafe)
{
    const interfaces::ChildWalletScan scan{
        ScanChildWallet(wallet, chain_id)};
    UniValue results{UniValue::VARR};
    CAmount selected_amount{0};

    LOCK(wallet.cs_wallet);
    for (const interfaces::ChildWalletCoin& coin : scan.coins) {
        if ((!coin.mempool && coin.height > scan.height) ||
            !MoneyRange(coin.output.nValue)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child wallet UTXO data is inconsistent");
        }
        const uint64_t confirmations{coin.mempool ? 0 :
            uint64_t{scan.height} - coin.height + 1};
        if (confirmations < static_cast<uint64_t>(std::max(min_depth, 0)) ||
            (max_depth >= 0 &&
             confirmations > static_cast<uint64_t>(max_depth)) ||
            wallet.IsLockedChildCoin(chain_id, coin.outpoint) ||
            coin.output.nValue < filter.min_amount ||
            coin.output.nValue > filter.max_amount ||
            (coin.mempool && !coin.trusted && !include_unsafe) ||
            (coin.coinbase && confirmations < COINBASE_MATURITY &&
             !filter.include_immature_coinbase)) {
            continue;
        }

        CTxDestination destination;
        if (!ExtractDestination(coin.output.scriptPubKey, destination) ||
            !std::holds_alternative<WitnessV1Taproot>(destination)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child wallet UTXO has an invalid recipient script");
        }
        const auto& recipient{std::get<WitnessV1Taproot>(destination)};

        UniValue entry{UniValue::VOBJ};
        entry.pushKV("txid", coin.outpoint.hash.GetHex());
        entry.pushKV("vout", coin.outpoint.n);
        entry.pushKV("chain_id", chain_id.GetHex());
        entry.pushKV("recipient_type",
                     chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT);
        entry.pushKV("recipient", HexStr(recipient));
        if (const auto* address_book_entry{
                wallet.FindAddressBookEntry(destination)}) {
            entry.pushKV("label", address_book_entry->GetLabel());
        }
        entry.pushKV("scriptPubKey", HexStr(coin.output.scriptPubKey));
        entry.pushKV("amount", ValueFromAmount(coin.output.nValue));
        entry.pushKV("confirmations", confirmations);
        entry.pushKV("coinbase", coin.coinbase);
        std::unique_ptr<SigningProvider> provider{
            wallet.GetSolvingProvider(coin.output.scriptPubKey)};
        entry.pushKV("solvable", provider != nullptr);
        if (provider) {
            if (auto descriptor{
                    InferDescriptor(coin.output.scriptPubKey, *provider)}) {
                entry.pushKV("desc", descriptor->ToString());
            }
        }
        PushParentDescriptors(wallet, coin.output.scriptPubKey, entry);
        entry.pushKV("safe", !coin.mempool || coin.trusted);
        results.push_back(std::move(entry));

        if (!MoneyRange(selected_amount + coin.output.nValue)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child wallet balance is out of range");
        }
        selected_amount += coin.output.nValue;
        if ((filter.max_count > 0 &&
             results.size() >= filter.max_count) ||
            (filter.min_sum_amount != MAX_MONEY &&
             selected_amount >= filter.min_sum_amount)) {
            break;
        }
    }
    return results;
}

bool SetChildCoinLocks(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    bool unlock,
    const UniValue& transactions,
    bool persistent)
{
    if (transactions.isNull()) {
        if (!unlock) return true;
        LOCK(wallet.cs_wallet);
        if (!wallet.UnlockAllChildCoins(chain_id)) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "Unlocking child coins failed");
        }
        return true;
    }

    const interfaces::ChildWalletScan scan{
        ScanChildWallet(wallet, chain_id)};
    std::set<COutPoint> unspent;
    for (const auto& coin : scan.coins) unspent.insert(coin.outpoint);

    std::vector<COutPoint> outputs;
    const UniValue& output_params{transactions.get_array()};
    outputs.reserve(output_params.size());
    for (const UniValue& value : output_params.getValues()) {
        const UniValue& object{value.get_obj()};
        RPCTypeCheckObj(
            object,
            {{"txid", UniValueType(UniValue::VSTR)},
             {"vout", UniValueType(UniValue::VNUM)}});
        const int output_index{object.find_value("vout").getInt<int>()};
        if (output_index < 0) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Invalid parameter, vout cannot be negative");
        }
        const COutPoint outpoint{
            Txid::FromUint256(ParseHashO(object, "txid")),
            static_cast<uint32_t>(output_index)};
        if (!unspent.contains(outpoint)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Invalid parameter, expected unspent child output");
        }
        outputs.push_back(outpoint);
    }

    LOCK(wallet.cs_wallet);
    for (const COutPoint& output : outputs) {
        const bool locked{wallet.IsLockedChildCoin(chain_id, output)};
        if (unlock && !locked) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Invalid parameter, expected locked child output");
        }
        if (!unlock && locked && !persistent) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Invalid parameter, child output already locked");
        }
    }
    for (const COutPoint& output : outputs) {
        const bool success{unlock
            ? wallet.UnlockChildCoin(chain_id, output)
            : wallet.LockChildCoin(chain_id, output, persistent)};
        if (!success) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                unlock ? "Unlocking child coin failed"
                       : "Locking child coin failed");
        }
    }
    return true;
}

} // namespace

static CAmount GetReceived(const CWallet& wallet, const UniValue& params, bool by_label) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::vector<CTxDestination> addresses;
    if (by_label) {
        // Get the set of addresses assigned to label
        addresses = wallet.ListAddrBookAddresses(CWallet::AddrBookFilter{LabelFromValue(params[0])});
        if (addresses.empty()) throw JSONRPCError(RPC_WALLET_ERROR, "Label not found in wallet");
    } else {
        // Get the address
        CTxDestination dest = DecodeDestination(params[0].get_str());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Kronein address");
        }
        addresses.emplace_back(dest);
    }

    // Filter by own scripts only
    std::set<CScript> output_scripts;
    for (const auto& address : addresses) {
        auto output_script{GetScriptForDestination(address)};
        if (wallet.IsMine(output_script)) {
            output_scripts.insert(output_script);
        }
    }

    if (output_scripts.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");
    }

    // Minimum confirmations
    int min_depth = 1;
    if (!params[1].isNull())
        min_depth = params[1].getInt<int>();

    const bool include_immature_coinbase{params[2].isNull() ? false : params[2].get_bool()};

    // Tally
    CAmount amount = 0;
    for (const auto& [_, wtx] : wallet.mapWallet) {
        int depth{wallet.GetTxDepthInMainChain(wtx)};
        if (depth < min_depth
            // Coinbase with less than 1 confirmation is no longer in the main chain
            || (wtx.IsCoinBase() && (depth < 1))
            || (wallet.IsTxImmatureCoinBase(wtx) && !include_immature_coinbase))
        {
            continue;
        }

        for (const CTxOut& txout : wtx.tx->vout) {
            if (output_scripts.contains(txout.scriptPubKey)) {
                amount += txout.nValue;
            }
        }
    }

    return amount;
}

static CAmount GetChildReceived(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const UniValue& params,
    bool by_label)
{
    std::set<CScript> scripts;
    {
        LOCK(wallet.cs_wallet);
        if (by_label) {
            const std::string label{LabelFromValue(params[0])};
            for (const auto& [destination, recipient_label] :
                 wallet.ListChildRecipients(chain_id)) {
                const auto* address_book{
                    wallet.FindAddressBookEntry(
                        destination, /*allow_change=*/true)};
                if (address_book && !address_book->IsChange() &&
                    recipient_label == label && wallet.IsMine(destination)) {
                    scripts.insert(GetScriptForDestination(destination));
                }
            }
            if (scripts.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   "Label not found in child wallet");
            }
        } else {
            const CTxDestination destination{
                ParseChildRecipient(params[0])};
            bool found{false};
            for (const auto& [owned, _] :
                 wallet.ListChildRecipients(chain_id)) {
                if (owned == destination) {
                    found = wallet.IsMine(destination);
                    break;
                }
            }
            if (!found) {
                throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    "Recipient not found in child wallet");
            }
            scripts.insert(GetScriptForDestination(destination));
        }
    }

    const int min_depth{params[1].isNull()
        ? 1 : params[1].getInt<int>()};
    const bool include_immature_coinbase{
        !params[2].isNull() && params[2].get_bool()};
    const auto tallies{TallyChildReceived(
        wallet, chain_id, scripts, min_depth,
        include_immature_coinbase)};
    CAmount amount{0};
    for (const auto& [_, tally] : tallies) {
        if (!MoneyRange(amount + tally.amount)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child received amount is out of range");
        }
        amount += tally.amount;
    }
    return amount;
}


RPCHelpMan getreceivedbyaddress()
{
    return RPCHelpMan{
        "getreceivedbyaddress",
        "Returns the total amount received by the given address in transactions with at least minconf confirmations.\n"
        "When chain_id is present, address is the 32-byte hexadecimal child recipient and only that child is scanned.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Kronein address for transactions."},
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Only include transactions confirmed at least this many times."},
                    {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase transactions."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received at this address."
                },
                RPCExamples{
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 6") +
            "\nThe amount with at least 6 confirmations including immature coinbase outputs\n"
            + HelpExampleCli("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 6 true") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getreceivedbyaddress", "\"" + EXAMPLE_ADDRESS[0] + "\", 6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        return ValueFromAmount(GetChildReceived(
            *pwallet, ParseChildChainId(*chain_arg), request.params,
            /*by_label=*/false));
    }

    LOCK(pwallet->cs_wallet);
    return ValueFromAmount(GetReceived(*pwallet, request.params, /*by_label=*/false));
},
    };
}


RPCHelpMan getreceivedbylabel()
{
    return RPCHelpMan{
        "getreceivedbylabel",
        "Returns the total amount received by addresses with <label> in transactions with at least [minconf] confirmations.\n"
        "When chain_id is present, only non-change recipients bound to that child are scanned.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The selected label, may be the default label using \"\"."},
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Only include transactions confirmed at least this many times."},
                    {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase transactions."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received for this label."
                },
                RPCExamples{
            "\nAmount received by the default label with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbylabel", "\"\"") +
            "\nAmount received at the tabby label including unconfirmed amounts with zero confirmations\n"
            + HelpExampleCli("getreceivedbylabel", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbylabel", "\"tabby\" 6") +
            "\nThe amount with at least 6 confirmations including immature coinbase outputs\n"
            + HelpExampleCli("getreceivedbylabel", "\"tabby\" 6 true") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getreceivedbylabel", "\"tabby\", 6, true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        return ValueFromAmount(GetChildReceived(
            *pwallet, ParseChildChainId(*chain_arg), request.params,
            /*by_label=*/true));
    }

    LOCK(pwallet->cs_wallet);
    return ValueFromAmount(GetReceived(*pwallet, request.params, /*by_label=*/true));
},
    };
}


RPCHelpMan getbalance()
{
    return RPCHelpMan{
        "getbalance",
        "Returns the total available balance.\n"
                "The available balance is what the wallet considers currently spendable, and is\n"
                "thus affected by options which limit spendability such as -spendzeroconfchange.\n"
                "When chain_id is omitted, the main-chain balance is returned as before.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Only include transactions confirmed at least this many times."},
                    {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{true}, "(only available if avoid_reuse wallet flag is set) Do not include balance in dirty outputs; addresses are considered dirty if they have previously been used in a transaction."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received for this wallet."
                },
                RPCExamples{
            "\nThe total amount in the wallet with 0 or more confirmations\n"
            + HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet with at least 6 confirmations\n"
            + HelpExampleCli("getbalance", "6") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("getbalance", "6")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    const auto min_depth{self.Arg<int>("minconf")};

    bool avoid_reuse;
    {
        LOCK(pwallet->cs_wallet);
        avoid_reuse = GetAvoidReuseFlag(*pwallet, request.params[1]);
    }

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        const auto balances{CalculateChildBalances(
            *pwallet, ParseChildChainId(*chain_arg), min_depth, avoid_reuse)};
        return ValueFromAmount(balances.trusted);
    }

    LOCK(pwallet->cs_wallet);

    const auto bal = GetBalance(*pwallet, min_depth, avoid_reuse);

    return ValueFromAmount(bal.m_mine_trusted);
},
    };
}

RPCHelpMan lockunspent()
{
    return RPCHelpMan{
        "lockunspent",
        "Updates list of temporarily unspendable outputs.\n"
                "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
                "If no transaction outputs are specified when unlocking then all current locked transaction outputs are unlocked.\n"
                "A locked transaction output will not be listed as available or chosen by automatic coin selection when spending KNE.\n"
                "When chain_id is provided, the lock applies only to that child chain and cannot affect the main chain or another child chain.\n"
                "Manually selected coins are automatically unlocked.\n"
                "Locks are stored in memory only, unless persistent=true, in which case they will be written to the\n"
                "wallet database and loaded on node start. Unwritten (persistent=false) locks are always cleared\n"
                "(by virtue of process exit) when a node stops or fails. Unlocking will clear both persistent and not.\n"
                "Also see the listunspent call\n",
                {
                    {"unlock", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Whether to unlock (true) or lock (false) the specified transactions"},
                    {"transactions", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "The transaction outputs and within each, the txid (string) vout (numeric).",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                },
                            },
                        },
                    },
                    {"persistent", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether to write/erase this lock in the wallet database, or keep the change in memory only. Ignored for unlocking."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Whether the command was successful or not"
                },
                RPCExamples{
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nLock the transaction persistently in the wallet database\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\" true") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("lockunspent", "false, \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    bool fUnlock = request.params[0].get_bool();

    const bool persistent{request.params[2].isNull() ? false : request.params[2].get_bool()};

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        return SetChildCoinLocks(
            *pwallet,
            ParseChildChainId(*chain_arg),
            fUnlock,
            request.params[1],
            persistent);
    }

    LOCK(pwallet->cs_wallet);

    if (request.params[1].isNull()) {
        if (fUnlock) {
            if (!pwallet->UnlockAllCoins())
                throw JSONRPCError(RPC_WALLET_ERROR, "Unlocking coins failed");
        }
        return true;
    }

    const UniValue& output_params = request.params[1].get_array();

    // Create and validate the COutPoints first.

    std::vector<COutPoint> outputs;
    outputs.reserve(output_params.size());

    for (unsigned int idx = 0; idx < output_params.size(); idx++) {
        const UniValue& o = output_params[idx].get_obj();

        RPCTypeCheckObj(o,
            {
                {"txid", UniValueType(UniValue::VSTR)},
                {"vout", UniValueType(UniValue::VNUM)},
            });

        const Txid txid = Txid::FromUint256(ParseHashO(o, "txid"));
        const int nOutput = o.find_value("vout").getInt<int>();
        if (nOutput < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout cannot be negative");
        }

        const COutPoint outpt(txid, nOutput);

        const auto it = pwallet->mapWallet.find(outpt.hash);
        if (it == pwallet->mapWallet.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, unknown transaction");
        }

        const CWalletTx& trans = it->second;

        if (outpt.n >= trans.tx->vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout index out of bounds");
        }

        if (pwallet->IsSpent(outpt)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected unspent output");
        }

        const bool is_locked = pwallet->IsLockedCoin(outpt);

        if (fUnlock && !is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected locked output");
        }

        if (!fUnlock && is_locked && !persistent) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output already locked");
        }

        outputs.push_back(outpt);
    }

    // Atomically set (un)locked status for the outputs.
    for (const COutPoint& outpt : outputs) {
        if (fUnlock) {
            if (!pwallet->UnlockCoin(outpt)) throw JSONRPCError(RPC_WALLET_ERROR, "Unlocking coin failed");
        } else {
            if (!pwallet->LockCoin(outpt, persistent)) throw JSONRPCError(RPC_WALLET_ERROR, "Locking coin failed");
        }
    }

    return true;
},
    };
}

RPCHelpMan listlockunspent()
{
    return RPCHelpMan{
        "listlockunspent",
        "Returns list of temporarily unspendable outputs for the selected chain.\n"
                "See the lockunspent call to lock and unlock transactions for spending.\n",
                {
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id locked"},
                            {RPCResult::Type::NUM, "vout", "The vout value"},
                            {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for the main chain"},
                        }},
                    }
                },
                RPCExamples{
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listlockunspent", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    std::optional<chainregistry::ChainId> child_chain;
    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        child_chain = ParseChildChainId(*chain_arg);
    }

    LOCK(pwallet->cs_wallet);

    std::vector<COutPoint> vOutpts;
    if (child_chain) {
        pwallet->ListLockedChildCoins(*child_chain, vOutpts);
    } else {
        pwallet->ListLockedCoins(vOutpts);
    }

    UniValue ret(UniValue::VARR);

    for (const COutPoint& outpt : vOutpts) {
        UniValue o(UniValue::VOBJ);

        o.pushKV("txid", outpt.hash.GetHex());
        o.pushKV("vout", outpt.n);
        if (child_chain) o.pushKV("chain_id", child_chain->GetHex());
        ret.push_back(std::move(o));
    }

    return ret;
},
    };
}

RPCHelpMan getbalances()
{
    return RPCHelpMan{
        "getbalances",
        "Returns an object with all balances in " + CURRENCY_UNIT + ".\n"
        "When chain_id is omitted, balances are from the main-chain wallet as before. When an exact child chain is provided, the loaded child UTXO set and isolated mempool are scanned for wallet recipients explicitly bound to that chain.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ, "mine", "balances from outputs that the wallet can sign",
                {
                    {RPCResult::Type::STR_AMOUNT, "trusted", "trusted balance (outputs created by the wallet or confirmed outputs)"},
                    {RPCResult::Type::STR_AMOUNT, "untrusted_pending", "untrusted pending balance (outputs created by others that are in the mempool)"},
                    {RPCResult::Type::STR_AMOUNT, "immature", "balance from immature coinbase outputs"},
                    {RPCResult::Type::STR_AMOUNT, "used", /*optional=*/true, "(only present if avoid_reuse is set) balance from coins sent to addresses that were previously spent from (potentially privacy violating)"},
                }},
                RESULT_LAST_PROCESSED_BLOCK,
                {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for the main chain"},
            }
            },
        RPCExamples{
            HelpExampleCli("getbalances", "") +
            HelpExampleCli("getbalances", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"") +
            HelpExampleRpc("getbalances", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> rpc_wallet = GetWalletForJSONRPCRequest(request);
    if (!rpc_wallet) return UniValue::VNULL;
    const CWallet& wallet = *rpc_wallet;

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        return GetChildBalances(wallet, ParseChildChainId(*chain_arg));
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    LOCK(wallet.cs_wallet);

    const auto bal = GetBalance(wallet);
    UniValue balances{UniValue::VOBJ};
    {
        UniValue balances_mine{UniValue::VOBJ};
        balances_mine.pushKV("trusted", ValueFromAmount(bal.m_mine_trusted));
        balances_mine.pushKV("untrusted_pending", ValueFromAmount(bal.m_mine_untrusted_pending));
        balances_mine.pushKV("immature", ValueFromAmount(bal.m_mine_immature));
        if (wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
            // If the AVOID_REUSE flag is set, bal has been set to just the un-reused address balance. Get
            // the total balance, and then subtract bal to get the reused address balance.
            const auto full_bal = GetBalance(wallet, 0, false);
            balances_mine.pushKV("used", ValueFromAmount(full_bal.m_mine_trusted + full_bal.m_mine_untrusted_pending - bal.m_mine_trusted - bal.m_mine_untrusted_pending));
        }
        balances.pushKV("mine", std::move(balances_mine));
    }
    AppendLastProcessedBlock(balances, wallet);
    return balances;
},
    };
}

RPCHelpMan listunspent()
{
    return RPCHelpMan{
        "listunspent",
        "Returns array of unspent transaction outputs\n"
                "with between minconf and maxconf (inclusive) confirmations.\n"
                "Optionally filter to only include txouts paid to specified addresses.\n"
                "When chain_id is provided, scan the loaded child chain and its isolated mempool for wallet recipients explicitly bound to that chain. Child recipients are raw P2TR output keys, so the main-chain addresses filter must be empty.\n",
                {
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum confirmations to filter"},
                    {"maxconf", RPCArg::Type::NUM, RPCArg::Default{9999999}, "The maximum confirmations to filter"},
                    {"addresses", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "The Kronein addresses to filter",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Kronein address"},
                        },
                    },
                    {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include outputs that are not safe to spend\n"
                              "See description of \"safe\" attribute below."},
                    {"query_options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                        {
                            {"minimumAmount", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(0)}, "Minimum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Maximum value of each UTXO in " + CURRENCY_UNIT + ""},
                            {"maximumCount", RPCArg::Type::NUM, RPCArg::DefaultHint{"unlimited"}, "Maximum number of UTXOs"},
                            {"minimumSumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Minimum sum value of all UTXOs in " + CURRENCY_UNIT + ""},
                            {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase UTXOs"}
                        },
                        RPCArgOptions{.oneline_description="query_options"}},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "the transaction id"},
                            {RPCResult::Type::NUM, "vout", "the vout value"},
                            {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Exact child-chain identifier; child results only"},
                            {RPCResult::Type::NUM, "recipient_type", /*optional=*/true, "Child recipient namespace; child results only"},
                            {RPCResult::Type::STR_HEX, "recipient", /*optional=*/true, "32-byte P2TR output key; child results only"},
                            {RPCResult::Type::STR, "address", /*optional=*/true, "the Kronein address"},
                            {RPCResult::Type::STR, "label", /*optional=*/true, "The associated label, or \"\" for the default label"},
                            {RPCResult::Type::STR, "scriptPubKey", "the output script"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "the transaction output amount in " + CURRENCY_UNIT},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                            {RPCResult::Type::BOOL, "coinbase", /*optional=*/true, "Whether this is a child coinbase output; child results only"},
                            {RPCResult::Type::NUM, "ancestorcount", /*optional=*/true, "The number of in-mempool ancestor transactions, including this one (if transaction is in the mempool)"},
                            {RPCResult::Type::NUM, "ancestorsize", /*optional=*/true, "The virtual transaction size of in-mempool ancestors, including this one (if transaction is in the mempool)"},
                            {RPCResult::Type::STR_AMOUNT, "ancestorfees", /*optional=*/true, "The total fees of in-mempool ancestors (including this one) with fee deltas used for mining priority in " + CURRENCY_ATOM + " (if transaction is in the mempool)"},
                            {RPCResult::Type::BOOL, "solvable", "Whether we know how to spend this output, ignoring the lack of keys"},
                            {RPCResult::Type::BOOL, "reused", /*optional=*/true, "(only present if avoid_reuse is set) Whether this output is reused/dirty (sent to an address that was previously spent from)"},
                            {RPCResult::Type::STR, "desc", /*optional=*/true, "(only when solvable) A descriptor for spending this output"},
                            {RPCResult::Type::ARR, "parent_descs", /*optional=*/false, "List of parent descriptors for the output script of this coin.", {
                                {RPCResult::Type::STR, "desc", "The descriptor string."},
                            }},
                            {RPCResult::Type::BOOL, "safe", "Whether this output is considered safe to spend. Unconfirmed transactions\n"
                                                            "from outside keys and unconfirmed replacement transactions are considered unsafe\n"
                                                            "and are not eligible for spending by fundrawtransaction and sendtoaddress."},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listunspent", "")
            + HelpExampleCli("listunspent", "6 9999999 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"")
            + HelpExampleRpc("listunspent", "6, 9999999 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"")
            + HelpExampleCli("listunspent", "6 9999999 '[]' true '{ \"minimumAmount\": 0.005 }'")
            + HelpExampleRpc("listunspent", "6, 9999999, [] , true, { \"minimumAmount\": 0.005 } ")
            + HelpExampleCli("listunspent", "1 9999999 '[]' true '{}' \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const auto chain_arg{self.MaybeArg<UniValue>("chain_id")};
    const std::optional<chainregistry::ChainId> child_chain{
        chain_arg ? std::optional{ParseChildChainId(*chain_arg)} : std::nullopt};

    int nMinDepth = 1;
    if (!request.params[0].isNull()) {
        nMinDepth = request.params[0].getInt<int>();
    }

    int nMaxDepth = 9999999;
    if (!request.params[1].isNull()) {
        nMaxDepth = request.params[1].getInt<int>();
    }

    std::set<CTxDestination> destinations;
    if (!request.params[2].isNull()) {
        UniValue inputs = request.params[2].get_array();
        if (child_chain && !inputs.empty()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "addresses must be empty when chain_id selects a child chain");
        }
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CTxDestination dest = DecodeDestination(input.get_str());
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Kronein address: ") + input.get_str());
            }
            if (!destinations.insert(dest).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + input.get_str());
            }
        }
    }

    bool include_unsafe = true;
    if (!request.params[3].isNull()) {
        include_unsafe = request.params[3].get_bool();
    }

    CoinFilterParams filter_coins;
    filter_coins.min_amount = 0;

    if (!request.params[4].isNull()) {
        const UniValue& options = request.params[4].get_obj();

        RPCTypeCheckObj(options,
            {
                {"minimumAmount", UniValueType()},
                {"maximumAmount", UniValueType()},
                {"minimumSumAmount", UniValueType()},
                {"maximumCount", UniValueType(UniValue::VNUM)},
                {"include_immature_coinbase", UniValueType(UniValue::VBOOL)}
            },
            true, true);

        if (options.exists("minimumAmount"))
            filter_coins.min_amount = AmountFromValue(options["minimumAmount"]);

        if (options.exists("maximumAmount"))
            filter_coins.max_amount = AmountFromValue(options["maximumAmount"]);

        if (options.exists("minimumSumAmount"))
            filter_coins.min_sum_amount = AmountFromValue(options["minimumSumAmount"]);

        if (options.exists("maximumCount"))
            filter_coins.max_count = options["maximumCount"].getInt<int64_t>();

        if (options.exists("include_immature_coinbase")) {
            filter_coins.include_immature_coinbase = options["include_immature_coinbase"].get_bool();
        }
    }

    if (child_chain) {
        return ListChildUnspent(
            *pwallet, *child_chain, nMinDepth, nMaxDepth, filter_coins,
            include_unsafe);
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue results(UniValue::VARR);
    std::vector<COutput> vecOutputs;
    {
        CCoinControl cctl;
        cctl.m_avoid_address_reuse = false;
        cctl.m_min_depth = nMinDepth;
        cctl.m_max_depth = nMaxDepth;
        cctl.m_include_unsafe_inputs = include_unsafe;
        LOCK(pwallet->cs_wallet);
        vecOutputs = AvailableCoins(*pwallet, &cctl, /*feerate=*/std::nullopt, filter_coins).All();
    }

    LOCK(pwallet->cs_wallet);

    const bool avoid_reuse = pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);

    for (const COutput& out : vecOutputs) {
        CTxDestination address;
        const CScript& scriptPubKey = out.txout.scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);
        bool reused = avoid_reuse && pwallet->IsSpentKey(scriptPubKey);

        if (destinations.size() && (!fValidAddress || !destinations.contains(address)))
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", out.outpoint.hash.GetHex());
        entry.pushKV("vout", out.outpoint.n);

        if (fValidAddress) {
            entry.pushKV("address", EncodeDestination(address));

            const auto* address_book_entry = pwallet->FindAddressBookEntry(address);
            if (address_book_entry) {
                entry.pushKV("label", address_book_entry->GetLabel());
            }

        }

        entry.pushKV("scriptPubKey", HexStr(scriptPubKey));
        entry.pushKV("amount", ValueFromAmount(out.txout.nValue));
        entry.pushKV("confirmations", out.depth);
        if (!out.depth) {
            size_t ancestor_count, unused_cluster_count, ancestor_size;
            CAmount ancestor_fees;
            pwallet->chain().getTransactionAncestry(out.outpoint.hash, ancestor_count, unused_cluster_count, &ancestor_size, &ancestor_fees);
            if (ancestor_count) {
                entry.pushKV("ancestorcount", ancestor_count);
                entry.pushKV("ancestorsize", ancestor_size);
                entry.pushKV("ancestorfees", ancestor_fees);
            }
        }
        entry.pushKV("solvable", out.solvable);
        if (out.solvable) {
            std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(scriptPubKey);
            if (provider) {
                if (auto descriptor{InferDescriptor(scriptPubKey, *provider)}) {
                    entry.pushKV("desc", descriptor->ToString());
                }
            }
        }
        PushParentDescriptors(*pwallet, scriptPubKey, entry);
        if (avoid_reuse) entry.pushKV("reused", reused);
        entry.pushKV("safe", out.safe);
        results.push_back(std::move(entry));
    }

    return results;
},
    };
}
} // namespace wallet
