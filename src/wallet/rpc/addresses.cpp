// Copyright (c) 2011-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chainregistry/child_template.h>
#include <consensus/chainregistry.h>
#include <core_io.h>
#include <key_io.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/solver.h>
#include <util/bip32.h>
#include <util/translation.h>
#include <wallet/receive.h>
#include <wallet/rpc/child_util.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <univalue.h>

#include <algorithm>
#include <set>
#include <variant>

namespace wallet {
namespace {

constexpr int MAX_CHILD_RECOVERY_KEY_COUNT{10'000};

void EnsureActiveReferenceChild(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id)
{
    auto snapshot{wallet.chain().getChainRegistrySnapshot(chain_id)};
    if (!snapshot.enabled || !snapshot.active_for_next_block) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "child-chain registry is not active for the next block");
    }
    if (!snapshot.record) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "chain_id is not registered");
    }
    if (snapshot.record->status != chainregistry::ChainStatus::ACTIVE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is retired");
    }
    if (snapshot.record->template_id !=
            chainregistry::REFERENCE_CHILD_TEMPLATE_ID ||
        snapshot.record->template_version !=
            chainregistry::REFERENCE_CHILD_TEMPLATE_VERSION) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "wallet does not support recipients for this child template");
    }
}

UniValue ChildRecipientToJSON(
    const chainregistry::ChainId& chain_id,
    const WitnessV1Taproot& recipient,
    const std::string& label)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV(
        "recipient_type",
        chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT);
    result.pushKV("recipient", HexStr(recipient));
    result.pushKV(
        "scriptPubKey", HexStr(GetScriptForDestination(recipient)));
    result.pushKV("label", label);
    return result;
}

} // namespace

RPCHelpMan getnewaddress()
{
    return RPCHelpMan{
        "getnewaddress",
        "Returns a new Kronein address for receiving payments.\n"
                "If 'label' is specified, it is added to the address book \n"
                "so payments received with the address will be associated with 'label'.\n"
                "When chain_id is present, returns a 32-byte hexadecimal child recipient instead of a main-chain address.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Default{""}, "The label name for the address to be linked to. It can also be set to the empty string \"\" to represent the default label. The label does not need to exist, it will be created if there is no label by the given name."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::STR, "address", "The new main-chain address, or raw child recipient when chain_id is present"
                },
                RPCExamples{
                    HelpExampleCli("getnewaddress", "")
            + HelpExampleRpc("getnewaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Parse the label first so we don't generate a key if there's an error
    const std::string label{LabelFromValue(request.params[0])};

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        const auto chain_id{ParseChildChainId(*chain_arg)};
        EnsureActiveReferenceChild(*pwallet, chain_id);
        const auto destination{
            pwallet->GetNewChildDestination(chain_id, label)};
        if (!destination) {
            throw JSONRPCError(
                RPC_WALLET_KEYPOOL_RAN_OUT,
                util::ErrorString(destination).original);
        }
        const auto* recipient{
            std::get_if<WitnessV1Taproot>(&*destination)};
        if (!recipient) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "wallet did not derive a Taproot child recipient");
        }
        return HexStr(*recipient);
    }

    LOCK(pwallet->cs_wallet);
    if (!pwallet->CanGetAddresses()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }
    auto op_dest = pwallet->GetNewDestination(label);
    if (!op_dest) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(op_dest).original);
    }

    return EncodeDestination(*op_dest);
},
    };
}

RPCHelpMan getnewchildrecipient()
{
    return RPCHelpMan{
        "getnewchildrecipient",
        "Derive and persist a new wallet-owned P2TR receiving key for one exact child chain. The result is the canonical recipient tuple used by FUND_CHAIN; it is not a main-chain address and must always be used together with the returned chain_id. Set for_registration only while preparing an unconfirmed REGISTER whose chain_id was derived from its exact anchor and specification.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact non-null registered child-chain identifier"},
            {"label", RPCArg::Type::STR, RPCArg::Default{""}, "Wallet label associated with the receiving key"},
            {"for_registration", RPCArg::Type::BOOL, RPCArg::Default{false}, "Allow derivation before this exact chain_id is present in the active registry"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Wallet-owned child recipient", {
            {RPCResult::Type::STR_HEX, "chain_id", "Exact child-chain identifier"},
            {RPCResult::Type::NUM, "recipient_type", "Reference-template P2TR recipient namespace; always 1"},
            {RPCResult::Type::STR_HEX, "recipient", "32-byte Taproot output key"},
            {RPCResult::Type::STR_HEX, "scriptPubKey", "Canonical P2TR output script credited by IMPORT"},
            {RPCResult::Type::STR, "label", "Persisted wallet label"},
        }},
        RPCExamples{
            HelpExampleCli("getnewchildrecipient", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"savings\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet{GetWalletForJSONRPCRequest(request)};
    if (!wallet) return UniValue::VNULL;
    wallet->BlockUntilSyncedToCurrentChain();

    const auto chain_id{ParseChildChainId(self.Arg<UniValue>("chain_id"))};
    if (!self.Arg<bool>("for_registration")) {
        EnsureActiveReferenceChild(*wallet, chain_id);
    }
    const std::string label{LabelFromValue(self.Arg<UniValue>("label"))};

    const auto destination{wallet->GetNewChildDestination(chain_id, label)};
    if (!destination) {
        throw JSONRPCError(
            RPC_WALLET_KEYPOOL_RAN_OUT,
            util::ErrorString(destination).original);
    }
    const auto* recipient{std::get_if<WitnessV1Taproot>(&*destination)};
    if (!recipient) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "wallet did not derive a Taproot child recipient");
    }
    return ChildRecipientToJSON(chain_id, *recipient, label);
},
    };
}

RPCHelpMan listchildrecipients()
{
    return RPCHelpMan{
        "listchildrecipients",
        "List wallet-owned receiving keys explicitly associated with one child-chain identifier. Local records remain queryable for recovery even if the chain is retired or no longer present in the active registry.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact non-null registered child-chain identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Persisted child recipients", {
            {RPCResult::Type::STR_HEX, "chain_id", "Exact child-chain identifier"},
            {RPCResult::Type::NUM, "recipient_count", "Number of wallet-owned recipients for this chain"},
            {RPCResult::Type::ARR, "recipients", "Wallet-owned recipients", {
                {RPCResult::Type::OBJ, "", "One receiving key", {
                    {RPCResult::Type::STR_HEX, "chain_id", "Exact child-chain identifier"},
                    {RPCResult::Type::NUM, "recipient_type", "Reference-template P2TR recipient namespace; always 1"},
                    {RPCResult::Type::STR_HEX, "recipient", "32-byte Taproot output key"},
                    {RPCResult::Type::STR_HEX, "scriptPubKey", "Canonical P2TR output script"},
                    {RPCResult::Type::STR, "label", "Wallet label"},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("listchildrecipients", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet{GetWalletForJSONRPCRequest(request)};
    if (!wallet) return UniValue::VNULL;
    const auto chain_id{ParseChildChainId(self.Arg<UniValue>("chain_id"))};

    UniValue recipients{UniValue::VARR};
    LOCK(wallet->cs_wallet);
    for (const auto& [destination, label] :
         wallet->ListChildRecipients(chain_id)) {
        const auto* recipient{std::get_if<WitnessV1Taproot>(&destination)};
        if (!recipient) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "wallet contains an invalid child recipient context");
        }
        recipients.push_back(
            ChildRecipientToJSON(chain_id, *recipient, label));
    }
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("recipient_count", recipients.size());
    result.pushKV("recipients", std::move(recipients));
    return result;
},
    };
}

RPCHelpMan recoverchildwallet()
{
    return RPCHelpMan{
        "recoverchildwallet",
        "Scan one bounded page of a loaded child chain for keys derived by this wallet. "
        "The command persists only keys observed in child transactions and returns a cursor for the previous page. "
        "Call again with next_height until complete is true. Mempool transactions are included only on the first page.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact non-null registered child-chain identifier"},
            {"key_start", RPCArg::Type::NUM, RPCArg::Default{0}, "First receive/change derivation index in this recovery window"},
            {"key_count", RPCArg::Type::NUM, RPCArg::Default{1000}, "Number of indices to scan for each receive/change role (1-10000)"},
            {"start_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Newest child height to scan; omit for the active tip and mempool"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Bounded child recovery page", {
            {RPCResult::Type::STR_HEX, "chain_id", "Exact child-chain identifier"},
            {RPCResult::Type::STR_HEX, "best_block", "Child tip held while this page was scanned"},
            {RPCResult::Type::NUM, "height", "Height of best_block"},
            {RPCResult::Type::NUM, "scanned_from_height", "Newest scanned child height"},
            {RPCResult::Type::NUM, "scanned_to_height", "Oldest scanned child height"},
            {RPCResult::Type::NUM, "key_start", "First derivation index checked"},
            {RPCResult::Type::NUM, "key_count", "Number of indices checked per role"},
            {RPCResult::Type::NUM, "next_key_start", "First index of the next non-overlapping key window"},
            {RPCResult::Type::NUM, "candidate_scripts", "Unique derived scripts checked"},
            {RPCResult::Type::NUM, "matched_transactions", "Transactions involving a candidate script"},
            {RPCResult::Type::NUM, "receive_used", "Observed receive scripts"},
            {RPCResult::Type::NUM, "change_used", "Observed change scripts"},
            {RPCResult::Type::NUM, "receive_next_index", "Next receive derivation index after recovery"},
            {RPCResult::Type::NUM, "change_next_index", "Next change derivation index after recovery"},
            {RPCResult::Type::BOOL, "complete", "Whether the scan reached the beginning of child history"},
            {RPCResult::Type::NUM, "next_height", /*optional=*/true, "Cursor for the next older page"},
        }},
        RPCExamples{
            HelpExampleCli("recoverchildwallet", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet{GetWalletForJSONRPCRequest(request)};
    if (!wallet) return UniValue::VNULL;
    wallet->BlockUntilSyncedToCurrentChain();

    const auto chain_id{ParseChildChainId(self.Arg<UniValue>("chain_id"))};
    EnsureActiveReferenceChild(*wallet, chain_id);
    const int64_t key_start{self.Arg<int>("key_start")};
    const int64_t key_count{self.Arg<int>("key_count")};
    constexpr int64_t MAX_KEY_RANGE_END{2147483647};
    if (key_start < 0 || key_start >= MAX_KEY_RANGE_END) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "key_start must be between 0 and 2147483646");
    }
    if (key_count < 1 || key_count > MAX_CHILD_RECOVERY_KEY_COUNT ||
        key_count > MAX_KEY_RANGE_END - key_start) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("key_count must be between 1 and %d and fit the unhardened derivation range",
                      MAX_CHILD_RECOVERY_KEY_COUNT));
    }
    std::optional<int> start_height;
    if (!request.params[3].isNull()) {
        start_height = request.params[3].getInt<int>();
    }
    if (start_height && *start_height < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "start_height must not be negative");
    }

    const auto derived{wallet->GetChildRecoveryScripts(
        chain_id,
        static_cast<uint32_t>(key_start),
        static_cast<uint32_t>(key_count))};
    if (!derived) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           util::ErrorString(derived).original);
    }
    std::set<CScript> candidates{derived->receive};
    candidates.insert(derived->change.begin(), derived->change.end());
    const auto page{ScanChildWalletHistory(
        *wallet,
        chain_id,
        candidates,
        start_height,
        /*include_mempool=*/!start_height.has_value())};

    std::set<CScript> receive_used;
    std::set<CScript> change_used;
    const auto record_script = [&](const CScript& script) {
        if (derived->receive.contains(script)) {
            receive_used.insert(script);
        } else if (derived->change.contains(script)) {
            change_used.insert(script);
        }
    };
    for (const auto& transaction : page.transactions) {
        for (const CTxOut& output : transaction.transaction->vout) {
            record_script(output.scriptPubKey);
        }
        for (const CTxOut& output : transaction.spent_outputs) {
            record_script(output.scriptPubKey);
        }
    }
    const auto recovered{wallet->ApplyChildRecoveryScripts(
        chain_id, receive_used, change_used)};
    if (!recovered) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           util::ErrorString(recovered).original);
    }

    const int scanned_from{start_height.value_or(
        static_cast<int>(page.height))};
    const int scanned_to{page.next_height ? *page.next_height + 1
                                          : std::min(scanned_from, 1)};
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("best_block", page.best_block.GetHex());
    result.pushKV("height", page.height);
    result.pushKV("scanned_from_height", scanned_from);
    result.pushKV("scanned_to_height", scanned_to);
    result.pushKV("key_start", key_start);
    result.pushKV("key_count", key_count);
    result.pushKV("next_key_start", key_start + key_count);
    result.pushKV("candidate_scripts", candidates.size());
    result.pushKV("matched_transactions", page.transactions.size());
    result.pushKV("receive_used", recovered->receive_used);
    result.pushKV("change_used", recovered->change_used);
    result.pushKV("receive_next_index", recovered->receive_next_index);
    result.pushKV("change_next_index", recovered->change_next_index);
    result.pushKV("complete", !page.next_height.has_value());
    if (page.next_height) result.pushKV("next_height", *page.next_height);
    return result;
},
    };
}

RPCHelpMan getrawchangeaddress()
{
    return RPCHelpMan{
        "getrawchangeaddress",
        "Returns a new Kronein address, for receiving change.\n"
                "This is for use with raw transactions, NOT normal use.\n"
                "When chain_id is present, returns a 32-byte hexadecimal child change recipient.\n",
                {
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::STR, "address", "The main-chain change address, or raw child change recipient when chain_id is present"
                },
                RPCExamples{
                    HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        const auto chain_id{ParseChildChainId(*chain_arg)};
        EnsureActiveReferenceChild(*pwallet, chain_id);
        const auto destination{
            pwallet->GetNewChildChangeDestination(chain_id)};
        if (!destination) {
            throw JSONRPCError(
                RPC_WALLET_KEYPOOL_RAN_OUT,
                util::ErrorString(destination).original);
        }
        const auto* recipient{
            std::get_if<WitnessV1Taproot>(&*destination)};
        if (!recipient) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "wallet did not derive a Taproot child change recipient");
        }
        return HexStr(*recipient);
    }

    LOCK(pwallet->cs_wallet);
    if (!pwallet->CanGetAddresses(true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: This wallet has no available keys");
    }

    auto op_dest = pwallet->GetNewChangeDestination();
    if (!op_dest) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(op_dest).original);
    }
    return EncodeDestination(*op_dest);
},
    };
}


RPCHelpMan setlabel()
{
    return RPCHelpMan{
        "setlabel",
        "Sets the label associated with the given address. When chain_id is present, relabel a wallet-owned non-change child recipient.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Kronein address, or 32-byte hexadecimal recipient when chain_id is present."},
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The label to assign to the address."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("setlabel", "\"" + EXAMPLE_ADDRESS[0] + "\" \"tabby\"")
            + HelpExampleRpc("setlabel", "\"" + EXAMPLE_ADDRESS[0] + "\", \"tabby\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    std::optional<chainregistry::ChainId> child_chain;
    CTxDestination dest;
    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        child_chain = ParseChildChainId(*chain_arg);
        dest = ParseChildRecipient(request.params[0]);
        bool bound{false};
        for (const auto& [owned, _] :
             pwallet->ListChildRecipients(*child_chain)) {
            if (owned == dest) {
                bound = true;
                break;
            }
        }
        if (!bound || !pwallet->IsMine(dest)) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "Recipient not found in child wallet");
        }
        const auto* address_book{pwallet->FindAddressBookEntry(
            dest, /*allow_change=*/true)};
        if (!address_book || address_book->IsChange()) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "Child change recipients cannot be relabeled");
        }
    } else {
        dest = DecodeDestination(request.params[0].get_str());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               "Invalid Kronein address");
        }
    }

    const std::string label{LabelFromValue(request.params[1])};

    const AddressPurpose purpose{
        child_chain || pwallet->IsMine(dest)
            ? AddressPurpose::RECEIVE
            : AddressPurpose::SEND};
    if (!pwallet->SetAddressBook(dest, label, purpose)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Could not persist address label");
    }

    return UniValue::VNULL;
},
    };
}

RPCHelpMan listaddressgroupings()
{
    return RPCHelpMan{
        "listaddressgroupings",
        "Lists groups of addresses which have had their common ownership\n"
                "made public by common use as inputs or as the resulting change\n"
                "in past transactions\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::ARR, "", "",
                        {
                            {RPCResult::Type::ARR_FIXED, "", "",
                            {
                                {RPCResult::Type::STR, "address", "The Kronein address"},
                                {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                                {RPCResult::Type::STR, "label", /*optional=*/true, "The label"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    std::map<CTxDestination, CAmount> balances = GetAddressBalances(*pwallet);
    for (const std::set<CTxDestination>& grouping : GetAddressGroupings(*pwallet)) {
        UniValue jsonGrouping(UniValue::VARR);
        for (const CTxDestination& address : grouping)
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(EncodeDestination(address));
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                const auto* address_book_entry = pwallet->FindAddressBookEntry(address);
                if (address_book_entry) {
                    addressInfo.push_back(address_book_entry->GetLabel());
                }
            }
            jsonGrouping.push_back(std::move(addressInfo));
        }
        jsonGroupings.push_back(std::move(jsonGrouping));
    }
    return jsonGroupings;
},
    };
}

RPCHelpMan keypoolrefill()
{
    return RPCHelpMan{"keypoolrefill",
                "Refills each descriptor keypool in the wallet up to the specified number of new keys.\n"
                "By default, wallets have active external and internal Taproot descriptors, each with " + util::ToString(DEFAULT_KEYPOOL_SIZE) + " entries.\n" +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"newsize", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%u, or as set by -keypool", DEFAULT_KEYPOOL_SIZE)}, "The new keypool size"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (!request.params[0].isNull()) {
        if (request.params[0].getInt<int>() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)request.params[0].getInt<int>();
    }

    EnsureWalletIsUnlocked(*pwallet);
    pwallet->TopUpKeyPool(kpSize);

    if (pwallet->GetKeyPoolSize() < kpSize) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }
    pwallet->RefreshAllTXOs();

    return UniValue::VNULL;
},
    };
}

RPCHelpMan getaddressinfo()
{
    return RPCHelpMan{
        "getaddressinfo",
        "Return information about the given Kronein address.\n"
                "Some of the information will only be present if the address is in the active wallet.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Kronein address, or 32-byte hexadecimal recipient when chain_id is present."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", /*optional=*/true, "The main-chain Kronein address validated; omitted for child results."},
                        {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for main-chain results."},
                        {RPCResult::Type::NUM, "recipient_type", /*optional=*/true, "Reference child recipient namespace; present for child results."},
                        {RPCResult::Type::STR_HEX, "recipient", /*optional=*/true, "32-byte child recipient; present for child results."},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The hex-encoded output script generated by the address."},
                        {RPCResult::Type::BOOL, "ismine", "If the address is yours."},
                        {RPCResult::Type::BOOL, "solvable", "If we know how to spend coins sent to this address, ignoring the possible lack of private keys."},
                        {RPCResult::Type::STR, "desc", /*optional=*/true, "A descriptor for spending coins sent to this address (only when solvable)."},
                        {RPCResult::Type::STR, "parent_desc", /*optional=*/true, "The descriptor used to derive this address if this is a descriptor wallet"},
                        {RPCResult::Type::BOOL, "ischange", "If the address was used for change output."},
                        {RPCResult::Type::NUM, "witness_version", /*optional=*/true, "The version number of the witness program."},
                        {RPCResult::Type::STR_HEX, "witness_program", /*optional=*/true, "The hex value of the witness program."},
                        {RPCResult::Type::NUM_TIME, "timestamp", /*optional=*/true, "The creation time of the key, if available, expressed in " + UNIX_EPOCH_TIME + "."},
                        {RPCResult::Type::STR, "hdkeypath", /*optional=*/true, "The HD keypath, if the key is HD and available."},
                        {RPCResult::Type::STR_HEX, "hdmasterfingerprint", /*optional=*/true, "The fingerprint of the master key."},
                        {RPCResult::Type::ARR, "labels", "Array of labels associated with the address. Currently limited to one label but returned\n"
                            "as an array to keep the API stable if multiple labels are enabled in the future.",
                        {
                            {RPCResult::Type::STR, "label name", "Label name (defaults to \"\")."},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getaddressinfo", "\"" + EXAMPLE_ADDRESS[0] + "\"") +
                    HelpExampleRpc("getaddressinfo", "\"" + EXAMPLE_ADDRESS[0] + "\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    std::optional<chainregistry::ChainId> child_chain;
    CTxDestination dest;
    bool child_bound{false};
    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        child_chain = ParseChildChainId(*chain_arg);
        dest = ParseChildRecipient(request.params[0]);
        for (const auto& [owned, _] :
             pwallet->ListChildRecipients(*child_chain)) {
            if (owned == dest) {
                child_bound = true;
                break;
            }
        }
    } else {
        std::string error_msg;
        dest = DecodeDestination(request.params[0].get_str(), error_msg);
        if (!IsValidDestination(dest)) {
            if (error_msg.empty()) error_msg = "Invalid address";
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error_msg);
        }
    }

    UniValue ret(UniValue::VOBJ);

    if (child_chain) {
        ret.pushKV("chain_id", child_chain->GetHex());
        ret.pushKV("recipient_type",
                   chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT);
        ret.pushKV("recipient", HexStr(std::get<WitnessV1Taproot>(dest)));
    } else {
        ret.pushKV("address", EncodeDestination(dest));
    }

    CScript scriptPubKey = GetScriptForDestination(dest);
    ret.pushKV("scriptPubKey", HexStr(scriptPubKey));

    std::unique_ptr<SigningProvider> provider;
    if (!child_chain || child_bound) {
        provider = pwallet->GetSolvingProvider(scriptPubKey);
    }

    bool mine = (!child_chain || child_bound) && pwallet->IsMine(dest);
    ret.pushKV("ismine", mine);

    if (provider) {
        if (auto inferred{InferDescriptor(scriptPubKey, *provider)}) {
            const bool solvable{inferred->IsSolvable()};
            ret.pushKV("solvable", solvable);
            if (solvable) {
                ret.pushKV("desc", inferred->ToString());
            }
        } else {
            ret.pushKV("solvable", false);
        }
    } else {
        ret.pushKV("solvable", false);
    }

    const auto spk_mans{child_chain && !child_bound
        ? std::set<ScriptPubKeyMan*>{}
        : pwallet->GetScriptPubKeyMans(scriptPubKey)};
    // In most cases there is only one matching ScriptPubKey manager and we can't resolve ambiguity in a better way
    ScriptPubKeyMan* spk_man{nullptr};
    if (spk_mans.size()) spk_man = *spk_mans.begin();

    DescriptorScriptPubKeyMan* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
    if (desc_spk_man) {
        std::string desc_str;
        if (desc_spk_man->GetDescriptorString(desc_str, /*priv=*/false)) {
            ret.pushKV("parent_desc", desc_str);
        }
    }

    UniValue detail = DescribeAddress(dest);
    ret.pushKVs(std::move(detail));

    bool is_change{false};
    if (child_chain) {
        if (const auto* entry{pwallet->FindAddressBookEntry(
                dest, /*allow_change=*/true)}; child_bound && entry) {
            is_change = entry->IsChange();
        }
    } else {
        is_change = ScriptIsChange(*pwallet, scriptPubKey);
    }
    ret.pushKV("ischange", is_change);

    if (spk_man) {
        if (const std::unique_ptr<KeyMetadata> meta = spk_man->GetMetadata(dest)) {
            ret.pushKV("timestamp", meta->creation_time);
            ret.pushKV("hdkeypath", WriteHDKeypath(meta->key_origin.path, /*apostrophe=*/false));
            ret.pushKV("hdmasterfingerprint", HexStr(meta->key_origin.fingerprint));
        }
    }

    // Return a `labels` array containing the label associated with the address,
    // equivalent to the `label` field above. Currently only one label can be
    // associated with an address, but we return an array so the API remains
    // stable if we allow multiple labels to be associated with an address in
    // the future.
    UniValue labels(UniValue::VARR);
    const auto* address_book_entry = pwallet->FindAddressBookEntry(dest);
    if (address_book_entry) {
        labels.push_back(address_book_entry->GetLabel());
    }
    ret.pushKV("labels", std::move(labels));

    return ret;
},
    };
}

RPCHelpMan getaddressesbylabel()
{
    return RPCHelpMan{
        "getaddressesbylabel",
        "Returns the list of addresses assigned the specified label. When chain_id is present, keys are raw child recipients.\n",
                {
                    {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "The label."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::OBJ_DYN, "", "json object with addresses as keys",
                    {
                        {RPCResult::Type::OBJ, "address", "json object with information about address",
                        {
                            {RPCResult::Type::STR, "purpose", "Purpose of address (\"send\" for sending address, \"receive\" for receiving address)"},
                            {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; present for child results"},
                            {RPCResult::Type::NUM, "recipient_type", /*optional=*/true, "Reference child recipient namespace; present for child results"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("getaddressesbylabel", "\"tabby\"")
            + HelpExampleRpc("getaddressesbylabel", "\"tabby\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    const std::string label{LabelFromValue(request.params[0])};

    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        const auto chain_id{ParseChildChainId(*chain_arg)};
        UniValue result{UniValue::VOBJ};
        for (const auto& [destination, recipient_label] :
             pwallet->ListChildRecipients(chain_id)) {
            const auto* recipient{
                std::get_if<WitnessV1Taproot>(&destination)};
            const auto* address_book{pwallet->FindAddressBookEntry(
                destination, /*allow_change=*/true)};
            if (!recipient || !address_book) {
                throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    "wallet contains an invalid child recipient context");
            }
            if (address_book->IsChange() || recipient_label != label) {
                continue;
            }
            UniValue value{UniValue::VOBJ};
            value.pushKV("purpose", "receive");
            value.pushKV("chain_id", chain_id.GetHex());
            value.pushKV("recipient_type",
                         chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT);
            result.pushKVEnd(HexStr(*recipient), std::move(value));
        }
        if (result.empty()) {
            throw JSONRPCError(
                RPC_WALLET_INVALID_LABEL_NAME,
                std::string("No child recipients with label " + label));
        }
        return result;
    }

    // Find all addresses that have the given label
    UniValue ret(UniValue::VOBJ);
    std::set<std::string> addresses;
    pwallet->ForEachAddrBookEntry([&](const CTxDestination& _dest, const std::string& _label, bool _is_change, const std::optional<AddressPurpose>& _purpose) {
        if (_is_change) return;
        if (_label == label) {
            std::string address = EncodeDestination(_dest);
            // CWallet::m_address_book is not expected to contain duplicate
            // address strings, but build a separate set as a precaution just in
            // case it does.
            bool unique = addresses.emplace(address).second;
            CHECK_NONFATAL(unique);
            // UniValue::pushKV checks if the key exists in O(N)
            // and since duplicate addresses are unexpected (checked with
            // std::set in O(log(N))), UniValue::pushKVEnd is used instead,
            // which currently is O(1).
            UniValue value(UniValue::VOBJ);
            value.pushKV("purpose", _purpose ? PurposeToString(*_purpose) : "unknown");
            ret.pushKVEnd(address, std::move(value));
        }
    });

    if (ret.empty()) {
        throw JSONRPCError(RPC_WALLET_INVALID_LABEL_NAME, std::string("No addresses with label " + label));
    }

    return ret;
},
    };
}

RPCHelpMan listlabels()
{
    return RPCHelpMan{
        "listlabels",
        "Returns the list of all labels, or labels that are assigned to addresses with a specific purpose. When chain_id is present, only labels of that child's receiving recipients are returned.\n",
                {
                    {"purpose", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Address purpose to list labels for ('send','receive'). An empty string is the same as not providing this argument."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::STR, "label", "Label name"},
                    }
                },
                RPCExamples{
            "\nList all labels\n"
            + HelpExampleCli("listlabels", "") +
            "\nList labels that have receiving addresses\n"
            + HelpExampleCli("listlabels", "receive") +
            "\nList labels that have sending addresses\n"
            + HelpExampleCli("listlabels", "send") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listlabels", "receive")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    std::optional<AddressPurpose> purpose;
    if (!request.params[0].isNull()) {
        std::string purpose_str = request.params[0].get_str();
        if (!purpose_str.empty()) {
            purpose = PurposeFromString(purpose_str);
            if (!purpose) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid 'purpose' argument, must be a known purpose string, typically 'send', or 'receive'.");
            }
        }
    }

    std::set<std::string> label_set;
    if (const auto chain_arg{self.MaybeArg<UniValue>("chain_id")}) {
        const auto chain_id{ParseChildChainId(*chain_arg)};
        if (!purpose || *purpose == AddressPurpose::RECEIVE) {
            for (const auto& [destination, label] :
                 pwallet->ListChildRecipients(chain_id)) {
                const auto* address_book{pwallet->FindAddressBookEntry(
                    destination, /*allow_change=*/true)};
                if (!address_book) {
                    throw JSONRPCError(
                        RPC_WALLET_ERROR,
                        "wallet child recipient is missing its address-book record");
                }
                if (!address_book->IsChange()) label_set.insert(label);
            }
        }
    } else {
        label_set = pwallet->ListAddrBookLabels(purpose);
    }

    UniValue ret(UniValue::VARR);
    for (const std::string& name : label_set) {
        ret.push_back(name);
    }

    return ret;
},
    };
}


#ifdef ENABLE_EXTERNAL_SIGNER
RPCHelpMan walletdisplayaddress()
{
    return RPCHelpMan{
        "walletdisplayaddress",
        "Display address on an external signer for verification.",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Kronein address to display"},
        },
        RPCResult{
            RPCResult::Type::OBJ,"","",
            {
                {RPCResult::Type::STR, "address", "The address as confirmed by the signer"},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;
            CWallet* const pwallet = wallet.get();

            LOCK(pwallet->cs_wallet);

            CTxDestination dest = DecodeDestination(request.params[0].get_str());

            // Make sure the destination is valid
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }

            util::Result<void> res = pwallet->DisplayAddress(dest);
            if (!res) throw JSONRPCError(RPC_MISC_ERROR, util::ErrorString(res).original);

            UniValue result(UniValue::VOBJ);
            result.pushKV("address", request.params[0].get_str());
            return result;
        }
    };
}
#endif // ENABLE_EXTERNAL_SIGNER
} // namespace wallet
