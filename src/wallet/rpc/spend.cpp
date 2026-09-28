// Copyright (c) 2011-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainregistry/child_template.h>
#include <common/messages.h>
#include <consensus/chainregistry.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key_io.h>
#include <node/types.h>
#include <policy/policy.h>
#include <primitives/chainregistry.h>
#include <primitives/deposit.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/util.h>
#include <script/script.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/translation.h>
#include <util/vector.h>
#include <wallet/coincontrol.h>
#include <wallet/feebumper.h>
#include <wallet/fees.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

using common::FeeModeFromString;
using common::FeeModesDetail;
using common::InvalidEstimateModeErrorMessage;
using common::StringForFeeReason;
using common::TransactionErrorString;
using node::TransactionError;

namespace wallet {
std::vector<CRecipient> CreateRecipients(const std::vector<std::pair<CTxDestination, CAmount>>& outputs, const std::set<int>& subtract_fee_outputs)
{
    std::vector<CRecipient> recipients;
    for (size_t i = 0; i < outputs.size(); ++i) {
        const auto& [destination, amount] = outputs.at(i);
        CRecipient recipient{destination, amount, subtract_fee_outputs.contains(i)};
        recipients.push_back(recipient);
    }
    return recipients;
}

static uint32_t ParseRegistryUint32(const UniValue& value, std::string_view name)
{
    const int64_t parsed{value.getInt<int64_t>()};
    if (parsed < 0 || static_cast<uint64_t>(parsed) >= std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must be between 0 and %u", name,
                                     std::numeric_limits<uint32_t>::max() - 1));
    }
    return static_cast<uint32_t>(parsed);
}

static chainregistry::ChainId ParseRegistryChainId(const UniValue& value)
{
    const auto chain_id{chainregistry::ChainId::FromHex(value.get_str())};
    if (!chain_id || chain_id->IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "chain_id must be exactly 32 non-null bytes encoded as hexadecimal");
    }
    return *chain_id;
}

static chainregistry::MetadataHash ParseRegistryMetadataHash(const UniValue& value)
{
    const auto metadata_hash{chainregistry::MetadataHash::FromHex(value.get_str())};
    if (!metadata_hash || metadata_hash->IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "metadata_hash must be exactly 32 non-null bytes encoded as hexadecimal");
    }
    return *metadata_hash;
}

static chainregistry::FundChain ParseFundDestination(const UniValue& chain_id_arg,
                                                     const UniValue& recipient_type_arg,
                                                     const UniValue& recipient_arg)
{
    const uint32_t recipient_type{ParseRegistryUint32(recipient_type_arg, "recipient_type")};
    if (recipient_type == 0 || recipient_type > std::numeric_limits<uint16_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "recipient_type must be between 1 and 65535");
    }
    if (recipient_arg.get_str().empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "recipient must contain at least 1 byte");
    }
    chainregistry::FundChain fund{
        .chain_id = ParseRegistryChainId(chain_id_arg),
        .recipient_type = static_cast<uint16_t>(recipient_type),
        .recipient = ParseHexV(recipient_arg, "recipient"),
    };
    switch (chainregistry::ValidateFund(fund)) {
    case chainregistry::FundValidationError::NONE:
        return fund;
    case chainregistry::FundValidationError::EMPTY_RECIPIENT:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "recipient must contain at least 1 byte");
    case chainregistry::FundValidationError::RECIPIENT_TOO_LARGE:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "recipient must not exceed 64 bytes");
    default:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid child deposit destination");
    }
}

static void ValidateFundDestinationForTemplate(
    const chainregistry::ChainRecord& record,
    const chainregistry::FundChain& fund)
{
    if (record.template_id != chainregistry::REFERENCE_CHILD_TEMPLATE_ID ||
        record.template_version != chainregistry::REFERENCE_CHILD_TEMPLATE_VERSION) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("wallet cannot validate deposit recipients for child template %u version %u",
                      record.template_id, record.template_version));
    }
    if (!chainregistry::IsValidReferenceChildRecipient(
            fund.recipient_type, fund.recipient)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "reference child template v1 requires recipient_type 1 and a valid 32-byte P2TR output key");
    }
}

static COutPoint ParseRegistryOutPoint(const UniValue& value, std::string_view name)
{
    const UniValue& object{value.get_obj()};
    RPCTypeCheckObj(object,
                    {{"txid", UniValueType{UniValue::VSTR}},
                     {"vout", UniValueType{UniValue::VNUM}}},
                    /*fAllowNull=*/false,
                    /*fStrict=*/true);
    const COutPoint outpoint{
        Txid::FromUint256(ParseHashO(object, "txid")),
        ParseRegistryUint32(object.find_value("vout"), strprintf("%s.vout", name))};
    if (outpoint.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must not be null", name));
    }
    return outpoint;
}

static chainregistry::ChainSpec ParseRegistryChainSpec(const UniValue& value)
{
    const UniValue& object{value.get_obj()};
    RPCTypeCheckObj(object,
                    {{"template_id", UniValueType{UniValue::VNUM}},
                     {"template_version", UniValueType{UniValue::VNUM}},
                     {"consensus_parameters", UniValueType{UniValue::VSTR}},
                     {"anchoring_policy", UniValueType{UniValue::VSTR}}},
                    /*fAllowNull=*/true,
                    /*fStrict=*/true);
    if (!object.exists("template_id") || !object.exists("template_version") ||
        !object.exists("consensus_parameters")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "spec requires template_id, template_version, and consensus_parameters");
    }
    if (object.exists("anchoring_policy") && object.find_value("anchoring_policy").get_str() != "bmm_v1") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "anchoring_policy must be bmm_v1");
    }

    chainregistry::ChainSpec spec{
        .protocol_version = chainregistry::PROTOCOL_VERSION,
        .template_id = ParseRegistryUint32(object.find_value("template_id"), "spec.template_id"),
        .template_version = ParseRegistryUint32(object.find_value("template_version"), "spec.template_version"),
        .consensus_parameters = ParseHexO(object, "consensus_parameters"),
        .anchoring_policy = chainregistry::AnchoringPolicy::BMM_V1,
    };
    switch (chainregistry::ValidateChainSpec(spec)) {
    case chainregistry::ManifestValidationError::NONE:
        return spec;
    case chainregistry::ManifestValidationError::INVALID_TEMPLATE_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "spec.template_id must be greater than zero");
    case chainregistry::ManifestValidationError::INVALID_TEMPLATE_VERSION:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "spec.template_version must be greater than zero");
    case chainregistry::ManifestValidationError::CONSENSUS_PARAMETERS_TOO_LARGE:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("spec.consensus_parameters exceeds %u bytes",
                                     chainregistry::MAX_CONSENSUS_PARAMETERS_SIZE));
    default:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid child-chain specification");
    }
}

static uint256 ParseRegistryHash(const UniValue& object, std::string_view key)
{
    const uint256 hash{ParseHashO(object, key)};
    if (hash.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must not be null", key));
    }
    return hash;
}

static CTxDestination ParseRegistryControlDestination(const UniValue& parameters)
{
    if (!parameters.exists("control_address")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "control_address is required");
    }
    const CTxDestination destination{DecodeDestination(parameters.find_value("control_address").get_str())};
    if (!IsValidDestination(destination) || !GetScriptForDestination(destination).IsPayToTaproot()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "control_address must be a valid Kronein Taproot (bech32m) address");
    }
    return destination;
}

static CAmount RegistryControlAmount(CWallet& wallet,
                                     const UniValue& parameters,
                                     const CTxDestination& destination)
{
    const CScript script{GetScriptForDestination(destination)};
    const CAmount minimum{GetDustThreshold(CTxOut{0, script}, wallet.chain().relayDustFee())};
    const CAmount amount{parameters.exists("control_amount")
                             ? AmountFromValue(parameters.find_value("control_amount"))
                             : minimum};
    if (amount < minimum) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("control_amount must be at least %s KNE",
                                     FormatMoney(minimum)));
    }
    return amount;
}

static void InterpretFeeEstimationInstructions(const UniValue& conf_target, const UniValue& estimate_mode, const UniValue& fee_rate, UniValue& options)
{
    if (options.exists("conf_target") || options.exists("estimate_mode")) {
        if (!conf_target.isNull() || !estimate_mode.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Pass conf_target and estimate_mode either as arguments or in the options object, but not both");
        }
    } else {
        options.pushKV("conf_target", conf_target);
        options.pushKV("estimate_mode", estimate_mode);
    }
    if (options.exists("fee_rate")) {
        if (!fee_rate.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Pass the fee_rate either as an argument, or in the options object, but not both");
        }
    } else {
        options.pushKV("fee_rate", fee_rate);
    }
    if (!options["conf_target"].isNull() && (options["estimate_mode"].isNull() || (options["estimate_mode"].get_str() == "unset"))) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Specify estimate_mode");
    }
}

std::set<int> InterpretSubtractFeeFromOutputInstructions(const UniValue& sffo_instructions, const std::vector<std::string>& destinations)
{
    std::set<int> sffo_set;
    if (sffo_instructions.isNull()) return sffo_set;

    for (const auto& sffo : sffo_instructions.getValues()) {
        int pos{-1};
        if (sffo.isStr()) {
            auto it = find(destinations.begin(), destinations.end(), sffo.get_str());
            if (it == destinations.end()) throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter 'subtract fee from output', destination %s not found in tx outputs", sffo.get_str()));
            pos = it - destinations.begin();
        } else if (sffo.isNum()) {
            pos = sffo.getInt<int>();
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter 'subtract fee from output', invalid value type: %s", uvTypeName(sffo.type())));
        }

        if (sffo_set.contains(pos))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter 'subtract fee from output', duplicated position: %d", pos));
        if (pos < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter 'subtract fee from output', negative position: %d", pos));
        if (pos >= int(destinations.size()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter 'subtract fee from output', position too large: %d", pos));
        sffo_set.insert(pos);
    }
    return sffo_set;
}

static UniValue FinishTransaction(const std::shared_ptr<CWallet> pwallet, const UniValue& options, CMutableTransaction& rawTx)
{
    bool can_anti_fee_snipe = !options.exists("locktime");

    for (const CTxIn& tx_in : rawTx.vin) {
        // Checks sequence values consistent with DiscourageFeeSniping
        can_anti_fee_snipe = can_anti_fee_snipe && (tx_in.nSequence == CTxIn::MAX_SEQUENCE_NONFINAL || tx_in.nSequence == MAX_BIP125_RBF_SEQUENCE);
    }

    if (can_anti_fee_snipe) {
        LOCK(pwallet->cs_wallet);
        FastRandomContext rng_fast;
        DiscourageFeeSniping(rawTx, rng_fast, pwallet->chain(), pwallet->GetLastBlockHash(), pwallet->GetLastBlockHeight());
    }

    // Make a blank psbt
    PartiallySignedTransaction psbtx(rawTx);

    // First fill transaction with our data without signing,
    // so external signers are not asked to sign more than once.
    bool complete;
    pwallet->FillPSBT(psbtx, {.sign = false, .bip32_derivs = true}, complete);
    const auto err{pwallet->FillPSBT(psbtx, {.sign = true, .bip32_derivs = false}, complete)};
    if (err) {
        throw JSONRPCPSBTError(*err);
    }

    CMutableTransaction mtx;
    complete = FinalizeAndExtractPSBT(psbtx, mtx);

    UniValue result(UniValue::VOBJ);

    const bool psbt_opt_in{options.exists("psbt") && options["psbt"].get_bool()};
    bool add_to_wallet{options.exists("add_to_wallet") ? options["add_to_wallet"].get_bool() : true};
    if (psbt_opt_in || !complete || !add_to_wallet) {
        // Serialize the PSBT
        DataStream ssTx{};
        ssTx << psbtx;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
    }

    if (complete) {
        std::string hex{EncodeHexTx(CTransaction(mtx))};
        CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
        result.pushKV("txid", tx->GetHash().GetHex());
        if (add_to_wallet && !psbt_opt_in) {
            pwallet->CommitTransaction(tx, {}, /*orderForm=*/{});
        } else {
            result.pushKV("hex", hex);
        }
    }
    result.pushKV("complete", complete);

    return result;
}

UniValue SendMoney(CWallet& wallet, const CCoinControl &coin_control, std::vector<CRecipient> &recipients, mapValue_t map_value, bool verbose)
{
    EnsureWalletIsUnlocked(wallet);

    // This function is only used by sendtoaddress and sendmany.
    // This should always try to sign, if we don't have private keys, don't try to do anything here.
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }

    // Shuffle recipient list
    std::shuffle(recipients.begin(), recipients.end(), FastRandomContext());

    // Send
    auto res = CreateTransaction(wallet, recipients, /*change_pos=*/std::nullopt, coin_control, true);
    if (!res) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, util::ErrorString(res).original);
    }
    const CTransactionRef& tx = res->tx;
    wallet.CommitTransaction(tx, std::move(map_value), /*orderForm=*/{});
    if (verbose) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", tx->GetHash().GetHex());
        entry.pushKV("fee_reason", StringForFeeReason(res->fee_calc.reason));
        return entry;
    }
    return tx->GetHash().GetHex();
}


/**
 * Update coin control with fee estimation based on the given parameters
 *
 * @param[in]     wallet            Wallet reference
 * @param[in,out] cc                Coin control to be updated
 * @param[in]     conf_target       UniValue integer; confirmation target in blocks, values between 1 and 1008 are valid per policy/fees/block_policy_estimator.h;
 * @param[in]     estimate_mode     UniValue string; fee estimation mode, valid values are "unset", "economical" or "conservative";
 * @param[in]     fee_rate          UniValue real; fee rate in sat/vB;
 *                                      if present, both conf_target and estimate_mode must either be null, or "unset"
 * @param[in]     override_min_fee  bool; whether to set fOverrideFeeRate to true to disable minimum fee rate checks and instead
 *                                      verify only that fee_rate is greater than 0
 * @throws a JSONRPCError if conf_target, estimate_mode, or fee_rate contain invalid values or are in conflict
 */
static void SetFeeEstimateMode(const CWallet& wallet, CCoinControl& cc, const UniValue& conf_target, const UniValue& estimate_mode, const UniValue& fee_rate, bool override_min_fee)
{
    if (!fee_rate.isNull()) {
        if (!conf_target.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both conf_target and fee_rate. Please provide either a confirmation target in blocks for automatic fee estimation, or an explicit fee rate.");
        }
        if (!estimate_mode.isNull() && estimate_mode.get_str() != "unset") {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both estimate_mode and fee_rate");
        }
        // Fee rates in sat/vB cannot represent more than 3 significant digits.
        cc.m_feerate = CFeeRate{AmountFromValue(fee_rate, /*decimals=*/3)};
        if (override_min_fee) cc.fOverrideFeeRate = true;
        // Default RBF to true for explicit fee_rate, if unset.
        if (!cc.m_signal_bip125_rbf) cc.m_signal_bip125_rbf = true;
        return;
    }
    if (!estimate_mode.isNull() && !FeeModeFromString(estimate_mode.get_str(), cc.m_fee_mode)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, InvalidEstimateModeErrorMessage());
    }
    if (!conf_target.isNull()) {
        cc.m_confirm_target = ParseConfirmTarget(conf_target, wallet.chain().estimateMaxBlocks());
    }
}

RPCHelpMan sendtoaddress()
{
    return RPCHelpMan{
        "sendtoaddress",
        "Send an amount to a given address." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Kronein address to send to."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to send. eg 0.1"},
                    {"comment", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A comment used to store what the transaction is for.\n"
                                         "This is not part of the transaction, just kept in your wallet."},
                    {"comment_to", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A comment to store the name of the person or organization\n"
                                         "to which you're sending the transaction. This is not part of the \n"
                                         "transaction, just kept in your wallet."},
                    {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "The fee will be deducted from the amount being sent.\n"
                                         "The recipient will receive less KNE than you enter in the amount field."},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Signal that this transaction can be replaced by a transaction (BIP 125)"},
                    {"conf_target", RPCArg::Type::NUM, RPCArg::DefaultHint{"wallet -txconfirmtarget"}, "Confirmation target in blocks"},
                    {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"unset"}, "The fee estimate mode, must be one of (case insensitive):\n"
                      + FeeModesDetail(std::string("economical mode is used if the transaction is replaceable;\notherwise, conservative mode is used"))},
                    {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{true}, "(only available if avoid_reuse wallet flag is set) Avoid spending from dirty addresses; addresses are considered\n"
                                         "dirty if they have previously been used in a transaction. If true, this also activates avoidpartialspends, grouping outputs by their addresses."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "txid", "The transaction id."
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
                            {RPCResult::Type::STR, "fee_reason", "The transaction fee reason."}
                        },
                    },
                },
                RPCExamples{
                    "\nSend 0.1 KNE\n"
                    + HelpExampleCli("sendtoaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0.1") +
                    "\nSend 0.1 KNE with a confirmation target of 6 blocks in economical fee estimate mode using positional arguments\n"
                    + HelpExampleCli("sendtoaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0.1 \"donation\" \"sean's outpost\" false true 6 economical") +
                    "\nSend 0.1 KNE with a fee rate of 1.1 " + CURRENCY_ATOM + "/vB, subtract fee from amount, BIP125-replaceable, using positional arguments\n"
                    + HelpExampleCli("sendtoaddress", "\"" + EXAMPLE_ADDRESS[0] + "\" 0.1 \"drinks\" \"room77\" true true null \"unset\" null 1.1") +
                    "\nSend 0.2 KNE with a confirmation target of 6 blocks in economical fee estimate mode using named arguments\n"
                    + HelpExampleCli("-named sendtoaddress", "address=\"" + EXAMPLE_ADDRESS[0] + "\" amount=0.2 conf_target=6 estimate_mode=\"economical\"") +
                    "\nSend 0.5 KNE with a fee rate of 25 " + CURRENCY_ATOM + "/vB using named arguments\n"
                    + HelpExampleCli("-named sendtoaddress", "address=\"" + EXAMPLE_ADDRESS[0] + "\" amount=0.5 fee_rate=25")
                    + HelpExampleCli("-named sendtoaddress", "address=\"" + EXAMPLE_ADDRESS[0] + "\" amount=0.5 fee_rate=25 subtractfeefromamount=false replaceable=true avoid_reuse=true comment=\"2 pizzas\" comment_to=\"jeremy\" verbose=true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    // Wallet comments
    mapValue_t mapValue;
    if (!request.params[2].isNull() && !request.params[2].get_str().empty())
        mapValue["comment"] = request.params[2].get_str();
    if (!request.params[3].isNull() && !request.params[3].get_str().empty())
        mapValue["to"] = request.params[3].get_str();

    CCoinControl coin_control;
    if (!request.params[5].isNull()) {
        coin_control.m_signal_bip125_rbf = request.params[5].get_bool();
    }

    coin_control.m_avoid_address_reuse = GetAvoidReuseFlag(*pwallet, request.params[8]);
    // We also enable partial spend avoidance if reuse avoidance is set.
    coin_control.m_avoid_partial_spends |= coin_control.m_avoid_address_reuse;

    SetFeeEstimateMode(*pwallet, coin_control, /*conf_target=*/request.params[6], /*estimate_mode=*/request.params[7], /*fee_rate=*/request.params[9], /*override_min_fee=*/false);

    EnsureWalletIsUnlocked(*pwallet);

    UniValue address_amounts(UniValue::VOBJ);
    const std::string address = request.params[0].get_str();
    address_amounts.pushKV(address, request.params[1]);

    std::set<int> sffo_set;
    if (!request.params[4].isNull() && request.params[4].get_bool()) {
        sffo_set.insert(0);
    }

    std::vector<CRecipient> recipients{CreateRecipients(ParseOutputs(address_amounts), sffo_set)};
    const bool verbose{request.params[10].isNull() ? false : request.params[10].get_bool()};

    return SendMoney(*pwallet, coin_control, recipients, mapValue, verbose);
},
    };
}

RPCHelpMan sendmany()
{
    return RPCHelpMan{"sendmany",
        "Send multiple times. Amounts are double-precision floating point numbers." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"amounts", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::NO, "The addresses and amounts",
                        {
                            {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The Kronein address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value"},
                        },
                    },
                    {"comment", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A comment"},
                    {"subtractfeefrom", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "The addresses.\n"
                                       "The fee will be equally deducted from the amount of each selected address.\n"
                                       "Those recipients will receive less KNE than you enter in their corresponding amount field.\n"
                                       "If no addresses are specified here, the sender pays the fee.",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Subtract fee from this address"},
                        },
                    },
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Signal that this transaction can be replaced by a transaction (BIP 125)"},
                    {"conf_target", RPCArg::Type::NUM, RPCArg::DefaultHint{"wallet -txconfirmtarget"}, "Confirmation target in blocks"},
                    {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"unset"}, "The fee estimate mode, must be one of (case insensitive):\n"
                      + FeeModesDetail(std::string("economical mode is used if the transaction is replaceable;\notherwise, conservative mode is used"))},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "txid", "The transaction id for the send. Only 1 transaction is created regardless of\n"
                "the number of addresses."
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id for the send. Only 1 transaction is created regardless of\n"
                "the number of addresses."},
                            {RPCResult::Type::STR, "fee_reason", "The transaction fee reason."}
                        },
                    },
                },
                RPCExamples{
            "\nSend two amounts to two different addresses:\n"
            + HelpExampleCli("sendmany", "\"{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.01,\\\"" + EXAMPLE_ADDRESS[1] + "\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n"
            + HelpExampleCli("sendmany", "\"{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.01,\\\"" + EXAMPLE_ADDRESS[1] + "\\\":0.02}\" \"testing\"") +
            "\nSend two amounts to two different addresses, subtract fee from amount:\n"
            + HelpExampleCli("sendmany", "\"{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.01,\\\"" + EXAMPLE_ADDRESS[1] + "\\\":0.02}\" \"\" \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("sendmany", "{\"" + EXAMPLE_ADDRESS[0] + "\":0.01,\"" + EXAMPLE_ADDRESS[1] + "\":0.02}, \"testing\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    UniValue sendTo = request.params[0].get_obj();

    mapValue_t mapValue;
    if (!request.params[1].isNull() && !request.params[1].get_str().empty())
        mapValue["comment"] = request.params[1].get_str();

    CCoinControl coin_control;
    if (!request.params[3].isNull()) {
        coin_control.m_signal_bip125_rbf = request.params[3].get_bool();
    }

    SetFeeEstimateMode(*pwallet, coin_control, /*conf_target=*/request.params[4], /*estimate_mode=*/request.params[5], /*fee_rate=*/request.params[6], /*override_min_fee=*/false);

    std::vector<CRecipient> recipients = CreateRecipients(
            ParseOutputs(sendTo),
            InterpretSubtractFeeFromOutputInstructions(request.params[2], sendTo.getKeys())
    );
    const bool verbose{request.params[7].isNull() ? false : request.params[7].get_bool()};

    return SendMoney(*pwallet, coin_control, recipients, std::move(mapValue), verbose);
},
    };
}

// Only includes key documentation where the key is snake_case in all RPC methods. MixedCase keys can be added later.
static std::vector<RPCArg> FundTxDoc(bool solving_data = true)
{
    std::vector<RPCArg> args = {
        {"conf_target", RPCArg::Type::NUM, RPCArg::DefaultHint{"wallet -txconfirmtarget"}, "Confirmation target in blocks", RPCArgOptions{.also_positional = true}},
        {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"unset"}, "The fee estimate mode, must be one of (case insensitive):\n"
          + FeeModesDetail(std::string("economical mode is used if the transaction is replaceable;\notherwise, conservative mode is used")), RPCArgOptions{.also_positional = true}},
        {
            "replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Marks this transaction as BIP125-replaceable.\n"
            "Allows this transaction to be replaced by a transaction with higher fees"
        },
    };
    if (solving_data) {
        args.push_back({"solving_data", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Keys and scripts needed for producing a final transaction with a dummy signature.\n"
        "Used for fee estimation during coin selection.",
            {
                {
                    "pubkeys", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Public keys involved in this transaction.",
                    {
                        {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A public key"},
                    }
                },
                {
                    "scripts", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Scripts involved in this transaction.",
                    {
                        {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A script"},
                    }
                },
                {
                    "descriptors", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Descriptors that provide solving data for this transaction.",
                    {
                        {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A descriptor"},
                    }
                },
            }
        });
    }
    return args;
}

CreatedTransactionResult FundTransaction(CWallet& wallet, const CMutableTransaction& tx, const std::vector<CRecipient>& recipients, const UniValue& options, CCoinControl& coinControl, bool override_min_fee)
{
    // We want to make sure tx.vout is not used now that we are passing outputs as a vector of recipients.
    // This sets us up to remove tx completely in a future PR in favor of passing the inputs directly.
    CHECK_NONFATAL(tx.vout.empty());
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    std::optional<unsigned int> change_position;
    bool lock_unspents = false;
    if (!options.isNull()) {
        RPCTypeCheckObj(options,
            {
                {"add_inputs", UniValueType(UniValue::VBOOL)},
                {"include_unsafe", UniValueType(UniValue::VBOOL)},
                {"add_to_wallet", UniValueType(UniValue::VBOOL)},
                {"change_address", UniValueType(UniValue::VSTR)},
                {"change_position", UniValueType(UniValue::VNUM)},
                {"inputs", UniValueType(UniValue::VARR)},
                {"lock_unspents", UniValueType(UniValue::VBOOL)},
                {"locktime", UniValueType(UniValue::VNUM)},
                {"fee_rate", UniValueType()}, // will be checked by AmountFromValue() in SetFeeEstimateMode()
                {"psbt", UniValueType(UniValue::VBOOL)},
                {"solving_data", UniValueType(UniValue::VOBJ)},
                {"subtract_fee_from_outputs", UniValueType(UniValue::VARR)},
                {"replaceable", UniValueType(UniValue::VBOOL)},
                {"conf_target", UniValueType(UniValue::VNUM)},
                {"estimate_mode", UniValueType(UniValue::VSTR)},
                {"minconf", UniValueType(UniValue::VNUM)},
                {"maxconf", UniValueType(UniValue::VNUM)},
                {"input_weights", UniValueType(UniValue::VARR)},
                {"max_tx_weight", UniValueType(UniValue::VNUM)},
            },
            true, true);

        if (options.exists("add_inputs")) {
            coinControl.m_allow_other_inputs = options["add_inputs"].get_bool();
        }

        if (options.exists("change_address")) {
            const std::string change_address_str = options["change_address"].get_str();
            CTxDestination dest = DecodeDestination(change_address_str);

            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Change address must be a valid Kronein address");
            }

            coinControl.destChange = dest;
        }

        if (options.exists("change_position")) {
            int pos = options["change_position"].getInt<int>();
            if (pos < 0 || (unsigned int)pos > recipients.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "change_position out of bounds");
            }
            change_position = (unsigned int)pos;
        }

        if (options.exists("lock_unspents")) {
            lock_unspents = options["lock_unspents"].get_bool();
        }

        if (options.exists("include_unsafe")) {
            coinControl.m_include_unsafe_inputs = options["include_unsafe"].get_bool();
        }

        if (options.exists("replaceable")) {
            coinControl.m_signal_bip125_rbf = options["replaceable"].get_bool();
        }

        if (options.exists("minconf")) {
            coinControl.m_min_depth = options["minconf"].getInt<int>();

            if (coinControl.m_min_depth < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative minconf");
            }
        }

        if (options.exists("maxconf")) {
            coinControl.m_max_depth = options["maxconf"].getInt<int>();

            if (coinControl.m_max_depth < coinControl.m_min_depth) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("maxconf can't be lower than minconf: %d < %d", coinControl.m_max_depth, coinControl.m_min_depth));
            }
        }
        SetFeeEstimateMode(wallet, coinControl, options["conf_target"], options["estimate_mode"], options["fee_rate"], override_min_fee);
    }

    if (options.exists("solving_data")) {
        const UniValue solving_data = options["solving_data"].get_obj();
        if (solving_data.exists("pubkeys")) {
            for (const UniValue& pk_univ : solving_data["pubkeys"].get_array().getValues()) {
                const CPubKey pubkey = HexToPubKey(pk_univ.get_str());
                coinControl.m_external_provider.pubkeys.emplace(pubkey.GetID(), pubkey);
            }
        }

        if (solving_data.exists("scripts")) {
            for (const UniValue& script_univ : solving_data["scripts"].get_array().getValues()) {
                const std::string& script_str = script_univ.get_str();
                if (!IsHex(script_str)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("'%s' is not hex", script_str));
                }
                std::vector<unsigned char> script_data(ParseHex(script_str));
                const CScript script(script_data.begin(), script_data.end());
                coinControl.m_external_provider.scripts.emplace(CScriptID(script), script);
            }
        }

        if (solving_data.exists("descriptors")) {
            for (const UniValue& desc_univ : solving_data["descriptors"].get_array().getValues()) {
                const std::string& desc_str  = desc_univ.get_str();
                FlatSigningProvider desc_out;
                std::string error;
                std::vector<CScript> scripts_temp;
                auto descs = Parse(desc_str, desc_out, error, true);
                if (descs.empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unable to parse descriptor '%s': %s", desc_str, error));
                }
                for (auto& desc : descs) {
                    desc->Expand(0, desc_out, scripts_temp, desc_out);
                }
                coinControl.m_external_provider.Merge(std::move(desc_out));
            }
        }
    }

    if (options.exists("input_weights")) {
        for (const UniValue& input : options["input_weights"].get_array().getValues()) {
            Txid txid = Txid::FromUint256(ParseHashO(input, "txid"));

            const UniValue& vout_v = input.find_value("vout");
            if (!vout_v.isNum()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
            }
            int vout = vout_v.getInt<int>();
            if (vout < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout cannot be negative");
            }

            const UniValue& weight_v = input.find_value("weight");
            if (!weight_v.isNum()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing weight key");
            }
            int64_t weight = weight_v.getInt<int64_t>();
            const int64_t min_input_weight = GetTransactionInputWeight(CTxIn());
            CHECK_NONFATAL(min_input_weight == 165);
            if (weight < min_input_weight) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, weight cannot be less than 165 (41 bytes (size of outpoint + sequence + empty scriptSig) * 4 (witness scaling factor)) + 1 (empty witness)");
            }
            if (weight > MAX_STANDARD_TX_WEIGHT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, weight cannot be greater than the maximum standard tx weight of %d", MAX_STANDARD_TX_WEIGHT));
            }

            coinControl.SetInputWeight(COutPoint(txid, vout), weight);
        }
    }

    if (options.exists("max_tx_weight")) {
        coinControl.m_max_tx_weight = options["max_tx_weight"].getInt<int>();
    }

    if (recipients.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");

    auto txr = FundTransaction(wallet, tx, recipients, change_position, lock_unspents, coinControl);
    if (!txr) {
        throw JSONRPCError(RPC_WALLET_ERROR, ErrorString(txr).original);
    }
    return *txr;
}

static void SetOptionsInputWeights(const UniValue& inputs, UniValue& options)
{
    if (options.exists("input_weights")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Input weights should be specified in inputs rather than in options.");
    }
    if (inputs.size() == 0) {
        return;
    }
    UniValue weights(UniValue::VARR);
    for (const UniValue& input : inputs.getValues()) {
        if (input.exists("weight")) {
            weights.push_back(input);
        }
    }
    options.pushKV("input_weights", std::move(weights));
}

RPCHelpMan fundrawtransaction()
{
    return RPCHelpMan{
        "fundrawtransaction",
        "If the transaction has no inputs, they will be automatically selected to meet its out value.\n"
                "It will add at most one change output to the outputs.\n"
                "No existing outputs will be modified unless \"subtract_fee_from_outputs\" is specified.\n"
                "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                "The inputs added will not be signed, use signrawtransactionwithkey\n"
                "or signrawtransactionwithwallet for that.\n"
                "All existing inputs must either have their previous output transaction be in the wallet\n"
                "or be in the UTXO set. Solving data must be provided for non-wallet inputs.\n"
                "All selected inputs must spend Taproot or pay-to-anchor outputs.\n"
                "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
                "Note that if specifying an exact fee rate, the resulting transaction may have a higher fee rate\n"
                "if the transaction has unconfirmed inputs. This is because the wallet will attempt to make the\n"
                "entire package have the given fee rate, not the resulting transaction.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the raw transaction"},
                    {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                        Cat<std::vector<RPCArg>>(
                        {
                            {"add_inputs", RPCArg::Type::BOOL, RPCArg::Default{true}, "For a transaction with existing inputs, automatically include more if they are not enough."},
                            {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include inputs that are not safe to spend (unconfirmed transactions from outside keys and unconfirmed replacement transactions).\n"
                                                          "Warning: the resulting transaction may become invalid if one of the unsafe inputs disappears.\n"
                                                          "If that happens, you will need to fund the transaction with different inputs and republish it."},
                            {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "If add_inputs is specified, require inputs with at least this many confirmations."},
                            {"maxconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If add_inputs is specified, require inputs with at most this many confirmations."},
                            {"change_address", RPCArg::Type::STR, RPCArg::DefaultHint{"automatic"}, "The Kronein address to receive the change"},
                            {"change_position", RPCArg::Type::NUM, RPCArg::DefaultHint{"random"}, "The index of the change output"},
                            {"lock_unspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected unspent outputs"},
                            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                            {"subtract_fee_from_outputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "The integers.\n"
                                                          "The fee will be equally deducted from the amount of each specified output.\n"
                                                          "Those recipients will receive less KNE than you enter in their corresponding amount field.\n"
                                                          "If no outputs are specified here, the sender pays the fee.",
                                {
                                    {"vout_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The zero-based output index, before a change output is added."},
                                },
                            },
                            {"input_weights", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Inputs and their corresponding weights",
                                {
                                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                        {
                                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output index"},
                                            {"weight", RPCArg::Type::NUM, RPCArg::Optional::NO, "The maximum weight for this input, "
                                                "including the weight of the outpoint and sequence number. "
                                                "Taproot Schnorr signatures are 64 bytes, or 65 bytes with a non-default sighash. "
                                                "Remember to convert serialized sizes to weight units when necessary."},
                                        },
                                    },
                                },
                             },
                            {"max_tx_weight", RPCArg::Type::NUM, RPCArg::Default{MAX_STANDARD_TX_WEIGHT}, "The maximum acceptable transaction weight.\n"
                                                          "Transaction building will fail if this can not be satisfied."},
                        },
                        FundTxDoc()),
                        RPCArgOptions{
                            .skip_type_check = true,
                            .oneline_description = "options",
                        }},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The resulting raw transaction (hex-encoded string)"},
                        {RPCResult::Type::STR_AMOUNT, "fee", "Fee in " + CURRENCY_UNIT + " the resulting transaction pays"},
                        {RPCResult::Type::NUM, "changepos", "The position of the added change output, or -1"},
                    }
                                },
                                RPCExamples{
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
                            "\nAdd sufficient unsigned inputs to meet the output value\n"
                            + HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") +
                            "\nSign the transaction\n"
                            + HelpExampleCli("signrawtransactionwithwallet", "\"fundedtransactionhex\"") +
                            "\nSend the transaction\n"
                            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
                                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // parse hex string from parameter
    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    UniValue options = request.params[1];
    std::vector<std::pair<CTxDestination, CAmount>> destinations;
    for (const auto& tx_out : tx.vout) {
        CTxDestination dest;
        ExtractDestination(tx_out.scriptPubKey, dest);
        destinations.emplace_back(dest, tx_out.nValue);
    }
    std::vector<std::string> dummy(destinations.size(), "dummy");
    std::vector<CRecipient> recipients = CreateRecipients(
            destinations,
            InterpretSubtractFeeFromOutputInstructions(options["subtract_fee_from_outputs"], dummy)
    );
    CCoinControl coin_control;
    // Automatically select (additional) coins. Can be overridden by options.add_inputs.
    coin_control.m_allow_other_inputs = true;
    // Clear tx.vout since it is not meant to be used now that we are passing outputs directly.
    // This sets us up for a future PR to completely remove tx from the function signature in favor of passing inputs directly
    tx.vout.clear();
    auto txr = FundTransaction(*pwallet, tx, recipients, options, coin_control, /*override_min_fee=*/true);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(*txr.tx));
    result.pushKV("fee", ValueFromAmount(txr.fee));
    result.pushKV("changepos", txr.change_pos ? (int)*txr.change_pos : -1);

    return result;
},
    };
}

RPCHelpMan signrawtransactionwithwallet()
{
    return RPCHelpMan{
        "signrawtransactionwithwallet",
        "Sign inputs for raw transaction (serialized, hex-encoded).\n"
                "The second optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string"},
                    {"prevtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "The previous dependent transaction outputs",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The output script"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "The amount spent (required for external Taproot inputs)"},
                                },
                            },
                        },
                    },
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT"}, "The signature hash type. Must be one of\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The hex-encoded raw transaction with signature(s)"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::ARR, "errors", /*optional=*/true, "Script verification errors (if there are any)",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The hash of the referenced, previous transaction"},
                                {RPCResult::Type::NUM, "vout", "The index of the output to spent and used as input"},
                                {RPCResult::Type::ARR, "witness", "",
                                {
                                    {RPCResult::Type::STR_HEX, "witness", ""},
                                }},
                                {RPCResult::Type::NUM, "sequence", "Script sequence number"},
                                {RPCResult::Type::STR, "error", "Verification or signing error related to the input"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("signrawtransactionwithwallet", "\"myhex\"")
            + HelpExampleRpc("signrawtransactionwithwallet", "\"myhex\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    // Sign the transaction
    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(*pwallet);

    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    pwallet->chain().findCoins(coins);

    // Parse the prevtxs array
    ParsePrevouts(request.params[1], nullptr, coins);

    std::optional<int> nHashType = ParseSighashString(request.params[2]);
    if (!nHashType) {
        nHashType = SIGHASH_DEFAULT;
    }

    // Script verification errors
    std::map<int, bilingual_str> input_errors;

    bool complete = pwallet->SignTransaction(mtx, coins, *nHashType, input_errors);
    UniValue result(UniValue::VOBJ);
    SignTransactionResultToJSON(mtx, complete, coins, input_errors, result);
    return result;
},
    };
}

// Definition of allowed formats of specifying transaction outputs in
// `bumpfee`, `psbtbumpfee`, `send` and `walletcreatefundedpsbt` RPCs.
static std::vector<RPCArg> OutputsDoc()
{
    return
    {
        {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "",
            {
                {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the Kronein address,\n"
                         "the value (float or string) is the amount in " + CURRENCY_UNIT + ""},
            },
        },
        {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
            {
                {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A key-value pair. The key must be \"data\", the value is hex-encoded data that becomes a part of an OP_RETURN output"},
            },
        },
    };
}

static RPCHelpMan bumpfee_helper(std::string method_name)
{
    const bool want_psbt = method_name == "psbtbumpfee";
    const std::string incremental_fee{CFeeRate(DEFAULT_INCREMENTAL_RELAY_FEE).ToString(FeeRateFormat::SAT_VB)};

    return RPCHelpMan{method_name,
        "Bumps the fee of a transaction T, replacing it with a new transaction B.\n"
        + std::string(want_psbt ? "Returns a PSBT instead of creating and signing a new transaction.\n" : "") +
        "A transaction with the given txid must be in the wallet.\n"
        "The command will pay the additional fee by reducing change outputs or adding inputs when necessary.\n"
        "It may add a new change output if one does not already exist.\n"
        "All inputs in the original transaction will be included in the replacement transaction.\n"
        "The command will fail if the wallet or mempool contains a transaction that spends one of T's outputs.\n"
        "By default, the new fee will be calculated automatically using the estimatesmartfee RPC.\n"
        "The user can specify a confirmation target for estimatesmartfee.\n"
        "Alternatively, the user can specify a fee rate in " + CURRENCY_ATOM + "/vB for the new transaction.\n"
        "At a minimum, the new fee rate must be high enough to pay an additional new relay fee (incrementalfee\n"
        "returned by getnetworkinfo) to enter the node's mempool.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The txid to be bumped"},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"conf_target", RPCArg::Type::NUM, RPCArg::DefaultHint{"wallet -txconfirmtarget"}, "Confirmation target in blocks\n"},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"},
                             "\nSpecify a fee rate in " + CURRENCY_ATOM + "/vB instead of relying on the built-in fee estimator.\n"
                             "Must be at least " + incremental_fee + " higher than the current transaction fee rate.\n"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true},
                             "Whether the new transaction should be\n"
                             "marked bip-125 replaceable. If true, the sequence numbers in the transaction will\n"
                             "be set to 0xfffffffd. If false, any input sequence numbers in the\n"
                             "transaction will be set to 0xfffffffe\n"
                             "so the new transaction will not be explicitly bip-125 replaceable (though it may\n"
                             "still be replaceable in practice, for example if it has unconfirmed ancestors which\n"
                             "are replaceable).\n"},
                    {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"unset"}, "The fee estimate mode, must be one of (case insensitive):\n"
                              + FeeModesDetail(std::string("economical mode is used if the transaction is replaceable;\notherwise, conservative mode is used"))},
                    {"outputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "The outputs specified as key-value pairs.\n"
                             "Each key may only appear once, i.e. there can only be one 'data' output, and no address may be duplicated.\n"
                             "At least one output of either type must be specified.\n"
                             "Cannot be provided if 'original_change_index' is specified.",
                        OutputsDoc(),
                        RPCArgOptions{.skip_type_check = true}},
                    {"original_change_index", RPCArg::Type::NUM, RPCArg::DefaultHint{"not set, detect change automatically"}, "The 0-based index of the change output on the original transaction. "
                                                                                                                            "The indicated output will be recycled into the new change output on the bumped transaction. "
                                                                                                                            "The remainder after paying the recipients and fees will be sent to the output script of the "
                                                                                                                            "original change output. The change output’s amount can increase if bumping the transaction "
                                                                                                                            "adds new inputs, otherwise it will decrease. Cannot be used in combination with the 'outputs' option."},
                },
                RPCArgOptions{.oneline_description="options"}},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", Cat(
                want_psbt ?
                std::vector<RPCResult>{{RPCResult::Type::STR, "psbt", "The base64-encoded unsigned PSBT of the new transaction."}} :
                std::vector<RPCResult>{{RPCResult::Type::STR_HEX, "txid", "The id of the new transaction."}},
            {
                {RPCResult::Type::STR_AMOUNT, "origfee", "The fee of the replaced transaction."},
                {RPCResult::Type::STR_AMOUNT, "fee", "The fee of the new transaction."},
                {RPCResult::Type::ARR, "errors", "Errors encountered during processing (may be empty).",
                {
                    {RPCResult::Type::STR, "", ""},
                }},
            })
        },
        RPCExamples{
    "\nBump the fee, get the new transaction\'s " + std::string(want_psbt ? "psbt" : "txid") + "\n" +
            HelpExampleCli(method_name, "<txid>")
        },
        [want_psbt](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && !pwallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER) && !want_psbt) {
        throw JSONRPCError(RPC_WALLET_ERROR, "bumpfee is not available with wallets that have private keys disabled. Use psbtbumpfee instead.");
    }

    Txid hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};

    CCoinControl coin_control;
    // optional parameters
    coin_control.m_signal_bip125_rbf = true;
    std::vector<CTxOut> outputs;

    std::optional<uint32_t> original_change_index;

    if (!request.params[1].isNull()) {
        UniValue options = request.params[1];
        RPCTypeCheckObj(options,
            {
                {"conf_target", UniValueType(UniValue::VNUM)},
                {"fee_rate", UniValueType()}, // will be checked by AmountFromValue() in SetFeeEstimateMode()
                {"replaceable", UniValueType(UniValue::VBOOL)},
                {"estimate_mode", UniValueType(UniValue::VSTR)},
                {"outputs", UniValueType()}, // will be checked by AddOutputs()
                {"original_change_index", UniValueType(UniValue::VNUM)},
            },
            true, true);

        if (options.exists("replaceable")) {
            coin_control.m_signal_bip125_rbf = options["replaceable"].get_bool();
        }
        SetFeeEstimateMode(*pwallet, coin_control, options["conf_target"], options["estimate_mode"], options["fee_rate"], /*override_min_fee=*/false);

        // Prepare new outputs by creating a temporary tx and calling AddOutputs().
        if (!options["outputs"].isNull()) {
            if (options["outputs"].isArray() && options["outputs"].empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output argument cannot be an empty array");
            }
            CMutableTransaction tempTx;
            AddOutputs(tempTx, options["outputs"]);
            outputs = tempTx.vout;
        }

        if (options.exists("original_change_index")) {
            original_change_index = options["original_change_index"].getInt<uint32_t>();
        }
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(*pwallet);


    std::vector<bilingual_str> errors;
    CAmount old_fee;
    CAmount new_fee;
    CMutableTransaction mtx;
    feebumper::Result res;
    // Targeting feerate bump.
    res = feebumper::CreateRateBumpTransaction(*pwallet, hash, coin_control, errors, old_fee, new_fee, mtx, /*require_mine=*/ !want_psbt, outputs, original_change_index);
    if (res != feebumper::Result::OK) {
        switch(res) {
            case feebumper::Result::INVALID_ADDRESS_OR_KEY:
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errors[0].original);
                break;
            case feebumper::Result::INVALID_REQUEST:
                throw JSONRPCError(RPC_INVALID_REQUEST, errors[0].original);
                break;
            case feebumper::Result::INVALID_PARAMETER:
                throw JSONRPCError(RPC_INVALID_PARAMETER, errors[0].original);
                break;
            case feebumper::Result::WALLET_ERROR:
                throw JSONRPCError(RPC_WALLET_ERROR, errors[0].original);
                break;
            default:
                throw JSONRPCError(RPC_MISC_ERROR, errors[0].original);
                break;
        }
    }

    UniValue result(UniValue::VOBJ);

    // For bumpfee, return the new transaction id.
    // For psbtbumpfee, return the base64-encoded unsigned PSBT of the new transaction.
    if (!want_psbt) {
        if (!feebumper::SignTransaction(*pwallet, mtx)) {
            if (pwallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Transaction incomplete. Try psbtbumpfee instead.");
            }
            throw JSONRPCError(RPC_WALLET_ERROR, "Can't sign transaction.");
        }

        Txid txid;
        if (feebumper::CommitTransaction(*pwallet, hash, std::move(mtx), errors, txid) != feebumper::Result::OK) {
            throw JSONRPCError(RPC_WALLET_ERROR, errors[0].original);
        }

        result.pushKV("txid", txid.GetHex());
    } else {
        PartiallySignedTransaction psbtx(mtx);
        bool complete = false;
        const auto err{pwallet->FillPSBT(psbtx, {.sign = false, .bip32_derivs = true}, complete)};
        CHECK_NONFATAL(!err);
        CHECK_NONFATAL(!complete);
        DataStream ssTx{};
        ssTx << psbtx;
        result.pushKV("psbt", EncodeBase64(ssTx.str()));
    }

    result.pushKV("origfee", ValueFromAmount(old_fee));
    result.pushKV("fee", ValueFromAmount(new_fee));
    UniValue result_errors(UniValue::VARR);
    for (const bilingual_str& error : errors) {
        result_errors.push_back(error.original);
    }
    result.pushKV("errors", std::move(result_errors));

    return result;
},
    };
}

RPCHelpMan bumpfee() { return bumpfee_helper("bumpfee"); }
RPCHelpMan psbtbumpfee() { return bumpfee_helper("psbtbumpfee"); }

RPCHelpMan send()
{
    return RPCHelpMan{
        "send",
        "EXPERIMENTAL warning: this call may be changed in future releases.\n"
        "\nSend a transaction.\n",
        {
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs specified as key-value pairs.\n"
                    "Each key may only appear once, i.e. there can only be one 'data' output, and no address may be duplicated.\n"
                    "At least one output of either type must be specified.",
                OutputsDoc(),
                },
            {"conf_target", RPCArg::Type::NUM, RPCArg::DefaultHint{"wallet -txconfirmtarget"}, "Confirmation target in blocks"},
            {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"unset"}, "The fee estimate mode, must be one of (case insensitive):\n"
              + FeeModesDetail(std::string("economical mode is used if the transaction is replaceable;\notherwise, conservative mode is used"))},
            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                Cat<std::vector<RPCArg>>(
                {
                    {"add_inputs", RPCArg::Type::BOOL, RPCArg::DefaultHint{"false when \"inputs\" are specified, true otherwise"},"Automatically include coins from the wallet to cover the target amount.\n"},
                    {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include inputs that are not safe to spend (unconfirmed transactions from outside keys and unconfirmed replacement transactions).\n"
                                                          "Warning: the resulting transaction may become invalid if one of the unsafe inputs disappears.\n"
                                                          "If that happens, you will need to fund the transaction with different inputs and republish it."},
                    {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "If add_inputs is specified, require inputs with at least this many confirmations."},
                    {"maxconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If add_inputs is specified, require inputs with at most this many confirmations."},
                    {"add_to_wallet", RPCArg::Type::BOOL, RPCArg::Default{true}, "When false, returns a serialized transaction which will not be added to the wallet or broadcast"},
                    {"change_address", RPCArg::Type::STR, RPCArg::DefaultHint{"automatic"}, "The Kronein address to receive the change"},
                    {"change_position", RPCArg::Type::NUM, RPCArg::DefaultHint{"random"}, "The index of the change output"},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB.", RPCArgOptions{.also_positional = true}},
                    {"inputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Specify inputs instead of adding them automatically.",
                        {
                          {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "", {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'replaceable' and 'locktime' arguments"}, "The sequence number"},
                            {"weight", RPCArg::Type::NUM, RPCArg::DefaultHint{"Calculated from wallet and solving data"}, "The maximum weight for this input, "
                                        "including the weight of the outpoint and sequence number. "
                                        "Taproot Schnorr signatures are 64 bytes, or 65 bytes with a non-default sighash. "
                                        "Remember to convert serialized sizes to weight units when necessary."},
                          }},
                        },
                    },
                    {"locktime", RPCArg::Type::NUM, RPCArg::DefaultHint{"locktime close to block height to prevent fee sniping"}, "Raw locktime. Non-0 value also locktime-activates inputs"},
                    {"lock_unspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected unspent outputs"},
                    {"psbt", RPCArg::Type::BOOL,  RPCArg::DefaultHint{"automatic"}, "Always return a PSBT, implies add_to_wallet=false."},
                    {"subtract_fee_from_outputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Outputs to subtract the fee from, specified as integer indices.\n"
                    "The fee will be equally deducted from the amount of each specified output.\n"
                    "Those recipients will receive less KNE than you enter in their corresponding amount field.\n"
                    "If no outputs are specified here, the sender pays the fee.",
                        {
                            {"vout_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The zero-based output index, before a change output is added."},
                        },
                    },
                    {"max_tx_weight", RPCArg::Type::NUM, RPCArg::Default{MAX_STANDARD_TX_WEIGHT}, "The maximum acceptable transaction weight.\n"
                                                  "Transaction building will fail if this can not be satisfied."},
                },
                FundTxDoc()),
                RPCArgOptions{.oneline_description="options"}},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                    {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "The transaction id for the send. Only 1 transaction is created regardless of the number of addresses."},
                    {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "If add_to_wallet is false, the hex-encoded raw transaction with signature(s)"},
                    {RPCResult::Type::STR, "psbt", /*optional=*/true, "If more signatures are needed, or if add_to_wallet is false, the base64-encoded (partially) signed transaction"}
                }
        },
        RPCExamples{""
        "\nSend 0.1 KNE with a confirmation target of 6 blocks in economical fee estimate mode\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.1}' 6 economical\n") +
        "Send 0.2 KNE with a fee rate of 1.1 " + CURRENCY_ATOM + "/vB using positional arguments\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.2}' null \"unset\" 1.1\n") +
        "Send 0.2 KNE with a fee rate of 1 " + CURRENCY_ATOM + "/vB using the options argument\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.2}' null \"unset\" null '{\"fee_rate\": 1}'\n") +
        "Send 0.3 KNE with a fee rate of 25 " + CURRENCY_ATOM + "/vB using named arguments\n"
        + HelpExampleCli("-named send", "outputs='{\"" + EXAMPLE_ADDRESS[0] + "\": 0.3}' fee_rate=25\n") +
        "Create a transaction that should confirm the next block, with a specific input, and return result without adding to wallet or broadcasting to the network\n"
        + HelpExampleCli("send", "'{\"" + EXAMPLE_ADDRESS[0] + "\": 0.1}' 1 economical null '{\"add_to_wallet\": false, \"inputs\": [{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\", \"vout\":1}]}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            UniValue options{request.params[4].isNull() ? UniValue::VOBJ : request.params[4]};
            InterpretFeeEstimationInstructions(/*conf_target=*/request.params[1], /*estimate_mode=*/request.params[2], /*fee_rate=*/request.params[3], options);
            bool rbf{options.exists("replaceable") ? options["replaceable"].get_bool() : pwallet->m_signal_rbf};
            UniValue outputs(UniValue::VOBJ);
            outputs = NormalizeOutputs(request.params[0]);
            std::vector<CRecipient> recipients = CreateRecipients(
                    ParseOutputs(outputs),
                    InterpretSubtractFeeFromOutputInstructions(options["subtract_fee_from_outputs"], outputs.getKeys())
            );
            CCoinControl coin_control;
            CMutableTransaction rawTx = ConstructTransaction(options["inputs"], request.params[0], options["locktime"], rbf);
            // Automatically select coins, unless at least one is manually selected. Can
            // be overridden by options.add_inputs.
            coin_control.m_allow_other_inputs = rawTx.vin.size() == 0;
            if (options.exists("max_tx_weight")) {
                coin_control.m_max_tx_weight = options["max_tx_weight"].getInt<int>();
            }

            SetOptionsInputWeights(options["inputs"], options);
            // Clear tx.vout since it is not meant to be used now that we are passing outputs directly.
            // This sets us up for a future PR to completely remove tx from the function signature in favor of passing inputs directly
            rawTx.vout.clear();
            auto txr = FundTransaction(*pwallet, rawTx, recipients, options, coin_control, /*override_min_fee=*/false);

            CMutableTransaction tx = CMutableTransaction(*txr.tx);
            return FinishTransaction(pwallet, options, tx);
        }
    };
}

RPCHelpMan sendall()
{
    return RPCHelpMan{"sendall",
        "EXPERIMENTAL warning: this call may be changed in future releases.\n"
        "\nSpend the value of all (or specific) confirmed UTXOs and unconfirmed change in the wallet to one or more recipients.\n"
        "Unconfirmed inbound UTXOs and locked UTXOs will not be spent. Sendall will respect the avoid_reuse wallet flag.\n"
        "If your wallet contains many small inputs, either because it received tiny payments or as a result of accumulating change, consider using `send_max` to exclude inputs that are worth less than the fees needed to spend them.\n",
        {
            {"recipients", RPCArg::Type::ARR, RPCArg::Optional::NO, "The sendall destinations. Each address may only appear once.\n"
                "Optionally some recipients can be specified with an amount to perform payments, but at least one address must appear without a specified amount.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "A Kronein address which receives an equal share of the unspecified amount."},
                    {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the Kronein address, the value (float or string) is the amount in " + CURRENCY_UNIT + ""},
                        },
                    },
                },
            },
            {"conf_target", RPCArg::Type::NUM, RPCArg::DefaultHint{"wallet -txconfirmtarget"}, "Confirmation target in blocks"},
            {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"unset"}, "The fee estimate mode, must be one of (case insensitive):\n"
              + FeeModesDetail(std::string("economical mode is used if the transaction is replaceable;\notherwise, conservative mode is used"))},
            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
            {
                "options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                Cat<std::vector<RPCArg>>(
                    {
                        {"add_to_wallet", RPCArg::Type::BOOL, RPCArg::Default{true}, "When false, returns the serialized transaction without broadcasting or adding it to the wallet"},
                        {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB.", RPCArgOptions{.also_positional = true}},
                        {"inputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Use exactly the specified inputs to build the transaction. Specifying inputs is incompatible with the send_max, minconf, and maxconf options.",
                            {
                                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                    {
                                        {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                        {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                        {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'replaceable' and 'locktime' arguments"}, "The sequence number"},
                                    },
                                },
                            },
                        },
                        {"locktime", RPCArg::Type::NUM, RPCArg::DefaultHint{"locktime close to block height to prevent fee sniping"}, "Raw locktime. Non-0 value also locktime-activates inputs"},
                        {"lock_unspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected unspent outputs"},
                        {"psbt", RPCArg::Type::BOOL,  RPCArg::DefaultHint{"automatic"}, "Always return a PSBT, implies add_to_wallet=false."},
                        {"send_max", RPCArg::Type::BOOL, RPCArg::Default{false}, "When true, only use UTXOs that can pay for their own fees to maximize the output amount. When 'false' (default), no UTXO is left behind. send_max is incompatible with providing specific inputs."},
                        {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Require inputs with at least this many confirmations."},
                        {"maxconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Require inputs with at most this many confirmations."},
                    },
                    FundTxDoc()
                ),
                RPCArgOptions{.oneline_description="options"}
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                    {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "The transaction id for the send. Only 1 transaction is created regardless of the number of addresses."},
                    {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "If add_to_wallet is false, the hex-encoded raw transaction with signature(s)"},
                    {RPCResult::Type::STR, "psbt", /*optional=*/true, "If more signatures are needed, or if add_to_wallet is false, the base64-encoded (partially) signed transaction"}
                }
        },
        RPCExamples{""
        "\nSpend all UTXOs from the wallet with a fee rate of 1 " + CURRENCY_ATOM + "/vB using named arguments\n"
        + HelpExampleCli("-named sendall", "recipients='[\"" + EXAMPLE_ADDRESS[0] + "\"]' fee_rate=1\n") +
        "Spend all UTXOs with a fee rate of 1.1 " + CURRENCY_ATOM + "/vB using positional arguments\n"
        + HelpExampleCli("sendall", "'[\"" + EXAMPLE_ADDRESS[0] + "\"]' null \"unset\" 1.1\n") +
        "Spend all UTXOs split into equal amounts to two addresses with a fee rate of 1.5 " + CURRENCY_ATOM + "/vB using the options argument\n"
        + HelpExampleCli("sendall", "'[\"" + EXAMPLE_ADDRESS[0] + "\", \"" + EXAMPLE_ADDRESS[1] + "\"]' null \"unset\" null '{\"fee_rate\": 1.5}'\n") +
        "Leave dust UTXOs in wallet, spend only UTXOs with positive effective value with a fee rate of 10 " + CURRENCY_ATOM + "/vB using the options argument\n"
        + HelpExampleCli("sendall", "'[\"" + EXAMPLE_ADDRESS[0] + "\"]' null \"unset\" null '{\"fee_rate\": 10, \"send_max\": true}'\n") +
        "Spend all UTXOs with a fee rate of 1.3 " + CURRENCY_ATOM + "/vB using named arguments and sending a 0.25 " + CURRENCY_UNIT + " to another recipient\n"
        + HelpExampleCli("-named sendall", "recipients='[{\"" + EXAMPLE_ADDRESS[1] + "\": 0.25}, \""+ EXAMPLE_ADDRESS[0] + "\"]' fee_rate=1.3\n")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet{GetWalletForJSONRPCRequest(request)};
            if (!pwallet) return UniValue::VNULL;
            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            UniValue options{request.params[4].isNull() ? UniValue::VOBJ : request.params[4]};
            InterpretFeeEstimationInstructions(/*conf_target=*/request.params[1], /*estimate_mode=*/request.params[2], /*fee_rate=*/request.params[3], options);
            std::set<std::string> addresses_without_amount;
            UniValue recipient_key_value_pairs(UniValue::VARR);
            const UniValue& recipients{request.params[0]};
            for (unsigned int i = 0; i < recipients.size(); ++i) {
                const UniValue& recipient{recipients[i]};
                if (recipient.isStr()) {
                    UniValue rkvp(UniValue::VOBJ);
                    rkvp.pushKV(recipient.get_str(), 0);
                    recipient_key_value_pairs.push_back(std::move(rkvp));
                    addresses_without_amount.insert(recipient.get_str());
                } else {
                    recipient_key_value_pairs.push_back(recipient);
                }
            }

            if (addresses_without_amount.size() == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Must provide at least one address without a specified amount");
            }

            CCoinControl coin_control;

            SetFeeEstimateMode(*pwallet, coin_control, options["conf_target"], options["estimate_mode"], options["fee_rate"], /*override_min_fee=*/false);

            if (options.exists("minconf")) {
                if (options["minconf"].getInt<int>() < 0)
                {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid minconf (minconf cannot be negative): %s", options["minconf"].getInt<int>()));
                }

                coin_control.m_min_depth = options["minconf"].getInt<int>();
            }

            if (options.exists("maxconf")) {
                coin_control.m_max_depth = options["maxconf"].getInt<int>();

                if (coin_control.m_max_depth < coin_control.m_min_depth) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("maxconf can't be lower than minconf: %d < %d", coin_control.m_max_depth, coin_control.m_min_depth));
                }
            }

            coin_control.m_max_tx_weight = MAX_STANDARD_TX_WEIGHT;

            const bool rbf{options.exists("replaceable") ? options["replaceable"].get_bool() : pwallet->m_signal_rbf};

            FeeCalculation fee_calc_out;
            CFeeRate fee_rate{GetMinimumFeeRate(*pwallet, coin_control, &fee_calc_out)};
            // Do not, ever, assume that it's fine to change the fee rate if the user has explicitly
            // provided one
            if (coin_control.m_feerate && fee_rate > *coin_control.m_feerate) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Fee rate (%s) is lower than the minimum fee rate setting (%s)", coin_control.m_feerate->ToString(FeeRateFormat::SAT_VB), fee_rate.ToString(FeeRateFormat::SAT_VB)));
            }
            if (fee_calc_out.reason == FeeReason::FALLBACK && !pwallet->m_allow_fallback_fee) {
                // eventually allow a fallback fee
                throw JSONRPCError(RPC_WALLET_ERROR, "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.");
            }

            CMutableTransaction rawTx{ConstructTransaction(options["inputs"], recipient_key_value_pairs, options["locktime"], rbf)};
            LOCK(pwallet->cs_wallet);

            CAmount total_input_value(0);
            bool send_max{options.exists("send_max") ? options["send_max"].get_bool() : false};
            if (options.exists("inputs") && options.exists("send_max")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot combine send_max with specific inputs.");
            } else if (options.exists("inputs") && (options.exists("minconf") || options.exists("maxconf"))) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot combine minconf or maxconf with specific inputs.");
            } else if (options.exists("inputs")) {
                for (const CTxIn& input : rawTx.vin) {
                    if (pwallet->IsSpent(input.prevout)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Input not available. UTXO (%s:%d) was already spent.", input.prevout.hash.ToString(), input.prevout.n));
                    }
                    const CWalletTx* tx{pwallet->GetWalletTx(input.prevout.hash)};
                    if (!tx || input.prevout.n >= tx->tx->vout.size() || !pwallet->IsMine(tx->tx->vout[input.prevout.n])) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Input not found. UTXO (%s:%d) is not part of wallet.", input.prevout.hash.ToString(), input.prevout.n));
                    }
                    total_input_value += tx->tx->vout[input.prevout.n].nValue;
                }
            } else {
                CoinFilterParams coins_params;
                coins_params.min_amount = 0;
                for (const COutput& output : AvailableCoins(*pwallet, &coin_control, fee_rate, coins_params).All()) {
                    if (send_max && fee_rate.GetFee(output.input_bytes) > output.txout.nValue) {
                        continue;
                    }
                    CTxIn input(output.outpoint.hash, output.outpoint.n, CScript(), rbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL);
                    rawTx.vin.push_back(input);
                    total_input_value += output.txout.nValue;
                }
            }

            std::vector<COutPoint> outpoints_spent;
            outpoints_spent.reserve(rawTx.vin.size());

            for (const CTxIn& tx_in : rawTx.vin) {
                outpoints_spent.push_back(tx_in.prevout);
            }

            // estimate final size of tx
            const TxSize tx_size{CalculateMaximumSignedTxSize(CTransaction(rawTx), pwallet.get())};
            if (tx_size.vsize == -1) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to determine the size of the transaction, the wallet contains unsolvable descriptors");
            }
            const CAmount fee_from_size{fee_rate.GetFee(tx_size.vsize)};
            const std::optional<CAmount> total_bump_fees{pwallet->chain().calculateCombinedBumpFee(outpoints_spent, fee_rate)};
            CAmount effective_value = total_input_value - fee_from_size - total_bump_fees.value_or(0);

            if (fee_from_size > pwallet->m_default_max_tx_fee) {
                throw JSONRPCError(RPC_WALLET_ERROR, TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED).original);
            }

            if (effective_value <= 0) {
                if (send_max) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Total value of UTXO pool too low to pay for transaction, try using lower feerate.");
                } else {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Total value of UTXO pool too low to pay for transaction. Try using lower feerate or excluding uneconomic UTXOs with 'send_max' option.");
                }
            }

            // If this transaction is too large, e.g. because the wallet has many UTXOs, it will be rejected by the node's mempool.
            if (tx_size.weight > coin_control.m_max_tx_weight) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Transaction too large.");
            }

            CAmount output_amounts_claimed{0};
            for (const CTxOut& out : rawTx.vout) {
                output_amounts_claimed += out.nValue;
            }

            if (output_amounts_claimed > total_input_value) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Assigned more value to outputs than available funds.");
            }

            const CAmount remainder{effective_value - output_amounts_claimed};
            if (remainder < 0) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds for fees after creating specified outputs.");
            }

            const CAmount per_output_without_amount{remainder / (long)addresses_without_amount.size()};

            bool gave_remaining_to_first{false};
            for (CTxOut& out : rawTx.vout) {
                CTxDestination dest;
                ExtractDestination(out.scriptPubKey, dest);
                std::string addr{EncodeDestination(dest)};
                if (addresses_without_amount.contains(addr)) {
                    out.nValue = per_output_without_amount;
                    if (!gave_remaining_to_first) {
                        out.nValue += remainder % addresses_without_amount.size();
                        gave_remaining_to_first = true;
                    }
                    if (IsDust(out, pwallet->chain().relayDustFee())) {
                        // Dynamically generated output amount is dust
                        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Dynamically assigned remainder results in dust output.");
                    }
                } else {
                    if (IsDust(out, pwallet->chain().relayDustFee())) {
                        // Specified output amount is dust
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Specified output amount to %s is below dust threshold.", addr));
                    }
                }
            }

            const bool lock_unspents{options.exists("lock_unspents") ? options["lock_unspents"].get_bool() : false};
            if (lock_unspents) {
                for (const CTxIn& txin : rawTx.vin) {
                    pwallet->LockCoin(txin.prevout, /*persist=*/false);
                }
            }

            return FinishTransaction(pwallet, options, rawTx);
        }
    };
}

RPCHelpMan walletprocesspsbt()
{
    return RPCHelpMan{
        "walletprocesspsbt",
        "Update a PSBT with input information from our wallet and then sign inputs\n"
                "that we can sign for." +
        HELP_REQUIRING_PASSPHRASE,
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction base64 string"},
                    {"sign", RPCArg::Type::BOOL, RPCArg::Default{true}, "Also sign the transaction when updating (requires wallet to be unlocked)"},
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT"}, "The signature hash type to sign with if not specified by the PSBT. Must be one of\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                    {"bip32derivs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include BIP 32 derivation paths for public keys if we know them"},
                    {"finalize", RPCArg::Type::BOOL, RPCArg::Default{true}, "Also finalize inputs if possible"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", "The base64-encoded partially signed transaction"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The hex-encoded network transaction if complete"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("walletprocesspsbt", "\"psbt\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    const CWallet& wallet{*pwallet};
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    // Unserialize the transaction
    util::Result<PartiallySignedTransaction> psbt_res = DecodeBase64PSBT(request.params[0].get_str());
    if (!psbt_res) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", util::ErrorString(psbt_res).original));
    }
    PartiallySignedTransaction psbtx = *psbt_res;

    // Get the sighash type
    std::optional<int> nHashType = ParseSighashString(request.params[2]);

    // Fill transaction with our data and also sign
    bool sign = request.params[1].isNull() ? true : request.params[1].get_bool();
    bool bip32derivs = request.params[3].isNull() ? true : request.params[3].get_bool();
    bool finalize = request.params[4].isNull() ? true : request.params[4].get_bool();
    bool complete = true;

    if (sign) EnsureWalletIsUnlocked(*pwallet);

    const auto err{wallet.FillPSBT(psbtx, {.sign = sign, .sighash_type = nHashType, .finalize = finalize, .bip32_derivs = bip32derivs}, complete)};
    if (err) {
        throw JSONRPCPSBTError(*err);
    }

    UniValue result(UniValue::VOBJ);
    DataStream ssTx{};
    ssTx << psbtx;
    result.pushKV("psbt", EncodeBase64(ssTx.str()));
    result.pushKV("complete", complete);
    if (complete) {
        CMutableTransaction mtx;
        // Returns true if complete, which we already think it is.
        CHECK_NONFATAL(FinalizeAndExtractPSBT(psbtx, mtx));
        DataStream ssTx_final;
        ssTx_final << TX_WITH_WITNESS(mtx);
        result.pushKV("hex", HexStr(ssTx_final));
    }

    return result;
},
    };
}

RPCHelpMan walletcreatefundedpsbt()
{
    return RPCHelpMan{
        "walletcreatefundedpsbt",
        "Creates and funds a transaction in the Partially Signed Transaction format.\n"
                "Implements the Creator and Updater roles.\n"
                "All existing inputs must either have their previous output transaction be in the wallet\n"
                "or be in the UTXO set. Solving data must be provided for non-wallet inputs.\n",
                {
                    {"inputs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Leave empty to add inputs automatically. See add_inputs option.",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'locktime' and 'options.replaceable' arguments"}, "The sequence number"},
                                    {"weight", RPCArg::Type::NUM, RPCArg::DefaultHint{"Calculated from wallet and solving data"}, "The maximum weight for this input, "
                                        "including the weight of the outpoint and sequence number. "
                                        "Taproot Schnorr signatures are 64 bytes, or 65 bytes with a non-default sighash. "
                                        "Remember to convert serialized sizes to weight units when necessary."},
                                },
                            },
                        },
                        },
                    {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs specified as key-value pairs.\n"
                            "Each key may only appear once, i.e. there can only be one 'data' output, and no address may be duplicated.\n"
                            "At least one output of either type must be specified.",
                        OutputsDoc(),
                        },
                    {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
                    {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                        Cat<std::vector<RPCArg>>(
                        {
                            {"add_inputs", RPCArg::Type::BOOL, RPCArg::DefaultHint{"false when \"inputs\" are specified, true otherwise"}, "Automatically include coins from the wallet to cover the target amount.\n"},
                            {"include_unsafe", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include inputs that are not safe to spend (unconfirmed transactions from outside keys and unconfirmed replacement transactions).\n"
                                                          "Warning: the resulting transaction may become invalid if one of the unsafe inputs disappears.\n"
                                                          "If that happens, you will need to fund the transaction with different inputs and republish it."},
                            {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "If add_inputs is specified, require inputs with at least this many confirmations."},
                            {"maxconf", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If add_inputs is specified, require inputs with at most this many confirmations."},
                            {"change_address", RPCArg::Type::STR, RPCArg::DefaultHint{"automatic"}, "The Kronein address to receive the change"},
                            {"change_position", RPCArg::Type::NUM, RPCArg::DefaultHint{"random"}, "The index of the change output"},
                            {"lock_unspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected unspent outputs"},
                            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"not set, fall back to wallet fee estimation"}, "Specify a fee rate in " + CURRENCY_ATOM + "/vB."},
                            {"subtract_fee_from_outputs", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "The outputs to subtract the fee from.\n"
                                                          "The fee will be equally deducted from the amount of each specified output.\n"
                                                          "Those recipients will receive less KNE than you enter in their corresponding amount field.\n"
                                                          "If no outputs are specified here, the sender pays the fee.",
                                {
                                    {"vout_index", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The zero-based output index, before a change output is added."},
                                },
                            },
                            {"max_tx_weight", RPCArg::Type::NUM, RPCArg::Default{MAX_STANDARD_TX_WEIGHT}, "The maximum acceptable transaction weight.\n"
                                                          "Transaction building will fail if this can not be satisfied."},
                        },
                        FundTxDoc()),
                        RPCArgOptions{.oneline_description="options"}},
                    {"bip32derivs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include BIP 32 derivation paths for public keys if we know them"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", "The resulting raw transaction (base64-encoded string)"},
                        {RPCResult::Type::STR_AMOUNT, "fee", "Fee in " + CURRENCY_UNIT + " the resulting transaction pays"},
                        {RPCResult::Type::NUM, "changepos", "The position of the added change output, or -1"},
                    }
                                },
                                RPCExamples{
                            "\nCreate a PSBT with automatically picked inputs that sends 0.5 KNE to an address and has a fee rate of 2 sat/vB:\n"
                            + HelpExampleCli("walletcreatefundedpsbt", "\"[]\" \"[{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.5}]\" 0 \"{\\\"add_inputs\\\":true,\\\"fee_rate\\\":2}\"")
                            + "\nCreate the same PSBT as the above one instead using named arguments:\n"
                            + HelpExampleCli("-named walletcreatefundedpsbt", "outputs=\"[{\\\"" + EXAMPLE_ADDRESS[0] + "\\\":0.5}]\" add_inputs=true fee_rate=2")
                                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    CWallet& wallet{*pwallet};
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    wallet.BlockUntilSyncedToCurrentChain();

    UniValue options{request.params[3].isNull() ? UniValue::VOBJ : request.params[3]};

    CCoinControl coin_control;

    const UniValue &replaceable_arg = options["replaceable"];
    const bool rbf{replaceable_arg.isNull() ? wallet.m_signal_rbf : replaceable_arg.get_bool()};
    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], rbf);
    UniValue outputs(UniValue::VOBJ);
    outputs = NormalizeOutputs(request.params[1]);
    std::vector<CRecipient> recipients = CreateRecipients(
            ParseOutputs(outputs),
            InterpretSubtractFeeFromOutputInstructions(options["subtract_fee_from_outputs"], outputs.getKeys())
    );
    // Automatically select coins, unless at least one is manually selected. Can
    // be overridden by options.add_inputs.
    coin_control.m_allow_other_inputs = rawTx.vin.size() == 0;
    SetOptionsInputWeights(request.params[0], options);
    // Clear tx.vout since it is not meant to be used now that we are passing outputs directly.
    // This sets us up for a future PR to completely remove tx from the function signature in favor of passing inputs directly
    rawTx.vout.clear();
    auto txr = FundTransaction(wallet, rawTx, recipients, options, coin_control, /*override_min_fee=*/true);

    // Make a blank psbt
    PartiallySignedTransaction psbtx(CMutableTransaction(*txr.tx));

    // Fill transaction with out data but don't sign
    bool bip32derivs = request.params[4].isNull() ? true : request.params[4].get_bool();
    bool complete = true;
    const auto err{wallet.FillPSBT(psbtx, {.sign = false, .bip32_derivs = bip32derivs}, complete)};
    if (err) {
        throw JSONRPCPSBTError(*err);
    }

    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;

    UniValue result(UniValue::VOBJ);
    result.pushKV("psbt", EncodeBase64(ssTx.str()));
    result.pushKV("fee", ValueFromAmount(txr.fee));
    result.pushKV("changepos", txr.change_pos ? (int)*txr.change_pos : -1);
    return result;
},
    };
}

RPCHelpMan walletcreatefundchainpsbt()
{
    return RPCHelpMan{
        "walletcreatefundchainpsbt",
        "Create and fund an unsigned PSBT for an irreversible main-chain to child-chain deposit.\n"
        "The canonical KFND burn is fixed at vout[0], and change, when present, is appended after it. This RPC does not sign or broadcast.\n"
        "The destination is validated against the registered child template before any PSBT is returned.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact non-null destination child-chain identifier"},
            {"recipient_type", RPCArg::Type::NUM, RPCArg::Optional::NO, "Non-zero recipient namespace defined by the child template"},
            {"recipient", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical child recipient bytes (1-64 bytes)"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of KNE to burn irreversibly on the main chain"},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "Funding options. The deposit output and amount cannot be altered by fee subtraction.", FundTxDoc(), RPCArgOptions{.oneline_description="options"}},
            {"bip32derivs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include known BIP32 derivation paths"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Funded, unsigned child-deposit transaction", {
            {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT"},
            {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee in KNE"},
            {RPCResult::Type::NUM, "changepos", "Change output position, or -1"},
            {RPCResult::Type::NUM, "deposit_vout", "KFND burn output index; always 0"},
            {RPCResult::Type::STR_AMOUNT, "amount", "Exact amount that will be destroyed on the main chain"},
            {RPCResult::Type::STR_HEX, "chain_id", "Destination child-chain identifier"},
            {RPCResult::Type::NUM, "recipient_type", "Child-template recipient namespace"},
            {RPCResult::Type::STR_HEX, "recipient", "Canonical recipient bytes"},
            {RPCResult::Type::BOOL, "irreversible", "Always true"},
            {RPCResult::Type::STR, "warning", "Human-readable irreversible-transfer warning"},
            {RPCResult::Type::STR_HEX, "registry_bestblockhash", "Registry tip against which the PSBT was created"},
            {RPCResult::Type::NUM, "registry_height", "Registry tip height"},
            {RPCResult::Type::STR_HEX, "registry_root", "Registry root at that tip"},
        }},
        RPCExamples{
            HelpExampleCli(
                "walletcreatefundchainpsbt",
                "\"1111111111111111111111111111111111111111111111111111111111111111\" 1 \"001122\" 0.25 '{\"fee_rate\":1}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet_ptr{GetWalletForJSONRPCRequest(request)};
    if (!wallet_ptr) return UniValue::VNULL;
    CWallet& wallet{*wallet_ptr};
    wallet.BlockUntilSyncedToCurrentChain();

    const chainregistry::FundChain fund{ParseFundDestination(
        self.Arg<UniValue>("chain_id"),
        self.Arg<UniValue>("recipient_type"),
        self.Arg<UniValue>("recipient"))};
    const CAmount amount{AmountFromValue(self.Arg<UniValue>("amount"))};
    const interfaces::ChainRegistrySnapshot snapshot{
        wallet.chain().getChainRegistrySnapshot(fund.chain_id)};
    if (!snapshot.enabled || !snapshot.deposits_enabled) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "one-way child deposits are disabled on this network");
    }
    if (!snapshot.active_for_next_block || !snapshot.deposits_active_for_next_block) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "one-way child deposits are not active for the next block");
    }
    if (!snapshot.record) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id is not registered");
    }
    if (snapshot.record->status != chainregistry::ChainStatus::ACTIVE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is retired");
    }
    ValidateFundDestinationForTemplate(*snapshot.record, fund);
    if (amount < snapshot.minimum_deposit_amount) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("amount must be at least %s KNE",
                      FormatMoney(snapshot.minimum_deposit_amount)));
    }

    const CScript deposit_script{chainregistry::BuildFundScript(fund)};
    std::vector<CRecipient> recipients{
        CRecipient{CNoDestination{deposit_script}, amount, false}};
    UniValue options{request.params[4].isNull() ? UniValue::VOBJ
                                                : request.params[4].get_obj()};
    for (const std::string_view forbidden : {
             "change_position", "subtract_fee_from_outputs", "inputs", "input_weights"}) {
        if (options.exists(std::string{forbidden})) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("options.%s cannot override child deposit structure", forbidden));
        }
    }
    options.pushKV("add_inputs", true);
    options.pushKV("change_position", 1);

    CMutableTransaction raw_tx;
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    auto tx_result{FundTransaction(wallet, raw_tx, recipients, options, coin_control,
                                   /*override_min_fee=*/true)};
    if (tx_result.tx->vout.empty() || tx_result.tx->vout[0].nValue != amount ||
        tx_result.tx->vout[0].scriptPubKey != deposit_script) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "wallet changed reserved child deposit output");
    }

    PartiallySignedTransaction psbt{CMutableTransaction{*tx_result.tx}};
    const bool bip32_derivs{self.Arg<bool>("bip32derivs")};
    bool complete{true};
    if (const auto error{wallet.FillPSBT(
            psbt, {.sign = false, .bip32_derivs = bip32_derivs}, complete)}) {
        throw JSONRPCPSBTError(*error);
    }
    DataStream stream;
    stream << psbt;

    UniValue result{UniValue::VOBJ};
    result.pushKV("psbt", EncodeBase64(stream.str()));
    result.pushKV("fee", ValueFromAmount(tx_result.fee));
    result.pushKV("changepos", tx_result.change_pos ? static_cast<int>(*tx_result.change_pos) : -1);
    result.pushKV("deposit_vout", 0);
    result.pushKV("amount", ValueFromAmount(amount));
    result.pushKV("chain_id", fund.chain_id.GetHex());
    result.pushKV("recipient_type", fund.recipient_type);
    result.pushKV("recipient", HexStr(fund.recipient));
    result.pushKV("irreversible", true);
    result.pushKV("warning", "This transfer permanently destroys main-chain KNE and cannot be reversed or withdrawn back to the main chain.");
    result.pushKV("registry_bestblockhash", snapshot.best_block.GetHex());
    result.pushKV("registry_height", snapshot.height);
    result.pushKV("registry_root", snapshot.registry_root.GetHex());
    return result;
}
    };
}

RPCHelpMan walletsubmitfundchainpsbt()
{
    return RPCHelpMan{
        "walletsubmitfundchainpsbt",
        "Validate, sign, finalize, and broadcast one canonical irreversible child deposit.\n"
        "The caller must explicitly confirm irreversibility and provide an amount cap. There is no child-to-main withdrawal path.\n" +
        HELP_REQUIRING_PASSPHRASE,
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded child-deposit PSBT"},
            {"confirm_irreversible", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Must be true to authorize permanent destruction of main-chain funds"},
            {"max_deposit_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Maximum main-chain amount the caller authorizes this transaction to destroy"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Submitted child deposit", {
            {RPCResult::Type::STR_HEX, "txid", "Funding transaction identifier"},
            {RPCResult::Type::STR_HEX, "hex", "Final network transaction"},
            {RPCResult::Type::NUM, "vout", "KFND burn output index; always 0"},
            {RPCResult::Type::STR_HEX, "deposit_id", "Network-bound identifier derived from the funding outpoint"},
            {RPCResult::Type::STR_HEX, "chain_id", "Destination child-chain identifier"},
            {RPCResult::Type::NUM, "recipient_type", "Child-template recipient namespace"},
            {RPCResult::Type::STR_HEX, "recipient", "Canonical recipient bytes"},
            {RPCResult::Type::STR_AMOUNT, "amount", "Amount permanently destroyed on the main chain"},
            {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee in KNE"},
            {RPCResult::Type::BOOL, "irreversible", "Always true"},
        }},
        RPCExamples{
            HelpExampleCli("walletsubmitfundchainpsbt", "\"cHNidP8...\" true 0.25")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!self.Arg<bool>("confirm_irreversible")) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "confirm_irreversible must be true; child deposits cannot return to the main chain");
    }
    const CAmount maximum_amount{AmountFromValue(
        self.Arg<UniValue>("max_deposit_amount"))};
    const std::shared_ptr<CWallet> wallet_ptr{GetWalletForJSONRPCRequest(request)};
    if (!wallet_ptr) return UniValue::VNULL;
    CWallet& wallet{*wallet_ptr};
    wallet.BlockUntilSyncedToCurrentChain();

    auto decoded{DecodeBase64PSBT(std::string{self.Arg<std::string_view>("psbt")})};
    if (!decoded) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           strprintf("PSBT decode failed: %s",
                                     util::ErrorString(decoded).original));
    }
    PartiallySignedTransaction psbt{std::move(*decoded)};
    const auto unsigned_tx{psbt.GetUnsignedTx()};
    if (!unsigned_tx) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           "PSBT does not contain a complete unsigned transaction");
    }
    const CTransaction tx_template{*unsigned_tx};
    const auto funds{chainregistry::ExtractTransactionFunds(tx_template)};
    if (!funds.IsValid() || funds.funds.size() != 1 ||
        funds.funds[0].output_index != 0) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "PSBT must contain exactly one valid child deposit at vout[0]");
    }
    const chainregistry::FundOutput& fund{funds.funds[0]};
    const interfaces::ChainRegistrySnapshot snapshot{
        wallet.chain().getChainRegistrySnapshot(fund.fund.chain_id)};
    if (!snapshot.enabled || !snapshot.deposits_enabled) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "one-way child deposits are disabled on this network");
    }
    if (!snapshot.active_for_next_block || !snapshot.deposits_active_for_next_block) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "one-way child deposits are not active for the next block");
    }
    if (!snapshot.record) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id is not registered");
    }
    if (snapshot.record->status != chainregistry::ChainStatus::ACTIVE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is retired");
    }
    ValidateFundDestinationForTemplate(*snapshot.record, fund.fund);
    if (fund.amount < snapshot.minimum_deposit_amount) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("deposit amount %s KNE is below consensus minimum %s KNE",
                      FormatMoney(fund.amount),
                      FormatMoney(snapshot.minimum_deposit_amount)));
    }
    if (fund.amount > maximum_amount) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("deposit amount %s KNE exceeds authorized maximum %s KNE",
                      FormatMoney(fund.amount), FormatMoney(maximum_amount)));
    }
    for (size_t index{0}; index < tx_template.vout.size(); ++index) {
        if (index != fund.output_index &&
            tx_template.vout[index].scriptPubKey.IsUnspendable()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "PSBT contains an additional unspendable output");
        }
    }

    CAmount input_value{0};
    {
        LOCK(wallet.cs_wallet);
        for (const auto& input : tx_template.vin) {
            const CWalletTx* wallet_tx{wallet.GetWalletTx(input.prevout.hash)};
            if (!wallet_tx || input.prevout.n >= wallet_tx->tx->vout.size() ||
                !wallet.IsMine(wallet_tx->tx->vout[input.prevout.n])) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    strprintf("PSBT input %s:%d is not owned by this wallet",
                              input.prevout.hash.ToString(), input.prevout.n));
            }
            const CAmount value{wallet_tx->tx->vout[input.prevout.n].nValue};
            if (!MoneyRange(value) || !MoneyRange(input_value + value)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "PSBT input value is out of range");
            }
            input_value += value;
        }
    }

    EnsureWalletIsUnlocked(wallet);
    bool complete{false};
    if (const auto error{wallet.FillPSBT(
            psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete)}) {
        throw JSONRPCPSBTError(*error);
    }
    if (!complete) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "wallet could not sign and finalize every child deposit input");
    }

    CAmount output_value{0};
    for (const auto& output : tx_template.vout) {
        if (!MoneyRange(output.nValue) || !MoneyRange(output_value + output.nValue)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                               "PSBT output value is out of range");
        }
        output_value += output.nValue;
    }
    const CAmount fee{input_value - output_value};
    if (fee < 0) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           "PSBT transaction fee is negative");
    }
    if (fee > wallet.m_default_max_tx_fee) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED).original);
    }

    CMutableTransaction final_tx;
    if (!FinalizeAndExtractPSBT(psbt, final_tx)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "failed to extract finalized child deposit transaction");
    }
    const std::string hex{EncodeHexTx(CTransaction{final_tx})};
    const CTransactionRef transaction{MakeTransactionRef(std::move(final_tx))};
    const COutPoint outpoint{transaction->GetHash(), fund.output_index};
    const chainregistry::DepositId deposit_id{chainregistry::DeriveDepositId(
        snapshot.main_genesis_hash, outpoint)};

    std::string broadcast_error;
    if (!wallet.chain().broadcastTransaction(
            transaction,
            wallet.m_default_max_tx_fee,
            node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
            broadcast_error)) {
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            strprintf("child deposit transaction rejected: %s", broadcast_error));
    }
    wallet.CommitTransaction(transaction, {}, /*orderForm=*/{});

    UniValue result{UniValue::VOBJ};
    result.pushKV("txid", transaction->GetHash().GetHex());
    result.pushKV("hex", hex);
    result.pushKV("vout", fund.output_index);
    result.pushKV("deposit_id", deposit_id.GetHex());
    result.pushKV("chain_id", fund.fund.chain_id.GetHex());
    result.pushKV("recipient_type", fund.fund.recipient_type);
    result.pushKV("recipient", HexStr(fund.fund.recipient));
    result.pushKV("amount", ValueFromAmount(fund.amount));
    result.pushKV("fee", ValueFromAmount(fee));
    result.pushKV("irreversible", true);
    return result;
}
    };
}

RPCHelpMan walletcreatechainregistrypsbt()
{
    return RPCHelpMan{
        "walletcreatechainregistrypsbt",
        "Create and fund a PSBT containing one canonical child-chain registry operation.\n"
        "The authority input is fixed at vin[0], the KREG output at vout[0], and a REGISTER/UPDATE successor Taproot control at vout[1].\n"
        "Change, when present, is appended after protocol outputs. The RPC does not sign or broadcast.\n",
        {
            {"operation", RPCArg::Type::STR, RPCArg::Optional::NO, "Operation type: register, update, or retire"},
            {"parameters", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Operation parameters", {
                {"registration_anchor", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "REGISTER: wallet UTXO consumed as vin[0]", {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction id"},
                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index"},
                }},
                {"spec", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "REGISTER: immutable child-chain specification", {
                    {"template_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Non-zero consensus template identifier"},
                    {"template_version", RPCArg::Type::NUM, RPCArg::Optional::NO, "Non-zero template version"},
                    {"consensus_parameters", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical template parameters"},
                    {"anchoring_policy", RPCArg::Type::STR, RPCArg::Default{"bmm_v1"}, "Anchoring policy"},
                }},
                {"child_genesis_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "REGISTER: non-null child genesis hash"},
                {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "REGISTER/UPDATE: non-null external metadata commitment"},
                {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "UPDATE/RETIRE: exact non-null child-chain identifier"},
                {"control_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "REGISTER/UPDATE: successor Taproot address"},
                {"control_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "REGISTER/UPDATE: successor value; defaults to the dust threshold"},
                {"registration_burn", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "REGISTER: amount permanently burned; defaults to the consensus minimum"},
            }},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "Funding options. Protocol input/output ordering cannot be overridden.", FundTxDoc(), RPCArgOptions{.oneline_description="options"}},
            {"bip32derivs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include known BIP32 derivation paths"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Funded, unsigned registry transaction", {
            {RPCResult::Type::STR, "psbt", "Base64-encoded PSBT"},
            {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee in KNE"},
            {RPCResult::Type::NUM, "changepos", "Change output position, or -1"},
            {RPCResult::Type::STR, "operation", "Registry operation type"},
            {RPCResult::Type::STR_HEX, "chain_id", "Affected or derived child-chain identifier"},
            {RPCResult::Type::STR_AMOUNT, "registration_burn", "Value permanently destroyed by REGISTER, otherwise zero"},
            {RPCResult::Type::OBJ, "authority_outpoint", "UTXO fixed at vin[0]", {
                {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                {RPCResult::Type::NUM, "vout", "Output index"},
            }},
            {RPCResult::Type::NUM, "operation_vout", "KREG output index; always 0"},
            {RPCResult::Type::NUM, "control_vout", /*optional=*/true, "Successor control output index; always 1"},
            {RPCResult::Type::STR_HEX, "registry_bestblockhash", "Registry tip against which this PSBT was created"},
            {RPCResult::Type::NUM, "registry_height", "Registry tip height"},
            {RPCResult::Type::STR_HEX, "registry_root", "Registry root at that tip"},
        }},
        RPCExamples{
            HelpExampleCli("walletcreatechainregistrypsbt", "\"retire\" '{\"chain_id\":\"1111111111111111111111111111111111111111111111111111111111111111\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet_ptr{GetWalletForJSONRPCRequest(request)};
    if (!wallet_ptr) return UniValue::VNULL;
    CWallet& wallet{*wallet_ptr};
    wallet.BlockUntilSyncedToCurrentChain();

    const std::string operation_name{self.Arg<std::string_view>("operation")};
    const UniValue parameters{self.Arg<UniValue>("parameters").get_obj()};
    RPCTypeCheckObj(parameters,
                    {{"registration_anchor", UniValueType{UniValue::VOBJ}},
                     {"spec", UniValueType{UniValue::VOBJ}},
                     {"child_genesis_hash", UniValueType{UniValue::VSTR}},
                     {"metadata_hash", UniValueType{UniValue::VSTR}},
                     {"chain_id", UniValueType{UniValue::VSTR}},
                     {"control_address", UniValueType{UniValue::VSTR}},
                     {"control_amount", UniValueType()},
                     {"registration_burn", UniValueType()}},
                    /*fAllowNull=*/true,
                    /*fStrict=*/true);

    const auto require_parameters{[&](std::initializer_list<std::string_view> required,
                                      std::initializer_list<std::string_view> allowed) {
        for (const auto name : required) {
            if (!parameters.exists(std::string{name})) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("%s requires %s", operation_name, name));
            }
        }
        for (const auto& key : parameters.getKeys()) {
            if (std::none_of(allowed.begin(), allowed.end(), [&](std::string_view candidate) {
                    return candidate == key;
                })) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("unexpected parameter %s for %s", key, operation_name));
            }
        }
    }};

    std::optional<chainregistry::ChainId> requested_chain_id;
    if (operation_name == "update" || operation_name == "retire") {
        if (!parameters.exists("chain_id")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s requires chain_id", operation_name));
        }
        requested_chain_id = ParseRegistryChainId(parameters.find_value("chain_id"));
    }

    const interfaces::ChainRegistrySnapshot registry_snapshot{
        wallet.chain().getChainRegistrySnapshot(requested_chain_id)};
    if (!registry_snapshot.enabled) {
        throw JSONRPCError(RPC_MISC_ERROR, "child-chain registry is disabled on this network");
    }
    if (!registry_snapshot.active_for_next_block) {
        throw JSONRPCError(RPC_MISC_ERROR, "child-chain registry is not active for the next block");
    }

    COutPoint authority_outpoint;
    chainregistry::ChainId chain_id;
    chainregistry::RegistryOperation operation;
    CAmount operation_amount{0};
    std::optional<CTxDestination> control_destination;
    CAmount control_amount{0};

    if (operation_name == "register") {
        require_parameters(
            {"registration_anchor", "spec", "child_genesis_hash", "metadata_hash", "control_address"},
            {"registration_anchor", "spec", "child_genesis_hash", "metadata_hash", "control_address", "control_amount", "registration_burn"});
        authority_outpoint = ParseRegistryOutPoint(parameters.find_value("registration_anchor"), "registration_anchor");
        const auto spec{ParseRegistryChainSpec(parameters.find_value("spec"))};
        operation = chainregistry::RegisterChain{
            .anchor_input = 0,
            .control_output = 1,
            .manifest = chainregistry::ChainManifest{
                .spec = spec,
                .child_genesis_hash = ParseRegistryHash(parameters, "child_genesis_hash"),
                .initial_metadata_hash = ParseRegistryMetadataHash(parameters.find_value("metadata_hash")),
            },
        };
        operation_amount = parameters.exists("registration_burn")
                               ? AmountFromValue(parameters.find_value("registration_burn"))
                               : registry_snapshot.minimum_registration_burn;
        if (operation_amount < registry_snapshot.minimum_registration_burn) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("registration_burn must be at least %s KNE",
                                         FormatMoney(registry_snapshot.minimum_registration_burn)));
        }
        control_destination = ParseRegistryControlDestination(parameters);
        control_amount = RegistryControlAmount(wallet, parameters, *control_destination);
        chain_id = chainregistry::DeriveChainId(
            registry_snapshot.main_genesis_hash, authority_outpoint, chainregistry::ComputeChainSpecHash(spec));
    } else if (operation_name == "update") {
        require_parameters(
            {"chain_id", "metadata_hash", "control_address"},
            {"chain_id", "metadata_hash", "control_address", "control_amount"});
        if (!registry_snapshot.record) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id is not registered");
        }
        if (registry_snapshot.record->status != chainregistry::ChainStatus::ACTIVE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is retired");
        }
        authority_outpoint = registry_snapshot.record->control_outpoint;
        chain_id = *requested_chain_id;
        operation = chainregistry::UpdateChain{
            .chain_id = chain_id,
            .control_output = 1,
            .metadata_hash = ParseRegistryMetadataHash(parameters.find_value("metadata_hash")),
        };
        control_destination = ParseRegistryControlDestination(parameters);
        control_amount = RegistryControlAmount(wallet, parameters, *control_destination);
    } else if (operation_name == "retire") {
        require_parameters({"chain_id"}, {"chain_id"});
        if (!registry_snapshot.record) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id is not registered");
        }
        if (registry_snapshot.record->status != chainregistry::ChainStatus::ACTIVE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is already retired");
        }
        authority_outpoint = registry_snapshot.record->control_outpoint;
        chain_id = *requested_chain_id;
        operation = chainregistry::RetireChain{.chain_id = chain_id};
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "operation must be register, update, or retire");
    }

    if (!WITH_LOCK(wallet.cs_wallet, return wallet.IsMine(authority_outpoint))) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           strprintf("wallet does not control authority outpoint %s:%u",
                                     authority_outpoint.hash.GetHex(), authority_outpoint.n));
    }

    const CScript operation_script{chainregistry::BuildOperationScript(operation)};
    std::vector<CRecipient> recipients;
    recipients.push_back(CRecipient{CNoDestination{operation_script}, operation_amount, false});
    if (control_destination) {
        recipients.push_back(CRecipient{*control_destination, control_amount, false});
    }

    UniValue options{request.params[2].isNull() ? UniValue::VOBJ : request.params[2].get_obj()};
    for (const std::string_view forbidden : {"change_position", "subtract_fee_from_outputs", "inputs", "input_weights"}) {
        if (options.exists(std::string{forbidden})) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("options.%s cannot override registry transaction structure", forbidden));
        }
    }
    options.pushKV("add_inputs", true);
    options.pushKV("change_position", static_cast<int>(recipients.size()));

    CMutableTransaction raw_tx;
    raw_tx.vin.emplace_back(authority_outpoint);
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    coin_control.m_allow_chain_registry_control_input = true;
    coin_control.Select(authority_outpoint).SetPosition(0);
    auto tx_result{FundTransaction(wallet, raw_tx, recipients, options, coin_control,
                                   /*override_min_fee=*/true)};

    if (tx_result.tx->vin.empty() || tx_result.tx->vin[0].prevout != authority_outpoint ||
        tx_result.tx->vout.empty() || tx_result.tx->vout[0].scriptPubKey != operation_script ||
        (control_destination &&
         (tx_result.tx->vout.size() < 2 ||
          tx_result.tx->vout[1].scriptPubKey != GetScriptForDestination(*control_destination)))) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "wallet changed reserved registry input/output positions");
    }

    PartiallySignedTransaction psbt{CMutableTransaction{*tx_result.tx}};
    const bool bip32_derivs{self.Arg<bool>("bip32derivs")};
    bool complete{true};
    if (const auto error{wallet.FillPSBT(psbt, {.sign = false, .bip32_derivs = bip32_derivs}, complete)}) {
        throw JSONRPCPSBTError(*error);
    }
    DataStream stream;
    stream << psbt;

    UniValue authority{UniValue::VOBJ};
    authority.pushKV("txid", authority_outpoint.hash.GetHex());
    authority.pushKV("vout", authority_outpoint.n);

    UniValue result{UniValue::VOBJ};
    result.pushKV("psbt", EncodeBase64(stream.str()));
    result.pushKV("fee", ValueFromAmount(tx_result.fee));
    result.pushKV("changepos", tx_result.change_pos ? static_cast<int>(*tx_result.change_pos) : -1);
    result.pushKV("operation", operation_name);
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("registration_burn", ValueFromAmount(operation_amount));
    result.pushKV("authority_outpoint", std::move(authority));
    result.pushKV("operation_vout", 0);
    if (control_destination) result.pushKV("control_vout", 1);
    result.pushKV("registry_bestblockhash", registry_snapshot.best_block.GetHex());
    result.pushKV("registry_height", registry_snapshot.height);
    result.pushKV("registry_root", registry_snapshot.registry_root.GetHex());
    return result;
},
    };
}

RPCHelpMan walletsubmitchainregistrypsbt()
{
    return RPCHelpMan{
        "walletsubmitchainregistrypsbt",
        "Validate, sign, finalize, and broadcast a funded child-chain registry PSBT.\n"
        "Only the canonical KREG output may destroy value. REGISTER burns are capped by max_registration_burn, which defaults to the consensus minimum.\n"
        "Registry authority is revalidated at submit time, and REGISTER/UPDATE successor controls must remain owned by this wallet.\n" +
        HELP_REQUIRING_PASSPHRASE,
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded registry PSBT"},
            {"max_registration_burn", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Maximum REGISTER burn authorized by the caller; defaults to the consensus minimum"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Submitted registry transaction", {
            {RPCResult::Type::STR_HEX, "txid", "Transaction identifier"},
            {RPCResult::Type::STR_HEX, "hex", "Final network transaction"},
            {RPCResult::Type::STR, "operation", "Registry operation type"},
            {RPCResult::Type::STR_HEX, "chain_id", "Affected or derived child-chain identifier"},
            {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee in KNE"},
            {RPCResult::Type::STR_AMOUNT, "registration_burn", "Value destroyed by REGISTER, otherwise zero"},
        }},
        RPCExamples{
            HelpExampleCli("walletsubmitchainregistrypsbt", "\"cHNidP8...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet_ptr{GetWalletForJSONRPCRequest(request)};
    if (!wallet_ptr) return UniValue::VNULL;
    CWallet& wallet{*wallet_ptr};
    wallet.BlockUntilSyncedToCurrentChain();

    const interfaces::ChainRegistrySnapshot initial_snapshot{
        wallet.chain().getChainRegistrySnapshot()};
    if (!initial_snapshot.enabled) {
        throw JSONRPCError(RPC_MISC_ERROR, "child-chain registry is disabled on this network");
    }
    if (!initial_snapshot.active_for_next_block) {
        throw JSONRPCError(RPC_MISC_ERROR, "child-chain registry is not active for the next block");
    }

    auto decoded{DecodeBase64PSBT(request.params[0].get_str())};
    if (!decoded) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           strprintf("PSBT decode failed: %s", util::ErrorString(decoded).original));
    }
    PartiallySignedTransaction psbt{std::move(*decoded)};
    const auto unsigned_tx{psbt.GetUnsignedTx()};
    if (!unsigned_tx) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "PSBT does not contain a complete unsigned transaction");
    }

    const CTransaction tx_template{*unsigned_tx};
    const auto extracted{chainregistry::ExtractTransactionOperation(
        tx_template, initial_snapshot.minimum_registration_burn)};
    if (!extracted.IsValid() || !extracted.operation) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT does not contain one valid chain registry operation");
    }

    const CAmount maximum_burn{request.params[1].isNull()
                                   ? initial_snapshot.minimum_registration_burn
                                   : AmountFromValue(request.params[1])};
    const uint32_t registry_output{extracted.operation->registry_output};
    const CAmount registration_burn{tx_template.vout[registry_output].nValue};
    if (registration_burn > maximum_burn) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("registration burn %s KNE exceeds authorized maximum %s KNE",
                                     FormatMoney(registration_burn), FormatMoney(maximum_burn)));
    }
    for (size_t index{0}; index < tx_template.vout.size(); ++index) {
        if (index != registry_output && tx_template.vout[index].scriptPubKey.IsUnspendable()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "PSBT contains an additional unspendable output");
        }
    }

    std::string operation_name;
    chainregistry::ChainId chain_id;
    std::optional<uint32_t> successor_control_output;
    std::visit([&](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<Payload, chainregistry::RegisterChain>) {
            operation_name = "register";
            successor_control_output = payload.control_output;
            chain_id = chainregistry::DeriveChainId(
                initial_snapshot.main_genesis_hash,
                tx_template.vin[payload.anchor_input].prevout,
                chainregistry::ComputeChainSpecHash(payload.manifest.spec));
        } else if constexpr (std::is_same_v<Payload, chainregistry::UpdateChain>) {
            operation_name = "update";
            successor_control_output = payload.control_output;
            chain_id = payload.chain_id;
        } else {
            operation_name = "retire";
            chain_id = payload.chain_id;
        }
    }, extracted.operation->operation);

    if (operation_name == "register") {
        const interfaces::ChainRegistrySnapshot snapshot{
            wallet.chain().getChainRegistrySnapshot(chain_id)};
        if (snapshot.record) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is already registered");
        }
    } else {
        const interfaces::ChainRegistrySnapshot snapshot{
            wallet.chain().getChainRegistrySnapshot(chain_id)};
        if (!snapshot.record) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id is not registered");
        }
        if (snapshot.record->status != chainregistry::ChainStatus::ACTIVE) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is retired");
        }
        if (tx_template.vin.empty() ||
            tx_template.vin[0].prevout != snapshot.record->control_outpoint) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "PSBT vin[0] is not the current child-chain control outpoint");
        }
    }
    if (successor_control_output &&
        !WITH_LOCK(wallet.cs_wallet,
                   return wallet.IsMine(tx_template.vout[*successor_control_output]))) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "PSBT successor control output is not owned by this wallet");
    }

    CAmount input_value{0};
    {
        LOCK(wallet.cs_wallet);
        for (const auto& input : tx_template.vin) {
            const CWalletTx* wallet_tx{wallet.GetWalletTx(input.prevout.hash)};
            if (!wallet_tx || input.prevout.n >= wallet_tx->tx->vout.size() ||
                !wallet.IsMine(wallet_tx->tx->vout[input.prevout.n])) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    strprintf("PSBT input %s:%d is not owned by this wallet",
                              input.prevout.hash.ToString(), input.prevout.n));
            }
            const CAmount value{wallet_tx->tx->vout[input.prevout.n].nValue};
            if (!MoneyRange(value) || !MoneyRange(input_value + value)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "PSBT input value is out of range");
            }
            input_value += value;
        }
    }

    EnsureWalletIsUnlocked(wallet);
    bool complete{false};
    if (const auto error{wallet.FillPSBT(
            psbt, {.sign = true, .finalize = true, .bip32_derivs = false}, complete)}) {
        throw JSONRPCPSBTError(*error);
    }
    if (!complete) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "wallet could not sign and finalize every registry transaction input");
    }

    CAmount output_value{0};
    for (const auto& output : tx_template.vout) {
        if (!MoneyRange(output.nValue) || !MoneyRange(output_value + output.nValue)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "PSBT output value is out of range");
        }
        output_value += output.nValue;
    }
    const CAmount fee{input_value - output_value};
    if (fee < 0) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "PSBT transaction fee is negative");
    }
    if (fee > wallet.m_default_max_tx_fee) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           TransactionErrorString(TransactionError::MAX_FEE_EXCEEDED).original);
    }

    CMutableTransaction final_tx;
    if (!FinalizeAndExtractPSBT(psbt, final_tx)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "failed to extract finalized registry transaction");
    }
    const std::string hex{EncodeHexTx(CTransaction{final_tx})};
    const CTransactionRef tx{MakeTransactionRef(std::move(final_tx))};

    std::string broadcast_error;
    if (!wallet.chain().broadcastTransaction(
            tx, wallet.m_default_max_tx_fee,
            node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL, broadcast_error)) {
        throw JSONRPCError(RPC_VERIFY_REJECTED,
                           strprintf("registry transaction rejected: %s", broadcast_error));
    }
    wallet.CommitTransaction(tx, {}, /*orderForm=*/{});

    UniValue result{UniValue::VOBJ};
    result.pushKV("txid", tx->GetHash().GetHex());
    result.pushKV("hex", hex);
    result.pushKV("operation", operation_name);
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("fee", ValueFromAmount(fee));
    result.pushKV("registration_burn", ValueFromAmount(registration_burn));
    return result;
},
    };
}
} // namespace wallet
