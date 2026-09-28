// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_psbt.h>
#include <chainregistry/child_psbt_sign.h>
#include <chainregistry/child_template.h>
#include <consensus/consensus.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <external_signer.h>
#include <interfaces/chain.h>
#include <policy/policy.h>
#include <psbt.h>
#include <random.h>
#include <rpc/util.h>
#include <script/signingprovider.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/rpc/child.h>
#include <wallet/rpc/child_util.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <univalue.h>

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace wallet {
namespace {

interfaces::ChildWalletScan ScanSupportedChildWallet(
    const CWallet& wallet,
    const chainregistry::ChainId& chain_id)
{
    auto scan{ScanChildWallet(wallet, chain_id)};
    if (!scan.completed ||
        scan.template_id != chainregistry::REFERENCE_CHILD_TEMPLATE_ID ||
        scan.template_version !=
            chainregistry::REFERENCE_CHILD_TEMPLATE_VERSION ||
        scan.genesis_hash.IsNull()) {
        throw JSONRPCError(
            RPC_INTERNAL_ERROR,
            "loaded child chain has an unsupported or incomplete consensus identity");
    }
    return scan;
}

chainregistry::ReferenceChildDefinition DefinitionFromScan(
    const chainregistry::ChainId& chain_id,
    const interfaces::ChildWalletScan& scan)
{
    chainregistry::ReferenceChildDefinition definition;
    definition.chain_id = chain_id;
    definition.genesis_hash = scan.genesis_hash;
    return definition;
}

uint64_t Confirmations(const interfaces::ChildWalletScan& scan,
                       const interfaces::ChildWalletCoin& coin)
{
    if (coin.mempool) return 0;
    if (coin.height > scan.height) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "child wallet UTXO height exceeds the child tip");
    }
    return uint64_t{scan.height} - coin.height + 1;
}

bool IsMature(const interfaces::ChildWalletScan& scan,
              const interfaces::ChildWalletCoin& coin)
{
    return !coin.coinbase || Confirmations(scan, coin) >= COINBASE_MATURITY;
}

void AddAmount(CAmount& total, CAmount amount, std::string_view name)
{
    if (amount < 0 || !MoneyRange(amount) ||
        amount > MAX_MONEY - total) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("%s amount is out of range", name));
    }
    total += amount;
}

void CheckTransactionStructure(const CMutableTransaction& transaction)
{
    TxValidationState state;
    if (!CheckTransaction(CTransaction{transaction}, state) ||
        !CheckNativeTransaction(CTransaction{transaction}, state)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("invalid child transaction: %s", state.ToString()));
    }
}

void CheckSignedWeight(CMutableTransaction transaction)
{
    for (CTxIn& input : transaction.vin) {
        input.scriptWitness.stack = {
            std::vector<unsigned char>(64, 0)};
    }
    if (GetTransactionWeight(CTransaction{transaction}) >
        MAX_STANDARD_TX_WEIGHT) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("child transaction exceeds maximum standard weight %d",
                      MAX_STANDARD_TX_WEIGHT));
    }
}

std::string EncodePSBT(const PartiallySignedTransaction& psbt)
{
    DataStream stream;
    stream << psbt;
    return EncodeBase64(stream.str());
}

std::map<COutPoint, const interfaces::ChildWalletCoin*>
IndexChildCoins(const interfaces::ChildWalletScan& scan)
{
    std::map<COutPoint, const interfaces::ChildWalletCoin*> indexed;
    for (const auto& coin : scan.coins) {
        if (!MoneyRange(coin.output.nValue) || coin.output.nValue <= 0 ||
            !indexed.emplace(coin.outpoint, &coin).second) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child wallet UTXO data is inconsistent");
        }
    }
    return indexed;
}

void FillChildInput(
    CWallet& wallet,
    PartiallySignedTransaction& psbt,
    unsigned int input_index,
    const chainregistry::ReferenceChildDefinition& definition,
    const PrecomputedTransactionData& txdata,
    bool sign,
    bool bip32_derivs,
    bool finalize,
    std::optional<int> sighash_type)
{
    LOCK(wallet.cs_wallet);
    const CScript& script{psbt.inputs.at(input_index).witness_utxo.scriptPubKey};
    bool found_provider{false};
    for (ScriptPubKeyMan* manager : wallet.GetScriptPubKeyMans(script)) {
        auto provider{manager->GetSigningProviderForTransaction(
            script, /*include_private=*/sign)};
        if (!provider) continue;
        found_provider = true;
        HidingSigningProvider filtered{
            provider.get(),
            /*hide_secret=*/!sign,
            /*hide_origin=*/!bip32_derivs};
        const auto updated{chainregistry::UpdateChildPSBTInput(
            filtered,
            psbt,
            input_index,
            definition,
            txdata,
            sighash_type,
            finalize)};
        if (!updated.IsValid()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("child PSBT input %u: %s (%s)",
                          input_index,
                          chainregistry::ChildPSBTSignErrorString(
                              updated.error),
                          chainregistry::ChildPSBTIdentityErrorString(
                              updated.identity_error)));
        }
        if (updated.signature_complete) return;
    }
    if (!found_provider) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf("wallet has no signing provider for child input %u",
                      input_index));
    }
}

void FillChildOutputs(CWallet& wallet,
                      PartiallySignedTransaction& psbt,
                      bool bip32_derivs)
{
    LOCK(wallet.cs_wallet);
    for (unsigned int index{0}; index < psbt.outputs.size(); ++index) {
        const CScript& script{psbt.outputs[index].script};
        for (ScriptPubKeyMan* manager : wallet.GetScriptPubKeyMans(script)) {
            auto provider{manager->GetSigningProviderForTransaction(
                script, /*include_private=*/false)};
            if (!provider) continue;
            HidingSigningProvider filtered{
                provider.get(),
                /*hide_secret=*/true,
                /*hide_origin=*/!bip32_derivs};
            UpdatePSBTOutput(filtered, psbt, index);
        }
    }
}

struct FundedChildPSBT {
    PartiallySignedTransaction psbt;
    interfaces::ChildWalletScan scan;
    CAmount fee{0};
    CAmount change{0};
    int change_position{-1};
    size_t input_count{0};
};

FundedChildPSBT FundChildPSBT(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::vector<std::pair<WitnessV1Taproot, CAmount>>& outputs,
    CAmount requested_fee,
    int minconf,
    bool bip32_derivs,
    const std::optional<std::set<COutPoint>>& input_filter = std::nullopt)
{
    if (requested_fee < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "fee must not be negative");
    }
    if (minconf < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "minconf must not be negative");
    }
    if (outputs.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "outputs must not be empty");
    }

    CMutableTransaction transaction;
    CAmount required{requested_fee};
    for (const auto& [recipient, amount] : outputs) {
        if (amount <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "output amount must be positive");
        }
        AddAmount(required, amount, "total output");
        CTxOut txout{amount, GetScriptForDestination(recipient)};
        if (IsDust(txout, wallet.chain().relayDustFee())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "child output is below the dust threshold");
        }
        transaction.vout.push_back(std::move(txout));
    }

    const interfaces::ChildWalletScan scan{
        ScanSupportedChildWallet(wallet, chain_id)};
    const auto definition{DefinitionFromScan(chain_id, scan)};
    std::vector<COutPoint> locked_outputs;
    {
        LOCK(wallet.cs_wallet);
        wallet.ListLockedChildCoins(chain_id, locked_outputs);
    }
    const std::set<COutPoint> locked{
        locked_outputs.begin(), locked_outputs.end()};
    std::vector<const interfaces::ChildWalletCoin*> candidates;
    for (const auto& coin : scan.coins) {
        if (!MoneyRange(coin.output.nValue) || coin.output.nValue <= 0) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child wallet UTXO amount is invalid");
        }
        if (Confirmations(scan, coin) < static_cast<uint64_t>(minconf) ||
            !IsMature(scan, coin) || !coin.trusted ||
            locked.contains(coin.outpoint) ||
            (input_filter && !input_filter->contains(coin.outpoint))) {
            continue;
        }
        candidates.push_back(&coin);
    }
    std::sort(candidates.begin(), candidates.end(), [](const auto* left,
                                                       const auto* right) {
        if (left->output.nValue != right->output.nValue) {
            return left->output.nValue > right->output.nValue;
        }
        return left->outpoint < right->outpoint;
    });

    CAmount selected{0};
    std::vector<const interfaces::ChildWalletCoin*> selected_coins;
    for (const auto* coin : candidates) {
        selected_coins.push_back(coin);
        AddAmount(selected, coin->output.nValue, "selected input");
        if (selected >= required) break;
    }
    if (selected < required) {
        throw JSONRPCError(
            RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("insufficient mature child funds: need %s KNE, have %s KNE",
                      FormatMoney(required), FormatMoney(selected)));
    }

    for (const auto* coin : selected_coins) {
        transaction.vin.emplace_back(coin->outpoint);
    }
    const CAmount change{selected - required};
    int change_position{-1};
    if (change > 0) {
        auto destination{wallet.GetNewChildChangeDestination(chain_id)};
        if (!destination) {
            throw JSONRPCError(
                RPC_WALLET_KEYPOOL_RAN_OUT,
                util::ErrorString(destination).original);
        }
        if (!std::holds_alternative<WitnessV1Taproot>(*destination)) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "wallet did not derive a Taproot child change recipient");
        }
        CTxOut change_output{
            change, GetScriptForDestination(*destination)};
        if (IsDust(change_output, wallet.chain().relayDustFee())) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "selected child change is below the dust threshold; adjust outputs or fee");
        }
        FastRandomContext random;
        change_position = random.randrange(transaction.vout.size() + 1);
        transaction.vout.insert(
            transaction.vout.begin() + change_position,
            std::move(change_output));
    }

    CheckTransactionStructure(transaction);
    CheckSignedWeight(transaction);
    PartiallySignedTransaction psbt{transaction};
    for (unsigned int index{0}; index < selected_coins.size(); ++index) {
        psbt.inputs[index].witness_utxo = selected_coins[index]->output;
    }
    const chainregistry::ChildPSBTIdentity identity{
        .chain_id = chain_id,
        .template_id = scan.template_id,
        .template_version = scan.template_version,
        .genesis_hash = scan.genesis_hash,
    };
    const auto identity_error{
        chainregistry::AddChildPSBTIdentity(psbt, identity)};
    if (identity_error != chainregistry::ChildPSBTIdentityError::NONE) {
        throw JSONRPCError(
            RPC_INTERNAL_ERROR,
            strprintf("could not bind child PSBT identity: %s",
                      chainregistry::ChildPSBTIdentityErrorString(
                          identity_error)));
    }
    const auto txdata{PrecomputePSBTData(psbt)};
    if (!txdata) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "could not precompute child PSBT data");
    }
    for (unsigned int index{0}; index < psbt.inputs.size(); ++index) {
        FillChildInput(wallet,
                       psbt,
                       index,
                       definition,
                       *txdata,
                       /*sign=*/false,
                       bip32_derivs,
                       /*finalize=*/false,
                       SIGHASH_DEFAULT);
    }
    FillChildOutputs(wallet, psbt, bip32_derivs);

    return {
        .psbt = std::move(psbt),
        .scan = scan,
        .fee = requested_fee,
        .change = change,
        .change_position = change_position,
        .input_count = selected_coins.size(),
    };
}

struct ProcessedChildPSBT {
    PartiallySignedTransaction psbt;
    chainregistry::ChildPSBTIdentity identity;
    CAmount fee{0};
    bool complete{false};
    std::optional<CTransaction> transaction;
};

ProcessedChildPSBT ProcessChildPSBT(
    CWallet& wallet,
    PartiallySignedTransaction psbt,
    CAmount maximum_fee,
    bool sign,
    std::optional<int> sighash_type,
    bool bip32_derivs,
    bool finalize)
{
    const auto parsed_identity{
        chainregistry::ExtractChildPSBTIdentity(psbt)};
    if (!parsed_identity.IsValid()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("invalid child PSBT identity: %s",
                      chainregistry::ChildPSBTIdentityErrorString(
                          parsed_identity.error)));
    }
    const auto identity{*parsed_identity.identity};
    const interfaces::ChildWalletScan scan{
        ScanSupportedChildWallet(wallet, identity.chain_id)};
    const auto definition{DefinitionFromScan(identity.chain_id, scan)};
    const auto identity_error{
        chainregistry::VerifyChildPSBTIdentity(psbt, definition)};
    if (identity_error != chainregistry::ChildPSBTIdentityError::NONE ||
        identity.template_id != scan.template_id ||
        identity.template_version != scan.template_version) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("child PSBT does not match the loaded child definition: %s",
                      chainregistry::ChildPSBTIdentityErrorString(
                          identity_error)));
    }

    const auto unsigned_tx{psbt.GetUnsignedTx()};
    if (!unsigned_tx) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           "child PSBT has no complete unsigned transaction");
    }
    CheckTransactionStructure(*unsigned_tx);
    CheckSignedWeight(*unsigned_tx);
    const auto coins{IndexChildCoins(scan)};
    if (psbt.inputs.size() != unsigned_tx->vin.size()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           "child PSBT input maps do not match its transaction");
    }

    CAmount input_value{0};
    for (unsigned int index{0}; index < unsigned_tx->vin.size(); ++index) {
        const COutPoint& outpoint{unsigned_tx->vin[index].prevout};
        const auto found{coins.find(outpoint)};
        if (found == coins.end()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("child input %u is spent, unknown, or not owned by this wallet",
                          index));
        }
        const auto& coin{*found->second};
        if (!IsMature(scan, coin)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("child input %u spends an immature coinbase", index));
        }
        PSBTInput& input{psbt.inputs[index]};
        if (!input.witness_utxo.IsNull() &&
            input.witness_utxo != coin.output) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("child input %u witness_utxo does not match the loaded UTXO set",
                          index));
        }
        input.witness_utxo = coin.output;
        AddAmount(input_value, coin.output.nValue, "child input");
    }
    CAmount output_value{0};
    for (const CTxOut& output : unsigned_tx->vout) {
        AddAmount(output_value, output.nValue, "child output");
    }
    if (output_value > input_value) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child PSBT outputs exceed its inputs");
    }
    const CAmount fee{input_value - output_value};
    if (maximum_fee < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "max_fee must not be negative");
    }
    if (fee > maximum_fee) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("child transaction fee %s KNE exceeds authorized maximum %s KNE",
                      FormatMoney(fee), FormatMoney(maximum_fee)));
    }

    const bool external_signer{
        sign && wallet.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)};
    if (sign) EnsureWalletIsUnlocked(wallet);
    const auto txdata{PrecomputePSBTData(psbt)};
    if (!txdata) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           "could not precompute child PSBT data");
    }
    for (unsigned int index{0}; index < psbt.inputs.size(); ++index) {
        FillChildInput(wallet,
                       psbt,
                       index,
                       definition,
                       *txdata,
                       sign,
                       bip32_derivs || external_signer,
                       finalize,
                       sighash_type);
    }
    FillChildOutputs(wallet, psbt, bip32_derivs || external_signer);

    if (external_signer) {
        const CTransaction authorized_transaction{*unsigned_tx};
        std::vector<CTxOut> authorized_inputs;
        authorized_inputs.reserve(psbt.inputs.size());
        for (const PSBTInput& input : psbt.inputs) {
            authorized_inputs.push_back(input.witness_utxo);
        }

        auto signer{ExternalSignerScriptPubKeyMan::GetExternalSigner()};
        if (!signer) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                util::ErrorString(signer).original);
        }
        std::string signer_error;
        if (!signer->SignTransaction(psbt, signer_error, &identity)) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf("external signer failed to sign child PSBT: %s",
                          signer_error));
        }

        const auto returned_transaction{psbt.GetUnsignedTx()};
        if (!returned_transaction ||
            CTransaction{*returned_transaction} != authorized_transaction ||
            psbt.inputs.size() != authorized_inputs.size() ||
            psbt.outputs.size() != authorized_transaction.vout.size() ||
            chainregistry::VerifyChildPSBTIdentity(psbt, definition) !=
                chainregistry::ChildPSBTIdentityError::NONE) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "external signer changed the authorized child transaction or identity");
        }
        for (unsigned int index{0}; index < psbt.inputs.size(); ++index) {
            if (psbt.inputs[index].witness_utxo != authorized_inputs[index]) {
                throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    strprintf("external signer changed child input %u UTXO",
                              index));
            }
            const auto finalized{chainregistry::UpdateChildPSBTInput(
                DUMMY_SIGNING_PROVIDER,
                psbt,
                index,
                definition,
                *txdata,
                sighash_type,
                finalize)};
            if (!finalized.IsValid()) {
                throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    strprintf("external signer returned invalid child input %u: %s",
                              index,
                              chainregistry::ChildPSBTSignErrorString(
                                  finalized.error)));
            }
        }
    }

    if (!bip32_derivs) {
        for (PSBTInput& input : psbt.inputs) {
            input.m_tap_bip32_paths.clear();
        }
        for (PSBTOutput& output : psbt.outputs) {
            output.m_tap_bip32_paths.clear();
        }
    }

    bool complete{true};
    for (unsigned int index{0}; index < psbt.inputs.size(); ++index) {
        complete &= chainregistry::ChildPSBTInputSignedAndVerified(
            psbt, index, definition, *txdata);
    }

    std::optional<CTransaction> transaction;
    if (complete) {
        CMutableTransaction extracted_transaction;
        const auto extracted{chainregistry::FinalizeAndExtractChildPSBT(
            psbt, definition, extracted_transaction)};
        if (!extracted.IsValid()) {
            throw JSONRPCError(
                RPC_INTERNAL_ERROR,
                strprintf("could not extract complete child transaction: %s",
                          chainregistry::ChildPSBTSignErrorString(
                              extracted.error)));
        }
        transaction.emplace(extracted_transaction);
    }
    return {
        .psbt = std::move(psbt),
        .identity = identity,
        .fee = fee,
        .complete = complete,
        .transaction = std::move(transaction),
    };
}

} // namespace

static ChildWalletSendResult SignFundedChildPSBT(
    CWallet& wallet,
    FundedChildPSBT funded)
{
    auto processed{ProcessChildPSBT(
        wallet,
        std::move(funded.psbt),
        funded.fee,
        /*sign=*/true,
        SIGHASH_DEFAULT,
        /*bip32_derivs=*/true,
        /*finalize=*/true)};
    if (!processed.complete || !processed.transaction) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "wallet could not completely sign the child transaction");
    }
    return {
        .transaction = MakeTransactionRef(std::move(*processed.transaction)),
        .fee = processed.fee,
        .psbt = EncodePSBT(processed.psbt),
    };
}

ChildWalletSendResult CreateSignedChildPayments(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::vector<ChildWalletPayment>& payments,
    CAmount fee,
    int minconf)
{
    wallet.BlockUntilSyncedToCurrentChain();
    if (fee < 0 || !MoneyRange(fee)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child_fee must be non-negative and in range");
    }
    const size_t subtract_count{static_cast<size_t>(std::count_if(
        payments.begin(), payments.end(),
        [](const auto& payment) { return payment.subtract_fee; }))};
    std::vector<std::pair<WitnessV1Taproot, CAmount>> outputs;
    outputs.reserve(payments.size());
    bool first_subtract{true};
    for (const auto& payment : payments) {
        if (payment.amount <= 0 || !MoneyRange(payment.amount)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "amount must be positive and in range");
        }
        CAmount recipient_amount{payment.amount};
        if (payment.subtract_fee) {
            recipient_amount -= fee / subtract_count;
            if (first_subtract) {
                recipient_amount -= fee % subtract_count;
                first_subtract = false;
            }
        }
        if (recipient_amount <= 0 || !MoneyRange(recipient_amount)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "child_fee leaves a non-positive recipient amount");
        }
        outputs.emplace_back(payment.recipient, recipient_amount);
    }
    auto funded{FundChildPSBT(
        wallet,
        chain_id,
        outputs,
        fee,
        minconf,
        /*bip32_derivs=*/true)};
    return SignFundedChildPSBT(wallet, std::move(funded));
}

ChildWalletSendResult CreateSignedChildSweep(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const std::vector<ChildWalletSweepRecipient>& recipients,
    CAmount fee,
    int minconf)
{
    wallet.BlockUntilSyncedToCurrentChain();
    if (fee < 0 || !MoneyRange(fee)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child_fee must be non-negative and in range");
    }
    if (minconf < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "minconf must not be negative");
    }
    if (recipients.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "recipients must not be empty");
    }

    const interfaces::ChildWalletScan scan{
        ScanSupportedChildWallet(wallet, chain_id)};
    std::vector<COutPoint> locked_outputs;
    {
        LOCK(wallet.cs_wallet);
        wallet.ListLockedChildCoins(chain_id, locked_outputs);
    }
    const std::set<COutPoint> locked{
        locked_outputs.begin(), locked_outputs.end()};
    std::set<COutPoint> selected;
    CAmount available{0};
    for (const auto& coin : scan.coins) {
        if (!MoneyRange(coin.output.nValue) || coin.output.nValue <= 0) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child wallet UTXO amount is invalid");
        }
        if (Confirmations(scan, coin) < static_cast<uint64_t>(minconf) ||
            !IsMature(scan, coin) || !coin.trusted ||
            locked.contains(coin.outpoint)) {
            continue;
        }
        if (!selected.insert(coin.outpoint).second) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "child wallet UTXO data is inconsistent");
        }
        AddAmount(available, coin.output.nValue, "selected input");
    }
    if (available <= fee) {
        throw JSONRPCError(
            RPC_WALLET_INSUFFICIENT_FUNDS,
            "child wallet has no spendable value after the explicit fee");
    }

    CAmount fixed_total{0};
    size_t open_count{0};
    for (const auto& recipient : recipients) {
        if (!recipient.amount) {
            ++open_count;
            continue;
        }
        if (*recipient.amount <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "specified child output amount must be positive");
        }
        AddAmount(fixed_total, *recipient.amount, "specified output");
    }
    if (open_count == 0) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "sendall requires at least one child recipient without an amount");
    }
    const CAmount distributable{available - fee};
    if (fixed_total >= distributable) {
        throw JSONRPCError(
            RPC_WALLET_INSUFFICIENT_FUNDS,
            "specified child outputs leave no spendable remainder");
    }
    const CAmount remainder{distributable - fixed_total};
    const CAmount divisor{static_cast<CAmount>(open_count)};
    const CAmount share{remainder / divisor};
    const CAmount excess{remainder % divisor};
    std::vector<std::pair<WitnessV1Taproot, CAmount>> outputs;
    outputs.reserve(recipients.size());
    bool first_open{true};
    for (const auto& recipient : recipients) {
        CAmount amount{recipient.amount.value_or(share)};
        if (!recipient.amount && first_open) {
            amount += excess;
            first_open = false;
        }
        outputs.emplace_back(recipient.recipient, amount);
    }
    auto funded{FundChildPSBT(
        wallet,
        chain_id,
        outputs,
        fee,
        minconf,
        /*bip32_derivs=*/true,
        selected)};
    return SignFundedChildPSBT(wallet, std::move(funded));
}

ChildWalletSendResult CreateSignedChildPayment(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const WitnessV1Taproot& recipient,
    CAmount amount,
    CAmount fee,
    bool subtract_fee_from_amount,
    int minconf)
{
    return CreateSignedChildPayments(
        wallet,
        chain_id,
        {{recipient, amount, subtract_fee_from_amount}},
        fee,
        minconf);
}

RPCHelpMan walletcreatechildpsbt()
{
    return RPCHelpMan{
        "walletcreatechildpsbt",
        "Create and fund a PSBT spending wallet UTXOs on one loaded reference child chain.\n"
        "Recipients are canonical 32-byte child P2TR output keys, not main-chain addresses. The absolute fee is explicit because child chains have no independent wallet fee estimator.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact non-null child-chain identifier"},
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Child transaction outputs", {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "One output", {
                    {"recipient", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Valid 32-byte reference-child P2TR output key"},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount in KNE"},
                }},
            }},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Exact absolute child-chain transaction fee in KNE"},
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum child-chain confirmations for selected inputs"},
            {"bip32derivs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include known BIP32 derivation paths"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Funded child PSBT", {
            {RPCResult::Type::STR, "psbt", "Base64-encoded PSBTv2 with mandatory Kronein child identity fields"},
            {RPCResult::Type::STR_HEX, "chain_id", "Exact child-chain identifier"},
            {RPCResult::Type::STR_HEX, "genesis_hash", "Loaded child genesis hash"},
            {RPCResult::Type::STR_AMOUNT, "fee", "Exact transaction fee"},
            {RPCResult::Type::NUM, "changepos", "Change output position, or -1"},
            {RPCResult::Type::STR_AMOUNT, "change", "Change amount"},
            {RPCResult::Type::NUM, "inputs", "Number of selected child UTXOs"},
            {RPCResult::Type::STR_HEX, "child_tip", "Child tip used for coin selection"},
            {RPCResult::Type::NUM, "child_height", "Child height used for coin selection"},
        }},
        RPCExamples{
            HelpExampleCli(
                "walletcreatechildpsbt",
                "\"1111111111111111111111111111111111111111111111111111111111111111\" '[{\"recipient\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"amount\":1.0}]' 0.00001")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet_ptr{
        GetWalletForJSONRPCRequest(request)};
    if (!wallet_ptr) return UniValue::VNULL;
    CWallet& wallet{*wallet_ptr};
    wallet.BlockUntilSyncedToCurrentChain();

    const auto chain_id{
        ParseChildChainId(self.Arg<UniValue>("chain_id"))};
    const CAmount requested_fee{
        AmountFromValue(self.Arg<UniValue>("fee"))};
    const int minconf{self.Arg<int>("minconf")};
    const bool bip32_derivs{self.Arg<bool>("bip32derivs")};

    std::vector<std::pair<WitnessV1Taproot, CAmount>> child_outputs;
    const UniValue& outputs{self.Arg<UniValue>("outputs")};
    for (const UniValue& output : outputs.getValues()) {
        const UniValue& object{output.get_obj()};
        RPCTypeCheckObj(object,
                        {{"recipient", UniValueType(UniValue::VSTR)},
                         {"amount", UniValueType()}},
                        /*allow_null=*/false,
                        /*strict=*/true);
        const CAmount amount{
            AmountFromValue(object.find_value("amount"))};
        child_outputs.emplace_back(
            ParseChildRecipient(object.find_value("recipient")), amount);
    }
    auto funded{FundChildPSBT(wallet,
                              chain_id,
                              child_outputs,
                              requested_fee,
                              minconf,
                              bip32_derivs)};

    UniValue result{UniValue::VOBJ};
    result.pushKV("psbt", EncodePSBT(funded.psbt));
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("genesis_hash", funded.scan.genesis_hash.GetHex());
    result.pushKV("fee", ValueFromAmount(funded.fee));
    result.pushKV("changepos", funded.change_position);
    result.pushKV("change", ValueFromAmount(funded.change));
    result.pushKV("inputs", funded.input_count);
    result.pushKV("child_tip", funded.scan.best_block.GetHex());
    result.pushKV("child_height", funded.scan.height);
    return result;
},
    };
}

RPCHelpMan walletprocesschildpsbt()
{
    return RPCHelpMan{
        "walletprocesschildpsbt",
        "Verify a child PSBT against the exact loaded child UTXO set, add wallet metadata, and optionally sign in the child-chain signature domain.\n"
        "Every input must be a wallet-owned UTXO associated with the embedded chain_id. The mandatory max_fee is checked before private keys are used.\n" +
            HELP_REQUIRING_PASSPHRASE,
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded child PSBTv2"},
            {"max_fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Maximum absolute child-chain fee authorized by the caller"},
            {"sign", RPCArg::Type::BOOL, RPCArg::Default{true}, "Sign wallet-owned inputs"},
            {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT"}, "Signature hash type"},
            {"bip32derivs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include BIP32 derivation paths"},
            {"finalize", RPCArg::Type::BOOL, RPCArg::Default{true}, "Finalize inputs when possible"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Processed child PSBT", {
            {RPCResult::Type::STR, "psbt", "Updated base64-encoded child PSBTv2"},
            {RPCResult::Type::STR_HEX, "chain_id", "Verified child-chain identifier"},
            {RPCResult::Type::STR_HEX, "genesis_hash", "Verified loaded child genesis hash"},
            {RPCResult::Type::STR_AMOUNT, "fee", "Verified child transaction fee"},
            {RPCResult::Type::BOOL, "complete", "Whether all finalized input witnesses verify in the child domain"},
            {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "Final child transaction when complete"},
            {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Final child transaction identifier when complete"},
        }},
        RPCExamples{
            HelpExampleCli("walletprocesschildpsbt",
                           "\"cHNidP8...\" 0.001")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet_ptr{
        GetWalletForJSONRPCRequest(request)};
    if (!wallet_ptr) return UniValue::VNULL;
    CWallet& wallet{*wallet_ptr};
    wallet.BlockUntilSyncedToCurrentChain();

    auto decoded{DecodeBase64PSBT(
        std::string{self.Arg<std::string_view>("psbt")})};
    if (!decoded) {
        throw JSONRPCError(
            RPC_DESERIALIZATION_ERROR,
            strprintf("child PSBT decode failed: %s",
                      util::ErrorString(decoded).original));
    }
    const CAmount maximum_fee{
        AmountFromValue(self.Arg<UniValue>("max_fee"))};
    const bool sign{self.Arg<bool>("sign")};
    const bool bip32_derivs{self.Arg<bool>("bip32derivs")};
    const bool finalize{self.Arg<bool>("finalize")};
    const std::optional<int> sighash_type{
        ParseSighashString(self.Arg<UniValue>("sighashtype"))};
    auto processed{ProcessChildPSBT(wallet,
                                    std::move(*decoded),
                                    maximum_fee,
                                    sign,
                                    sighash_type,
                                    bip32_derivs,
                                    finalize)};

    UniValue result{UniValue::VOBJ};
    result.pushKV("psbt", EncodePSBT(processed.psbt));
    result.pushKV("chain_id", processed.identity.chain_id.GetHex());
    result.pushKV("genesis_hash", processed.identity.genesis_hash.GetHex());
    result.pushKV("fee", ValueFromAmount(processed.fee));
    result.pushKV("complete", processed.complete);
    if (processed.transaction) {
        result.pushKV("hex", EncodeHexTx(*processed.transaction));
        result.pushKV("txid", processed.transaction->GetHash().GetHex());
    }
    return result;
},
    };
}

static UniValue ChildAutoBidPolicyToJSON(
    const chainregistry::ChainId& chain_id,
    const std::optional<ChildAutoBidPolicy>& policy)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("enabled", policy.has_value());
    if (policy) {
        result.pushKV("version", policy->version);
        result.pushKV("fee_rate", ValueFromAmount(policy->fee_rate_per_kvb));
        result.pushKV("max_security_bid", ValueFromAmount(policy->max_bid));
        result.pushKV("daily_budget", ValueFromAmount(policy->daily_budget));
        result.pushKV("min_interval", policy->min_interval);
    }
    return result;
}

static UniValue ChildAutoBidResultToJSON(const ChildAutoBidResult& bid)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", bid.chain_id.GetHex());
    result.pushKV("status", ChildAutoBidStatusString(bid.status));
    result.pushKV("submitted", bid.Submitted());
    result.pushKV("daily_spent", ValueFromAmount(bid.daily_spent));
    if (!bid.child_block_hash.IsNull()) {
        result.pushKV("child_block_hash", bid.child_block_hash.GetHex());
    }
    if (!bid.txid.IsNull()) result.pushKV("txid", bid.txid.GetHex());
    if (bid.security_bid > 0) {
        result.pushKV("security_bid", ValueFromAmount(bid.security_bid));
    }
    if (!bid.error.empty()) result.pushKV("error", bid.error);
    return result;
}

RPCHelpMan getchildanchorautobid()
{
    return RPCHelpMan{
        "getchildanchorautobid",
        "Return this wallet's explicit automatic BMM security-bid policy for one child chain. Absence means disabled.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact non-null child-chain identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Automatic bid policy", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::BOOL, "enabled", "Whether automatic wallet spending is explicitly enabled"},
            {RPCResult::Type::NUM, "version", /*optional=*/true, "Policy format version"},
            {RPCResult::Type::STR_AMOUNT, "fee_rate", /*optional=*/true, "Configured main-chain fee rate in KNE/kvB"},
            {RPCResult::Type::STR_AMOUNT, "max_security_bid", /*optional=*/true, "Maximum fee for one anchor transaction"},
            {RPCResult::Type::STR_AMOUNT, "daily_budget", /*optional=*/true, "Maximum aggregate anchor fees in a rolling 24-hour window"},
            {RPCResult::Type::NUM_TIME, "min_interval", /*optional=*/true, "Minimum seconds between automatic anchor transactions"},
        }},
        RPCExamples{
            HelpExampleCli("getchildanchorautobid", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet{
        GetWalletForJSONRPCRequest(request)};
    if (!wallet) return UniValue::VNULL;
    const auto chain_id{ParseChildChainId(self.Arg<UniValue>("chain_id"))};
    return ChildAutoBidPolicyToJSON(
        chain_id, wallet->GetChildAutoBidPolicy(chain_id));
},
    };
}

RPCHelpMan setchildanchorautobid()
{
    return RPCHelpMan{
        "setchildanchorautobid",
        "Enable or disable automatic publication of BMM security bids by this wallet for one exact child chain.\n"
        "The policy is disabled by default. Enabling requires all monetary limits and persists them in the wallet. No funds are spent by this configuration call.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact non-null child-chain identifier"},
            {"enabled", RPCArg::Type::BOOL, RPCArg::Optional::NO, "True to store an opt-in policy; false to erase it"},
            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Required when enabling: main-chain fee rate in KNE/kvB"},
            {"max_security_bid", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Required when enabling: maximum fee for one anchor transaction"},
            {"daily_budget", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Required when enabling: rolling 24-hour aggregate fee limit"},
            {"min_interval", RPCArg::Type::NUM, RPCArg::Default{600}, "Minimum seconds between automatic anchor transactions (60-86400)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Stored automatic bid policy", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::BOOL, "enabled", "Whether automatic wallet spending is explicitly enabled"},
            {RPCResult::Type::NUM, "version", /*optional=*/true, "Policy format version"},
            {RPCResult::Type::STR_AMOUNT, "fee_rate", /*optional=*/true, "Configured main-chain fee rate in KNE/kvB"},
            {RPCResult::Type::STR_AMOUNT, "max_security_bid", /*optional=*/true, "Maximum fee for one anchor transaction"},
            {RPCResult::Type::STR_AMOUNT, "daily_budget", /*optional=*/true, "Rolling 24-hour aggregate fee limit"},
            {RPCResult::Type::NUM_TIME, "min_interval", /*optional=*/true, "Minimum seconds between automatic anchor transactions"},
        }},
        RPCExamples{
            HelpExampleCli("setchildanchorautobid", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" true 0.00002 0.001 0.01 600") +
            HelpExampleCli("setchildanchorautobid", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet{
        GetWalletForJSONRPCRequest(request)};
    if (!wallet) return UniValue::VNULL;
    const auto chain_id{ParseChildChainId(self.Arg<UniValue>("chain_id"))};
    const bool enabled{self.Arg<bool>("enabled")};
    if (!enabled) {
        if (!request.params[2].isNull() || !request.params[3].isNull() ||
            !request.params[4].isNull()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "fee_rate, max_security_bid, and daily_budget must be omitted when disabling automatic bids");
        }
        if (!wallet->EraseChildAutoBidPolicy(chain_id)) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "could not erase automatic BMM bid policy");
        }
        return ChildAutoBidPolicyToJSON(chain_id, std::nullopt);
    }

    if (request.params[2].isNull() || request.params[3].isNull() ||
        request.params[4].isNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "fee_rate, max_security_bid, and daily_budget are required when enabling automatic bids");
    }
    const auto snapshot{wallet->chain().getChainRegistrySnapshot(chain_id)};
    if (!snapshot.record) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "chain_id is not registered");
    }
    if (snapshot.record->status != chainregistry::ChainStatus::ACTIVE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is retired");
    }
    const int min_interval{self.Arg<int>("min_interval")};
    ChildAutoBidPolicy policy{
        .fee_rate_per_kvb = AmountFromValue(request.params[2]),
        .max_bid = AmountFromValue(request.params[3]),
        .daily_budget = AmountFromValue(request.params[4]),
        .min_interval = min_interval < 0 ? 0 : static_cast<uint32_t>(min_interval),
    };
    if (!IsValidChildAutoBidPolicy(policy)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "automatic bid policy requires a positive fee rate and bid, a daily budget at least equal to the bid cap, and an interval from 60 to 86400 seconds");
    }
    if (policy.max_bid > wallet->m_default_max_tx_fee) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "max_security_bid exceeds the wallet maximum transaction fee");
    }
    if (!wallet->SetChildAutoBidPolicy(chain_id, policy)) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "could not persist automatic BMM bid policy");
    }
    return ChildAutoBidPolicyToJSON(chain_id, policy);
},
    };
}

RPCHelpMan runchildanchorautobid()
{
    return RPCHelpMan{
        "runchildanchorautobid",
        "Immediately evaluate this wallet's stored automatic BMM bid policy for one child chain.\n"
        "At most one eligible proposal is anchored. All configured interval, per-bid, and rolling daily limits are enforced.\n" +
            HELP_REQUIRING_PASSPHRASE,
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact non-null child-chain identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Automatic bid attempt", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::STR, "status", "Machine-readable outcome"},
            {RPCResult::Type::BOOL, "submitted", "Whether a transaction was signed and broadcast"},
            {RPCResult::Type::STR_AMOUNT, "daily_spent", "Automatic anchor fees in the current rolling 24-hour window"},
            {RPCResult::Type::STR_HEX, "child_block_hash", /*optional=*/true, "Eligible child block, when one was found"},
            {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Submitted main-chain transaction"},
            {RPCResult::Type::STR_AMOUNT, "security_bid", /*optional=*/true, "Fee of the constructed or submitted anchor transaction"},
            {RPCResult::Type::STR, "error", /*optional=*/true, "Failure detail"},
        }},
        RPCExamples{
            HelpExampleCli("runchildanchorautobid", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<CWallet> wallet{
        GetWalletForJSONRPCRequest(request)};
    if (!wallet) return UniValue::VNULL;
    const auto chain_id{ParseChildChainId(self.Arg<UniValue>("chain_id"))};
    return ChildAutoBidResultToJSON(RunChildAutoBid(*wallet, chain_id));
},
    };
}

} // namespace wallet
