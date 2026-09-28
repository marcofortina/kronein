// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_psbt_sign.h>

#include <chainregistry/child_sign.h>
#include <policy/policy.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>

#include <algorithm>

namespace chainregistry {

std::string_view ChildPSBTSignErrorString(ChildPSBTSignError error)
{
    switch (error) {
    case ChildPSBTSignError::NONE: return "none";
    case ChildPSBTSignError::INVALID_IDENTITY:
        return "invalid child PSBT identity";
    case ChildPSBTSignError::INVALID_TRANSACTION:
        return "invalid child PSBT transaction";
    case ChildPSBTSignError::INPUT_OUT_OF_RANGE:
        return "child PSBT input index out of range";
    case ChildPSBTSignError::MISSING_INPUT:
        return "child PSBT input is missing its UTXO";
    case ChildPSBTSignError::UNSUPPORTED_SCRIPT:
        return "child PSBT input script is unsupported";
    case ChildPSBTSignError::SIGHASH_MISMATCH:
        return "child PSBT sighash type mismatch";
    case ChildPSBTSignError::INVALID_SIGNATURE:
        return "invalid child PSBT signature";
    }
    return "unknown child PSBT signing error";
}

bool ChildPSBTInputSignedAndVerified(
    const PartiallySignedTransaction& psbt,
    unsigned int input_index,
    const ReferenceChildDefinition& definition,
    const PrecomputedTransactionData& txdata)
{
    if (VerifyChildPSBTIdentity(psbt, definition) !=
            ChildPSBTIdentityError::NONE ||
        input_index >= psbt.inputs.size()) {
        return false;
    }
    const PSBTInput& input{psbt.inputs[input_index]};
    if (input.witness_utxo.IsNull() || input.final_script_witness.IsNull()) {
        return false;
    }
    const auto transaction{psbt.GetUnsignedTx()};
    if (!transaction) return false;

    const ReferenceChildMutableTransactionSignatureChecker checker{
        definition.chain_id,
        &*transaction,
        input_index,
        txdata,
        MissingDataBehavior::FAIL};
    return VerifyScript(CScript{},
                        input.witness_utxo.scriptPubKey,
                        &input.final_script_witness,
                        STANDARD_SCRIPT_VERIFY_FLAGS,
                        checker);
}

ChildPSBTSignResult UpdateChildPSBTInput(
    const SigningProvider& provider,
    PartiallySignedTransaction& psbt,
    unsigned int input_index,
    const ReferenceChildDefinition& definition,
    const PrecomputedTransactionData& txdata,
    std::optional<int> sighash_type,
    bool finalize,
    SignatureData* output_signature_data)
{
    const auto identity_error{VerifyChildPSBTIdentity(psbt, definition)};
    if (identity_error != ChildPSBTIdentityError::NONE) {
        return {
            .error = ChildPSBTSignError::INVALID_IDENTITY,
            .identity_error = identity_error,
        };
    }
    if (input_index >= psbt.inputs.size()) {
        return {.error = ChildPSBTSignError::INPUT_OUT_OF_RANGE};
    }
    const auto transaction{psbt.GetUnsignedTx()};
    if (!transaction) {
        return {.error = ChildPSBTSignError::INVALID_TRANSACTION};
    }

    PSBTInput& input{psbt.inputs[input_index]};
    if (input.witness_utxo.IsNull()) {
        return {.error = ChildPSBTSignError::MISSING_INPUT};
    }
    if (!input.witness_utxo.scriptPubKey.IsPayToTaproot()) {
        return {.error = ChildPSBTSignError::UNSUPPORTED_SCRIPT};
    }
    if (!input.final_script_witness.IsNull()) {
        if (ChildPSBTInputSignedAndVerified(
                psbt, input_index, definition, txdata)) {
            return {
                .error = ChildPSBTSignError::NONE,
                .signature_complete = true,
            };
        }
        return {.error = ChildPSBTSignError::INVALID_SIGNATURE};
    }

    const int sighash{sighash_type.value_or(SIGHASH_DEFAULT)};
    if (input.sighash_type && *input.sighash_type != sighash) {
        return {.error = ChildPSBTSignError::SIGHASH_MISMATCH};
    }
    if (sighash != SIGHASH_DEFAULT) input.sighash_type = sighash;

    if (sighash == SIGHASH_DEFAULT) {
        if ((!input.m_tap_key_sig.empty() &&
             input.m_tap_key_sig.size() != 64) ||
            std::ranges::any_of(input.m_tap_script_sigs, [](const auto& item) {
                return item.second.size() != 64;
            })) {
            return {.error = ChildPSBTSignError::SIGHASH_MISMATCH};
        }
    } else if ((!input.m_tap_key_sig.empty() &&
                (input.m_tap_key_sig.size() != 65 ||
                 input.m_tap_key_sig.back() != sighash)) ||
               std::ranges::any_of(
                   input.m_tap_script_sigs, [sighash](const auto& item) {
                       return item.second.size() != 65 ||
                              item.second.back() != sighash;
                   })) {
        return {.error = ChildPSBTSignError::SIGHASH_MISMATCH};
    }

    const bool had_signatures{input.HasSignatures()};
    SignatureData signature_data;
    input.FillSignatureData(signature_data);
    const ReferenceChildSignatureCreator creator{
        definition.chain_id,
        *transaction,
        input_index,
        txdata,
        sighash};
    const bool signature_complete{ProduceSignature(
        provider,
        creator,
        input.witness_utxo.scriptPubKey,
        signature_data)};
    if (!signature_complete && had_signatures) {
        return {.error = ChildPSBTSignError::INVALID_SIGNATURE};
    }
    if (!finalize && signature_data.complete) {
        signature_data.complete = false;
    }
    input.FromSignatureData(signature_data);
    if (output_signature_data) {
        *output_signature_data = std::move(signature_data);
    }
    return {
        .error = ChildPSBTSignError::NONE,
        .signature_complete = signature_complete,
    };
}

ChildPSBTSignResult FinalizeAndExtractChildPSBT(
    PartiallySignedTransaction& psbt,
    const ReferenceChildDefinition& definition,
    CMutableTransaction& result)
{
    const auto identity_error{VerifyChildPSBTIdentity(psbt, definition)};
    if (identity_error != ChildPSBTIdentityError::NONE) {
        return {
            .error = ChildPSBTSignError::INVALID_IDENTITY,
            .identity_error = identity_error,
        };
    }
    const auto txdata{PrecomputePSBTData(psbt)};
    if (!txdata) {
        return {.error = ChildPSBTSignError::INVALID_TRANSACTION};
    }
    for (unsigned int index{0}; index < psbt.inputs.size(); ++index) {
        const auto update{UpdateChildPSBTInput(
            DUMMY_SIGNING_PROVIDER,
            psbt,
            index,
            definition,
            *txdata,
            psbt.inputs[index].sighash_type,
            /*finalize=*/true)};
        if (!update.IsValid()) return update;
        if (!ChildPSBTInputSignedAndVerified(
                psbt, index, definition, *txdata)) {
            return {.error = ChildPSBTSignError::INVALID_SIGNATURE};
        }
    }

    const auto transaction{psbt.GetUnsignedTx()};
    if (!transaction) {
        return {.error = ChildPSBTSignError::INVALID_TRANSACTION};
    }
    result = *transaction;
    for (unsigned int index{0}; index < result.vin.size(); ++index) {
        result.vin[index].scriptWitness =
            psbt.inputs[index].final_script_witness;
    }
    return {
        .error = ChildPSBTSignError::NONE,
        .signature_complete = true,
    };
}

} // namespace chainregistry
