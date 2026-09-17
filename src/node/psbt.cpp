// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/amount.h>
#include <node/psbt.h>
#include <policy/policy.h>
#include <tinyformat.h>

#include <numeric>

namespace node {
PSBTAnalysis AnalyzePSBT(PartiallySignedTransaction psbtx)
{
    // Go through each input and build status
    PSBTAnalysis result;

    std::optional<CMutableTransaction> unsigned_tx = psbtx.GetUnsignedTx();
    if (!unsigned_tx) {
        result.SetInvalid("PSBT cannot be made into a valid transaction");
        return result;
    }
    CMutableTransaction& mtx = *unsigned_tx;

    bool calc_fee = true;

    CAmount in_amt = 0;

    result.inputs.resize(psbtx.inputs.size());

    // PrecomputePSBTData calls GetUnsignedTx() which we checked already works
    const PrecomputedTransactionData txdata = *PrecomputePSBTData(psbtx);

    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        PSBTInput& input = psbtx.inputs[i];
        PSBTInputAnalysis& input_analysis = result.inputs[i];

        // We set next role here and ratchet backwards as required
        input_analysis.next = PSBTRole::EXTRACTOR;

        // Check for a UTXO
        CTxOut utxo;
        if (input.GetUTXO(utxo)) {
            if (!MoneyRange(utxo.nValue) || !MoneyRange(in_amt + utxo.nValue)) {
                result.SetInvalid(strprintf("PSBT is not valid. Input %u has invalid value", i));
                return result;
            }
            in_amt += utxo.nValue;
            input_analysis.has_utxo = true;
        } else {
            input_analysis.has_utxo = false;
            input_analysis.is_final = false;
            input_analysis.next = PSBTRole::UPDATER;
            calc_fee = false;
        }

        if (!utxo.IsNull() && utxo.scriptPubKey.IsUnspendable()) {
            result.SetInvalid(strprintf("PSBT is not valid. Input %u spends unspendable output", i));
            return result;
        }

        // Check if it is final
        if (!PSBTInputSignedAndVerified(psbtx, i, &txdata)) {
            input_analysis.is_final = false;

            // Figure out what is missing
            SignatureData outdata;
            const auto sign_result = SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, &txdata, std::nullopt, &outdata);
            bool complete = sign_result.has_value();

            // Things are missing
            if (!complete) {
                input_analysis.missing_pubkeys = outdata.missing_pubkeys;
                input_analysis.next = PSBTRole::UPDATER;
            } else {
                input_analysis.next = PSBTRole::FINALIZER;
            }
        } else if (!utxo.IsNull()){
            input_analysis.is_final = true;
        }
    }

    // Calculate next role for PSBT by grabbing "minimum" PSBTInput next role
    result.next = PSBTRole::EXTRACTOR;
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        PSBTInputAnalysis& input_analysis = result.inputs[i];
        result.next = std::min(result.next, input_analysis.next);
    }
    assert(result.next > PSBTRole::CREATOR);

    if (calc_fee) {
        // Get the output amount
        CAmount out_amt = std::accumulate(psbtx.outputs.begin(), psbtx.outputs.end(), CAmount(0),
            [](CAmount a, const PSBTOutput& b) {
                if (!MoneyRange(a) || !MoneyRange(b.amount) || !MoneyRange(a + b.amount)) {
                    return CAmount(-1);
                }
                return a += b.amount;
            }
        );
        if (!MoneyRange(out_amt)) {
            result.SetInvalid("PSBT is not valid. Output amount invalid");
            return result;
        }

        // Get the fee
        CAmount fee = in_amt - out_amt;
        result.fee = fee;

        // Estimate the size
        bool success = true;

        for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
            PSBTInput& input = psbtx.inputs[i];
            CTxOut prevout;

            const auto sign_result = SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, nullptr, std::nullopt);
            if (!sign_result.has_value() || !input.GetUTXO(prevout)) {
                success = false;
                break;
            } else {
                mtx.vin[i].scriptWitness = input.final_script_witness;
            }
        }

        if (success) {
            CTransaction ctx = CTransaction(mtx);
            size_t size(GetVirtualTransactionSize(ctx));
            result.estimated_vsize = size;
            // Estimate fee rate
            CFeeRate feerate(fee, size);
            result.estimated_feerate = feerate;
        }

    }

    return result;
}
} // namespace node
