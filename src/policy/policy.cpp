// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include <policy/policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>

#include <algorithm>
#include <cstddef>
#include <vector>

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // Estimate the cost of creating and spending a native witness output.
    if (txout.scriptPubKey.IsUnspendable())
        return 0;

    uint64_t nSize{GetSerializeSize(txout)};
    int witnessversion = 0;
    std::vector<unsigned char> witnessprogram;

    if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        // Outpoint, empty scriptSig, sequence, and a discounted key-path witness.
        nSize += (32 + 4 + 1 + (66 / WITNESS_SCALE_FACTOR) + 4);
    } else {
        return 0;
    }

    return dustRelayFeeIn.GetFee(nSize);
}

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    return (txout.nValue < GetDustThreshold(txout, dustRelayFeeIn));
}

std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate)
{
    std::vector<uint32_t> dust_outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        if (IsDust(tx.vout[i], dust_relay_rate)) dust_outputs.push_back(i);
    }
    return dust_outputs;
}

bool IsStandard(const CScript& scriptPubKey, TxoutType& whichType)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    whichType = Solver(scriptPubKey, vSolutions);
    return whichType == TxoutType::WITNESS_V1_TAPROOT ||
           whichType == TxoutType::ANCHOR ||
           whichType == TxoutType::NULL_DATA;
}

bool IsStandardTx(const CTransaction& tx, const std::optional<unsigned>& max_datacarrier_bytes, const CFeeRate& dust_relay_fee, std::string& reason)
{
    if (tx.version != CTransaction::CURRENT_VERSION) {
        reason = "version";
        return false;
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_WEIGHT mitigates CPU exhaustion attacks.
    unsigned int sz = GetTransactionWeight(tx);
    if (sz > MAX_STANDARD_TX_WEIGHT) {
        reason = "tx-size";
        return false;
    }

    for (const CTxIn& txin : tx.vin) {
        if (!txin.scriptSig.empty()) {
            reason = "scriptsig-not-empty";
            return false;
        }
    }

    unsigned int datacarrier_bytes_left = max_datacarrier_bytes.value_or(0);
    TxoutType whichType;
    for (const CTxOut& txout : tx.vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType)) {
            reason = "scriptpubkey";
            return false;
        }

        if (whichType == TxoutType::NULL_DATA) {
            unsigned int size = txout.scriptPubKey.size();
            if (size > datacarrier_bytes_left) {
                reason = "datacarrier";
                return false;
            }
            datacarrier_bytes_left -= size;
        }
    }

    // Only MAX_DUST_OUTPUTS_PER_TX dust is permitted(on otherwise valid ephemeral dust)
    if (GetDust(tx, dust_relay_fee).size() > MAX_DUST_OUTPUTS_PER_TX) {
        reason = "dust";
        return false;
    }

    return true;
}

bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase()) {
        return true; // Coinbases don't use vin normally
    }

    for (const CTxIn& txin : tx.vin) {
        std::vector<std::vector<unsigned char>> solutions;
        const TxoutType type{Solver(mapInputs.AccessCoin(txin.prevout).out.scriptPubKey, solutions)};
        if (type != TxoutType::WITNESS_V1_TAPROOT && type != TxoutType::ANCHOR) return false;
    }

    return true;
}

bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases are skipped

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // We don't care if witness for this input is empty, since it must not be bloated.
        // If the script is invalid without witness, it would be caught sooner or later during validation.
        if (tx.vin[i].scriptWitness.IsNull())
            continue;

        const CTxOut &prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        // witness stuffing detected
        if (prev.scriptPubKey.IsPayToAnchor()) {
            return false;
        }

        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;
        if (!prev.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram) ||
            witnessversion != 1 || witnessprogram.size() != WITNESS_V1_TAPROOT_SIZE) return false;

        // Check policy limits for Taproot spends:
        // - MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE limit for stack item size
        // - No annexes
        {
            // Taproot spend (non-P2SH-wrapped, version 1, witness program size 32; see BIP 341)
            std::span stack{tx.vin[i].scriptWitness.stack};
            if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
                // Annexes are nonstandard as long as no semantics are defined for them.
                return false;
            }
            if (stack.size() >= 2) {
                // Script path spend (2 or more stack elements after removing optional annex)
                const auto& control_block = SpanPopBack(stack);
                SpanPopBack(stack); // Ignore script
                if (control_block.empty()) return false; // Empty control block is invalid
                if ((control_block[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT) {
                    // Leaf version 0xc0 (aka Tapscript, see BIP 342)
                    for (const auto& item : stack) {
                        if (item.size() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE) return false;
                    }
                }
            } else if (stack.size() == 1) {
                // Key path spend (1 stack element after removing optional annex)
                // (no policy rules apply)
            } else {
                // 0 stack elements; this is already invalid by consensus rules
                return false;
            }
        }
    }
    return true;
}

bool SpendsNonAnchorWitnessProg(const CTransaction& tx, const CCoinsViewCache& prevouts)
{
    if (tx.IsCoinBase()) {
        return false;
    }

    int version;
    std::vector<uint8_t> program;
    for (const auto& txin: tx.vin) {
        const auto& prev_spk{prevouts.AccessCoin(txin.prevout).out.scriptPubKey};

        // Note this includes not-yet-defined witness programs.
        if (prev_spk.IsWitnessProgram(version, program) && !prev_spk.IsPayToAnchor(version, program)) {
            return true;
        }

    }

    return false;
}

int64_t GetVirtualTransactionSize(int64_t weight)
{
    return (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}
