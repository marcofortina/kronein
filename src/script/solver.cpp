// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <span.h>

#include <algorithm>
#include <cassert>
#include <string>

typedef std::vector<unsigned char> valtype;

std::string GetTxnOutputType(TxoutType t)
{
    switch (t) {
    case TxoutType::NONSTANDARD: return "nonstandard";
    case TxoutType::NULL_DATA: return "nulldata";
    case TxoutType::ANCHOR: return "anchor";
    case TxoutType::WITNESS_V1_TAPROOT: return "witness_v1_taproot";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

/** Test for "small positive integer" script opcodes - OP_1 through OP_16. */
static constexpr bool IsSmallInteger(opcodetype opcode)
{
    return opcode >= OP_1 && opcode <= OP_16;
}

/** Retrieve a minimally-encoded number in range [min,max] from an (opcode, data) pair,
 *  whether it's OP_n or through a push. */
static std::optional<int> GetScriptNumber(opcodetype opcode, valtype data, int min, int max)
{
    int count;
    if (IsSmallInteger(opcode)) {
        count = CScript::DecodeOP_N(opcode);
    } else if (IsPushdataOp(opcode)) {
        if (!CheckMinimalPush(data, opcode)) return {};
        try {
            count = CScriptNum(data, /* fRequireMinimal = */ true).getint();
        } catch (const scriptnum_error&) {
            return {};
        }
    } else {
        return {};
    }
    if (count < min || count > max) return {};
    return count;
}

std::optional<std::pair<int, std::vector<std::span<const unsigned char>>>> MatchMultiA(const CScript& script)
{
    std::vector<std::span<const unsigned char>> keyspans;

    // Redundant, but very fast and selective test.
    if (script.size() == 0 || script[0] != 32 || script.back() != OP_NUMEQUAL) return {};

    // Parse keys
    auto it = script.begin();
    while (script.end() - it >= 34) {
        if (*it != 32) return {};
        ++it;
        keyspans.emplace_back(&*it, 32);
        it += 32;
        if (*it != (keyspans.size() == 1 ? OP_CHECKSIG : OP_CHECKSIGADD)) return {};
        ++it;
    }
    if (keyspans.size() == 0 || keyspans.size() > MAX_PUBKEYS_PER_MULTI_A) return {};

    // Parse threshold.
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(it, opcode, data)) return {};
    if (it == script.end()) return {};
    if (*it != OP_NUMEQUAL) return {};
    ++it;
    if (it != script.end()) return {};
    auto threshold = GetScriptNumber(opcode, data, 1, (int)keyspans.size());
    if (!threshold) return {};

    // Construct result.
    return std::pair{*threshold, std::move(keyspans)};
}

TxoutType Solver(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& vSolutionsRet)
{
    vSolutionsRet.clear();

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE) {
            vSolutionsRet.push_back(std::move(witnessprogram));
            return TxoutType::WITNESS_V1_TAPROOT;
        }
        if (scriptPubKey.IsPayToAnchor()) {
            return TxoutType::ANCHOR;
        }
        return TxoutType::NONSTANDARD;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        return TxoutType::NULL_DATA;
    }

    return TxoutType::NONSTANDARD;
}
