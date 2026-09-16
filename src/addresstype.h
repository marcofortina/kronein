// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDRESSTYPE_H
#define BITCOIN_ADDRESSTYPE_H

#include <attributes.h>
#include <pubkey.h>
#include <script/script.h>
#include <util/check.h>

#include <variant>
#include <vector>

class CNoDestination
{
private:
    CScript m_script;

public:
    CNoDestination() = default;
    explicit CNoDestination(const CScript& script) : m_script(script) {}

    const CScript& GetScript() const LIFETIMEBOUND { return m_script; }

    friend bool operator==(const CNoDestination& a, const CNoDestination& b) { return a.GetScript() == b.GetScript(); }
    friend bool operator<(const CNoDestination& a, const CNoDestination& b) { return a.GetScript() < b.GetScript(); }
};

struct WitnessV1Taproot : public XOnlyPubKey
{
    WitnessV1Taproot() : XOnlyPubKey() {}
    explicit WitnessV1Taproot(const XOnlyPubKey& xpk) : XOnlyPubKey(xpk) {}
};

/** Witness program for Pay-to-Anchor output script type */
static const std::vector<unsigned char> ANCHOR_BYTES{0x4e, 0x73};

struct PayToAnchor
{
    PayToAnchor() {
        Assume(CScript::IsPayToAnchor(1, ANCHOR_BYTES));
    };

    unsigned int GetWitnessVersion() const { return 1; }
    const std::vector<unsigned char>& GetWitnessProgram() const LIFETIMEBOUND { return ANCHOR_BYTES; }

    friend bool operator==(const PayToAnchor&, const PayToAnchor&) = default;
    friend bool operator<(const PayToAnchor&, const PayToAnchor&) { return false; }
};

/**
 * A txout script categorized into standard templates.
 *  * CNoDestination: Optionally a script, no corresponding address.
 *  * WitnessV1Taproot: TxoutType::WITNESS_V1_TAPROOT destination (P2TR address)
 *  * PayToAnchor: TxoutType::ANCHOR destination (P2A address)
 *  A CTxDestination is the internal data type encoded in an address.
 */
using CTxDestination = std::variant<CNoDestination, WitnessV1Taproot, PayToAnchor>;

/** Check whether a CTxDestination corresponds to one with an address. */
bool IsValidDestination(const CTxDestination& dest);

/**
 * Parse a scriptPubKey for the destination.
 *
 * For native scripts that have addresses, a corresponding CTxDestination is
 * assigned to addressRet. For all other scripts, addressRet is assigned as a
 * CNoDestination containing the scriptPubKey.
 *
 * Returns true for P2TR and P2A scripts, and false otherwise.
 */
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet);

/**
 * Generate a native scriptPubKey for the given CTxDestination.
 */
CScript GetScriptForDestination(const CTxDestination& dest);

#endif // BITCOIN_ADDRESSTYPE_H
