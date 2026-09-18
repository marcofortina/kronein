// Copyright (c) 2017-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_TX_CHECK_H
#define BITCOIN_CONSENSUS_TX_CHECK_H

/**
 * Context-independent transaction checking code that can be called outside the
 * node and doesn't depend on chain or mempool state. Transaction
 * verification code that does call server functions or depend on server state
 * belongs in tx_verify.h/cpp instead.
 */

class CTransaction;
class TxValidationState;
class CScript;

bool CheckTransaction(const CTransaction& tx, TxValidationState& state);

/** Return whether an output uses one of the native script forms of this chain. */
bool IsNativeOutputScript(const CScript& script_pub_key);

/** Return whether an output can be spent through Taproot or pay-to-anchor. */
bool IsNativeSpendableOutputScript(const CScript& script_pub_key);

/** Enforce the native transaction format used by every transaction after genesis. */
bool CheckNativeTransaction(const CTransaction& tx, TxValidationState& state);

#endif // BITCOIN_CONSENSUS_TX_CHECK_H
