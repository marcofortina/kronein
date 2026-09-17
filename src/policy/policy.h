// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_POLICY_H
#define BITCOIN_POLICY_POLICY_H

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/solver.h>
#include <util/feefrac.h>

#include <cstdint>
#include <string>

class CCoinsViewCache;
class CFeeRate;
class CScript;

/** Default for -blockmaxweight, which controls the range of block weights the mining code will create **/
static constexpr unsigned int DEFAULT_BLOCK_MAX_WEIGHT{MAX_BLOCK_WEIGHT};
/** Default for -blockreservedweight **/
static constexpr unsigned int DEFAULT_BLOCK_RESERVED_WEIGHT{8000};
/** This accounts for the block header, var_int encoding of the transaction count and a minimally viable
 * coinbase transaction. It adds an additional safety margin, because even with a thorough understanding
 * of block serialization, it's easy to make a costly mistake when trying to squeeze every last byte.
 * Setting a lower value is prevented at startup. */
static constexpr unsigned int MINIMUM_BLOCK_RESERVED_WEIGHT{2000};
/** Default for -blockmintxfee, which sets the minimum feerate for a transaction in blocks created by mining code **/
static constexpr unsigned int DEFAULT_BLOCK_MIN_TX_FEE{1};
/** The maximum weight for transactions we're willing to relay/mine */
static constexpr int32_t MAX_STANDARD_TX_WEIGHT{400000};
/** The minimum non-witness size for transactions we're willing to relay/mine: one larger than 64  */
static constexpr unsigned int MIN_STANDARD_TX_NONWITNESS_SIZE{65};
/** Default for -incrementalrelayfee, which sets the minimum feerate increase for mempool limiting or replacement **/
static constexpr unsigned int DEFAULT_INCREMENTAL_RELAY_FEE{100};
/** Limits retained for parsing Miniscript descriptors. Witness-v0 outputs are not native chain outputs. */
static constexpr unsigned int MAX_STANDARD_P2WSH_STACK_ITEMS{100};
static constexpr unsigned int MAX_STANDARD_P2WSH_SCRIPT_SIZE{3600};
/** The maximum size in bytes of each witness stack item in a standard BIP 342 script (Taproot, leaf version 0xc0) */
static constexpr unsigned int MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE{80};
/** Min feerate for defining dust.
 * Changing the dust limit changes which transactions are
 * standard and should be done with care and ideally rarely. It makes sense to
 * only increase the dust limit after prior releases were already not creating
 * outputs below the new threshold */
static constexpr unsigned int DUST_RELAY_TX_FEE{3000};
/** Default for -minrelaytxfee, minimum relay fee for transactions */
static constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE{100};
/** Maximum number of transactions per cluster (default) */
static constexpr unsigned int DEFAULT_CLUSTER_LIMIT{64};
/** Maximum size of cluster in virtual kilobytes */
static constexpr unsigned int DEFAULT_CLUSTER_SIZE_LIMIT_KVB{101};
/** Default for -datacarrier */
static const bool DEFAULT_ACCEPT_DATACARRIER = true;
/**
 * Default setting for -datacarriersize in vbytes.
 */
static const unsigned int MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR;
/**
 * An extra transaction can be added to a package, as long as it only has one
 * ancestor and is no larger than this. Not really any reason to make this
 * configurable as it doesn't materially change DoS parameters.
 */
static constexpr unsigned int EXTRA_DESCENDANT_TX_SIZE_LIMIT{10000};

/**
 * Maximum number of ephemeral dust outputs allowed.
 */
static constexpr unsigned int MAX_DUST_OUTPUTS_PER_TX{1};

/**
 * Mandatory script verification flags that all new transactions must comply with for
 * them to be valid. Failing one of these tests may trigger a DoS ban;
 * see CheckInputScripts() for details.
 *
 * Note that this does not affect consensus validity; see GetBlockScriptFlags()
 * for that.
 */
static constexpr script_verify_flags MANDATORY_SCRIPT_VERIFY_FLAGS{SCRIPT_VERIFY_DERSIG |
                                                                  SCRIPT_VERIFY_NULLDUMMY};

/**
 * Standard script verification flags that relayed transactions must comply with.
 */
static constexpr script_verify_flags STANDARD_SCRIPT_VERIFY_FLAGS{MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                             SCRIPT_VERIFY_STRICTENC |
                                                             SCRIPT_VERIFY_MINIMALDATA |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                                                             SCRIPT_VERIFY_NULLFAIL |
                                                             SCRIPT_VERIFY_LOW_S |
                                                             SCRIPT_VERIFY_CONST_SCRIPTCODE |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
                                                             SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE};

/** For convenience, standard but not mandatory verify flags. */
static constexpr script_verify_flags STANDARD_NOT_MANDATORY_VERIFY_FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS};

/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
static constexpr unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS{LOCKTIME_VERIFY_SEQUENCE};

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsStandard(const CScript& scriptPubKey, TxoutType& whichType);

/** Get the vout index numbers of all dust outputs */
std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate);

/**
* Check for standard transaction types
* @return True if all outputs (scriptPubKeys) use only standard transaction forms
*/
bool IsStandardTx(const CTransaction& tx, const std::optional<unsigned>& max_datacarrier_bytes, const CFeeRate& dust_relay_fee, std::string& reason);
/**
* Check for standard transaction types
* @param[in] mapInputs       Map of previous transactions that have outputs we're spending
* @return True if all inputs (scriptSigs) use only standard transaction forms
*/
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);
/**
 * Enforce the Taproot stack-item size limit and disallow annexes.
*/
bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);
/**
 * Check whether this transaction spends any witness program but P2A, including not-yet-defined ones.
 * May return `false` early for consensus-invalid transactions.
 */
bool SpendsNonAnchorWitnessProg(const CTransaction& tx, const CCoinsViewCache& prevouts);

/** Compute the virtual transaction size (weight reinterpreted as bytes). */
int64_t GetVirtualTransactionSize(int64_t weight);

static inline int64_t GetVirtualTransactionSize(const CTransaction& tx)
{
    return GetVirtualTransactionSize(GetTransactionWeight(tx));
}

static inline int64_t GetVirtualTransactionInputSize(const CTxIn& tx)
{
    return GetVirtualTransactionSize(GetTransactionInputWeight(tx));
}

static inline FeePerVSize ToFeePerVSize(FeePerWeight feerate) { return {feerate.fee, (feerate.size + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR}; }

#endif // BITCOIN_POLICY_POLICY_H
