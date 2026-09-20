// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_CHAINREGISTRY_CHILD_SIGHASH_H
#define KRONEIN_CHAINREGISTRY_CHILD_SIGHASH_H

#include <primitives/chainregistry.h>
#include <script/interpreter.h>
#include <uint256.h>

#include <optional>
#include <span>
#include <string_view>

class CTransaction;
class PrecomputedTransactionData;
class XOnlyPubKey;

namespace chainregistry {

inline constexpr std::string_view CHILD_SIGHASH_TAG{"Kronein/ChildSighash/v1"};

/**
 * Bind an already computed BIP341/BIP342 signature hash to one child chain.
 *
 * A null ChainId is not an alias for the main chain and is always rejected.
 */
std::optional<uint256> ComputeReferenceChildSignatureHash(
    const ChainId& chain_id,
    const uint256& base_sighash);

/** Taproot signature checker with mandatory child-chain domain separation. */
class ReferenceChildTransactionSignatureChecker final : public TransactionSignatureChecker
{
private:
    ChainId m_chain_id;

protected:
    bool VerifySchnorrSignature(std::span<const unsigned char> signature,
                                const XOnlyPubKey& pubkey,
                                const uint256& base_sighash) const override;

public:
    ReferenceChildTransactionSignatureChecker(
        const ChainId& chain_id,
        const CTransaction* transaction,
        unsigned int input_index,
        const PrecomputedTransactionData& txdata,
        MissingDataBehavior missing_data_behavior);
};

} // namespace chainregistry

#endif // KRONEIN_CHAINREGISTRY_CHILD_SIGHASH_H
