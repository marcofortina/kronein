// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_CHAINREGISTRY_CHILD_SIGN_H
#define KRONEIN_CHAINREGISTRY_CHILD_SIGN_H

#include <chainregistry/child_sighash.h>
#include <primitives/chainregistry.h>
#include <script/sign.h>

#include <optional>
#include <utility>
#include <vector>

namespace chainregistry {

/**
 * Signature creator for child-chain transactions.
 *
 * It computes the normal BIP341/BIP342 signature hash first, then binds it to
 * the full child ChainId using ComputeReferenceChildSignatureHash(). A null
 * ChainId is rejected and MuSig2 remains disabled until its nonce/session
 * protocol is explicitly domain-separated as well.
 */
class ReferenceChildSignatureCreator final : public BaseSignatureCreator
{
private:
    const ChainId m_chain_id;
    const CMutableTransaction& m_transaction;
    const unsigned int m_input_index;
    const int m_hash_type;
    const PrecomputedTransactionData& m_txdata;
    const ReferenceChildMutableTransactionSignatureChecker m_checker;

    std::optional<uint256> ComputeSignatureHash(
        const uint256* leaf_hash,
        SigVersion sigversion) const;

public:
    ReferenceChildSignatureCreator(
        const ChainId& chain_id,
        const CMutableTransaction& transaction LIFETIMEBOUND,
        unsigned int input_index,
        const PrecomputedTransactionData& txdata,
        int hash_type);

    const BaseSignatureChecker& Checker() const override { return m_checker; }

    bool CreateSchnorrSig(
        const SigningProvider& provider,
        std::vector<unsigned char>& signature,
        const XOnlyPubKey& pubkey,
        const uint256* leaf_hash,
        const uint256* merkle_root,
        SigVersion sigversion) const override;

    std::vector<uint8_t> CreateMuSig2Nonce(
        const SigningProvider& provider,
        const CPubKey& aggregate_pubkey,
        const CPubKey& script_pubkey,
        const CPubKey& participant_pubkey,
        const uint256* leaf_hash,
        const uint256* merkle_root,
        SigVersion sigversion,
        const SignatureData& sigdata) const override;

    bool CreateMuSig2PartialSig(
        const SigningProvider& provider,
        uint256& partial_signature,
        const CPubKey& aggregate_pubkey,
        const CPubKey& script_pubkey,
        const CPubKey& participant_pubkey,
        const uint256* leaf_hash,
        const std::vector<std::pair<uint256, bool>>& tweaks,
        SigVersion sigversion,
        const SignatureData& sigdata) const override;

    bool CreateMuSig2AggregateSig(
        const std::vector<CPubKey>& participants,
        std::vector<uint8_t>& signature,
        const CPubKey& aggregate_pubkey,
        const CPubKey& script_pubkey,
        const uint256* leaf_hash,
        const std::vector<std::pair<uint256, bool>>& tweaks,
        SigVersion sigversion,
        const SignatureData& sigdata) const override;
};

} // namespace chainregistry

#endif // KRONEIN_CHAINREGISTRY_CHILD_SIGN_H
