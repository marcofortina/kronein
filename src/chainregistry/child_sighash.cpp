// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_sighash.h>

#include <hash.h>
#include <pubkey.h>

#include <string>

namespace chainregistry {

std::optional<uint256> ComputeReferenceChildSignatureHash(
    const ChainId& chain_id,
    const uint256& base_sighash)
{
    if (chain_id.IsNull()) return std::nullopt;

    auto hasher{TaggedHash(std::string{CHILD_SIGHASH_TAG})};
    hasher << chain_id << base_sighash;
    return hasher.GetSHA256();
}

ReferenceChildTransactionSignatureChecker::ReferenceChildTransactionSignatureChecker(
    const ChainId& chain_id,
    const CTransaction* transaction,
    unsigned int input_index,
    const PrecomputedTransactionData& txdata,
    MissingDataBehavior missing_data_behavior)
    : TransactionSignatureChecker{transaction,
                                  input_index,
                                  txdata,
                                  missing_data_behavior},
      m_chain_id{chain_id}
{
}

bool ReferenceChildTransactionSignatureChecker::VerifySchnorrSignature(
    std::span<const unsigned char> signature,
    const XOnlyPubKey& pubkey,
    const uint256& base_sighash) const
{
    const auto child_sighash{
        ComputeReferenceChildSignatureHash(m_chain_id, base_sighash)};
    return child_sighash.has_value() &&
           pubkey.VerifySchnorr(*child_sighash, signature);
}

ReferenceChildMutableTransactionSignatureChecker::ReferenceChildMutableTransactionSignatureChecker(
    const ChainId& chain_id,
    const CMutableTransaction* transaction,
    unsigned int input_index,
    const PrecomputedTransactionData& txdata,
    MissingDataBehavior missing_data_behavior)
    : MutableTransactionSignatureChecker{transaction,
                                         input_index,
                                         txdata,
                                         missing_data_behavior},
      m_chain_id{chain_id}
{
}

bool ReferenceChildMutableTransactionSignatureChecker::VerifySchnorrSignature(
    std::span<const unsigned char> signature,
    const XOnlyPubKey& pubkey,
    const uint256& base_sighash) const
{
    const auto child_sighash{
        ComputeReferenceChildSignatureHash(m_chain_id, base_sighash)};
    return child_sighash.has_value() &&
           pubkey.VerifySchnorr(*child_sighash, signature);
}

} // namespace chainregistry
