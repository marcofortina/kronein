// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_sign.h>

#include <key.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/signingprovider.h>

#include <cassert>

namespace chainregistry {

ReferenceChildSignatureCreator::ReferenceChildSignatureCreator(
    const ChainId& chain_id,
    const CMutableTransaction& transaction,
    unsigned int input_index,
    const PrecomputedTransactionData& txdata,
    int hash_type)
    : m_chain_id{chain_id},
      m_transaction{transaction},
      m_input_index{input_index},
      m_hash_type{hash_type},
      m_txdata{txdata},
      m_checker{chain_id,
                &m_transaction,
                m_input_index,
                txdata,
                MissingDataBehavior::FAIL}
{
}

std::optional<uint256> ReferenceChildSignatureCreator::ComputeSignatureHash(
    const uint256* leaf_hash,
    SigVersion sigversion) const
{
    assert(sigversion == SigVersion::TAPROOT ||
           sigversion == SigVersion::TAPSCRIPT);
    if (m_chain_id.IsNull() ||
        !m_txdata.m_bip341_taproot_ready ||
        !m_txdata.m_spent_outputs_ready) {
        return std::nullopt;
    }

    ScriptExecutionData execution_data;
    execution_data.m_annex_init = true;
    execution_data.m_annex_present = false;
    if (sigversion == SigVersion::TAPSCRIPT) {
        if (!leaf_hash) return std::nullopt;
        execution_data.m_codeseparator_pos_init = true;
        execution_data.m_codeseparator_pos = 0xffffffff;
        execution_data.m_tapleaf_hash_init = true;
        execution_data.m_tapleaf_hash = *leaf_hash;
    }

    uint256 base_sighash;
    if (!SignatureHashSchnorr(base_sighash,
                              execution_data,
                              m_transaction,
                              m_input_index,
                              m_hash_type,
                              sigversion,
                              m_txdata,
                              MissingDataBehavior::FAIL)) {
        return std::nullopt;
    }
    return ComputeReferenceChildSignatureHash(m_chain_id, base_sighash);
}

bool ReferenceChildSignatureCreator::CreateSchnorrSig(
    const SigningProvider& provider,
    std::vector<unsigned char>& signature,
    const XOnlyPubKey& pubkey,
    const uint256* leaf_hash,
    const uint256* merkle_root,
    SigVersion sigversion) const
{
    CKey key;
    if (!provider.GetKeyByXOnly(pubkey, key)) return false;

    const auto sighash{ComputeSignatureHash(leaf_hash, sigversion)};
    if (!sighash) return false;

    signature.resize(64);
    if (!key.SignSchnorr(*sighash, signature, merkle_root, {})) return false;
    if (m_hash_type != SIGHASH_DEFAULT) {
        signature.push_back(m_hash_type);
    }
    return true;
}

std::vector<uint8_t> ReferenceChildSignatureCreator::CreateMuSig2Nonce(
    const SigningProvider&,
    const CPubKey&,
    const CPubKey&,
    const CPubKey&,
    const uint256*,
    const uint256*,
    SigVersion,
    const SignatureData&) const
{
    return {};
}

bool ReferenceChildSignatureCreator::CreateMuSig2PartialSig(
    const SigningProvider&,
    uint256&,
    const CPubKey&,
    const CPubKey&,
    const CPubKey&,
    const uint256*,
    const std::vector<std::pair<uint256, bool>>&,
    SigVersion,
    const SignatureData&) const
{
    return false;
}

bool ReferenceChildSignatureCreator::CreateMuSig2AggregateSig(
    const std::vector<CPubKey>&,
    std::vector<uint8_t>&,
    const CPubKey&,
    const CPubKey&,
    const uint256*,
    const std::vector<std::pair<uint256, bool>>&,
    SigVersion,
    const SignatureData&) const
{
    return false;
}

} // namespace chainregistry
