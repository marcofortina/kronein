// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <primitives/chainregistry.h>

#include <hash.h>
#include <primitives/transaction.h>

#include <string>

namespace chainregistry {

ChainSpecHash ComputeChainSpecHash(std::span<const std::byte> canonical_spec)
{
    auto hasher{TaggedHash(std::string{CHAIN_SPEC_HASH_TAG})};
    hasher.write(canonical_spec);
    return ChainSpecHash::FromUint256(hasher.GetSHA256());
}

ChainId DeriveChainId(const uint256& main_genesis_hash,
                      const COutPoint& registration_outpoint,
                      const ChainSpecHash& spec_hash)
{
    auto hasher{TaggedHash(std::string{CHAIN_ID_TAG})};
    hasher << main_genesis_hash << registration_outpoint << spec_hash;
    return ChainId::FromUint256(hasher.GetSHA256());
}

DepositId DeriveDepositId(const uint256& main_genesis_hash, const COutPoint& burn_outpoint)
{
    auto hasher{TaggedHash(std::string{DEPOSIT_ID_TAG})};
    hasher << main_genesis_hash << burn_outpoint;
    return DepositId::FromUint256(hasher.GetSHA256());
}

} // namespace chainregistry
