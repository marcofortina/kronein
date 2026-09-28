// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_CHILD_DERIVATION_H
#define BITCOIN_WALLET_CHILD_DERIVATION_H

#include <primitives/chainregistry.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace wallet {

/** Hardened BIP32 namespace encoded as the ASCII bytes "KNE". */
inline constexpr uint32_t CHILD_KEY_DERIVATION_PURPOSE{0x004b4e45};
inline constexpr uint32_t CHILD_KEY_DERIVATION_VERSION{1};
inline constexpr uint32_t CHILD_KEY_HARDENED{0x80000000U};
inline constexpr size_t CHILD_KEY_CHAIN_COMPONENTS{9};
inline constexpr size_t CHILD_KEY_ACCOUNT_DEPTH{
    2 + CHILD_KEY_CHAIN_COMPONENTS};
inline constexpr size_t CHILD_KEY_PATH_DEPTH{CHILD_KEY_ACCOUNT_DEPTH + 2};

enum class ChildKeyRole : uint32_t {
    RECEIVE = 0,
    CHANGE = 1,
};

/**
 * Return the versioned, hardened account path for one exact child chain.
 *
 * The 256-bit chain ID is read in displayed (big-endian) order and split
 * injectively into eight 31-bit components followed by one 8-bit component.
 * Every account component is hardened. A null chain ID is never a main-chain
 * alias and is rejected.
 */
std::optional<std::vector<uint32_t>> ChildKeyAccountPath(
    const chainregistry::ChainId& chain_id);

/** Append the external/change role and one unhardened address index. */
std::optional<std::vector<uint32_t>> ChildKeyPath(
    const chainregistry::ChainId& chain_id,
    ChildKeyRole role,
    uint32_t index);

} // namespace wallet

#endif // BITCOIN_WALLET_CHILD_DERIVATION_H
