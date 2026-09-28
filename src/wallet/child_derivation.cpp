// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/child_derivation.h>

#include <cassert>

namespace wallet {

std::optional<std::vector<uint32_t>> ChildKeyAccountPath(
    const chainregistry::ChainId& chain_id)
{
    if (chain_id.IsNull()) return std::nullopt;

    std::vector<uint32_t> path;
    path.reserve(CHILD_KEY_ACCOUNT_DEPTH);
    path.push_back(CHILD_KEY_HARDENED | CHILD_KEY_DERIVATION_PURPOSE);
    path.push_back(CHILD_KEY_HARDENED | CHILD_KEY_DERIVATION_VERSION);

    uint32_t component{0};
    unsigned int component_bits{0};
    const auto* bytes{chain_id.begin()};
    for (size_t byte_index{0}; byte_index < chainregistry::ChainId::size();
         ++byte_index) {
        // Identifier serialization is little endian; derivation is defined
        // over the same big-endian byte order exposed by GetHex().
        const uint8_t byte{std::to_integer<uint8_t>(
            bytes[chainregistry::ChainId::size() - 1 - byte_index])};
        for (int bit{7}; bit >= 0; --bit) {
            component = (component << 1) | ((byte >> bit) & 1U);
            if (++component_bits == 31) {
                path.push_back(CHILD_KEY_HARDENED | component);
                component = 0;
                component_bits = 0;
            }
        }
    }
    assert(component_bits == 8);
    path.push_back(CHILD_KEY_HARDENED | component);
    assert(path.size() == CHILD_KEY_ACCOUNT_DEPTH);
    return path;
}

std::optional<std::vector<uint32_t>> ChildKeyPath(
    const chainregistry::ChainId& chain_id,
    ChildKeyRole role,
    uint32_t index)
{
    if (index >= CHILD_KEY_HARDENED) return std::nullopt;
    auto path{ChildKeyAccountPath(chain_id)};
    if (!path) return std::nullopt;
    path->push_back(static_cast<uint32_t>(role));
    path->push_back(index);
    assert(path->size() == CHILD_KEY_PATH_DEPTH);
    return path;
}

} // namespace wallet
