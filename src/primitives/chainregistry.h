// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_PRIMITIVES_CHAINREGISTRY_H
#define KRONEIN_PRIMITIVES_CHAINREGISTRY_H

#include <attributes.h>
#include <uint256.h>

#include <compare>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>

class COutPoint;

namespace chainregistry {

namespace detail {
struct ChainIdTag {};
struct ChainSpecHashTag {};
struct DepositIdTag {};
} // namespace detail

/** A strongly typed 256-bit protocol identifier. */
template <typename Tag>
class Identifier
{
private:
    uint256 m_value;

    explicit Identifier(const uint256& value) : m_value{value} {}

public:
    Identifier() = default;
    consteval explicit Identifier(std::string_view hex) : m_value{hex} {}

    static Identifier FromUint256(const uint256& value) { return Identifier{value}; }
    static std::optional<Identifier> FromHex(std::string_view hex)
    {
        const auto value{uint256::FromHex(hex)};
        if (!value) return std::nullopt;
        return FromUint256(*value);
    }

    const uint256& ToUint256() const LIFETIMEBOUND { return m_value; }
    bool IsNull() const { return m_value.IsNull(); }
    std::string GetHex() const { return m_value.GetHex(); }
    std::string ToString() const { return m_value.ToString(); }

    static constexpr size_t size() { return uint256::size(); }
    const std::byte* begin() const { return reinterpret_cast<const std::byte*>(m_value.begin()); }
    const std::byte* end() const { return reinterpret_cast<const std::byte*>(m_value.end()); }

    friend bool operator==(const Identifier&, const Identifier&) = default;
    friend std::strong_ordering operator<=>(const Identifier& lhs, const Identifier& rhs)
    {
        return lhs.m_value.Compare(rhs.m_value) <=> 0;
    }

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        m_value.Serialize(stream);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        m_value.Unserialize(stream);
    }
};

/** Stable identity of a registered child chain. */
using ChainId = Identifier<detail::ChainIdTag>;
/** Tagged hash of the canonical pre-genesis consensus specification. */
using ChainSpecHash = Identifier<detail::ChainSpecHashTag>;
/** Stable identity of a main-chain burn output. */
using DepositId = Identifier<detail::DepositIdTag>;

inline constexpr std::string_view CHAIN_SPEC_HASH_TAG{"Kronein/ChainSpec/v1"};
inline constexpr std::string_view CHAIN_ID_TAG{"Kronein/ChainId/v1"};
inline constexpr std::string_view DEPOSIT_ID_TAG{"Kronein/DepositId/v1"};

/** Hash canonical pre-genesis specification bytes. This function does not validate their schema. */
ChainSpecHash ComputeChainSpecHash(std::span<const std::byte> canonical_spec);

/**
 * Derive a child-chain identity from the main network, registration outpoint,
 * and immutable pre-genesis specification hash. The registration outpoint is
 * an existing UTXO consumed by the registration transaction, so the identity
 * is known before the child genesis is generated.
 */
ChainId DeriveChainId(const uint256& main_genesis_hash,
                      const COutPoint& registration_outpoint,
                      const ChainSpecHash& spec_hash);

/** Derive the identity consumed by a one-way child-chain import. */
DepositId DeriveDepositId(const uint256& main_genesis_hash, const COutPoint& burn_outpoint);

} // namespace chainregistry

#endif // KRONEIN_PRIMITIVES_CHAINREGISTRY_H
