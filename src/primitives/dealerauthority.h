// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PRIMITIVES_DEALERAUTHORITY_H
#define BITCOIN_PRIMITIVES_DEALERAUTHORITY_H

#include <serialize.h>
#include <uint256.h>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <utility>
#include <vector>

namespace chainregistry {

inline constexpr size_t MAX_DEALER_AUTHORITY_KEYS{5};
inline constexpr uint32_t DEALER_AUTHORITY_ROTATION_DELAY{144};
using DealerAuthorityKey = std::array<unsigned char, 32>;
using DealerAuthoritySignature = std::array<unsigned char, 64>;

/** Canonical, strictly increasing x-only keys and the required signature count. */
struct DealerAuthority {
    uint8_t threshold{0};
    std::vector<DealerAuthorityKey> keys{};

    bool IsValid() const;
    uint256 GetHash() const;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        if (!IsValid()) throw std::ios_base::failure("Invalid dealer authority policy");
        stream << threshold << static_cast<uint8_t>(keys.size());
        for (const auto& key : keys) stream << key;
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        DealerAuthority decoded;
        uint8_t count;
        stream >> decoded.threshold >> count;
        if (count == 0 || count > MAX_DEALER_AUTHORITY_KEYS ||
            decoded.threshold == 0 || decoded.threshold > count) {
            throw std::ios_base::failure("Invalid dealer authority policy size");
        }
        decoded.keys.resize(count);
        for (auto& key : decoded.keys) stream >> key;
        if (!decoded.IsValid()) throw std::ios_base::failure("Invalid dealer authority keys");
        *this = std::move(decoded);
    }
    friend bool operator==(const DealerAuthority&, const DealerAuthority&) = default;
};

/** Last confirmed authority handover. Height selects the effective policy.
 * Keeping both policies makes activation and reorgs deterministic without a
 * synthetic registry operation at the activation boundary. */
struct DealerAuthorityTransition {
    uint32_t activation_height{0};
    DealerAuthority previous{};
    DealerAuthority next{};

    bool IsValid() const;
    bool Pending(uint32_t height) const { return activation_height != 0 && height < activation_height; }
    const DealerAuthority& Effective(uint32_t height, const DealerAuthority& initial) const
    {
        if (activation_height == 0) return initial;
        return Pending(height) ? previous : next;
    }
    uint256 GetHash() const;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        if (!IsValid()) throw std::ios_base::failure("Invalid dealer authority transition");
        stream << activation_height;
        if (activation_height != 0) stream << previous << next;
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        DealerAuthorityTransition decoded;
        stream >> decoded.activation_height;
        if (decoded.activation_height != 0) stream >> decoded.previous >> decoded.next;
        if (!decoded.IsValid()) throw std::ios_base::failure("Invalid dealer authority transition");
        *this = std::move(decoded);
    }
    friend bool operator==(const DealerAuthorityTransition&, const DealerAuthorityTransition&) = default;
};

/** One signature per set bit, in increasing key-index order. No length prefix. */
struct DealerAuthoritySignatures {
    uint8_t signers{0};
    std::vector<DealerAuthoritySignature> signatures{};

    bool IsWellFormed() const
    {
        return signers < (1U << MAX_DEALER_AUTHORITY_KEYS) &&
               signatures.size() == static_cast<size_t>(std::popcount(signers));
    }

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        if (!IsWellFormed()) throw std::ios_base::failure("Invalid dealer authority signature bitmap");
        ::Serialize(stream, signers);
        for (const auto& signature : signatures) ::Serialize(stream, signature);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        uint8_t bitmap;
        ::Unserialize(stream, bitmap);
        // Check before allocating or reading any signatures.
        if (bitmap >= (1U << MAX_DEALER_AUTHORITY_KEYS)) {
            throw std::ios_base::failure("Invalid dealer authority signature bitmap");
        }
        DealerAuthoritySignatures decoded;
        decoded.signers = bitmap;
        decoded.signatures.resize(std::popcount(bitmap));
        for (auto& signature : decoded.signatures) ::Unserialize(stream, signature);
        *this = std::move(decoded);
    }

    /** Verify every supplied signature, including those exceeding the threshold. */
    bool Verify(const uint256& digest, const DealerAuthority& authority, bool require_quorum = true) const;
    friend bool operator==(const DealerAuthoritySignatures&, const DealerAuthoritySignatures&) = default;
};

} // namespace chainregistry

#endif // BITCOIN_PRIMITIVES_DEALERAUTHORITY_H
