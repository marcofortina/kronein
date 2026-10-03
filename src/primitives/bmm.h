// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PRIMITIVES_BMM_H
#define BITCOIN_PRIMITIVES_BMM_H

#include <primitives/chainregistry.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

class CTransaction;

namespace chainregistry {

inline constexpr std::array<unsigned char, 4> BMM_ANCHOR_MAGIC{'K', 'B', 'M', 'M'};
inline constexpr uint8_t BMM_ANCHOR_VERSION{1};
inline constexpr size_t BMM_ANCHOR_DATA_SIZE{
    BMM_ANCHOR_MAGIC.size() + sizeof(BMM_ANCHOR_VERSION) + ChainId::size() + uint256::size()};

/**
 * Minimal main-chain commitment to one child block.
 *
 * The child block hash already commits to the child parent, transaction root,
 * timestamp and the rest of the native 80-byte child header. Child height is
 * derived from the validated parent. Repeating either field here would only
 * create malleable representations of the same candidate.
 */
struct BmmAnchor {
    ChainId chain_id;
    uint256 child_block_hash;

    SERIALIZE_METHODS(BmmAnchor, obj)
    {
        READWRITE(obj.chain_id, obj.child_block_hash);
    }

    friend bool operator==(const BmmAnchor&, const BmmAnchor&) = default;
};

enum class BmmAnchorValidationError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    NULL_CHILD_BLOCK_HASH,
};

enum class BmmAnchorParseError : uint8_t {
    NONE,
    NOT_ANCHOR,
    MALFORMED_SCRIPT,
    NON_CANONICAL_SCRIPT,
    INVALID_LENGTH,
    UNSUPPORTED_VERSION,
    INVALID_ANCHOR,
};

struct BmmAnchorParseResult {
    BmmAnchorParseError error{BmmAnchorParseError::NOT_ANCHOR};
    std::optional<BmmAnchor> anchor;

    explicit operator bool() const
    {
        return error == BmmAnchorParseError::NONE && anchor.has_value();
    }
};

enum class TxBmmAnchorError : uint8_t {
    NONE,
    INVALID_ANCHOR,
    MULTIPLE_ANCHORS,
    NONZERO_VALUE,
};

struct TxBmmAnchorResult {
    TxBmmAnchorError error{TxBmmAnchorError::NONE};
    BmmAnchorParseError parse_error{BmmAnchorParseError::NONE};
    std::optional<uint32_t> output_index;
    std::optional<BmmAnchor> anchor;

    bool IsValid() const { return error == TxBmmAnchorError::NONE; }
};

BmmAnchorValidationError ValidateBmmAnchor(const BmmAnchor& anchor);
CScript BuildBmmAnchorScript(const BmmAnchor& anchor);
BmmAnchorParseResult ParseBmmAnchorScript(const CScript& script);

/** A proposal transaction contains at most one zero-valued BMM anchor. */
TxBmmAnchorResult ExtractTransactionBmmAnchor(const CTransaction& tx);

} // namespace chainregistry

#endif // BITCOIN_PRIMITIVES_BMM_H
