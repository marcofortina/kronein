// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <primitives/bmm.h>

#include <primitives/transaction.h>
#include <streams.h>

#include <algorithm>
#include <span>
#include <utility>
#include <vector>

namespace chainregistry {

static_assert(BMM_ANCHOR_DATA_SIZE == 69);

BmmAnchorValidationError ValidateBmmAnchor(const BmmAnchor& anchor)
{
    if (anchor.chain_id.IsNull()) {
        return BmmAnchorValidationError::NULL_CHAIN_ID;
    }
    if (anchor.child_block_hash.IsNull()) {
        return BmmAnchorValidationError::NULL_CHILD_BLOCK_HASH;
    }
    return BmmAnchorValidationError::NONE;
}

CScript BuildBmmAnchorScript(const BmmAnchor& anchor)
{
    std::vector<unsigned char> data{
        BMM_ANCHOR_MAGIC.begin(), BMM_ANCHOR_MAGIC.end()};
    VectorWriter writer{data, data.size()};
    writer << BMM_ANCHOR_VERSION << anchor;
    return CScript{} << OP_RETURN << data;
}

BmmAnchorParseResult ParseBmmAnchorScript(const CScript& script)
{
    auto cursor{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(cursor, opcode) || opcode != OP_RETURN) {
        return {BmmAnchorParseError::NOT_ANCHOR, std::nullopt};
    }
    if (!script.GetOp(cursor, opcode, data)) {
        return {BmmAnchorParseError::NOT_ANCHOR, std::nullopt};
    }
    if (data.size() < BMM_ANCHOR_MAGIC.size() ||
        !std::equal(BMM_ANCHOR_MAGIC.begin(),
                    BMM_ANCHOR_MAGIC.end(),
                    data.begin())) {
        return {BmmAnchorParseError::NOT_ANCHOR, std::nullopt};
    }
    if (opcode > OP_PUSHDATA4 || cursor != script.end()) {
        return {BmmAnchorParseError::MALFORMED_SCRIPT, std::nullopt};
    }
    if (script != (CScript{} << OP_RETURN << data)) {
        return {BmmAnchorParseError::NON_CANONICAL_SCRIPT, std::nullopt};
    }
    if (data.size() != BMM_ANCHOR_DATA_SIZE) {
        return {BmmAnchorParseError::INVALID_LENGTH, std::nullopt};
    }

    SpanReader reader{
        std::span{data}.subspan(BMM_ANCHOR_MAGIC.size())};
    uint8_t version;
    BmmAnchor anchor;
    reader >> version >> anchor;
    if (version != BMM_ANCHOR_VERSION) {
        return {BmmAnchorParseError::UNSUPPORTED_VERSION, std::nullopt};
    }
    if (!reader.empty() ||
        ValidateBmmAnchor(anchor) != BmmAnchorValidationError::NONE) {
        return {BmmAnchorParseError::INVALID_ANCHOR, std::nullopt};
    }
    return {BmmAnchorParseError::NONE, std::move(anchor)};
}

TxBmmAnchorResult ExtractTransactionBmmAnchor(const CTransaction& tx)
{
    TxBmmAnchorResult result;
    for (size_t output_index{0}; output_index < tx.vout.size(); ++output_index) {
        const auto parsed{
            ParseBmmAnchorScript(tx.vout[output_index].scriptPubKey)};
        if (parsed.error == BmmAnchorParseError::NOT_ANCHOR) continue;
        if (!parsed) {
            result.error = TxBmmAnchorError::INVALID_ANCHOR;
            result.parse_error = parsed.error;
            result.output_index.reset();
            result.anchor.reset();
            return result;
        }
        if (result.anchor) {
            result.error = TxBmmAnchorError::MULTIPLE_ANCHORS;
            result.output_index.reset();
            result.anchor.reset();
            return result;
        }
        if (tx.vout[output_index].nValue != 0) {
            result.error = TxBmmAnchorError::NONZERO_VALUE;
            return result;
        }
        result.output_index = static_cast<uint32_t>(output_index);
        result.anchor = *parsed.anchor;
    }
    return result;
}

} // namespace chainregistry
