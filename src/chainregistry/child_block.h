// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_CHAINREGISTRY_CHILD_BLOCK_H
#define KRONEIN_CHAINREGISTRY_CHILD_BLOCK_H

#include <chainregistry/child_import.h>
#include <chainregistry/deposit_import.h>
#include <consensus/amount.h>
#include <consensus/deposit_proof.h>
#include <consensus/validation.h>
#include <script/script_error.h>
#include <serialize.h>
#include <undo.h>

#include <cstddef>
#include <cstdint>
#include <optional>

class CBlock;
class CBlockIndex;
class CCoinsViewCache;

namespace chainregistry {

inline constexpr uint8_t REFERENCE_CHILD_BLOCK_UNDO_VERSION{1};

/** Undo data for UTXOs and main-chain deposits consumed by one child block. */
struct ReferenceChildBlockUndo {
    uint8_t version{REFERENCE_CHILD_BLOCK_UNDO_VERSION};
    uint256 block_hash;
    uint256 parent_hash;
    uint32_t block_height{0};
    CBlockUndo coins;
    DepositImportUndo imports;

    SERIALIZE_METHODS(ReferenceChildBlockUndo, obj)
    {
        READWRITE(obj.version,
                  obj.block_hash,
                  obj.parent_hash,
                  obj.block_height,
                  obj.coins,
                  obj.imports);
    }

    friend bool operator==(const ReferenceChildBlockUndo& left,
                           const ReferenceChildBlockUndo& right)
    {
        if (left.version != right.version ||
            left.block_hash != right.block_hash ||
            left.parent_hash != right.parent_hash ||
            left.block_height != right.block_height ||
            left.imports != right.imports ||
            left.coins.vtxundo.size() != right.coins.vtxundo.size()) {
            return false;
        }
        for (size_t transaction{0};
             transaction < left.coins.vtxundo.size();
             ++transaction) {
            const auto& left_coins{
                left.coins.vtxundo[transaction].vprevout};
            const auto& right_coins{
                right.coins.vtxundo[transaction].vprevout};
            if (left_coins.size() != right_coins.size()) return false;
            for (size_t input{0}; input < left_coins.size(); ++input) {
                if (left_coins[input].out != right_coins[input].out ||
                    left_coins[input].nHeight != right_coins[input].nHeight ||
                    left_coins[input].IsCoinBase() !=
                        right_coins[input].IsCoinBase()) {
                    return false;
                }
            }
        }
        return true;
    }
};

enum class ReferenceChildBlockError : uint8_t {
    NONE,
    INVALID_DEFINITION,
    INVALID_RUNTIME_CONTEXT,
    SAFE_HALT,
    INVALID_PARENT,
    HEIGHT_OVERFLOW,
    INVALID_HEADER,
    TIME_TOO_OLD,
    TIME_MOVED_BACKWARDS,
    TIME_TOO_NEW,
    EMPTY_BLOCK,
    INVALID_MERKLE_ROOT,
    MUTATED_MERKLE_TREE,
    BLOCK_TOO_HEAVY,
    INVALID_COINBASE,
    INVALID_TRANSACTION,
    DUPLICATE_TRANSACTION,
    NONFINAL_TRANSACTION,
    INVALID_WITNESS_COMMITMENT,
    INVALID_IMPORT,
    IMPORT_REJECTED,
    UTXO_OVERWRITE,
    INPUTS_REJECTED,
    SEQUENCE_LOCKED,
    SCRIPT_REJECTED,
    FEE_OUT_OF_RANGE,
    COINBASE_PAYS_TOO_MUCH,
    INVALID_UNDO,
    UTXO_MISMATCH,
};

struct ReferenceChildBlockResult {
    ReferenceChildBlockError error{ReferenceChildBlockError::NONE};
    std::optional<size_t> failed_transaction;
    TxValidationResult transaction_error{TxValidationResult::TX_RESULT_UNSET};
    ScriptError script_error{SCRIPT_ERR_OK};
    ChildImportError import_error{ChildImportError::NONE};
    DepositImportError deposit_error{DepositImportError::NONE};
    AuthenticatedDepositError authentication_error{AuthenticatedDepositError::NONE};
    CAmount total_fees{0};
    std::optional<ReferenceChildBlockUndo> undo;

    bool IsValid() const
    {
        return error == ReferenceChildBlockError::NONE;
    }
};

/**
 * Validate and atomically connect one candidate reference-child block.
 *
 * The caller supplies the selected parent index. BMM fork choice is external
 * to this state transition and will decide which valid candidate is canonical.
 */
ReferenceChildBlockResult ConnectReferenceChildBlock(
    const CBlock& block,
    const CBlockIndex& parent,
    int64_t current_time,
    const ReferenceChildDefinition& definition,
    const MainHeaderChain& main_headers,
    CCoinsViewCache& coins,
    DepositImportState& imports);

/** Atomically reverse a previously connected reference-child block. */
ReferenceChildBlockResult DisconnectReferenceChildBlock(
    const CBlock& block,
    const ReferenceChildBlockUndo& undo,
    CCoinsViewCache& coins,
    DepositImportState& imports);

} // namespace chainregistry

#endif // KRONEIN_CHAINREGISTRY_CHILD_BLOCK_H
