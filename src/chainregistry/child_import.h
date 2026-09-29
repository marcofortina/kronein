// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CHAINREGISTRY_CHILD_IMPORT_H
#define BITCOIN_CHAINREGISTRY_CHILD_IMPORT_H

#include <chainregistry/child_template.h>
#include <consensus/deposit_proof.h>
#include <primitives/chainregistry.h>
#include <primitives/transaction.h>

#include <cstdint>
#include <optional>

namespace chainregistry {

/** Reserved synthetic outpoint index identifying a child IMPORT transaction. */
inline constexpr uint32_t CHILD_IMPORT_PREVOUT_INDEX{COutPoint::NULL_INDEX - 1};

enum class ChildImportError : uint8_t {
    NONE,
    NOT_IMPORT,
    INVALID_PARAMETERS,
    INVALID_DEFINITION,
    INVALID_SHAPE,
    INVALID_WITNESS,
    PROOF_TOO_LARGE,
    PROOF_ENCODE_FAILED,
    PROOF_DECODE_FAILED,
    PROOF_TRAILING_DATA,
    INVALID_PROOF,
    MANIFEST_MISMATCH,
    DEPOSIT_ID_MISMATCH,
    INVALID_RECIPIENT,
    INVALID_OUTPUT,
    TRANSACTION_TOO_HEAVY,
};

struct ChildImportResult {
    ChildImportError error{ChildImportError::NONE};
    DepositProofValidationError proof_error{DepositProofValidationError::NONE};
    std::optional<DepositProof> proof;
    std::optional<DepositId> deposit_id;

    bool IsValid() const
    {
        return error == ChildImportError::NONE &&
               proof.has_value() && deposit_id.has_value();
    }
};

struct ChildImportBuildResult {
    ChildImportError error{ChildImportError::NONE};
    DepositProofValidationError proof_error{DepositProofValidationError::NONE};
    std::optional<CMutableTransaction> transaction;
    std::optional<DepositId> deposit_id;

    bool IsValid() const
    {
        return error == ChildImportError::NONE &&
               transaction.has_value() && deposit_id.has_value();
    }
};

/** Test only the reserved base-transaction marker, without trusting witness data. */
bool IsReferenceChildImport(const CTransaction& transaction);

/** Build the canonical one-input, one-output IMPORT transaction. */
ChildImportBuildResult BuildReferenceChildImportTransaction(
    const DepositProof& proof,
    const ReferenceChildDefinition& definition);

/** Decode and structurally validate an IMPORT; main-header maturity is external. */
ChildImportResult ParseReferenceChildImportTransaction(
    const CTransaction& transaction,
    const ReferenceChildDefinition& definition);

} // namespace chainregistry

#endif // BITCOIN_CHAINREGISTRY_CHILD_IMPORT_H
