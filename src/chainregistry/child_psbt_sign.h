// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CHAINREGISTRY_CHILD_PSBT_SIGN_H
#define BITCOIN_CHAINREGISTRY_CHILD_PSBT_SIGN_H

#include <chainregistry/child_psbt.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string_view>

struct PrecomputedTransactionData;
class SigningProvider;
class PartiallySignedTransaction;
struct SignatureData;

namespace chainregistry {

enum class ChildPSBTSignError : uint8_t {
    NONE,
    INVALID_IDENTITY,
    INVALID_TRANSACTION,
    INPUT_OUT_OF_RANGE,
    MISSING_INPUT,
    UNSUPPORTED_SCRIPT,
    SIGHASH_MISMATCH,
    INVALID_SIGNATURE,
};

struct ChildPSBTSignResult {
    ChildPSBTSignError error{ChildPSBTSignError::NONE};
    ChildPSBTIdentityError identity_error{ChildPSBTIdentityError::NONE};
    bool signature_complete{false};

    bool IsValid() const { return error == ChildPSBTSignError::NONE; }
};

std::string_view ChildPSBTSignErrorString(ChildPSBTSignError error);

/** Verify one finalized input in the exact reference-child signature domain. */
bool ChildPSBTInputSignedAndVerified(
    const PartiallySignedTransaction& psbt,
    unsigned int input_index,
    const ReferenceChildDefinition& definition,
    const PrecomputedTransactionData& txdata);

/**
 * Add signing metadata/signatures for one input and optionally finalize it.
 * The PSBT identity is checked before any signing work and existing invalid
 * signatures are never replaced silently.
 */
ChildPSBTSignResult UpdateChildPSBTInput(
    const SigningProvider& provider,
    PartiallySignedTransaction& psbt,
    unsigned int input_index,
    const ReferenceChildDefinition& definition,
    const PrecomputedTransactionData& txdata,
    std::optional<int> sighash_type = std::nullopt,
    bool finalize = true,
    SignatureData* output_signature_data = nullptr);

/** Finalize all existing child signatures, verify them, and extract the tx. */
ChildPSBTSignResult FinalizeAndExtractChildPSBT(
    PartiallySignedTransaction& psbt,
    const ReferenceChildDefinition& definition,
    CMutableTransaction& result);

} // namespace chainregistry

#endif // BITCOIN_CHAINREGISTRY_CHILD_PSBT_SIGN_H
