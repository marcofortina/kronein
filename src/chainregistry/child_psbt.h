// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CHAINREGISTRY_CHILD_PSBT_H
#define BITCOIN_CHAINREGISTRY_CHILD_PSBT_H

#include <chainregistry/child_template.h>
#include <primitives/chainregistry.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string_view>

class PartiallySignedTransaction;

namespace chainregistry {

/** Canonical global identity carried by every reference-child PSBT. */
struct ChildPSBTIdentity {
    ChainId chain_id;
    uint32_t template_id{0};
    uint32_t template_version{0};
    uint256 genesis_hash;

    friend bool operator==(const ChildPSBTIdentity&, const ChildPSBTIdentity&) = default;
};

enum class ChildPSBTIdentityError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    NULL_GENESIS_HASH,
    UNSUPPORTED_TEMPLATE,
    RESERVED_FIELDS_PRESENT,
    MALFORMED_RESERVED_FIELD,
    UNKNOWN_RESERVED_FIELD,
    DUPLICATE_RESERVED_FIELD,
    MISSING_CHAIN_ID,
    MISSING_TEMPLATE_ID,
    MISSING_TEMPLATE_VERSION,
    MISSING_GENESIS_HASH,
    CHAIN_ID_MISMATCH,
    TEMPLATE_ID_MISMATCH,
    TEMPLATE_VERSION_MISMATCH,
    GENESIS_HASH_MISMATCH,
};

struct ChildPSBTIdentityResult {
    ChildPSBTIdentityError error{ChildPSBTIdentityError::NONE};
    std::optional<ChildPSBTIdentity> identity;

    bool IsValid() const
    {
        return error == ChildPSBTIdentityError::NONE && identity.has_value();
    }
};

std::string_view ChildPSBTIdentityErrorString(ChildPSBTIdentityError error);

ChildPSBTIdentity MakeChildPSBTIdentity(
    const ReferenceChildDefinition& definition);

/** Add all four mandatory global fields, refusing any pre-existing Kronein field. */
ChildPSBTIdentityError AddChildPSBTIdentity(
    PartiallySignedTransaction& psbt,
    const ChildPSBTIdentity& identity);

/** Parse the exact v1 field set. Missing, duplicate and unknown fields fail closed. */
ChildPSBTIdentityResult ExtractChildPSBTIdentity(
    const PartiallySignedTransaction& psbt);

/** Extract and bind the PSBT identity to the loaded child definition. */
ChildPSBTIdentityError VerifyChildPSBTIdentity(
    const PartiallySignedTransaction& psbt,
    const ReferenceChildDefinition& definition);

} // namespace chainregistry

#endif // BITCOIN_CHAINREGISTRY_CHILD_PSBT_H
