// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_psbt.h>

#include <psbt.h>
#include <serialize.h>
#include <streams.h>

#include <algorithm>
#include <array>
#include <ios>
#include <set>
#include <span>
#include <vector>

namespace chainregistry {
namespace {

constexpr std::array<unsigned char, 7> CHILD_PSBT_IDENTIFIER{
    'k', 'r', 'o', 'n', 'e', 'i', 'n'};

enum class ChildPSBTSubtype : uint64_t {
    CHAIN_ID = 1,
    TEMPLATE_ID = 2,
    TEMPLATE_VERSION = 3,
    GENESIS_HASH = 4,
};

std::vector<unsigned char> StreamBytes(const DataStream& stream)
{
    const auto bytes{MakeUCharSpan(stream)};
    return {bytes.begin(), bytes.end()};
}

std::vector<unsigned char> SerializeValue(const auto& value)
{
    DataStream stream;
    stream << value;
    return StreamBytes(stream);
}

PSBTProprietary MakeField(ChildPSBTSubtype subtype,
                          std::vector<unsigned char> value)
{
    DataStream key;
    WriteCompactSize(key, PSBT_GLOBAL_PROPRIETARY);
    key << std::vector<unsigned char>{CHILD_PSBT_IDENTIFIER.begin(),
                                     CHILD_PSBT_IDENTIFIER.end()};
    WriteCompactSize(key, static_cast<uint64_t>(subtype));

    return PSBTProprietary{
        .subtype = static_cast<uint64_t>(subtype),
        .identifier = {CHILD_PSBT_IDENTIFIER.begin(),
                       CHILD_PSBT_IDENTIFIER.end()},
        .key = StreamBytes(key),
        .value = std::move(value),
    };
}

bool IsReservedIdentifier(const PSBTProprietary& field)
{
    return std::ranges::equal(field.identifier, CHILD_PSBT_IDENTIFIER);
}

bool HasCanonicalKey(const PSBTProprietary& field)
{
    try {
        SpanReader reader{field.key};
        if (ReadCompactSize(reader) != PSBT_GLOBAL_PROPRIETARY) return false;

        std::vector<unsigned char> identifier;
        reader >> identifier;
        if (!std::ranges::equal(identifier, CHILD_PSBT_IDENTIFIER)) return false;
        if (ReadCompactSize(reader) != field.subtype) return false;
        return reader.empty();
    } catch (const std::ios_base::failure&) {
        return false;
    }
}

template <typename T>
bool ParseExactValue(const std::vector<unsigned char>& bytes, T& value)
{
    try {
        SpanReader reader{bytes};
        reader >> value;
        return reader.empty();
    } catch (const std::ios_base::failure&) {
        return false;
    }
}

ChildPSBTIdentityError ValidateIdentityBasics(const ChildPSBTIdentity& identity)
{
    if (identity.chain_id.IsNull()) {
        return ChildPSBTIdentityError::NULL_CHAIN_ID;
    }
    if (identity.genesis_hash.IsNull()) {
        return ChildPSBTIdentityError::NULL_GENESIS_HASH;
    }
    return ChildPSBTIdentityError::NONE;
}

} // namespace

std::string_view ChildPSBTIdentityErrorString(ChildPSBTIdentityError error)
{
    switch (error) {
    case ChildPSBTIdentityError::NONE: return "none";
    case ChildPSBTIdentityError::NULL_CHAIN_ID: return "null chain id";
    case ChildPSBTIdentityError::NULL_GENESIS_HASH: return "null genesis hash";
    case ChildPSBTIdentityError::UNSUPPORTED_TEMPLATE:
        return "unsupported child template";
    case ChildPSBTIdentityError::RESERVED_FIELDS_PRESENT:
        return "Kronein child fields already present";
    case ChildPSBTIdentityError::MALFORMED_RESERVED_FIELD:
        return "malformed Kronein child field";
    case ChildPSBTIdentityError::UNKNOWN_RESERVED_FIELD:
        return "unknown Kronein child field";
    case ChildPSBTIdentityError::DUPLICATE_RESERVED_FIELD:
        return "duplicate Kronein child field";
    case ChildPSBTIdentityError::MISSING_CHAIN_ID: return "missing child chain id";
    case ChildPSBTIdentityError::MISSING_TEMPLATE_ID: return "missing child template id";
    case ChildPSBTIdentityError::MISSING_TEMPLATE_VERSION:
        return "missing child template version";
    case ChildPSBTIdentityError::MISSING_GENESIS_HASH: return "missing child genesis hash";
    case ChildPSBTIdentityError::CHAIN_ID_MISMATCH: return "child chain id mismatch";
    case ChildPSBTIdentityError::TEMPLATE_ID_MISMATCH: return "child template id mismatch";
    case ChildPSBTIdentityError::TEMPLATE_VERSION_MISMATCH:
        return "child template version mismatch";
    case ChildPSBTIdentityError::GENESIS_HASH_MISMATCH: return "child genesis hash mismatch";
    }
    return "unknown child PSBT identity error";
}

ChildPSBTIdentity MakeChildPSBTIdentity(
    const ReferenceChildDefinition& definition)
{
    return ChildPSBTIdentity{
        .chain_id = definition.chain_id,
        .template_id = REFERENCE_CHILD_TEMPLATE_ID,
        .template_version = REFERENCE_CHILD_TEMPLATE_VERSION,
        .genesis_hash = definition.genesis_hash,
    };
}

ChildPSBTIdentityError AddChildPSBTIdentity(
    PartiallySignedTransaction& psbt,
    const ChildPSBTIdentity& identity)
{
    if (const auto error{ValidateIdentityBasics(identity)};
        error != ChildPSBTIdentityError::NONE) {
        return error;
    }
    if (identity.template_id != REFERENCE_CHILD_TEMPLATE_ID ||
        identity.template_version != REFERENCE_CHILD_TEMPLATE_VERSION) {
        return ChildPSBTIdentityError::UNSUPPORTED_TEMPLATE;
    }
    if (std::ranges::any_of(psbt.m_proprietary, IsReservedIdentifier)) {
        return ChildPSBTIdentityError::RESERVED_FIELDS_PRESENT;
    }

    psbt.m_proprietary.insert(MakeField(
        ChildPSBTSubtype::CHAIN_ID, SerializeValue(identity.chain_id)));
    psbt.m_proprietary.insert(MakeField(
        ChildPSBTSubtype::TEMPLATE_ID, SerializeValue(identity.template_id)));
    psbt.m_proprietary.insert(MakeField(
        ChildPSBTSubtype::TEMPLATE_VERSION,
        SerializeValue(identity.template_version)));
    psbt.m_proprietary.insert(MakeField(
        ChildPSBTSubtype::GENESIS_HASH,
        SerializeValue(identity.genesis_hash)));
    return ChildPSBTIdentityError::NONE;
}

ChildPSBTIdentityResult ExtractChildPSBTIdentity(
    const PartiallySignedTransaction& psbt)
{
    ChildPSBTIdentity identity;
    std::set<ChildPSBTSubtype> found;

    for (const auto& field : psbt.m_proprietary) {
        if (!IsReservedIdentifier(field)) continue;
        if (!HasCanonicalKey(field)) {
            return {ChildPSBTIdentityError::MALFORMED_RESERVED_FIELD,
                    std::nullopt};
        }

        const auto subtype{static_cast<ChildPSBTSubtype>(field.subtype)};
        switch (subtype) {
        case ChildPSBTSubtype::CHAIN_ID:
            if (!found.insert(subtype).second) {
                return {ChildPSBTIdentityError::DUPLICATE_RESERVED_FIELD,
                        std::nullopt};
            }
            if (!ParseExactValue(field.value, identity.chain_id)) {
                return {ChildPSBTIdentityError::MALFORMED_RESERVED_FIELD,
                        std::nullopt};
            }
            break;
        case ChildPSBTSubtype::TEMPLATE_ID:
            if (!found.insert(subtype).second) {
                return {ChildPSBTIdentityError::DUPLICATE_RESERVED_FIELD,
                        std::nullopt};
            }
            if (!ParseExactValue(field.value, identity.template_id)) {
                return {ChildPSBTIdentityError::MALFORMED_RESERVED_FIELD,
                        std::nullopt};
            }
            break;
        case ChildPSBTSubtype::TEMPLATE_VERSION:
            if (!found.insert(subtype).second) {
                return {ChildPSBTIdentityError::DUPLICATE_RESERVED_FIELD,
                        std::nullopt};
            }
            if (!ParseExactValue(field.value, identity.template_version)) {
                return {ChildPSBTIdentityError::MALFORMED_RESERVED_FIELD,
                        std::nullopt};
            }
            break;
        case ChildPSBTSubtype::GENESIS_HASH:
            if (!found.insert(subtype).second) {
                return {ChildPSBTIdentityError::DUPLICATE_RESERVED_FIELD,
                        std::nullopt};
            }
            if (!ParseExactValue(field.value, identity.genesis_hash)) {
                return {ChildPSBTIdentityError::MALFORMED_RESERVED_FIELD,
                        std::nullopt};
            }
            break;
        default:
            return {ChildPSBTIdentityError::UNKNOWN_RESERVED_FIELD,
                    std::nullopt};
        }
    }

    if (!found.contains(ChildPSBTSubtype::CHAIN_ID)) {
        return {ChildPSBTIdentityError::MISSING_CHAIN_ID, std::nullopt};
    }
    if (!found.contains(ChildPSBTSubtype::TEMPLATE_ID)) {
        return {ChildPSBTIdentityError::MISSING_TEMPLATE_ID, std::nullopt};
    }
    if (!found.contains(ChildPSBTSubtype::TEMPLATE_VERSION)) {
        return {ChildPSBTIdentityError::MISSING_TEMPLATE_VERSION,
                std::nullopt};
    }
    if (!found.contains(ChildPSBTSubtype::GENESIS_HASH)) {
        return {ChildPSBTIdentityError::MISSING_GENESIS_HASH, std::nullopt};
    }
    if (const auto error{ValidateIdentityBasics(identity)};
        error != ChildPSBTIdentityError::NONE) {
        return {error, std::nullopt};
    }
    return {ChildPSBTIdentityError::NONE, identity};
}

ChildPSBTIdentityError VerifyChildPSBTIdentity(
    const PartiallySignedTransaction& psbt,
    const ReferenceChildDefinition& definition)
{
    const auto parsed{ExtractChildPSBTIdentity(psbt)};
    if (!parsed.IsValid()) return parsed.error;

    const auto& identity{*parsed.identity};
    if (identity.chain_id != definition.chain_id) {
        return ChildPSBTIdentityError::CHAIN_ID_MISMATCH;
    }
    if (identity.template_id != REFERENCE_CHILD_TEMPLATE_ID) {
        return ChildPSBTIdentityError::TEMPLATE_ID_MISMATCH;
    }
    if (identity.template_version != REFERENCE_CHILD_TEMPLATE_VERSION) {
        return ChildPSBTIdentityError::TEMPLATE_VERSION_MISMATCH;
    }
    if (identity.genesis_hash != definition.genesis_hash) {
        return ChildPSBTIdentityError::GENESIS_HASH_MISMATCH;
    }
    return ChildPSBTIdentityError::NONE;
}

} // namespace chainregistry
