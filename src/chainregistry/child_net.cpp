// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_net.h>

#include <consensus/consensus.h>
#include <hash.h>

#include <algorithm>
#include <set>
#include <string>

namespace chainregistry {
namespace {

ChildNetValidationError ValidateVersionAndChain(
    uint16_t version,
    const ChainId& chain_id,
    const ChainId& expected_chain_id)
{
    if (version != CHILD_P2P_PROTOCOL_VERSION) {
        return ChildNetValidationError::UNSUPPORTED_VERSION;
    }
    if (chain_id.IsNull() || expected_chain_id.IsNull()) {
        return ChildNetValidationError::NULL_CHAIN_ID;
    }
    if (chain_id != expected_chain_id) {
        return ChildNetValidationError::WRONG_CHAIN;
    }
    return ChildNetValidationError::NONE;
}

} // namespace

MessageStartChars DeriveChildMessageStart(const ChainId& chain_id)
{
    auto hasher{TaggedHash(std::string{CHILD_MESSAGE_START_TAG})};
    hasher << chain_id;
    const uint256 hash{hasher.GetSHA256()};
    MessageStartChars result;
    std::copy_n(hash.begin(), result.size(), result.begin());
    return result;
}

ChildNetValidationError ValidateChildNetHello(
    const ChildNetHello& hello,
    const ChainId& expected_chain_id,
    const uint256& expected_genesis_hash)
{
    if (const auto error{ValidateVersionAndChain(
            hello.version, hello.chain_id, expected_chain_id)};
        error != ChildNetValidationError::NONE) {
        return error;
    }
    if (hello.genesis_hash.IsNull() || expected_genesis_hash.IsNull()) {
        return ChildNetValidationError::NULL_GENESIS;
    }
    if (hello.genesis_hash != expected_genesis_hash) {
        return ChildNetValidationError::WRONG_GENESIS;
    }
    return ChildNetValidationError::NONE;
}

ChildNetValidationError ValidateChildBlockHashes(
    const ChildBlockHashes& message,
    const ChainId& expected_chain_id)
{
    if (const auto error{ValidateVersionAndChain(
            message.version, message.chain_id, expected_chain_id)};
        error != ChildNetValidationError::NONE) {
        return error;
    }
    if (message.block_hashes.empty()) {
        return ChildNetValidationError::EMPTY_HASH_LIST;
    }
    if (message.block_hashes.size() > MAX_CHILD_BLOCK_REQUEST_HASHES) {
        return ChildNetValidationError::TOO_MANY_HASHES;
    }
    std::set<uint256> unique;
    for (const auto& hash : message.block_hashes) {
        if (hash.IsNull()) {
            return ChildNetValidationError::NULL_BLOCK_HASH;
        }
        if (!unique.insert(hash).second) {
            return ChildNetValidationError::DUPLICATE_BLOCK_HASH;
        }
    }
    return ChildNetValidationError::NONE;
}

ChildNetValidationError ValidateChildBlockData(
    const ChildBlockData& message,
    const ChainId& expected_chain_id,
    const uint256& requested_block_hash)
{
    if (const auto error{ValidateVersionAndChain(
            message.version, message.chain_id, expected_chain_id)};
        error != ChildNetValidationError::NONE) {
        return error;
    }
    if (requested_block_hash.IsNull()) {
        return ChildNetValidationError::NULL_BLOCK_HASH;
    }
    if (GetSerializeSize(TX_WITH_WITNESS(message.block)) >
        MAX_BLOCK_SERIALIZED_SIZE) {
        return ChildNetValidationError::BLOCK_TOO_LARGE;
    }
    if (message.block.GetHash() != requested_block_hash) {
        return ChildNetValidationError::UNEXPECTED_BLOCK_HASH;
    }
    return ChildNetValidationError::NONE;
}

ChildNetValidationError ValidateChildTransactionData(
    const ChildTransactionData& message,
    const ChainId& expected_chain_id)
{
    if (const auto error{ValidateVersionAndChain(
            message.version, message.chain_id, expected_chain_id)};
        error != ChildNetValidationError::NONE) {
        return error;
    }
    if (GetSerializeSize(TX_WITH_WITNESS(message.transaction)) >
        MAX_BLOCK_SERIALIZED_SIZE) {
        return ChildNetValidationError::TRANSACTION_TOO_LARGE;
    }
    return ChildNetValidationError::NONE;
}

ChildNetValidationError ValidateChildAddressRequest(
    const ChildAddressRequest& message,
    const ChainId& expected_chain_id)
{
    return ValidateVersionAndChain(
        message.version, message.chain_id, expected_chain_id);
}

ChildNetValidationError ValidateChildAddresses(
    const ChildAddresses& message,
    const ChainId& expected_chain_id)
{
    if (const auto error{ValidateVersionAndChain(
            message.version, message.chain_id, expected_chain_id)};
        error != ChildNetValidationError::NONE) {
        return error;
    }
    if (message.addresses.size() > MAX_CHILD_RELAY_ADDRESSES) {
        return ChildNetValidationError::TOO_MANY_ADDRESSES;
    }
    std::set<CService> unique;
    for (const auto& address : message.addresses) {
        const CService& endpoint{address.endpoint};
        if (!endpoint.IsValid() || !endpoint.IsRoutable() ||
            (!endpoint.IsIPv4() && !endpoint.IsIPv6()) ||
            endpoint.GetPort() == 0) {
            return ChildNetValidationError::INVALID_ADDRESS;
        }
        if (!unique.insert(endpoint).second) {
            return ChildNetValidationError::DUPLICATE_ADDRESS;
        }
    }
    return ChildNetValidationError::NONE;
}

} // namespace chainregistry
