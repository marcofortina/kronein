// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_CHAINREGISTRY_CHILD_NET_H
#define KRONEIN_CHAINREGISTRY_CHILD_NET_H

#include <kernel/messagestartchars.h>
#include <primitives/block.h>
#include <primitives/chainregistry.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <ios>
#include <string_view>
#include <vector>

namespace chainregistry {

inline constexpr uint16_t CHILD_P2P_PROTOCOL_VERSION{1};
inline constexpr uint64_t MAX_CHILD_BLOCK_REQUEST_HASHES{16};
inline constexpr std::string_view CHILD_MESSAGE_START_TAG{
    "Kronein/ChildMessageStart/v1"};

namespace ChildNetMsgType {
inline constexpr std::string_view HELLO{"chhello"};
inline constexpr std::string_view INVENTORY{"chinv"};
inline constexpr std::string_view GET_BLOCKS{"getchblock"};
inline constexpr std::string_view BLOCK{"chblock"};
} // namespace ChildNetMsgType

MessageStartChars DeriveChildMessageStart(const ChainId& chain_id);

struct ChildNetHello {
    uint16_t version{CHILD_P2P_PROTOCOL_VERSION};
    ChainId chain_id;
    uint256 genesis_hash;

    SERIALIZE_METHODS(ChildNetHello, obj)
    {
        READWRITE(obj.version, obj.chain_id, obj.genesis_hash);
    }
};

struct ChildBlockHashes {
    uint16_t version{CHILD_P2P_PROTOCOL_VERSION};
    ChainId chain_id;
    std::vector<uint256> block_hashes;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        if (block_hashes.size() > MAX_CHILD_BLOCK_REQUEST_HASHES) {
            throw std::ios_base::failure(
                "Child block hash request is too large.");
        }
        stream << version;
        stream << chain_id;
        WriteCompactSize(stream, block_hashes.size());
        for (const auto& hash : block_hashes) stream << hash;
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        stream >> version;
        stream >> chain_id;
        const uint64_t count{ReadCompactSize(stream)};
        if (count > MAX_CHILD_BLOCK_REQUEST_HASHES) {
            throw std::ios_base::failure(
                "Child block hash request is too large.");
        }
        block_hashes.resize(count);
        for (auto& hash : block_hashes) stream >> hash;
    }
};

struct ChildBlockData {
    uint16_t version{CHILD_P2P_PROTOCOL_VERSION};
    ChainId chain_id;
    CBlock block;

    SERIALIZE_METHODS(ChildBlockData, obj)
    {
        READWRITE(obj.version, obj.chain_id, TX_WITH_WITNESS(obj.block));
    }
};

enum class ChildNetValidationError : uint8_t {
    NONE,
    UNSUPPORTED_VERSION,
    NULL_CHAIN_ID,
    WRONG_CHAIN,
    NULL_GENESIS,
    WRONG_GENESIS,
    EMPTY_HASH_LIST,
    TOO_MANY_HASHES,
    NULL_BLOCK_HASH,
    DUPLICATE_BLOCK_HASH,
    BLOCK_TOO_LARGE,
    UNEXPECTED_BLOCK_HASH,
};

ChildNetValidationError ValidateChildNetHello(
    const ChildNetHello& hello,
    const ChainId& expected_chain_id,
    const uint256& expected_genesis_hash);

ChildNetValidationError ValidateChildBlockHashes(
    const ChildBlockHashes& message,
    const ChainId& expected_chain_id);

ChildNetValidationError ValidateChildBlockData(
    const ChildBlockData& message,
    const ChainId& expected_chain_id,
    const uint256& requested_block_hash);

} // namespace chainregistry

#endif // KRONEIN_CHAINREGISTRY_CHILD_NET_H
