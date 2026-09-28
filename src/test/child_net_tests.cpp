// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_net.h>

#include <streams.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <ios>
#include <string_view>

namespace {

const chainregistry::ChainId CHAIN_ID{
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
const chainregistry::ChainId OTHER_CHAIN_ID{
    "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
const uint256 GENESIS_HASH{
    "223456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"};

CBlock ChildBlock(uint32_t discriminator)
{
    CBlock block;
    block.nVersion = CBlockHeader::CURRENT_VERSION;
    block.hashPrevBlock = GENESIS_HASH;
    block.hashMerkleRoot = uint256{static_cast<uint8_t>(discriminator)};
    block.nTime = discriminator;
    block.nBits = 0;
    block.nNonce = 0;
    return block;
}

} // namespace

BOOST_AUTO_TEST_SUITE(child_net_tests)

BOOST_AUTO_TEST_CASE(derives_isolated_message_start)
{
    const auto message_start{
        chainregistry::DeriveChildMessageStart(CHAIN_ID)};
    BOOST_CHECK(message_start ==
                chainregistry::DeriveChildMessageStart(CHAIN_ID));
    BOOST_CHECK(message_start !=
                chainregistry::DeriveChildMessageStart(OTHER_CHAIN_ID));
    BOOST_CHECK(std::any_of(
        message_start.begin(), message_start.end(), [](uint8_t value) {
            return value != 0;
        }));

    BOOST_CHECK_LE(chainregistry::ChildNetMsgType::HELLO.size(), 12U);
    BOOST_CHECK_LE(chainregistry::ChildNetMsgType::INVENTORY.size(), 12U);
    BOOST_CHECK_LE(chainregistry::ChildNetMsgType::GET_BLOCKS.size(), 12U);
    BOOST_CHECK_LE(chainregistry::ChildNetMsgType::BLOCK.size(), 12U);
}

BOOST_AUTO_TEST_CASE(validates_full_chain_handshake)
{
    chainregistry::ChildNetHello hello{
        .nonce = 123,
        .chain_id = CHAIN_ID,
        .genesis_hash = GENESIS_HASH,
    };
    BOOST_CHECK(
        chainregistry::ValidateChildNetHello(
            hello, CHAIN_ID, GENESIS_HASH) ==
        chainregistry::ChildNetValidationError::NONE);

    hello.version++;
    BOOST_CHECK(
        chainregistry::ValidateChildNetHello(
            hello, CHAIN_ID, GENESIS_HASH) ==
        chainregistry::ChildNetValidationError::UNSUPPORTED_VERSION);
    hello.version = chainregistry::CHILD_P2P_PROTOCOL_VERSION;
    hello.chain_id = OTHER_CHAIN_ID;
    BOOST_CHECK(
        chainregistry::ValidateChildNetHello(
            hello, CHAIN_ID, GENESIS_HASH) ==
        chainregistry::ChildNetValidationError::WRONG_CHAIN);
    hello.chain_id = CHAIN_ID;
    hello.genesis_hash = uint256{1};
    BOOST_CHECK(
        chainregistry::ValidateChildNetHello(
            hello, CHAIN_ID, GENESIS_HASH) ==
        chainregistry::ChildNetValidationError::WRONG_GENESIS);

    DataStream encoded;
    const chainregistry::ChildNetHello expected{
        .nonce = 456,
        .chain_id = CHAIN_ID,
        .genesis_hash = GENESIS_HASH,
    };
    encoded << expected;
    chainregistry::ChildNetHello decoded;
    encoded >> decoded;
    BOOST_CHECK(encoded.empty());
    BOOST_CHECK_EQUAL(decoded.version, expected.version);
    BOOST_CHECK_EQUAL(decoded.nonce, expected.nonce);
    BOOST_CHECK(decoded.chain_id == expected.chain_id);
    BOOST_CHECK(decoded.genesis_hash == expected.genesis_hash);
}

BOOST_AUTO_TEST_CASE(bounds_and_validates_block_hash_messages)
{
    chainregistry::ChildBlockHashes hashes{
        .chain_id = CHAIN_ID,
        .block_hashes = {uint256{1}, uint256{2}},
    };
    BOOST_CHECK(
        chainregistry::ValidateChildBlockHashes(hashes, CHAIN_ID) ==
        chainregistry::ChildNetValidationError::NONE);

    hashes.block_hashes.clear();
    BOOST_CHECK(
        chainregistry::ValidateChildBlockHashes(hashes, CHAIN_ID) ==
        chainregistry::ChildNetValidationError::EMPTY_HASH_LIST);
    hashes.block_hashes = {uint256{1}, uint256{1}};
    BOOST_CHECK(
        chainregistry::ValidateChildBlockHashes(hashes, CHAIN_ID) ==
        chainregistry::ChildNetValidationError::DUPLICATE_BLOCK_HASH);
    hashes.block_hashes = {uint256{}};
    BOOST_CHECK(
        chainregistry::ValidateChildBlockHashes(hashes, CHAIN_ID) ==
        chainregistry::ChildNetValidationError::NULL_BLOCK_HASH);

    hashes.block_hashes.assign(
        chainregistry::MAX_CHILD_BLOCK_REQUEST_HASHES + 1, uint256{1});
    BOOST_CHECK(
        chainregistry::ValidateChildBlockHashes(hashes, CHAIN_ID) ==
        chainregistry::ChildNetValidationError::TOO_MANY_HASHES);
    DataStream encoded;
    BOOST_CHECK_THROW(encoded << hashes, std::ios_base::failure);

    DataStream hostile;
    hostile << chainregistry::CHILD_P2P_PROTOCOL_VERSION;
    hostile << CHAIN_ID;
    WriteCompactSize(
        hostile, chainregistry::MAX_CHILD_BLOCK_REQUEST_HASHES + 1);
    chainregistry::ChildBlockHashes decoded;
    BOOST_CHECK_THROW(hostile >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(binds_block_data_to_request_and_chain)
{
    const CBlock block{ChildBlock(7)};
    chainregistry::ChildBlockData data{
        .chain_id = CHAIN_ID,
        .block = block,
    };
    BOOST_CHECK(
        chainregistry::ValidateChildBlockData(
            data, CHAIN_ID, block.GetHash()) ==
        chainregistry::ChildNetValidationError::NONE);
    BOOST_CHECK(
        chainregistry::ValidateChildBlockData(
            data, OTHER_CHAIN_ID, block.GetHash()) ==
        chainregistry::ChildNetValidationError::WRONG_CHAIN);
    BOOST_CHECK(
        chainregistry::ValidateChildBlockData(
            data, CHAIN_ID, uint256{8}) ==
        chainregistry::ChildNetValidationError::UNEXPECTED_BLOCK_HASH);

    DataStream encoded;
    encoded << data;
    chainregistry::ChildBlockData decoded;
    encoded >> decoded;
    BOOST_CHECK(encoded.empty());
    BOOST_CHECK_EQUAL(decoded.version, data.version);
    BOOST_CHECK(decoded.chain_id == data.chain_id);
    BOOST_CHECK(decoded.block.GetHash() == block.GetHash());
}

BOOST_AUTO_TEST_SUITE_END()
