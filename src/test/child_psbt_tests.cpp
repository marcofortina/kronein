// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_psbt.h>

#include <primitives/transaction.h>
#include <psbt.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>

namespace {

const chainregistry::ChainId CHILD_ID{
    "1111111111111111111111111111111111111111111111111111111111111111"};
const uint256 CHILD_GENESIS{
    "2222222222222222222222222222222222222222222222222222222222222222"};

chainregistry::ChildPSBTIdentity TestIdentity()
{
    return {
        .chain_id = CHILD_ID,
        .template_id = chainregistry::REFERENCE_CHILD_TEMPLATE_ID,
        .template_version = chainregistry::REFERENCE_CHILD_TEMPLATE_VERSION,
        .genesis_hash = CHILD_GENESIS,
    };
}

PartiallySignedTransaction EmptyPSBT()
{
    CMutableTransaction transaction;
    return PartiallySignedTransaction{transaction};
}

void EraseSubtype(PartiallySignedTransaction& psbt, uint64_t subtype)
{
    std::erase_if(psbt.m_proprietary, [subtype](const auto& field) {
        return field.identifier ==
                   std::vector<unsigned char>{'k', 'r', 'o', 'n', 'e', 'i', 'n'} &&
               field.subtype == subtype;
    });
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(child_psbt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(identity_roundtrips_through_psbt_serialization)
{
    auto psbt{EmptyPSBT()};
    const auto identity{TestIdentity()};
    BOOST_CHECK(chainregistry::AddChildPSBTIdentity(psbt, identity) ==
                chainregistry::ChildPSBTIdentityError::NONE);
    BOOST_CHECK_EQUAL(psbt.m_proprietary.size(), 4U);

    const auto parsed{chainregistry::ExtractChildPSBTIdentity(psbt)};
    BOOST_REQUIRE(parsed.IsValid());
    BOOST_CHECK(*parsed.identity == identity);

    DataStream stream;
    stream << psbt;
    PartiallySignedTransaction decoded{deserialize, stream};
    const auto decoded_identity{
        chainregistry::ExtractChildPSBTIdentity(decoded)};
    BOOST_REQUIRE(decoded_identity.IsValid());
    BOOST_CHECK(*decoded_identity.identity == identity);
    BOOST_CHECK(stream.empty());
}

BOOST_AUTO_TEST_CASE(identity_is_mandatory_complete_and_unique)
{
    auto missing{EmptyPSBT()};
    BOOST_CHECK(chainregistry::ExtractChildPSBTIdentity(missing).error ==
                chainregistry::ChildPSBTIdentityError::MISSING_CHAIN_ID);

    auto psbt{EmptyPSBT()};
    BOOST_REQUIRE(chainregistry::AddChildPSBTIdentity(psbt, TestIdentity()) ==
                  chainregistry::ChildPSBTIdentityError::NONE);
    BOOST_CHECK(chainregistry::AddChildPSBTIdentity(psbt, TestIdentity()) ==
                chainregistry::ChildPSBTIdentityError::RESERVED_FIELDS_PRESENT);

    EraseSubtype(psbt, 2);
    BOOST_CHECK(chainregistry::ExtractChildPSBTIdentity(psbt).error ==
                chainregistry::ChildPSBTIdentityError::MISSING_TEMPLATE_ID);

    auto malformed{EmptyPSBT()};
    BOOST_REQUIRE(chainregistry::AddChildPSBTIdentity(malformed, TestIdentity()) ==
                  chainregistry::ChildPSBTIdentityError::NONE);
    auto field{*malformed.m_proprietary.begin()};
    malformed.m_proprietary.erase(malformed.m_proprietary.begin());
    field.key.push_back(0x00);
    malformed.m_proprietary.insert(field);
    BOOST_CHECK(chainregistry::ExtractChildPSBTIdentity(malformed).error ==
                chainregistry::ChildPSBTIdentityError::MALFORMED_RESERVED_FIELD);

    auto unknown{EmptyPSBT()};
    BOOST_REQUIRE(chainregistry::AddChildPSBTIdentity(unknown, TestIdentity()) ==
                  chainregistry::ChildPSBTIdentityError::NONE);
    auto unknown_field{*unknown.m_proprietary.begin()};
    unknown.m_proprietary.erase(unknown.m_proprietary.begin());
    unknown_field.subtype = 5;
    unknown_field.key.back() = 5;
    unknown.m_proprietary.insert(unknown_field);
    BOOST_CHECK(chainregistry::ExtractChildPSBTIdentity(unknown).error ==
                chainregistry::ChildPSBTIdentityError::UNKNOWN_RESERVED_FIELD);
}

BOOST_AUTO_TEST_CASE(identity_rejects_null_and_wrong_child_context)
{
    auto psbt{EmptyPSBT()};
    auto identity{TestIdentity()};
    identity.chain_id = {};
    BOOST_CHECK(chainregistry::AddChildPSBTIdentity(psbt, identity) ==
                chainregistry::ChildPSBTIdentityError::NULL_CHAIN_ID);
    identity = TestIdentity();
    identity.genesis_hash.SetNull();
    BOOST_CHECK(chainregistry::AddChildPSBTIdentity(psbt, identity) ==
                chainregistry::ChildPSBTIdentityError::NULL_GENESIS_HASH);
    identity = TestIdentity();
    ++identity.template_version;
    BOOST_CHECK(chainregistry::AddChildPSBTIdentity(psbt, identity) ==
                chainregistry::ChildPSBTIdentityError::UNSUPPORTED_TEMPLATE);

    BOOST_REQUIRE(chainregistry::AddChildPSBTIdentity(psbt, TestIdentity()) ==
                  chainregistry::ChildPSBTIdentityError::NONE);
    chainregistry::ReferenceChildDefinition definition;
    definition.chain_id = CHILD_ID;
    definition.genesis_hash = CHILD_GENESIS;
    BOOST_CHECK(chainregistry::VerifyChildPSBTIdentity(psbt, definition) ==
                chainregistry::ChildPSBTIdentityError::NONE);

    definition.chain_id = chainregistry::ChainId{
        "3333333333333333333333333333333333333333333333333333333333333333"};
    BOOST_CHECK(chainregistry::VerifyChildPSBTIdentity(psbt, definition) ==
                chainregistry::ChildPSBTIdentityError::CHAIN_ID_MISMATCH);
    definition.chain_id = CHILD_ID;
    definition.genesis_hash = uint256{
        "4444444444444444444444444444444444444444444444444444444444444444"};
    BOOST_CHECK(chainregistry::VerifyChildPSBTIdentity(psbt, definition) ==
                chainregistry::ChildPSBTIdentityError::GENESIS_HASH_MISMATCH);
}

BOOST_AUTO_TEST_SUITE_END()
