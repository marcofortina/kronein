// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/child_derivation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>

namespace wallet {
namespace {

BOOST_AUTO_TEST_SUITE(child_derivation_tests)

BOOST_AUTO_TEST_CASE(path_domain_separation)
{
    constexpr chainregistry::ChainId chain_a{
        "0101010101010101010101010101010101010101010101010101010101010101"};
    constexpr chainregistry::ChainId chain_b{
        "0101010101010101010101010101010101010101010101010101010101010102"};

    const auto receive_a{ChildKeyPath(chain_a, ChildKeyRole::RECEIVE, 7)};
    const auto receive_b{ChildKeyPath(chain_b, ChildKeyRole::RECEIVE, 7)};
    const auto change_a{ChildKeyPath(chain_a, ChildKeyRole::CHANGE, 7)};
    BOOST_REQUIRE(receive_a);
    BOOST_REQUIRE(receive_b);
    BOOST_REQUIRE(change_a);
    BOOST_CHECK_EQUAL(receive_a->size(), CHILD_KEY_PATH_DEPTH);
    BOOST_CHECK(*receive_a != *receive_b);
    BOOST_CHECK(*receive_a != *change_a);
    BOOST_CHECK_EQUAL((*receive_a)[CHILD_KEY_ACCOUNT_DEPTH], 0U);
    BOOST_CHECK_EQUAL((*change_a)[CHILD_KEY_ACCOUNT_DEPTH], 1U);
    BOOST_CHECK_EQUAL(receive_a->back(), 7U);

    BOOST_CHECK(std::ranges::all_of(
        receive_a->begin(),
        receive_a->begin() + CHILD_KEY_ACCOUNT_DEPTH,
        [](uint32_t component) {
            return (component & CHILD_KEY_HARDENED) != 0;
        }));
}

BOOST_AUTO_TEST_CASE(full_chain_id_encoding)
{
    constexpr chainregistry::ChainId all_bits{
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    const auto account{ChildKeyAccountPath(all_bits)};
    BOOST_REQUIRE(account);
    BOOST_REQUIRE_EQUAL(account->size(), CHILD_KEY_ACCOUNT_DEPTH);
    BOOST_CHECK_EQUAL(
        (*account)[0], CHILD_KEY_HARDENED | CHILD_KEY_DERIVATION_PURPOSE);
    BOOST_CHECK_EQUAL(
        (*account)[1], CHILD_KEY_HARDENED | CHILD_KEY_DERIVATION_VERSION);
    for (size_t index{2}; index < account->size() - 1; ++index) {
        BOOST_CHECK_EQUAL((*account)[index], 0xffffffffU);
    }
    BOOST_CHECK_EQUAL(account->back(), CHILD_KEY_HARDENED | 0xffU);
}

BOOST_AUTO_TEST_CASE(reject_invalid_domain)
{
    BOOST_CHECK(!ChildKeyAccountPath({}));
    constexpr chainregistry::ChainId chain{
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    BOOST_CHECK(!ChildKeyPath(
        chain, ChildKeyRole::RECEIVE, CHILD_KEY_HARDENED));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet
