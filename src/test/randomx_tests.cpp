// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/randomx.h>

#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <span>
#include <string_view>

BOOST_AUTO_TEST_SUITE(randomx_tests)

BOOST_AUTO_TEST_CASE(upstream_v2_vector)
{
    static constexpr std::string_view KEY{"test key 000"};
    static constexpr std::string_view INPUT{"This is a test"};
    const auto hash{randomx_pow::HashLight(
        std::span{reinterpret_cast<const unsigned char*>(KEY.data()), KEY.size()},
        std::span{reinterpret_cast<const unsigned char*>(INPUT.data()), INPUT.size()})};
    BOOST_REQUIRE(hash);
    BOOST_CHECK_EQUAL(HexStr(*hash), "22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f");
}

BOOST_AUTO_TEST_CASE(context_cache_reuse)
{
    static constexpr std::string_view KEY{"Kronein RandomX cache test"};
    const auto key{std::span{reinterpret_cast<const unsigned char*>(KEY.data()), KEY.size()}};
    auto first{randomx_pow::GetCachedHasher(key, randomx_pow::Mode::LIGHT)};
    auto second{randomx_pow::GetCachedHasher(key, randomx_pow::Mode::LIGHT)};
    BOOST_REQUIRE(first);
    BOOST_CHECK(first == second);
}

BOOST_AUTO_TEST_CASE(light_full_equivalence)
{
    static constexpr std::string_view KEY{"Kronein RandomX light/full equivalence"};
    static constexpr std::string_view INPUT{"native 80-byte header hashing must agree"};
    const auto key{std::span{reinterpret_cast<const unsigned char*>(KEY.data()), KEY.size()}};
    const auto input{std::span{reinterpret_cast<const unsigned char*>(INPUT.data()), INPUT.size()}};
    const auto light{randomx_pow::GetCachedHasher(key, randomx_pow::Mode::LIGHT)};
    const auto full{randomx_pow::GetCachedHasher(key, randomx_pow::Mode::FULL, /*dataset_threads=*/2)};
    BOOST_REQUIRE(light);
    BOOST_REQUIRE(full);
    const auto light_hash{light->HashData(input)};
    const auto full_hash{full->HashData(input)};
    BOOST_REQUIRE(light_hash);
    BOOST_REQUIRE(full_hash);
    BOOST_CHECK_EQUAL(HexStr(*light_hash), HexStr(*full_hash));
}

BOOST_AUTO_TEST_SUITE_END()
