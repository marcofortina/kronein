// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <key_io.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <variant>

BOOST_FIXTURE_TEST_SUITE(key_io_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(taproot_address)
{
    SelectParams(ChainType::MAIN);

    const std::string address{"bc1pqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsyjer9e"};
    const CTxDestination destination{DecodeDestination(address)};
    BOOST_REQUIRE(IsValidDestination(destination));
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(destination));
    BOOST_CHECK_EQUAL(HexStr(GetScriptForDestination(destination)), "51200101010101010101010101010101010101010101010101010101010101010101");
    BOOST_CHECK_EQUAL(EncodeDestination(destination), address);

    std::string invalid_checksum{address};
    invalid_checksum.back() = invalid_checksum.back() == 'q' ? 'p' : 'q';
    BOOST_CHECK(!IsValidDestination(DecodeDestination(invalid_checksum)));
}

BOOST_AUTO_TEST_CASE(private_keys)
{
    SelectParams(ChainType::MAIN);
    const std::string main_wif{"Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw"};
    CKey key{DecodeSecret(main_wif)};
    BOOST_REQUIRE(key.IsValid());
    BOOST_CHECK(key.IsCompressed());
    BOOST_CHECK_EQUAL(EncodeSecret(key), main_wif);

    SelectParams(ChainType::REGTEST);
    const std::string regtest_wif{"cVpF924EspNh8KjYsfhgY96mmxvT6DgdWiTYMtMjuM74hJaU5psW"};
    key = DecodeSecret(regtest_wif);
    BOOST_REQUIRE(key.IsValid());
    BOOST_CHECK(key.IsCompressed());
    BOOST_CHECK_EQUAL(EncodeSecret(key), regtest_wif);

    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
