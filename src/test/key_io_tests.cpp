// Copyright (c) 2011-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
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

    const std::string address{"kne1pqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqstshygf"};
    const CTxDestination destination{DecodeDestination(address)};
    BOOST_REQUIRE(IsValidDestination(destination));
    BOOST_CHECK(std::holds_alternative<WitnessV1Taproot>(destination));
    BOOST_CHECK_EQUAL(HexStr(GetScriptForDestination(destination)), "51200101010101010101010101010101010101010101010101010101010101010101");
    BOOST_CHECK_EQUAL(EncodeDestination(destination), address);

    std::string invalid_checksum{address};
    invalid_checksum.back() = invalid_checksum.back() == 'q' ? 'p' : 'q';
    BOOST_CHECK(!IsValidDestination(DecodeDestination(invalid_checksum)));
}

BOOST_AUTO_TEST_CASE(native_bech32m_addresses)
{
    SelectParams(ChainType::REGTEST);

    const std::string anchor_address{"rkne1pfeesz3243u"};
    const CTxDestination anchor{DecodeDestination(anchor_address)};
    BOOST_REQUIRE(IsValidDestination(anchor));
    BOOST_CHECK(std::holds_alternative<PayToAnchor>(anchor));
    BOOST_CHECK_EQUAL(EncodeDestination(anchor), anchor_address);

}

BOOST_AUTO_TEST_CASE(private_keys)
{
    SelectParams(ChainType::MAIN);
    const std::string main_wif{"TdzpqQdWG9YBXA8JKfypJpwiU7pxv9fhVZ4CP5dp6yWxsgxYvXyZ"};
    CKey key{DecodeSecret(main_wif)};
    BOOST_REQUIRE(key.IsValid());
    BOOST_CHECK(key.IsCompressed());
    BOOST_CHECK_EQUAL(EncodeSecret(key), main_wif);

    SelectParams(ChainType::TESTNET4);
    const std::string testnet4_wif{"cnyWHLn3E8Cy5Mm5ypVU8VHkGqKkm4E5qbhoUo3vtJcVFy4PwZN7"};
    key = DecodeSecret(testnet4_wif);
    BOOST_REQUIRE(key.IsValid());
    BOOST_CHECK(key.IsCompressed());
    BOOST_CHECK_EQUAL(EncodeSecret(key), testnet4_wif);

    SelectParams(ChainType::SIGNET);
    const std::string signet_wif{"cwZ8rW8wQH873smrXttMvfPEXGXQbUVp13Kw3FQ2NnNCYJDnhQ3C"};
    key = DecodeSecret(signet_wif);
    BOOST_REQUIRE(key.IsValid());
    BOOST_CHECK(key.IsCompressed());
    BOOST_CHECK_EQUAL(EncodeSecret(key), signet_wif);

    SelectParams(ChainType::REGTEST);
    const std::string regtest_wif{"d68mRfVqaS3F2Pnd5yHFiqUimhj4RtmYAUx4bhk7sG7updNJy1my"};
    key = DecodeSecret(regtest_wif);
    BOOST_REQUIRE(key.IsValid());
    BOOST_CHECK(key.IsCompressed());
    BOOST_CHECK_EQUAL(EncodeSecret(key), regtest_wif);

    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()
