// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compressor.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <vector>

#include <boost/test/unit_test.hpp>

// amounts 0.00000001 .. 0.00100000
#define NUM_MULTIPLES_UNIT 100000

// amounts 0.01 .. 100.00
#define NUM_MULTIPLES_CENT 10000

// amounts 1 .. 10000
#define NUM_MULTIPLES_1BTC 10000

// amounts 50 .. 21000000
#define NUM_MULTIPLES_50BTC 420000

BOOST_FIXTURE_TEST_SUITE(compress_tests, BasicTestingSetup)

bool static TestEncode(uint64_t in) {
    return in == DecompressAmount(CompressAmount(in));
}

bool static TestDecode(uint64_t in) {
    return in == CompressAmount(DecompressAmount(in));
}

bool static TestPair(uint64_t dec, uint64_t enc) {
    return CompressAmount(dec) == enc &&
           DecompressAmount(enc) == dec;
}

BOOST_AUTO_TEST_CASE(compress_amounts)
{
    BOOST_CHECK(TestPair(            0,       0x0));
    BOOST_CHECK(TestPair(            1,       0x1));
    BOOST_CHECK(TestPair(         CENT,       0x7));
    BOOST_CHECK(TestPair(         COIN,       0x9));
    BOOST_CHECK(TestPair(      50*COIN,      0x32));
    BOOST_CHECK(TestPair(21000000*COIN, 0x1406f40));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_UNIT; i++)
        BOOST_CHECK(TestEncode(i));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_CENT; i++)
        BOOST_CHECK(TestEncode(i * CENT));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_1BTC; i++)
        BOOST_CHECK(TestEncode(i * COIN));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_50BTC; i++)
        BOOST_CHECK(TestEncode(i * 50 * COIN));

    for (uint64_t i = 0; i < 100000; i++)
        BOOST_CHECK(TestDecode(i));
}

BOOST_AUTO_TEST_CASE(compress_p2tr_script)
{
    std::vector<unsigned char> witness_program(32);
    std::iota(witness_program.begin(), witness_program.end(), 0);
    const CScript script{CScript{} << OP_1 << witness_program};
    BOOST_CHECK(script.IsPayToTaproot());

    CompressedScript out;
    BOOST_REQUIRE(CompressScript(script, out));
    BOOST_REQUIRE_EQUAL(out.size(), 33U);
    BOOST_CHECK_EQUAL(out[0], 0x00);
    BOOST_CHECK(std::equal(witness_program.begin(), witness_program.end(), out.begin() + 1));

    out.erase(out.begin());
    CScript decompressed;
    BOOST_REQUIRE(DecompressScript(decompressed, 0, out));
    BOOST_CHECK(script == decompressed);
}

BOOST_AUTO_TEST_CASE(compress_p2a_script)
{
    const CScript script{CScript{} << OP_1 << std::vector<unsigned char>{0x4e, 0x73}};
    BOOST_CHECK(script.IsPayToAnchor());

    CompressedScript out;
    BOOST_REQUIRE(CompressScript(script, out));
    BOOST_REQUIRE_EQUAL(out.size(), 1U);
    BOOST_CHECK_EQUAL(out[0], 0x01);

    out.clear();
    CScript decompressed;
    BOOST_REQUIRE(DecompressScript(decompressed, 1, out));
    BOOST_CHECK(script == decompressed);
}

BOOST_AUTO_TEST_CASE(data_scripts_use_generic_encoding)
{
    CompressedScript out;
    const CScript data{CScript{} << OP_RETURN << std::vector<unsigned char>{0x01, 0x02}};
    BOOST_CHECK(!CompressScript(data, out));
}

BOOST_AUTO_TEST_CASE(native_script_sizes_and_invalid_payloads)
{
    BOOST_CHECK_EQUAL(GetSpecialScriptSize(0), 32U);
    BOOST_CHECK_EQUAL(GetSpecialScriptSize(1), 0U);
    BOOST_CHECK_EQUAL(GetSpecialScriptSize(2), 0U);

    CScript script;
    BOOST_CHECK(!DecompressScript(script, 0, CompressedScript(31, 0x00)));
    BOOST_CHECK(!DecompressScript(script, 1, CompressedScript(1, 0x00)));
    BOOST_CHECK(!DecompressScript(script, 2, {}));
}

BOOST_AUTO_TEST_SUITE_END()
