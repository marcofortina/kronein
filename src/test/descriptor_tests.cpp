// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/tx_check.h>
#include <key_io.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view INTERNAL_KEY{"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"};
constexpr std::string_view LEAF_KEY{"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"};

void CheckNativeDescriptor(const std::string& descriptor, bool ranged = false)
{
    FlatSigningProvider keys;
    std::string error;
    auto descriptors{Parse(descriptor, keys, error)};
    BOOST_REQUIRE_MESSAGE(!descriptors.empty(), error);
    BOOST_REQUIRE_EQUAL(descriptors.size(), 1U);
    BOOST_CHECK_EQUAL(descriptors[0]->IsRange(), ranged);

    FlatSigningProvider expanded;
    std::vector<CScript> scripts;
    BOOST_REQUIRE(descriptors[0]->Expand(/*pos=*/0, keys, scripts, expanded));
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
    BOOST_CHECK(IsNativeOutputScript(scripts[0]));
    const auto output_type{descriptors[0]->GetOutputType()};
    if (scripts[0].empty() || scripts[0][0] != OP_RETURN) {
        BOOST_REQUIRE(output_type.has_value());
        BOOST_CHECK_EQUAL(static_cast<int>(*output_type), static_cast<int>(OutputType::BECH32M));
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(descriptor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(native_descriptor_grammar)
{
    CheckNativeDescriptor("tr(" + std::string{INTERNAL_KEY} + ")");
    CheckNativeDescriptor("rawtr(" + std::string{INTERNAL_KEY} + ")");
    CheckNativeDescriptor("tr(" + std::string{INTERNAL_KEY} + ",pk(" + std::string{LEAF_KEY} + "))");
    CheckNativeDescriptor("tr(" + std::string{INTERNAL_KEY} + ",multi_a(1," + std::string{INTERNAL_KEY} + "," + std::string{LEAF_KEY} + "))");
    CheckNativeDescriptor("tr(" + std::string{INTERNAL_KEY} + ",and_v(v:pk(" + std::string{LEAF_KEY} + "),older(10)))");

    const XOnlyPubKey output_key{ParseHex(INTERNAL_KEY)};
    const std::string address{EncodeDestination(WitnessV1Taproot{output_key})};
    CheckNativeDescriptor("addr(" + address + ")");

    const CScript taproot_script{GetScriptForDestination(WitnessV1Taproot{output_key})};
    CheckNativeDescriptor("raw(" + HexStr(taproot_script) + ")");
    CheckNativeDescriptor("raw(6a0474657374)");
}

BOOST_AUTO_TEST_CASE(taproot_key_forms)
{
    CheckNativeDescriptor(
        "tr(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/0/*)",
        /*ranged=*/true);

    CheckNativeDescriptor(
        "tr(musig(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,"
        "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,"
        "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66))");
}

BOOST_AUTO_TEST_CASE(checksum_and_inference)
{
    const std::string descriptor{"tr(" + std::string{INTERNAL_KEY} + ")"};
    const std::string checksum{GetDescriptorChecksum(descriptor)};
    BOOST_REQUIRE_EQUAL(checksum.size(), 8U);

    FlatSigningProvider keys;
    std::string error;
    BOOST_CHECK_EQUAL(Parse(descriptor, keys, error, /*require_checksum=*/true).size(), 0U);
    BOOST_CHECK_EQUAL(error, "Missing checksum");
    BOOST_REQUIRE_EQUAL(Parse(descriptor + "#" + checksum, keys, error, /*require_checksum=*/true).size(), 1U);

    const XOnlyPubKey output_key{ParseHex(INTERNAL_KEY)};
    const CScript taproot_script{GetScriptForDestination(WitnessV1Taproot{output_key})};
    const auto inferred_taproot{InferDescriptor(taproot_script, keys)};
    BOOST_REQUIRE(inferred_taproot);
    BOOST_CHECK(inferred_taproot->ToString().starts_with("rawtr("));

    const auto inferred_data{InferDescriptor(CScript{} << OP_RETURN << std::vector<unsigned char>{'t', 'e', 's', 't'}, keys)};
    BOOST_REQUIRE(inferred_data);
    BOOST_CHECK(inferred_data->ToString().starts_with("raw("));
}

BOOST_AUTO_TEST_CASE(descriptor_literal_null_byte)
{
    FlatSigningProvider keys;
    std::string error;
    auto descriptors{Parse("tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)", keys, error)};
    BOOST_REQUIRE_MESSAGE(!descriptors.empty(), error);
}

BOOST_AUTO_TEST_CASE(descriptor_older_warnings)
{
    const auto parse_warnings = [](uint32_t value) {
        FlatSigningProvider keys;
        std::string error;
        const std::string descriptor{
            "tr(" + std::string{INTERNAL_KEY} + ",and_v(v:pk(" + std::string{LEAF_KEY} + "),older(" + util::ToString(value) + ")))"};
        auto descriptors{Parse(descriptor, keys, error)};
        BOOST_REQUIRE_MESSAGE(!descriptors.empty(), error);
        return descriptors[0]->Warnings();
    };

    BOOST_CHECK(parse_warnings(65535).empty());
    const auto height_warnings{parse_warnings(65536)};
    BOOST_REQUIRE_EQUAL(height_warnings.size(), 1U);
    BOOST_CHECK(height_warnings[0].find("height-based relative locktime") != std::string::npos);

    const auto time_warnings{parse_warnings(65536 | CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)};
    BOOST_REQUIRE_EQUAL(time_warnings.size(), 1U);
    BOOST_CHECK(time_warnings[0].find("time-based relative locktime") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
