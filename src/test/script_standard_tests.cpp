// Copyright (c) 2017-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/bip341_wallet_vectors.json.h>

#include <addresstype.h>
#include <key.h>
#include <key_io.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

using namespace util::hex_literals;

BOOST_FIXTURE_TEST_SUITE(script_standard_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(dest_default_is_no_dest)
{
    CTxDestination dest;
    BOOST_CHECK(!IsValidDestination(dest));
}

BOOST_AUTO_TEST_CASE(script_standard_Solver)
{
    std::vector<std::vector<unsigned char>> solutions;

    const CScript taproot{CScript{} << OP_1 << ToByteVector(uint256::ZERO)};
    BOOST_CHECK_EQUAL(Solver(taproot, solutions), TxoutType::WITNESS_V1_TAPROOT);
    BOOST_REQUIRE_EQUAL(solutions.size(), 1U);
    BOOST_CHECK(solutions[0] == ToByteVector(uint256::ZERO));

    const CScript anchor{CScript{} << OP_1 << ANCHOR_BYTES};
    BOOST_CHECK_EQUAL(Solver(anchor, solutions), TxoutType::ANCHOR);
    BOOST_CHECK(solutions.empty());

    const CScript data{CScript{} << OP_RETURN << std::vector<unsigned char>{0x01, 0x02}};
    BOOST_CHECK_EQUAL(Solver(data, solutions), TxoutType::NULL_DATA);
    BOOST_CHECK(solutions.empty());

    const std::vector<CScript> unsupported{
        CScript{},
        CScript{} << OP_TRUE,
        CScript{} << OP_1 << std::vector<unsigned char>(31, 0x01),
        CScript{} << OP_1 << std::vector<unsigned char>(33, 0x01),
        CScript{} << OP_2 << std::vector<unsigned char>(32, 0x01),
        CScript{} << OP_9 << OP_ADD << OP_11 << OP_EQUAL,
    };
    for (const CScript& script : unsupported) {
        BOOST_CHECK_EQUAL(Solver(script, solutions), TxoutType::NONSTANDARD);
        BOOST_CHECK(solutions.empty());
    }
}

BOOST_AUTO_TEST_CASE(script_standard_ExtractDestination)
{
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();

    CScript s;
    CTxDestination address;
    const auto check_unsupported = [&](const CScript& script) {
        BOOST_CHECK(!ExtractDestination(script, address));
        BOOST_REQUIRE(std::holds_alternative<CNoDestination>(address));
        BOOST_CHECK(std::get<CNoDestination>(address).GetScript() == script);
    };

    // OP_RETURN has no destination.
    s.clear();
    s << OP_RETURN << std::vector<unsigned char>({75});
    check_unsupported(s);

    // An arbitrary script has no destination.
    s.clear();
    s << OP_TRUE;
    check_unsupported(s);

    // P2TR is the native spendable destination.
    s.clear();
    auto xpk = XOnlyPubKey(pubkey);
    s << OP_1 << ToByteVector(xpk);
    BOOST_CHECK(ExtractDestination(s, address));
    BOOST_CHECK(std::get<WitnessV1Taproot>(address) == WitnessV1Taproot(xpk));

    // P2A remains a native destination.
    s.clear();
    s << OP_1 << ANCHOR_BYTES;
    BOOST_CHECK(ExtractDestination(s, address));
    BOOST_CHECK(std::get<PayToAnchor>(address) == PayToAnchor());

    // Undefined witness programs are unsupported.
    // Version 1 with an undefined program size (33 bytes in this test case).
    s.clear();
    s << OP_1 << ToByteVector(pubkey);
    check_unsupported(s);
    s.clear();
    // Witness versions 2+ are not part of the transaction model.
    s << OP_2 << ToByteVector(xpk);
    check_unsupported(s);
}

BOOST_AUTO_TEST_CASE(script_standard_GetScriptFor_)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey{key.GetPubKey()};

    CScript expected, result;

    // CNoDestination
    expected << OP_RETURN << std::vector<unsigned char>{0x01, 0x02};
    result = GetScriptForDestination(CNoDestination{expected});
    BOOST_CHECK(result == expected);

    // WitnessV1Taproot
    auto xpk = XOnlyPubKey(pubkey);
    expected.clear();
    expected << OP_1 << ToByteVector(xpk);
    result = GetScriptForDestination(WitnessV1Taproot(xpk));
    BOOST_CHECK(result == expected);

    // PayToAnchor
    expected.clear();
    expected << OP_1 << ANCHOR_BYTES;
    result = GetScriptForDestination(PayToAnchor());
    BOOST_CHECK(result == expected);
}

BOOST_AUTO_TEST_CASE(script_standard_taproot_builder)
{
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({}), true);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0}), true);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,1}), true);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,0,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,0,1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,0,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,1,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,1,1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,1,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,2,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,2,1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({0,2,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,0,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,0,1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,0,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,1,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,1,1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,1,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,2,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,2,1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({1,2,2}), true);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,0,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,0,1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,0,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,1,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,1,1}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,1,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,2,0}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,2,1}), true);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,2,2}), false);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({2,2,2,3,4,5,6,7,8,9,10,11,12,14,14,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,31,31,31,31,31,31,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,128}), true);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({128,128,127,126,125,124,123,122,121,120,119,118,117,116,115,114,113,112,111,110,109,108,107,106,105,104,103,102,101,100,99,98,97,96,95,94,93,92,91,90,89,88,87,86,85,84,83,82,81,80,79,78,77,76,75,74,73,72,71,70,69,68,67,66,65,64,63,62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1}), true);
    BOOST_CHECK_EQUAL(TaprootBuilder::ValidDepths({129,129,128,127,126,125,124,123,122,121,120,119,118,117,116,115,114,113,112,111,110,109,108,107,106,105,104,103,102,101,100,99,98,97,96,95,94,93,92,91,90,89,88,87,86,85,84,83,82,81,80,79,78,77,76,75,74,73,72,71,70,69,68,67,66,65,64,63,62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1}), false);

    XOnlyPubKey key_inner{"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"_hex_u8};
    XOnlyPubKey key_1{"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"_hex_u8};
    XOnlyPubKey key_2{"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"_hex_u8};
    CScript script_1 = CScript() << ToByteVector(key_1) << OP_CHECKSIG;
    CScript script_2 = CScript() << ToByteVector(key_2) << OP_CHECKSIG;
    constexpr uint256 hash_3{"31fe7061656bea2a36aa60a2f7ef940578049273746935d296426dc0afd86b68"};

    TaprootBuilder builder;
    BOOST_CHECK(builder.IsValid() && builder.IsComplete());
    builder.Add(2, script_2, 0xc0);
    BOOST_CHECK(builder.IsValid() && !builder.IsComplete());
    builder.AddOmitted(2, hash_3);
    BOOST_CHECK(builder.IsValid() && !builder.IsComplete());
    builder.Add(1, script_1, 0xc0);
    BOOST_CHECK(builder.IsValid() && builder.IsComplete());
    builder.Finalize(key_inner);
    BOOST_CHECK(builder.IsValid() && builder.IsComplete());
    BOOST_CHECK_EQUAL(EncodeDestination(builder.GetOutput()), "kne1pj6gaw944fy0xpmzzu45ugqde4rz7mqj5kj0tg8kmr5f0pjq8vnaq8xa59f");
}

BOOST_AUTO_TEST_CASE(bip341_spk_test_vectors)
{
    using control_set = decltype(TaprootSpendData::scripts)::mapped_type;

    UniValue tests;
    tests.read(json_tests::bip341_wallet_vectors);

    const auto& vectors = tests["scriptPubKey"];

    for (const auto& vec : vectors.getValues()) {
        TaprootBuilder spktest;
        std::map<std::pair<std::vector<unsigned char>, int>, int> scriptposes;
        std::function<void (const UniValue&, int)> parse_tree = [&](const UniValue& node, int depth) {
            if (node.isNull()) return;
            if (node.isObject()) {
                auto script = ParseHex(node["script"].get_str());
                int idx = node["id"].getInt<int>();
                int leaf_version = node["leafVersion"].getInt<int>();
                scriptposes[{script, leaf_version}] = idx;
                spktest.Add(depth, script, leaf_version);
            } else {
                parse_tree(node[0], depth + 1);
                parse_tree(node[1], depth + 1);
            }
        };
        parse_tree(vec["given"]["scriptTree"], 0);
        spktest.Finalize(XOnlyPubKey(ParseHex(vec["given"]["internalPubkey"].get_str())));
        BOOST_CHECK_EQUAL(HexStr(GetScriptForDestination(spktest.GetOutput())), vec["expected"]["scriptPubKey"].get_str());
        BOOST_CHECK_EQUAL(EncodeDestination(spktest.GetOutput()), vec["expected"]["kroneinAddress"].get_str());
        auto spend_data = spktest.GetSpendData();
        BOOST_CHECK_EQUAL(vec["intermediary"]["merkleRoot"].isNull(), spend_data.merkle_root.IsNull());
        if (!spend_data.merkle_root.IsNull()) {
            BOOST_CHECK_EQUAL(vec["intermediary"]["merkleRoot"].get_str(), HexStr(spend_data.merkle_root));
        }
        BOOST_CHECK_EQUAL(spend_data.scripts.size(), scriptposes.size());
        for (const auto& scriptpos : scriptposes) {
            BOOST_CHECK(spend_data.scripts[scriptpos.first] == control_set{ParseHex(vec["expected"]["scriptPathControlBlocks"][scriptpos.second].get_str())});
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
