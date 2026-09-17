// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/bip341_wallet_vectors.json.h>

#include <addresstype.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

using namespace util::hex_literals;

namespace {

TxoutType GetTxoutType(const CScript& output_script)
{
    std::vector<std::vector<uint8_t>> unused;
    return Solver(output_script, unused);
}

#define CHECK_SCRIPT_STATIC_SIZE(script, expected_size)                   \
    do {                                                                  \
        BOOST_CHECK_EQUAL((script).size(), (expected_size));              \
        BOOST_CHECK_EQUAL((script).capacity(), CScriptBase::STATIC_SIZE); \
        BOOST_CHECK_EQUAL((script).allocated_memory(), 0);                \
    } while (0)

} // namespace

BOOST_FIXTURE_TEST_SUITE(script_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(script_size_and_capacity)
{
    BOOST_CHECK_EQUAL(sizeof(CompressedScript), 40);
    BOOST_CHECK_EQUAL(sizeof(CScriptBase), 40);
    BOOST_CHECK_NE(sizeof(CScriptBase), sizeof(prevector<CScriptBase::STATIC_SIZE + 1, uint8_t>));
    BOOST_CHECK_EQUAL(sizeof(CScript), 40);
    BOOST_CHECK_EQUAL(sizeof(CTxOut), 48);

    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);

    const auto data_script{CScript{} << OP_RETURN << std::vector<uint8_t>(10, 0xaa)};
    BOOST_CHECK_EQUAL(GetTxoutType(data_script), TxoutType::NULL_DATA);
    CHECK_SCRIPT_STATIC_SIZE(data_script, 12);

    const auto taproot_script{GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{key.GetPubKey()}})};
    BOOST_CHECK_EQUAL(GetTxoutType(taproot_script), TxoutType::WITNESS_V1_TAPROOT);
    CHECK_SCRIPT_STATIC_SIZE(taproot_script, 34);
}

BOOST_AUTO_TEST_CASE(native_output_verification)
{
    ScriptError error;
    const CScript anchor{GetScriptForDestination(PayToAnchor{})};
    BOOST_CHECK(VerifyScript({}, anchor, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker{}, &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    const CScript nonempty_script_sig{CScript{} << OP_0};
    BOOST_CHECK(!VerifyScript(nonempty_script_sig, anchor, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker{}, &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_MALLEATED);

    const std::vector<CScript> unsupported{
        CScript{},
        CScript{} << OP_RETURN << std::vector<unsigned char>{0x01},
        CScript{} << std::vector<unsigned char>(33, 0x02) << OP_CHECKSIG, // P2PK
        CScript{} << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x01) << OP_EQUALVERIFY << OP_CHECKSIG, // P2PKH
        CScript{} << OP_HASH160 << std::vector<unsigned char>(20, 0x01) << OP_EQUAL, // P2SH
        CScript{} << OP_0 << std::vector<unsigned char>(20, 0x01), // P2WPKH
        CScript{} << OP_0 << std::vector<unsigned char>(32, 0x01), // P2WSH
        CScript{} << OP_1 << std::vector<unsigned char>(31, 0x01),
        CScript{} << OP_1 << std::vector<unsigned char>(33, 0x01),
        CScript{} << OP_2 << std::vector<unsigned char>(32, 0x01),
    };
    for (const CScript& script : unsupported) {
        BOOST_CHECK(!VerifyScript({}, script, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker{}, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
    }
}

BOOST_AUTO_TEST_CASE(sign_invalid_miniscript)
{
    FillableSigningProvider keystore;
    SignatureData sig_data;
    CMutableTransaction prev, curr;

    const auto invalid_pubkey{"173d36c8c9c9c9ffffffffffff0200000000021e1e37373721361818181818181e1e1e1e19000000000000000000b19292929292926b006c9b9b9292"_hex_u8};
    TaprootBuilder builder;
    builder.Add(0, {invalid_pubkey}, TAPROOT_LEAF_TAPSCRIPT);
    builder.Finalize(XOnlyPubKey::NUMS_H);
    prev.vout.emplace_back(0, GetScriptForDestination(builder.GetOutput()));
    curr.vin.emplace_back(COutPoint{prev.GetHash(), 0});
    sig_data.tr_spenddata = builder.GetSpendData();

    BOOST_CHECK(!SignSignature(keystore, CTransaction{prev}, curr, 0, SIGHASH_ALL, sig_data));
}

BOOST_AUTO_TEST_CASE(sign_pay_to_anchor)
{
    FillableSigningProvider keystore;
    SignatureData sig_data;
    CMutableTransaction prev, curr;
    prev.vout.emplace_back(0, GetScriptForDestination(PayToAnchor{}));
    curr.vin.emplace_back(COutPoint{prev.GetHash(), 0});

    BOOST_CHECK(SignSignature(keystore, CTransaction{prev}, curr, 0, SIGHASH_ALL, sig_data));
}

BOOST_AUTO_TEST_CASE(bip341_keypath_test_vectors)
{
    UniValue tests;
    tests.read(json_tests::bip341_wallet_vectors);

    for (const auto& vec : tests["keyPathSpending"].getValues()) {
        const auto tx_hex{ParseHex(vec["given"]["rawUnsignedTx"].get_str())};
        CMutableTransaction tx;
        SpanReader{tx_hex} >> TX_BASE(tx);

        std::vector<CTxOut> utxos;
        for (const auto& utxo_spent : vec["given"]["utxosSpent"].getValues()) {
            const auto script_bytes{ParseHex(utxo_spent["scriptPubKey"].get_str())};
            const CScript script{script_bytes.begin(), script_bytes.end()};
            utxos.emplace_back(utxo_spent["amountSats"].getInt<int>(), script);
        }

        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{utxos});

        BOOST_CHECK(txdata.m_bip341_taproot_ready);
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_amounts_single_hash), vec["intermediary"]["hashAmounts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_outputs_single_hash), vec["intermediary"]["hashOutputs"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_prevouts_single_hash), vec["intermediary"]["hashPrevouts"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_spent_scripts_single_hash), vec["intermediary"]["hashScriptPubkeys"].get_str());
        BOOST_CHECK_EQUAL(HexStr(txdata.m_sequences_single_hash), vec["intermediary"]["hashSequences"].get_str());

        for (const auto& input : vec["inputSpending"].getValues()) {
            const unsigned int input_index{input["given"]["txinIndex"].getInt<unsigned int>()};
            const int hash_type{input["given"]["hashType"].getInt<int>()};

            const auto private_key{ParseHex(input["given"]["internalPrivkey"].get_str())};
            CKey key;
            key.Set(private_key.begin(), private_key.end(), /*fCompressedIn=*/true);

            uint256 merkle_root;
            if (!input["given"]["merkleRoot"].isNull()) {
                merkle_root = uint256{ParseHex(input["given"]["merkleRoot"].get_str())};
            }

            XOnlyPubKey pubkey{key.GetPubKey()};
            BOOST_CHECK_EQUAL(HexStr(pubkey), input["intermediary"]["internalPubkey"].get_str());

            FlatSigningProvider provider;
            provider.keys[key.GetPubKey().GetID()] = key;
            MutableTransactionSignatureCreator creator{tx, input_index, &txdata, hash_type};
            std::vector<unsigned char> signature;
            BOOST_CHECK(creator.CreateSchnorrSig(provider, signature, pubkey, nullptr, &merkle_root, SigVersion::TAPROOT));
            BOOST_CHECK_EQUAL(HexStr(signature), input["expected"]["witness"][0].get_str());

            BOOST_CHECK_EQUAL(HexStr(pubkey.ComputeTapTweakHash(merkle_root.IsNull() ? nullptr : &merkle_root)), input["intermediary"]["tweak"].get_str());

            ScriptExecutionData execution_data;
            execution_data.m_annex_init = true;
            execution_data.m_annex_present = false;
            uint256 sighash;
            BOOST_CHECK(SignatureHashSchnorr(sighash, execution_data, tx, input_index, hash_type, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL));
            BOOST_CHECK_EQUAL(HexStr(sighash), input["intermediary"]["sigHash"].get_str());
            BOOST_CHECK_EQUAL(HexStr((HashWriter{HASHER_TAPSIGHASH} << std::span<const uint8_t>{ParseHex(input["intermediary"]["sigMsg"].get_str())}).GetSHA256()), input["intermediary"]["sigHash"].get_str());
        }
    }
}

BOOST_AUTO_TEST_CASE(taproot_hashes)
{
    constexpr uint256 hash1{"8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7"};
    constexpr uint256 hash2{"f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a"};
    constexpr uint256 branch{"a64c5b7b943315f9b805d7a7296bedfcfd08919270a1f7a1466e98f8693d8cd9"};
    BOOST_CHECK_EQUAL(ComputeTapbranchHash(hash1, hash2), branch);

    constexpr uint8_t script[6] = {'f', 'o', 'o', 'b', 'a', 'r'};
    constexpr uint256 leaf_c0{"edbc10c272a1215dcdcc11d605b9027b5ad6ed97cd45521203f136767b5b9c06"};
    constexpr uint256 leaf_c2{"8b5c4f90ae6bf76e259dbef5d8a59df06359c391b59263741b25eca76451b27a"};
    BOOST_CHECK_EQUAL(ComputeTapleafHash(0xc0, std::span{script}), leaf_c0);
    BOOST_CHECK_EQUAL(ComputeTapleafHash(0xc2, std::span{script}), leaf_c2);
}

BOOST_AUTO_TEST_SUITE_END()
