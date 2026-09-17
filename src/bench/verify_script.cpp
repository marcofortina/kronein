// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <bench/bench.h>
#include <coins.h>
#include <key.h>
#include <primitives/transaction.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <span.h>
#include <test/util/transaction_utils.h>
#include <uint256.h>
#include <util/translation.h>

#include <cassert>
#include <cstdint>
#include <map>
#include <vector>

// Microbenchmark for verification of a Taproot key-path spend.
static void VerifyScriptBench(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};

    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const CPubKey pubkey{key.GetPubKey()};
    FlatSigningProvider provider;
    provider.keys.emplace(pubkey.GetID(), key);
    provider.pubkeys.emplace(pubkey.GetID(), pubkey);

    const CScript script_pub_key{GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{pubkey}})};
    const CMutableTransaction tx_credit{BuildCreditingTransaction(script_pub_key, 1)};
    CMutableTransaction tx_spend{BuildSpendingTransaction({}, {}, CTransaction{tx_credit})};

    std::map<COutPoint, Coin> coins;
    coins.emplace(tx_spend.vin[0].prevout, Coin{tx_credit.vout[0], /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
    std::map<int, bilingual_str> input_errors;
    assert(SignTransaction(tx_spend, &provider, coins, SIGHASH_ALL, input_errors));

    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, std::vector<CTxOut>{tx_credit.vout[0]});
    const MutableTransactionSignatureChecker checker{&tx_spend, 0, txdata, MissingDataBehavior::ASSERT_FAIL};

    // Benchmark.
    bench.run([&] {
        ScriptError err;
        bool success = VerifyScript(
            tx_spend.vin[0].scriptSig,
            tx_credit.vout[0].scriptPubKey,
            &tx_spend.vin[0].scriptWitness,
            STANDARD_SCRIPT_VERIFY_FLAGS,
            checker,
            &err);
        assert(err == SCRIPT_ERR_OK);
        assert(success);
    });
}

static void VerifyNestedIfScript(benchmark::Bench& bench)
{
    std::vector<std::vector<unsigned char>> stack;
    CScript script;
    for (int i = 0; i < 100; ++i) {
        script << OP_1 << OP_IF;
    }
    for (int i = 0; i < 1000; ++i) {
        script << OP_1;
    }
    for (int i = 0; i < 100; ++i) {
        script << OP_ENDIF;
    }
    bench.run([&] {
        auto stack_copy = stack;
        ScriptError error;
        bool ret = EvalScript(stack_copy, script, 0, BaseSignatureChecker(), SigVersion::TAPSCRIPT, &error);
        assert(ret);
    });
}

BENCHMARK(VerifyScriptBench);
BENCHMARK(VerifyNestedIfScript);
