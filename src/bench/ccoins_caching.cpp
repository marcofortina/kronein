// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <bench/bench.h>
#include <coins.h>
#include <consensus/amount.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <array>
#include <cassert>
#include <vector>

// Microbenchmark for simple accesses to a CCoinsViewCache database. Note from
// laanwj, "replicating the actual usage patterns of the client is hard though,
// many times micro-benchmarks of the database showed completely different
// characteristics than e.g. reindex timings. But that's not a requirement of
// every benchmark."
// (https://github.com/bitcoin/bitcoin/issues/7883#issuecomment-224807484)
static void CCoinsCaching(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};

    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    const std::array<CAmount, 4> values{11 * COIN, 50 * COIN, 21 * COIN, 22 * COIN};
    std::vector<CMutableTransaction> dummyTransactions(2);
    for (size_t i{0}; i < values.size(); ++i) {
        CKey key;
        key.MakeNewKey(/*fCompressed=*/true);
        dummyTransactions[i / 2].vout.emplace_back(
            values[i], GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{key.GetPubKey()}}));
    }
    AddCoins(coins, CTransaction{dummyTransactions[0]}, 0);
    AddCoins(coins, CTransaction{dummyTransactions[1]}, 0);

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t1.vin[0].prevout.n = 1;
    t1.vin[1].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[1].prevout.n = 0;
    t1.vin[2].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[2].prevout.n = 1;
    t1.vout.resize(2);
    t1.vout[0].nValue = 90 * COIN;
    t1.vout[0].scriptPubKey << OP_1;

    // Benchmark.
    const CTransaction tx_1(t1);
    bench.run([&] {
        bool success{AreInputsStandard(tx_1, coins)};
        assert(success);
    });
}

BENCHMARK(CCoinsCaching);
