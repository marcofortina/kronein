// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>
#include <crypto/common.h>
#include <crypto/randomx.h>

#include <array>
#include <cstdint>
#include <stdexcept>

namespace {

void RandomXHeaders(benchmark::Bench& bench, randomx_pow::Mode mode)
{
    // Public benchmark fixture, not a network seed or a proposed genesis.
    std::array<unsigned char, 32> seed{};
    seed[0] = 0x4b;
    auto hasher{randomx_pow::Hasher::Create(seed, mode)};
    if (!hasher) throw std::runtime_error("Cannot allocate RandomX benchmark context");
    std::array<unsigned char, 80> header{};
    uint32_t nonce{0};
    // Measure the exact wrapper used by the built-in miner, after cache/dataset
    // initialization. Hashing is single-VM: dataset construction threads do not
    // multiply the reported mining throughput.
    bench.batch(1).unit("hash").run([&] {
        WriteLE32(header.data() + 76, nonce++);
        const auto hash{hasher->HashData(header)};
        if (!hash) throw std::runtime_error("RandomX benchmark hashing failed");
        ankerl::nanobench::doNotOptimizeAway(*hash);
    });
}

void RandomXFull(benchmark::Bench& bench)
{
    RandomXHeaders(bench, randomx_pow::Mode::FULL);
}

void RandomXLight(benchmark::Bench& bench)
{
    RandomXHeaders(bench, randomx_pow::Mode::LIGHT);
}

} // namespace

BENCHMARK(RandomXFull);
BENCHMARK(RandomXLight);
