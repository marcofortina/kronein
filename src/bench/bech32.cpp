// Copyright (c) 2018-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bech32.h>
#include <bench/bench.h>
#include <util/strencodings.h>

#include <vector>

using namespace util::hex_literals;

static void Bech32mEncode(benchmark::Bench& bench)
{
    constexpr std::array<uint8_t, 32> v{"c97f5a67ec381b760aeaf67573bc164845ff39a3bb26a1cee401ac67243b48db"_hex_u8};
    std::vector<unsigned char> tmp = {1};
    tmp.reserve(1 + v.size() * 8 / 5);
    ConvertBits<8, 5, true>([&](unsigned char c) { tmp.push_back(c); }, v.begin(), v.end());
    bench.batch(v.size()).unit("byte").run([&] {
        bech32::Encode("kne", tmp);
    });
}


static void Bech32mDecode(benchmark::Bench& bench)
{
    std::string addr = "kne1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqd564ll";
    bench.batch(addr.size()).unit("byte").run([&] {
        bech32::Decode(addr);
    });
}


BENCHMARK(Bech32mEncode);
BENCHMARK(Bech32mDecode);
