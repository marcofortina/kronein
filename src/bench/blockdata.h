// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_BENCH_BLOCKDATA_H
#define BITCOIN_BENCH_BLOCKDATA_H

#include <cstddef>
#include <vector>

class CBlock;

namespace benchmark {

const CBlock& GetNativeBenchBlock();
const std::vector<std::byte>& GetNativeBenchBlockData();

} // namespace benchmark

#endif // BITCOIN_BENCH_BLOCKDATA_H
