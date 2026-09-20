// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/blockdata.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/merkle.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <cstdint>
#include <utility>
#include <vector>

namespace benchmark {
namespace {

constexpr uint32_t BENCH_TX_COUNT{10'500};

CScript NativeOutputScript()
{
    return CScript{} << OP_1 << std::vector<unsigned char>(32);
}

CBlock CreateNativeBenchBlock()
{
    CBlock block;
    block.nVersion = CBlockHeader::CURRENT_VERSION;
    block.hashPrevBlock = uint256::ONE;

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{}, CScript{} << OP_0 << OP_0);
    coinbase.vout.emplace_back(0, NativeOutputScript());
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));

    for (uint32_t index{1}; index <= BENCH_TX_COUNT; ++index) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), index});
        tx.vout.emplace_back(0, NativeOutputScript());
        tx.nLockTime = index;
        block.vtx.push_back(MakeTransactionRef(std::move(tx)));
    }

    block.hashMerkleRoot = BlockMerkleRoot(block);

    ArgsManager args;
    const auto params{CreateChainParams(args, ChainType::REGTEST)};
    block.nTime = params->GenesisBlock().nTime + 1;
    block.nBits = params->GenesisBlock().nBits;
    uint64_t max_tries{std::numeric_limits<uint32_t>::max()};
    CHECK_NONFATAL(MineProofOfWork(block, params->GetConsensus(), max_tries));

    return block;
}

} // namespace

const CBlock& GetNativeBenchBlock()
{
    static const CBlock block{CreateNativeBenchBlock()};
    return block;
}

const std::vector<std::byte>& GetNativeBenchBlockData()
{
    static const std::vector<std::byte> data{[] {
        DataStream stream;
        stream << TX_WITH_WITNESS(GetNativeBenchBlock());
        return std::vector<std::byte>{stream.begin(), stream.end()};
    }()};
    return data;
}

} // namespace benchmark
