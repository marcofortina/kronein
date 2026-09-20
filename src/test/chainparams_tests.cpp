// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chain.h>
#include <chainparamsbase.h>
#include <kernel/coinstats.h>
#include <kernel/chainparams.h>
#include <node/context.h>
#include <pow.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <util/check.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <memory>
#include <ranges>
#include <set>
#include <string_view>
#include <vector>

BOOST_AUTO_TEST_SUITE(chainparams_tests)

BOOST_AUTO_TEST_CASE(network_identity)
{
    struct NetworkIdentity {
        std::unique_ptr<const CChainParams> params;
        std::string_view hrp;
        MessageStartChars message_start;
        uint16_t p2p_port;
        uint16_t rpc_port;
        ChainType chain_type;
        std::vector<unsigned char> secret_key_prefix;
        std::vector<unsigned char> ext_public_prefix;
        std::vector<unsigned char> ext_secret_prefix;
    };
    const std::array networks{
        NetworkIdentity{CChainParams::Main(), "kne", {0xa3, 0xcf, 0xcf, 0xf8}, 26762, 26761, ChainType::MAIN, {0xb4}, {0x01, 0x87, 0x6a, 0xbe}, {0x01, 0x87, 0x66, 0x84}},
        NetworkIdentity{CChainParams::TestNet4(), "tkne", {0xe9, 0x9d, 0x8b, 0xa2}, 36762, 36761, ChainType::TESTNET4, {0xf1}, {0x58, 0xff, 0xab, 0x38}, {0x58, 0xff, 0xa6, 0xfe}},
        NetworkIdentity{CChainParams::SigNet({}), "skne", {0x4c, 0x4a, 0x0e, 0xc6}, 46762, 46761, ChainType::SIGNET, {0xf2}, {0x58, 0xea, 0xe0, 0xa4}, {0x58, 0xea, 0xdc, 0x6a}},
        NetworkIdentity{CChainParams::RegTest({}), "rkne", {0xe0, 0xf9, 0xab, 0xb0}, 56762, 56761, ChainType::REGTEST, {0xf3}, {0x58, 0xd6, 0x16, 0x10}, {0x58, 0xd6, 0x11, 0xd6}},
    };

    std::set<MessageStartChars> message_starts;
    std::set<uint16_t> p2p_ports;
    std::set<uint16_t> rpc_ports;
    std::set<std::vector<unsigned char>> secret_key_prefixes;
    std::set<std::vector<unsigned char>> ext_public_prefixes;
    std::set<std::vector<unsigned char>> ext_secret_prefixes;
    for (const auto& network : networks) {
        const auto& params{network.params};
        const auto chain_type{network.chain_type};
        BOOST_CHECK_EQUAL(params->Bech32HRP(), network.hrp);
        BOOST_CHECK(params->MessageStart() == network.message_start);
        BOOST_CHECK_EQUAL(params->GetDefaultPort(), network.p2p_port);
        BOOST_CHECK_EQUAL(CreateBaseChainParams(chain_type)->RPCPort(), network.rpc_port);
        BOOST_CHECK(params->Base58Prefix(CChainParams::SECRET_KEY) == network.secret_key_prefix);
        BOOST_CHECK(params->Base58Prefix(CChainParams::EXT_PUBLIC_KEY) == network.ext_public_prefix);
        BOOST_CHECK(params->Base58Prefix(CChainParams::EXT_SECRET_KEY) == network.ext_secret_prefix);
        message_starts.insert(params->MessageStart());
        p2p_ports.insert(params->GetDefaultPort());
        rpc_ports.insert(network.rpc_port);
        secret_key_prefixes.insert(network.secret_key_prefix);
        ext_public_prefixes.insert(network.ext_public_prefix);
        ext_secret_prefixes.insert(network.ext_secret_prefix);
        BOOST_CHECK(
            params->GetConsensus().nMinimumChainWork ==
            ArithToUint256(GetBlockProof(params->GenesisBlock())));
        BOOST_CHECK(params->GetConsensus().defaultAssumeValid.IsNull());
        BOOST_CHECK(!params->GetConsensus().chain_registry.Enabled());
        BOOST_CHECK(!params->GetConsensus().chain_registry.IsActive(0));
    }
    BOOST_CHECK_EQUAL(message_starts.size(), networks.size());
    BOOST_CHECK_EQUAL(p2p_ports.size(), networks.size());
    BOOST_CHECK_EQUAL(rpc_ports.size(), networks.size());
    BOOST_CHECK_EQUAL(secret_key_prefixes.size(), networks.size());
    BOOST_CHECK_EQUAL(ext_public_prefixes.size(), networks.size());
    BOOST_CHECK_EQUAL(ext_secret_prefixes.size(), networks.size());

    for (const CChainParams* params : {networks[0].params.get(), networks[1].params.get()}) {
        BOOST_CHECK(params->DNSSeeds().empty());
        BOOST_CHECK(params->FixedSeeds().empty());
        BOOST_CHECK_EQUAL(params->AssumedBlockchainSize(), 0);
        BOOST_CHECK_EQUAL(params->AssumedChainStateSize(), 0);
        BOOST_CHECK_EQUAL(params->TxData().nTime, 0);
        BOOST_CHECK_EQUAL(params->TxData().tx_count, 0);
        BOOST_CHECK_EQUAL(params->TxData().dTxRate, 0);
    }
}

BOOST_AUTO_TEST_CASE(randomx_genesis_proofs)
{
    const std::array networks{
        std::pair{CChainParams::Main(), std::string_view{"mainnet"}},
        std::pair{CChainParams::TestNet4(), std::string_view{"testnet4"}},
        std::pair{CChainParams::SigNet({}), std::string_view{"signet"}},
        std::pair{CChainParams::RegTest({}), std::string_view{"regtest"}},
    };
    for (const auto& [params, name] : networks) {
        BOOST_TEST_CONTEXT(name) {
            BOOST_CHECK(CheckProofOfWork(params->GenesisBlock(), params->GetConsensus()));
            BOOST_CHECK_EQUAL(GetSerializeSize(static_cast<const CBlockHeader&>(params->GenesisBlock())), 80U);
        }
    }
}

BOOST_AUTO_TEST_CASE(randomx_seed_schedule)
{
    const auto params{CChainParams::Main()};
    const auto& consensus{params->GetConsensus()};
    BOOST_CHECK(!GetRandomXSeedHeight(63, consensus));
    BOOST_CHECK_EQUAL(*GetRandomXSeedHeight(64, consensus), 0);
    BOOST_CHECK_EQUAL(*GetRandomXSeedHeight(2111, consensus), 0);
    BOOST_CHECK_EQUAL(*GetRandomXSeedHeight(2112, consensus), 2048);

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    std::vector<uint256> hashes;
    chain.reserve(2113);
    hashes.reserve(2113);
    for (int height = 0; height <= 2112; ++height) {
        CBlockHeader header;
        header.nVersion = CBlockHeader::CURRENT_VERSION;
        header.nTime = height;
        header.nNonce = height;
        if (height != 0) header.hashPrevBlock = hashes.back();
        hashes.push_back(header.GetHash());
        chain.push_back(std::make_unique<CBlockIndex>(header));
        CBlockIndex& index{*chain.back()};
        index.nHeight = height;
        index.phashBlock = &hashes.back();
        index.pprev = height == 0 ? nullptr : chain[height - 1].get();
        index.BuildSkip();
    }

    const auto seed_64{GetRandomXSeed(chain[63].get(), 64, consensus)};
    BOOST_REQUIRE(seed_64);
    BOOST_CHECK(std::ranges::equal(*seed_64, std::span{hashes[0].begin(), hashes[0].size()}));
    const auto seed_2112{GetRandomXSeed(chain[2111].get(), 2112, consensus)};
    BOOST_REQUIRE(seed_2112);
    BOOST_CHECK(std::ranges::equal(*seed_2112, std::span{hashes[2048].begin(), hashes[2048].size()}));
}

BOOST_AUTO_TEST_CASE(assumeutxo_fuzz_snapshot)
{
    const auto params{CChainParams::RegTest({})};
    const auto chain{CreateBlockChain(2 * COINBASE_MATURITY, *params)};
    const auto setup{MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST, TestOpts{.setup_net = false})};
    const auto& node{setup->m_node};
    for (const auto& block : chain) ProcessBlock(node, block);

    LOCK(cs_main);
    auto& chainstate{node.chainman->ActiveChainstate()};
    chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
    const auto stats{*Assert(kernel::ComputeUTXOStats(
        kernel::CoinStatsHashType::MUHASH, &chainstate.CoinsDB(), node.chainman->m_blockman))};
    const auto expected{*Assert(params->AssumeutxoForHeight(2 * COINBASE_MATURITY))};

    BOOST_CHECK_EQUAL(stats.nHeight, expected.height);
    BOOST_CHECK_EQUAL(stats.nTransactions + 1, expected.m_chain_tx_count); // Include genesis.
    BOOST_CHECK_EQUAL(stats.hashBlock.ToString(), expected.blockhash.ToString());
    BOOST_CHECK_EQUAL(stats.muhash.ToString(), expected.muhash.ToString());
}

BOOST_AUTO_TEST_SUITE_END()
