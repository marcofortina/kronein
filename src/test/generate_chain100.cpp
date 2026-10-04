// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Explicitly regenerate src/test/data/regtest_chain100.json on standard output.
#include <addresstype.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <pubkey.h>
#include <script/solver.h>
#include <streams.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <validation.h>

#include <exception>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

const std::function<void(const std::string&)> G_TEST_LOG_FUN{};
const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS{};
const std::function<std::string()> G_TEST_GET_FULL_NAME{};

int main()
{
    try {
        if (EnableFuzzDeterminism()) {
            std::cerr << "Fixture generation requires a non-fuzz build with real RandomX proofs\n";
            return 1;
        }
        UniValue result{UniValue::VOBJ};
        result.pushKV("format_version", 1);
        result.pushKV("network", "regtest");
        for (const bool registry_active : {true, false}) {
            TestOpts opts;
            opts.setup_net = false;
            if (!registry_active) {
                opts.extra_args = {
                    "-chainregistryactivationheight=101",
                    "-chaindealerauthoritykey=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    "-chainregistrymaxoperations=4",
                };
            }
            TestChain100Setup setup{ChainType::REGTEST, opts, TestChain100Setup::BlockSource::MINE};
            if (registry_active) {
                const auto& consensus{Params().GetConsensus()};
                result.pushKV("genesis_hash", consensus.hashGenesisBlock.GetHex());
                result.pushKV("randomx_seed", HexStr(consensus.randomx.bootstrap_key));
                result.pushKV("coinbase_script", HexStr(GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{setup.coinbaseKey.GetPubKey()}})));
            }
            UniValue profile{UniValue::VOBJ};
            UniValue blocks{UniValue::VARR};
            auto& chainman{*Assert(setup.m_node.chainman)};
            LOCK(cs_main);
            Assert(chainman.ActiveHeight() == COINBASE_MATURITY);
            for (int height{1}; height <= COINBASE_MATURITY; ++height) {
                CBlock block;
                Assert(chainman.m_blockman.ReadBlock(block, *chainman.ActiveChain()[height]));
                DataStream stream;
                stream << TX_WITH_WITNESS(block);
                blocks.push_back(HexStr(stream));
            }
            profile.pushKV("tip_hash", chainman.ActiveChain().Tip()->GetBlockHash().GetHex());
            profile.pushKV("blocks", std::move(blocks));
            result.pushKV(registry_active ? "registry_active" : "registry_inactive", std::move(profile));
        }
        std::cout << result.write(2) << '\n';
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fixture generation failed: " << e.what() << '\n';
        return 1;
    }
}
