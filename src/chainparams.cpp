// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/moneystr.h>
#include <util/strencodings.h>

#include <cassert>
#include <limits>
#include <stdexcept>

void ReadSigNetArgs(const ArgsManager& args, CChainParams::SigNetOptions& options)
{
    if (!args.GetArgs("-signetseednode").empty()) {
        options.seeds.emplace(args.GetArgs("-signetseednode"));
    }
    if (!args.GetArgs("-signetchallenge").empty()) {
        const auto signet_challenge = args.GetArgs("-signetchallenge");
        if (signet_challenge.size() != 1) {
            throw std::runtime_error("-signetchallenge cannot be multiple values.");
        }
        const auto val{TryParseHex<uint8_t>(signet_challenge[0])};
        if (!val) {
            throw std::runtime_error(strprintf("-signetchallenge must be hex, not '%s'.", signet_challenge[0]));
        }
        options.challenge.emplace(*val);
    }
}

void ReadRegTestArgs(const ArgsManager& args, CChainParams::RegTestOptions& options)
{
    if (auto value = args.GetBoolArg("-fastprune")) options.fastprune = *value;
    if (HasTestOption(args, "bip94")) options.enforce_bip94 = true;

    const bool has_activation{args.IsArgSet("-chainregistryactivationheight")};
    const bool has_burn{args.IsArgSet("-chainregistryminregistrationburn")};
    const bool has_max_operations{args.IsArgSet("-chainregistrymaxoperations")};
    if (!has_activation && !has_burn && !has_max_operations) return;
    if (!has_activation || !has_burn || !has_max_operations) {
        throw std::runtime_error("The regtest chain registry requires -chainregistryactivationheight, "
                                 "-chainregistryminregistrationburn, and -chainregistrymaxoperations together.");
    }

    const auto activation_height{args.GetIntArg("-chainregistryactivationheight")};
    if (!activation_height || *activation_height < 1 || *activation_height > std::numeric_limits<int>::max()) {
        throw std::runtime_error("-chainregistryactivationheight must be between 1 and INT_MAX.");
    }

    const auto minimum_burn{ParseMoney(*args.GetArg("-chainregistryminregistrationburn"))};
    if (!minimum_burn || *minimum_burn <= 0) {
        throw std::runtime_error("-chainregistryminregistrationburn must be a positive KNE amount.");
    }

    const auto maximum_operations{args.GetIntArg("-chainregistrymaxoperations")};
    if (!maximum_operations || *maximum_operations < 1 || *maximum_operations > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("-chainregistrymaxoperations must be between 1 and UINT32_MAX.");
    }

    options.chain_registry = Consensus::Params::ChainRegistryParams{
        .activation_height = static_cast<int>(*activation_height),
        .minimum_registration_burn = *minimum_burn,
        .maximum_operations = static_cast<uint32_t>(*maximum_operations),
    };
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain)
{
    switch (chain) {
    case ChainType::MAIN:
        return CChainParams::Main();
    case ChainType::TESTNET4:
        return CChainParams::TestNet4();
    case ChainType::SIGNET: {
        auto opts = CChainParams::SigNetOptions{};
        ReadSigNetArgs(args, opts);
        return CChainParams::SigNet(opts);
    }
    case ChainType::REGTEST: {
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        return CChainParams::RegTest(opts);
    }
    }
    assert(false);
}

void SelectParams(const ChainType chain)
{
    SelectBaseParams(chain);
    globalChainParams = CreateChainParams(gArgs, chain);
}
