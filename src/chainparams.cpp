// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <pubkey.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/moneystr.h>
#include <util/strencodings.h>

#include <algorithm>
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
    const bool has_authority{args.IsArgSet("-chaindealerauthoritykey")};
    const bool has_max_operations{args.IsArgSet("-chainregistrymaxoperations")};
    const bool has_deposit_activation{args.IsArgSet("-chaindepositactivationheight")};
    const bool has_deposit_minimum{args.IsArgSet("-chaindepositminimumamount")};
    const bool has_max_deposits{args.IsArgSet("-chaindepositmaxperblock")};
    const bool has_bmm_activation{args.IsArgSet("-chainbmmactivationheight")};
    const bool has_max_bmm_anchors{args.IsArgSet("-chainbmmmaxanchorsperblock")};
    const bool has_registry_options{has_activation || has_authority || has_max_operations || args.IsArgSet("-chaindealerauthoritythreshold")};
    const bool has_deposit_options{has_deposit_activation || has_deposit_minimum || has_max_deposits};
    const bool has_bmm_options{has_bmm_activation || has_max_bmm_anchors};
    if (!has_registry_options && !has_deposit_options && !has_bmm_options) return;
    if (!has_activation || !has_authority || !has_max_operations) {
        throw std::runtime_error("The regtest chain registry requires -chainregistryactivationheight, "
                                 "-chaindealerauthoritykey, and -chainregistrymaxoperations together.");
    }
    if (has_deposit_options && (!has_deposit_activation || !has_deposit_minimum || !has_max_deposits)) {
        throw std::runtime_error("Regtest child-chain deposits require -chaindepositactivationheight, "
                                 "-chaindepositminimumamount, and -chaindepositmaxperblock together.");
    }
    if (has_bmm_options && (!has_bmm_activation || !has_max_bmm_anchors)) {
        throw std::runtime_error("Regtest BMM anchors require -chainbmmactivationheight and "
                                 "-chainbmmmaxanchorsperblock together.");
    }

    const auto activation_height{args.GetIntArg("-chainregistryactivationheight")};
    if (!activation_height || *activation_height < 1 || *activation_height > std::numeric_limits<int>::max()) {
        throw std::runtime_error("-chainregistryactivationheight must be between 1 and INT_MAX.");
    }

    chainregistry::DealerAuthority authority;
    const auto authority_keys{args.GetArgs("-chaindealerauthoritykey")};
    if (authority_keys.size() > chainregistry::MAX_DEALER_AUTHORITY_KEYS) {
        throw std::runtime_error("At most five -chaindealerauthoritykey values are allowed.");
    }
    const auto threshold{args.GetIntArg("-chaindealerauthoritythreshold")};
    if ((!threshold && authority_keys.size() != 1) ||
        (threshold && (*threshold < 1 || *threshold > static_cast<int64_t>(authority_keys.size())))) {
        throw std::runtime_error("-chaindealerauthoritythreshold must be between 1 and the number of authority keys (required for multiple keys).");
    }
    authority.threshold = static_cast<uint8_t>(threshold.value_or(1));
    for (const auto& value : authority_keys) {
        const auto key{TryParseHex<uint8_t>(value)};
        if (!key || key->size() != 32 || !XOnlyPubKey{*key}.IsFullyValid()) {
            throw std::runtime_error("-chaindealerauthoritykey must be a valid 32-byte x-only public key.");
        }
        std::copy(key->begin(), key->end(), authority.keys.emplace_back().begin());
    }
    if (!authority.IsValid()) {
        throw std::runtime_error("Dealer authority keys must be distinct and in increasing hexadecimal order.");
    }

    const auto maximum_operations{args.GetIntArg("-chainregistrymaxoperations")};
    if (!maximum_operations || *maximum_operations < 1 || *maximum_operations > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("-chainregistrymaxoperations must be between 1 and UINT32_MAX.");
    }

    Consensus::Params::ChainRegistryParams registry{
        .activation_height = static_cast<int>(*activation_height),
        .dealer_authority = std::move(authority),
        .maximum_operations = static_cast<uint32_t>(*maximum_operations),
    };

    if (has_deposit_options) {
        const auto deposit_activation_height{args.GetIntArg("-chaindepositactivationheight")};
        if (!deposit_activation_height || *deposit_activation_height < *activation_height ||
            *deposit_activation_height > std::numeric_limits<int>::max()) {
            throw std::runtime_error("-chaindepositactivationheight must be between the chain registry "
                                     "activation height and INT_MAX.");
        }

        const auto minimum_deposit{ParseMoney(*args.GetArg("-chaindepositminimumamount"))};
        if (!minimum_deposit || *minimum_deposit <= 0) {
            throw std::runtime_error("-chaindepositminimumamount must be a positive KNE amount.");
        }

        const auto maximum_deposits{args.GetIntArg("-chaindepositmaxperblock")};
        if (!maximum_deposits || *maximum_deposits < 1 ||
            *maximum_deposits > std::numeric_limits<uint32_t>::max()) {
            throw std::runtime_error("-chaindepositmaxperblock must be between 1 and UINT32_MAX.");
        }

        registry.deposit_activation_height = static_cast<int>(*deposit_activation_height);
        registry.minimum_deposit_amount = *minimum_deposit;
        registry.maximum_deposits = static_cast<uint32_t>(*maximum_deposits);
    }
    if (has_bmm_options) {
        const auto bmm_activation_height{args.GetIntArg("-chainbmmactivationheight")};
        if (!bmm_activation_height || *bmm_activation_height < *activation_height ||
            *bmm_activation_height > std::numeric_limits<int>::max()) {
            throw std::runtime_error("-chainbmmactivationheight must be between the chain registry "
                                     "activation height and INT_MAX.");
        }
        const auto maximum_bmm_anchors{args.GetIntArg("-chainbmmmaxanchorsperblock")};
        if (!maximum_bmm_anchors || *maximum_bmm_anchors < 1 ||
            *maximum_bmm_anchors > std::numeric_limits<uint32_t>::max()) {
            throw std::runtime_error("-chainbmmmaxanchorsperblock must be between 1 and UINT32_MAX.");
        }
        registry.bmm_activation_height = static_cast<int>(*bmm_activation_height);
        registry.maximum_bmm_anchors = static_cast<uint32_t>(*maximum_bmm_anchors);
    }
    options.chain_registry = registry;
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
