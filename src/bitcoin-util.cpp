// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <core_io.h>
#include <consensus/consensus.h>
#include <kernel/genesis.h>
#include <pow.h>
#include <primitives/chainregistry.h>
#include <streams.h>
#include <univalue.h>
#include <util/exception.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>

static const int CONTINUE_EXECUTION=-1;

const TranslateFn G_TRANSLATION_FUN{nullptr};

static void SetupBitcoinUtilArgs(ArgsManager &argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    argsman.AddCommand("grind", "Perform RandomX v2 proof of work on hex header string");
    argsman.AddCommand("verify", "Verify RandomX proof of work without changing the supplied header");
    argsman.AddCommand("genesisinfo", "Export current network parameters for an offline genesis ceremony");
    argsman.AddCommand("genesis", "Construct a genesis candidate: <timestamp-hex> <time> <bits-hex> <nonce>");
    argsman.AddArg("-randomxlight", "Use RandomX light mode (256 MiB cache) instead of the full mining dataset", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    SetupChainParamsBaseOptions(argsman);
}

// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
static int AppInitUtil(ArgsManager& args, int argc, char* argv[])
{
    SetupBitcoinUtilArgs(args);
    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    if (HelpRequested(args) || args.GetBoolArg("-version", false)) {
        // First part of help message is specific to this utility
        std::string strUsage = CLIENT_NAME " kronein-util utility version " + FormatFullVersion() + "\n";

        if (args.GetBoolArg("-version", false)) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "The kronein-util tool provides Kronein-related functionality that does not rely on the ability to access a running node. Available [commands] are listed below.\n"
                "\n"
                "Usage:  kronein-util [options] [command]\n"
                "or:     kronein-util [options] grind <hex-block-header> [<randomx-seed>]\n"
                "or:     kronein-util [options] grind -  # read header [seed] requests from stdin\n"
                "or:     kronein-util [options] verify <hex-block-header> [<randomx-seed>]\n"
                "or:     kronein-util [options] genesisinfo\n"
                "or:     kronein-util [options] genesis <timestamp-hex> <time> <bits-hex> <nonce>\n";
            strUsage += "\n" + args.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);

        if (argc < 2) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // Check for chain settings (Params() calls are only valid after this clause)
    try {
        SelectParams(args.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return CONTINUE_EXECUTION;
}

static int GrindOne(const std::vector<std::string>& args, std::string& strPrint, bool verify_only = false)
{
    if (args.empty() || args.size() > 2) {
        strPrint = "Must specify a block header and, optionally, its 32-byte RandomX seed";
        return EXIT_FAILURE;
    }

    RandomXSeed seed{Params().GetConsensus().randomx.bootstrap_key};
    if (args.size() == 2) {
        if (!IsHex(args[1]) || args[1].size() != seed.size() * 2) {
            strPrint = "RandomX seed must be exactly 32 bytes encoded as hexadecimal";
            return EXIT_FAILURE;
        }
        const auto parsed_seed{ParseHex(args[1])};
        std::copy(parsed_seed.begin(), parsed_seed.end(), seed.begin());
    }

    CBlockHeader header;
    if ((verify_only && args[0].size() != 160) || !DecodeHexBlockHeader(header, args[0])) {
        strPrint = "Could not decode block header";
        return EXIT_FAILURE;
    }

    if (verify_only) {
        if (!CheckProofOfWork(header, seed, Params().GetConsensus())) {
            strPrint = "Invalid RandomX proof of work";
            return EXIT_FAILURE;
        }
        strPrint = args[0];
        return EXIT_SUCCESS;
    }

    uint64_t max_tries{static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1};
    if (!MineProofOfWork(header, seed, Params().GetConsensus(), max_tries, /*threads=*/0, /*use_full_memory=*/!gArgs.GetBoolArg("-randomxlight", false))) {
        strPrint = "Could not satisfy difficulty target";
        return EXIT_FAILURE;
    }

    DataStream ss{};
    ss << header;
    strPrint = HexStr(ss);
    return EXIT_SUCCESS;
}

static int Grind(const std::vector<std::string>& args, std::string& strPrint)
{
    if (args.size() != 1 || args[0] != "-") return GrindOne(args, strPrint);

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream request{line};
        std::vector<std::string> request_args;
        for (std::string arg; request >> arg;) request_args.push_back(std::move(arg));
        if (request_args.empty()) continue;

        std::string result;
        const int ret{GrindOne(request_args, result)};
        if (ret != EXIT_SUCCESS) {
            strPrint = std::move(result);
            return ret;
        }
        std::cout << result << '\n';
    }
    strPrint.clear();
    return EXIT_SUCCESS;
}

static UniValue GenesisInfo()
{
    const auto& params{Params()};
    const auto& c{params.GetConsensus()};
    const auto& r{c.chain_registry};
    UniValue info{UniValue::VOBJ};
    info.pushKV("network", ChainTypeToString(gArgs.GetChainType()));
    info.pushKV("development_only", true);
    info.pushKV("currency", "KNE");
    info.pushKV("atomic_unit", "KNE atomic unit");
    info.pushKV("atomic_units_per_coin", COIN);
    info.pushKV("maximum_money", MAX_MONEY);
    info.pushKV("initial_subsidy", params.GenesisBlock().vtx[0]->vout[0].nValue);
    info.pushKV("halving_interval", c.nSubsidyHalvingInterval);
    info.pushKV("coinbase_maturity", COINBASE_MATURITY);
    info.pushKV("maximum_block_weight", MAX_BLOCK_WEIGHT);
    info.pushKV("target_spacing", c.nPowTargetSpacing);
    info.pushKV("pow_limit", c.powLimit.GetHex());
    info.pushKV("initial_bits", strprintf("%08x", params.GenesisBlock().nBits));
    info.pushKV("pow", "RandomX-2.0.1");
    info.pushKV("randomx_bootstrap_seed", HexStr(c.randomx.bootstrap_key));
    info.pushKV("randomx_epoch", c.randomx.epoch_blocks);
    info.pushKV("randomx_lag", c.randomx.epoch_lag);
    info.pushKV("randomx_fixed_seed", c.randomx.fixed_seed);
    info.pushKV("asert", c.asert.enabled);
    info.pushKV("asert_half_life", c.asert.half_life);
    info.pushKV("minimum_difficulty", c.fPowAllowMinDifficultyBlocks);
    info.pushKV("no_retargeting", c.fPowNoRetargeting);
    info.pushKV("bip94", c.enforce_BIP94);
    info.pushKV("monotonic_timestamps", c.enforce_timestamp_monotonicity);
    info.pushKV("registry_activation", r.activation_height);
    info.pushKV("registry_maximum_operations", r.maximum_operations);
    info.pushKV("deposit_activation", r.deposit_activation_height);
    info.pushKV("minimum_deposit", r.minimum_deposit_amount);
    info.pushKV("maximum_deposits", r.maximum_deposits);
    info.pushKV("bmm_activation", r.bmm_activation_height);
    info.pushKV("maximum_bmm_anchors", r.maximum_bmm_anchors);
    info.pushKV("dealer_initial_licenses", chainregistry::DEALER_INITIAL_LICENSES);
    info.pushKV("dealer_max_added_licenses", chainregistry::DEALER_MAX_ADDED_LICENSES);
    info.pushKV("authority_rotation_delay", chainregistry::DEALER_AUTHORITY_ROTATION_DELAY);
    info.pushKV("authority_threshold", r.dealer_authority.threshold);
    UniValue keys{UniValue::VARR};
    for (const auto& key : r.dealer_authority.keys) keys.push_back(HexStr(key));
    info.pushKV("authority_keys", std::move(keys));
    info.pushKV("signet_challenge", HexStr(c.signet_challenge));
    info.pushKV("hrp", params.Bech32HRP());
    info.pushKV("p2p_port", params.GetDefaultPort());
    info.pushKV("rpc_port", BaseParams().RPCPort());
    info.pushKV("onion_port", params.GetDefaultPort() + 1);
    info.pushKV("message_start", HexStr(params.MessageStart()));
    info.pushKV("wif", HexStr(params.Base58Prefix(CChainParams::SECRET_KEY)));
    info.pushKV("extended_public", HexStr(params.Base58Prefix(CChainParams::EXT_PUBLIC_KEY)));
    info.pushKV("extended_private", HexStr(params.Base58Prefix(CChainParams::EXT_SECRET_KEY)));
    info.pushKV("genesis_output_script", HexStr(params.GenesisBlock().vtx[0]->vout[0].scriptPubKey));
    return info;
}

static int Genesis(const std::vector<std::string>& args, std::string& result)
{
    if (args.size() != 4) throw std::runtime_error{"Expected timestamp-hex, time, bits-hex and nonce"};
    const auto timestamp{TryParseHex<unsigned char>(args[0])};
    const auto time{ToIntegral<uint32_t>(args[1])};
    const auto bits{ToIntegral<uint32_t>(args[2], 16)};
    const auto nonce{ToIntegral<uint32_t>(args[3])};
    if (!timestamp || timestamp->empty() || timestamp->size() > 90 || !time || !bits || !nonce) {
        throw std::runtime_error{"Invalid genesis fields"};
    }
    const auto& params{Params()};
    const auto& output{params.GenesisBlock().vtx[0]->vout[0]};
    const auto block{CreateGenesisBlock(
        {reinterpret_cast<const char*>(timestamp->data()), timestamp->size()},
        output.scriptPubKey, *time, *nonce, *bits, 1, output.nValue)};
    if (block.vtx[0]->vin[0].scriptSig.size() > 100 || !output.scriptPubKey.IsUnspendable()) {
        throw std::runtime_error{"Genesis must have a bounded coinbase and an unspendable output"};
    }
    bool negative, overflow;
    arith_uint256 target;
    target.SetCompact(*bits, &negative, &overflow);
    if (negative || overflow || target == 0 || target > UintToArith256(params.GetConsensus().powLimit) ||
        target.GetCompact() != *bits) throw std::runtime_error{"Genesis target must be canonical and within powLimit"};
    DataStream header, encoded;
    header << static_cast<const CBlockHeader&>(block);
    encoded << TX_WITH_WITNESS(block);
    UniValue info{UniValue::VOBJ};
    info.pushKV("timestamp_hex", HexStr(*timestamp));
    info.pushKV("time", *time);
    info.pushKV("bits", strprintf("%08x", *bits));
    info.pushKV("nonce", *nonce);
    info.pushKV("header", HexStr(header));
    info.pushKV("block", HexStr(encoded));
    info.pushKV("hash", block.GetHash().GetHex());
    info.pushKV("merkle_root", block.hashMerkleRoot.GetHex());
    info.pushKV("randomx_seed", HexStr(params.GetConsensus().randomx.bootstrap_key));
    result = info.write();
    return EXIT_SUCCESS;
}

MAIN_FUNCTION
{
    ArgsManager& args = gArgs;
    SetupEnvironment();

    try {
        int ret = AppInitUtil(args, argc, argv);
        if (ret != CONTINUE_EXECUTION) {
            return ret;
        }
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitUtil()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitUtil()");
        return EXIT_FAILURE;
    }

    const auto cmd = args.GetCommand();
    if (!cmd) {
        tfm::format(std::cerr, "Error: must specify a command\n");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    std::string strPrint;
    try {
        if (cmd->command == "grind") {
            ret = Grind(cmd->args, strPrint);
        } else if (cmd->command == "verify") {
            ret = GrindOne(cmd->args, strPrint, true);
        } else if (cmd->command == "genesis") {
            ret = Genesis(cmd->args, strPrint);
        } else if (cmd->command == "genesisinfo") {
            if (!cmd->args.empty()) throw std::runtime_error{"genesisinfo takes no arguments"};
            strPrint = GenesisInfo().write();
            ret = EXIT_SUCCESS;
        } else {
            assert(false); // unknown command should be caught earlier
        }
    } catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
    } catch (...) {
        strPrint = "unknown error";
    }

    if (strPrint != "") {
        tfm::format(ret == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }

    return ret;
}
