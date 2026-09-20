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
#include <pow.h>
#include <streams.h>
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
                "or:     kronein-util [options] grind -  # read header [seed] requests from stdin\n";
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

static int GrindOne(const std::vector<std::string>& args, std::string& strPrint)
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
    if (!DecodeHexBlockHeader(header, args[0])) {
        strPrint = "Could not decode block header";
        return EXIT_FAILURE;
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
