// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <outputtype.h>

#include <util/string.h>

#include <cassert>
#include <optional>
#include <string>

static const std::string OUTPUT_TYPE_STRING_LEGACY = "legacy";
static const std::string OUTPUT_TYPE_STRING_P2SH_SEGWIT = "p2sh-segwit";
static const std::string OUTPUT_TYPE_STRING_BECH32 = "bech32";
static const std::string OUTPUT_TYPE_STRING_BECH32M = "bech32m";
static const std::string OUTPUT_TYPE_STRING_UNKNOWN = "unknown";

std::optional<OutputType> ParseOutputType(std::string_view type)
{
    if (type == OUTPUT_TYPE_STRING_LEGACY) {
        return OutputType::LEGACY;
    } else if (type == OUTPUT_TYPE_STRING_P2SH_SEGWIT) {
        return OutputType::P2SH_SEGWIT;
    } else if (type == OUTPUT_TYPE_STRING_BECH32) {
        return OutputType::BECH32;
    } else if (type == OUTPUT_TYPE_STRING_BECH32M) {
        return OutputType::BECH32M;
    }
    return std::nullopt;
}

const std::string& FormatOutputType(OutputType type)
{
    switch (type) {
    case OutputType::LEGACY: return OUTPUT_TYPE_STRING_LEGACY;
    case OutputType::P2SH_SEGWIT: return OUTPUT_TYPE_STRING_P2SH_SEGWIT;
    case OutputType::BECH32: return OUTPUT_TYPE_STRING_BECH32;
    case OutputType::BECH32M: return OUTPUT_TYPE_STRING_BECH32M;
    case OutputType::UNKNOWN: return OUTPUT_TYPE_STRING_UNKNOWN;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::string FormatAllOutputTypes()
{
    return util::Join(OUTPUT_TYPES, ", ", [](const auto& i) { return "\"" + FormatOutputType(i) + "\""; });
}

std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest) {
    if (std::holds_alternative<PKHash>(dest) ||
        std::holds_alternative<ScriptHash>(dest)) {
        return OutputType::LEGACY;
    }
    if (std::holds_alternative<WitnessV0KeyHash>(dest) ||
        std::holds_alternative<WitnessV0ScriptHash>(dest)) {
        return OutputType::BECH32;
    }
    if (std::holds_alternative<WitnessV1Taproot>(dest) ||
        std::holds_alternative<WitnessUnknown>(dest)) {
        return OutputType::BECH32M;
    }
    return std::nullopt;
}
