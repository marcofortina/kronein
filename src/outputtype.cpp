// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <outputtype.h>

#include <cassert>
#include <optional>
#include <string>

static const std::string OUTPUT_TYPE_STRING_BECH32M = "bech32m";
static const std::string OUTPUT_TYPE_STRING_UNKNOWN = "unknown";

const std::string& FormatOutputType(OutputType type)
{
    switch (type) {
    case OutputType::BECH32M: return OUTPUT_TYPE_STRING_BECH32M;
    case OutputType::UNKNOWN: return OUTPUT_TYPE_STRING_UNKNOWN;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest) {
    if (std::holds_alternative<WitnessV1Taproot>(dest) ||
        std::holds_alternative<PayToAnchor>(dest)) {
        return OutputType::BECH32M;
    }
    return std::nullopt;
}
