// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_OUTPUTTYPE_H
#define BITCOIN_OUTPUTTYPE_H

#include <addresstype.h>

#include <array>
#include <optional>
#include <string>

enum class OutputType {
    BECH32M,
    UNKNOWN,
};

static constexpr auto OUTPUT_TYPES = std::array{
    OutputType::BECH32M,
};

const std::string& FormatOutputType(OutputType type);

/** Get the OutputType for a CTxDestination */
std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest);

#endif // BITCOIN_OUTPUTTYPE_H
