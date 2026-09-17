// Copyright (c) 2017, 2021 Pieter Wuille
// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bech32m is the string encoding format used by native addresses.
// The output consists of a human-readable part
// (alphanumeric), a separator character (1), and a base32 data
// section, the last 6 characters of which are a checksum.
//
// For more information, see BIP 350.

#ifndef BITCOIN_BECH32_H
#define BITCOIN_BECH32_H

#include <cstdint>
#include <string>
#include <vector>

namespace bech32
{

static constexpr size_t CHECKSUM_SIZE = 6;
static constexpr char SEPARATOR = '1';
static constexpr size_t MAX_LENGTH = 90;

static_assert(MAX_LENGTH <= 0x7fffffff);

/** Encode a Bech32m string. If hrp contains uppercase characters, this will cause an assertion error. */
std::string Encode(const std::string& hrp, const std::vector<uint8_t>& values);

struct DecodeResult
{
    bool valid{false};          //!< Whether decoding succeeded.
    std::string hrp;           //!< The human readable part
    std::vector<uint8_t> data; //!< The payload (excluding checksum)

    DecodeResult() = default;
    DecodeResult(std::string&& h, std::vector<uint8_t>&& d) : valid(true), hrp(std::move(h)), data(std::move(d)) {}
};

/** Decode a Bech32m string. */
DecodeResult Decode(const std::string& str, size_t limit = MAX_LENGTH);

/** Return the positions of errors in a Bech32m string. */
std::pair<std::string, std::vector<int>> LocateErrors(const std::string& str, size_t limit = MAX_LENGTH);

} // namespace bech32

#endif // BITCOIN_BECH32_H
