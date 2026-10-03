// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/hex_base.h>
#include <crypto/randomx.h>
#include <util/strencodings.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

// Keep the native sanitizer runtime outside the uninstrumented Python process.
// Each request is two hex lines (key, input); each response is one hash line.
int main()
{
    std::string key_hex, input_hex;
    while (std::getline(std::cin, key_hex)) {
        if (!std::getline(std::cin, input_hex)) return 1;
        const auto key{TryParseHex<uint8_t>(key_hex)};
        const auto input{TryParseHex<uint8_t>(input_hex)};
        if (!key || key->empty() || !input || input->empty()) return 1;
        const auto hash{randomx_pow::HashLight(*key, *input)};
        if (!hash) return 1;
        std::cout << HexStr(*hash) << std::endl;
        if (!std::cout) return 1;
    }
    return std::cin.eof() ? 0 : 1;
}
