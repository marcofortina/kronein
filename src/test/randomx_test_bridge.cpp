// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/randomx.h>

#include <algorithm>
#include <cstddef>
#include <span>

#if defined(_WIN32)
#define KRONEIN_TEST_EXPORT __declspec(dllexport)
#else
#define KRONEIN_TEST_EXPORT __attribute__((visibility("default")))
#endif

extern "C" KRONEIN_TEST_EXPORT int kronein_randomx_v2_hash(
    const unsigned char* key,
    size_t key_size,
    const unsigned char* input,
    size_t input_size,
    unsigned char output[32])
{
    if (key == nullptr || input == nullptr || output == nullptr) return 0;
    const auto hash{randomx_pow::HashLight({key, key_size}, {input, input_size})};
    if (!hash) return 0;
    std::copy(hash->begin(), hash->end(), output);
    return 1;
}
