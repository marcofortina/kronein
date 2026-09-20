// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CRYPTO_RANDOMX_H
#define BITCOIN_CRYPTO_RANDOMX_H

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>

namespace randomx_pow {

static constexpr size_t HASH_SIZE{32};
using Hash = std::array<unsigned char, HASH_SIZE>;

enum class Mode {
    LIGHT,
    FULL,
};

/**
 * A RandomX v2.0.1 hashing context bound to one cache key.
 *
 * LIGHT uses the 256 MiB verification cache. FULL additionally builds the
 * roughly 2 GiB dataset intended for repeated mining hashes. Instances are
 * safe to share: Hash() serializes access to the underlying RandomX VM.
 */
class Hasher
{
private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    explicit Hasher(std::unique_ptr<Impl> impl);

public:
    ~Hasher();
    Hasher(Hasher&&) noexcept;
    Hasher& operator=(Hasher&&) noexcept;
    Hasher(const Hasher&) = delete;
    Hasher& operator=(const Hasher&) = delete;

    static std::shared_ptr<Hasher> Create(std::span<const unsigned char> key, Mode mode, unsigned int dataset_threads = 0);
    std::optional<Hash> HashData(std::span<const unsigned char> input);
    Mode GetMode() const;
};

/**
 * Return a process-wide cached context. Two light contexts are retained to
 * make epoch transitions and shallow reorgs cheap; one full mining context is
 * retained. Returns null when the required memory or VM cannot be allocated.
 */
std::shared_ptr<Hasher> GetCachedHasher(std::span<const unsigned char> key, Mode mode, unsigned int dataset_threads = 0);

/** Convenience helper for one light-mode verification hash. */
std::optional<Hash> HashLight(std::span<const unsigned char> key, std::span<const unsigned char> input);

} // namespace randomx_pow

#endif // BITCOIN_CRYPTO_RANDOMX_H
