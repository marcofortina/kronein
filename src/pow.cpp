// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <crypto/common.h>
#include <crypto/randomx.h>
#include <primitives/block.h>
#include <streams.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <span>

namespace {

/**
 * Return min(value * numerator / denominator, limit) without overflowing the
 * fixed-width arith_uint256 intermediate value.
 */
arith_uint256 ScaleTarget(const arith_uint256& value, uint64_t numerator, uint64_t denominator, const arith_uint256& limit)
{
    assert(denominator != 0);

    const arith_uint256 quotient{value / denominator};
    const arith_uint256 remainder{value - quotient * denominator};
    if (quotient > limit / numerator) return limit;

    arith_uint256 result{quotient * numerator};
    const arith_uint256 remainder_term{remainder * numerator / denominator};
    if (result > limit - remainder_term) return limit;
    result += remainder_term;
    return result;
}

/**
 * Return min(value * multiplier * 2^shift, limit) without overflowing the
 * 256-bit arithmetic type. The temporary product is represented as nine
 * 32-bit limbs, which is sufficient for a 256-by-17-bit multiplication.
 */
arith_uint256 MultiplyShift(const arith_uint256& value, uint32_t multiplier, int64_t shift, const arith_uint256& limit)
{
    std::array<uint32_t, 9> product{};
    uint64_t carry{0};
    for (unsigned int i = 0; i < 8; ++i) {
        const uint32_t limb{static_cast<uint32_t>((value >> (i * 32)).GetLow64())};
        const uint64_t multiplied{uint64_t{limb} * multiplier + carry};
        product[i] = static_cast<uint32_t>(multiplied);
        carry = multiplied >> 32;
    }
    product[8] = static_cast<uint32_t>(carry);

    int product_bits{0};
    for (int i = product.size() - 1; i >= 0; --i) {
        if (product[i] != 0) {
            product_bits = i * 32 + std::bit_width(product[i]);
            break;
        }
    }

    arith_uint256 result{0};
    if (shift >= 0) {
        if (shift >= 256 || product_bits + shift > 256) return limit;
        for (int i = 7; i >= 0; --i) {
            result <<= 32;
            result += product[i];
        }
        result <<= static_cast<unsigned int>(shift);
    } else {
        const uint64_t right_shift{static_cast<uint64_t>(-(shift + 1)) + 1};
        if (right_shift >= product.size() * 32) return result;

        std::array<uint32_t, 8> shifted{};
        for (unsigned int i = 0; i < shifted.size(); ++i) {
            const uint64_t source_bit{uint64_t{i} * 32 + right_shift};
            const size_t source_limb{static_cast<size_t>(source_bit / 32)};
            const unsigned int offset{static_cast<unsigned int>(source_bit % 32)};
            if (source_limb >= product.size()) break;

            uint64_t word{product[source_limb] >> offset};
            if (offset != 0 && source_limb + 1 < product.size()) {
                word |= uint64_t{product[source_limb + 1]} << (32 - offset);
            }
            shifted[i] = static_cast<uint32_t>(word);
        }
        for (int i = shifted.size() - 1; i >= 0; --i) {
            result <<= 32;
            result += shifted[i];
        }
    }

    return std::min(result, limit);
}

} // namespace

arith_uint256 CalculateASERT(const arith_uint256& ref_target, int64_t target_spacing,
                            int64_t time_diff, int64_t height_diff,
                            const arith_uint256& pow_limit, int64_t half_life)
{
    assert(ref_target > 0 && ref_target <= pow_limit);
    assert(target_spacing > 0);
    assert(height_diff >= 0);
    assert(half_life > 0);
    assert(height_diff < std::numeric_limits<int64_t>::max() / target_spacing - 1);

    const int64_t schedule_error{time_diff - target_spacing * (height_diff + 1)};
    assert(schedule_error > std::numeric_limits<int64_t>::min() / 65536);
    assert(schedule_error < std::numeric_limits<int64_t>::max() / 65536);
    const int64_t exponent{schedule_error * 65536 / half_life};

    // Decompose the fixed-point exponent into integer and fractional parts.
    // Arithmetic right shift is well-defined for signed integers since C++20.
    static_assert(int64_t{-1} >> 1 == int64_t{-1});
    const int64_t integer_part{exponent >> 16};
    const uint16_t fractional_part{static_cast<uint16_t>(exponent)};
    assert(exponent == integer_part * 65536 + fractional_part);

    // Cubic approximation of 2^x for 0 <= x < 1. The maximum relative error
    // is below 0.013%, matching the published ASERTI3 specification.
    const uint64_t fraction{fractional_part};
    const uint32_t factor{static_cast<uint32_t>(
        65536 + ((195766423245049ULL * fraction +
                  971821376ULL * fraction * fraction +
                  5127ULL * fraction * fraction * fraction +
                  (1ULL << 47)) >> 48))};

    arith_uint256 next_target{MultiplyShift(ref_target, factor, integer_part - 16, pow_limit)};
    if (next_target == 0) next_target = 1;
    return next_target;
}

namespace {

uint32_t GetNextASERTWorkRequired(int64_t previous_height, int64_t previous_time, const Consensus::Params& params)
{
    assert(params.asert.enabled);
    assert(previous_height >= params.asert.anchor_height);

    arith_uint256 reference_target;
    reference_target.SetCompact(params.asert.anchor_bits);
    const arith_uint256 pow_limit{UintToArith256(params.powLimit)};
    assert(reference_target > 0 && reference_target <= pow_limit);

    return CalculateASERT(reference_target,
                          params.nPowTargetSpacing,
                          previous_time - params.asert.anchor_parent_time,
                          previous_height - params.asert.anchor_height,
                          pow_limit,
                          params.asert.half_life).GetCompact();
}

} // namespace

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    if (params.fPowNoRetargeting) return pindexLast->nBits;

    // Public test networks may reset to minimum difficulty after a long gap.
    if (params.fPowAllowMinDifficultyBlocks && pblock != nullptr &&
        pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2) {
        return nProofOfWorkLimit;
    }

    if (params.asert.enabled) {
        return GetNextASERTWorkRequired(pindexLast->nHeight, pindexLast->GetBlockTime(), params);
    }

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Return the last non-special-min-difficulty-rules-block.
            const CBlockIndex* pindex = pindexLast;
            while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                pindex = pindex->pprev;
            return pindex->nBits;
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew = ScaleTarget(bnNew, nActualTimespan, params.nPowTargetTimespan, bnPowLimit);

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height,
                                   int64_t previous_time, int64_t current_time,
                                   uint32_t old_nbits, uint32_t new_nbits)
{
    if (!DeriveTarget(new_nbits, params.powLimit)) return false;
    if (params.fPowNoRetargeting) return old_nbits == new_nbits;

    if (params.fPowAllowMinDifficultyBlocks &&
        current_time > previous_time + params.nPowTargetSpacing * 2) {
        return new_nbits == UintToArith256(params.powLimit).GetCompact();
    }

    if (params.asert.enabled) {
        return new_nbits == GetNextASERTWorkRequired(height - 1, previous_time, params);
    }

    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target = ScaleTarget(largest_difficulty_target, largest_timespan, params.nPowTargetTimespan, pow_limit);

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target = ScaleTarget(smallest_difficulty_target, smallest_timespan, params.nPowTargetTimespan, pow_limit);

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

bool CheckProofOfWorkTarget(uint256 work_hash, unsigned int nBits, const Consensus::Params& params)
{
    const auto target{DeriveTarget(nBits, params.powLimit)};
    return target && UintToArith256(work_hash) <= *target;
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

std::optional<int> GetRandomXSeedHeight(int block_height, const Consensus::Params& params)
{
    if (block_height < 0 || params.randomx.epoch_blocks == 0 || params.randomx.epoch_lag == 0) return std::nullopt;
    if (params.randomx.fixed_seed || static_cast<uint32_t>(block_height) < params.randomx.epoch_lag) return std::nullopt;
    return static_cast<int>(((static_cast<uint32_t>(block_height) - params.randomx.epoch_lag) /
                             params.randomx.epoch_blocks) * params.randomx.epoch_blocks);
}

std::optional<RandomXSeed> GetRandomXSeed(const CBlockIndex* pindex_prev, int block_height, const Consensus::Params& params)
{
    const auto seed_height{GetRandomXSeedHeight(block_height, params)};
    if (!seed_height) return params.randomx.bootstrap_key;
    if (pindex_prev == nullptr || *seed_height > pindex_prev->nHeight) return std::nullopt;
    const CBlockIndex* seed_index{pindex_prev->GetAncestor(*seed_height)};
    if (seed_index == nullptr) return std::nullopt;
    const uint256 seed_hash{seed_index->GetBlockHash()};
    RandomXSeed seed;
    std::copy(seed_hash.begin(), seed_hash.end(), seed.begin());
    return seed;
}

std::optional<uint256> GetRandomXWorkHash(const CBlockHeader& header, std::span<const unsigned char> seed)
{
    DataStream stream;
    stream << header;
    if (stream.size() != 80) return std::nullopt;
    const auto input{std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(stream.data()), stream.size()}};
    // The same header is often checked more than once, including the frozen
    // genesis when constructing chain parameters. Retain only the last result
    // per thread, with exact header and seed equality (not just block identity).
    // Target and contextual difficulty checks remain outside this hash cache.
    struct CachedWorkHash {
        std::array<unsigned char, 80> header;
        RandomXSeed seed;
        uint256 hash;
    };
    static thread_local std::optional<CachedWorkHash> last_hash;
    if (last_hash && std::ranges::equal(last_hash->header, input) &&
        std::ranges::equal(last_hash->seed, seed)) {
        return last_hash->hash;
    }
    const auto hash{randomx_pow::HashLight(seed, input)};
    if (!hash) return std::nullopt;
    uint256 work_hash;
    std::copy(hash->begin(), hash->end(), work_hash.begin());
    if (seed.size() == RandomXSeed{}.size()) {
        auto& cached{last_hash.emplace()};
        std::copy(input.begin(), input.end(), cached.header.begin());
        std::copy(seed.begin(), seed.end(), cached.seed.begin());
        cached.hash = work_hash;
    }
    return work_hash;
}

bool CheckProofOfWork(const CBlockHeader& header, std::span<const unsigned char> seed, const Consensus::Params& params)
{
    // Keep fuzz targets fast while preserving deterministic accept/reject behavior.
    if (EnableFuzzDeterminism()) {
        return DeriveTarget(header.nBits, params.powLimit) && (header.GetHash().data()[31] & 0x80) == 0;
    }
    return CheckProofOfWorkImpl(header, seed, params);
}

bool CheckProofOfWorkImpl(const CBlockHeader& header, std::span<const unsigned char> seed, const Consensus::Params& params)
{
    if (!DeriveTarget(header.nBits, params.powLimit)) return false;
    const auto work_hash{GetRandomXWorkHash(header, seed)};
    return work_hash && CheckProofOfWorkTarget(*work_hash, header.nBits, params);
}

bool CheckProofOfWork(const CBlockHeader& header, const Consensus::Params& params)
{
    return CheckProofOfWork(header, params.randomx.bootstrap_key, params);
}

bool MineProofOfWork(CBlockHeader& header, std::span<const unsigned char> seed, const Consensus::Params& params, uint64_t& max_tries, unsigned int threads, bool use_full_memory)
{
    const auto target{DeriveTarget(header.nBits, params.powLimit)};
    if (!target || seed.empty()) return false;

    if (EnableFuzzDeterminism()) {
        while (max_tries > 0) {
            if (CheckProofOfWork(header, seed, params)) return true;
            --max_tries;
            if (header.nNonce == std::numeric_limits<uint32_t>::max()) return false;
            ++header.nNonce;
        }
        return false;
    }

    const randomx_pow::Mode mode{use_full_memory && !params.randomx.fixed_seed ? randomx_pow::Mode::FULL : randomx_pow::Mode::LIGHT};
    auto hasher{randomx_pow::GetCachedHasher(seed, mode, threads)};
    if (!hasher && mode == randomx_pow::Mode::FULL) {
        // Full mode is a mining optimization, not a consensus requirement.
        // Keep the built-in miner usable on hosts that cannot allocate the
        // dataset by falling back to the identical light-mode hash.
        hasher = randomx_pow::GetCachedHasher(seed, randomx_pow::Mode::LIGHT);
    }
    if (!hasher) return false;

    DataStream stream;
    stream << header;
    if (stream.size() != 80) return false;
    auto* serialized_header{reinterpret_cast<unsigned char*>(stream.data())};
    while (max_tries > 0) {
        WriteLE32(serialized_header + 76, header.nNonce);
        const auto input{std::span<const unsigned char>{serialized_header, stream.size()}};
        const auto hash{hasher->HashData(input)};
        if (!hash) return false;
        uint256 work_hash;
        std::copy(hash->begin(), hash->end(), work_hash.begin());
        if (UintToArith256(work_hash) <= *target) return true;
        --max_tries;
        if (header.nNonce == std::numeric_limits<uint32_t>::max()) return false;
        ++header.nNonce;
    }

    return false;
}

bool MineProofOfWork(CBlockHeader& header, const Consensus::Params& params, uint64_t& max_tries, unsigned int threads, bool use_full_memory)
{
    return MineProofOfWork(header, params.randomx.bootstrap_key, params, max_tries, threads, use_full_memory);
}
