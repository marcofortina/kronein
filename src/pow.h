// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

using RandomXSeed = std::array<unsigned char, 32>;

/**
 * Convert nBits value to target.
 *
 * @param[in] nBits     compact representation of the target
 * @param[in] pow_limit PoW limit (consensus parameter)
 *
 * @return              the proof-of-work target or nullopt if the nBits value
 *                      is invalid (due to overflow or exceeding pow_limit)
 */
std::optional<arith_uint256> DeriveTarget(unsigned int nBits, uint256 pow_limit);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/**
 * Calculate the ASERTI3 target from a fixed reference target and schedule.
 * All arithmetic is integer-only and the result is clamped to pow_limit.
 */
arith_uint256 CalculateASERT(const arith_uint256& ref_target, int64_t target_spacing,
                            int64_t time_diff, int64_t height_diff,
                            const arith_uint256& pow_limit, int64_t half_life);

/** Check only target encoding/range and compare an already-authenticated work result. */
bool CheckProofOfWorkTarget(uint256 work_hash, unsigned int nBits, const Consensus::Params&);

/** Return the block height supplying the RandomX cache key, or null for the bootstrap key. */
std::optional<int> GetRandomXSeedHeight(int block_height, const Consensus::Params&);
/** Derive the RandomX cache key for a block from its already-validated ancestors. */
std::optional<RandomXSeed> GetRandomXSeed(const CBlockIndex* pindex_prev, int block_height, const Consensus::Params&);
/** Compute the RandomX v2 work hash of the canonical 80-byte header. */
std::optional<uint256> GetRandomXWorkHash(const CBlockHeader& header, std::span<const unsigned char> seed);
/** Check RandomX v2 work against the compact target committed by the header. */
bool CheckProofOfWork(const CBlockHeader& header, std::span<const unsigned char> seed, const Consensus::Params&);
/** Verify real RandomX work even in a fuzz build (e.g. frozen genesis proofs). */
bool CheckProofOfWorkImpl(const CBlockHeader& header, std::span<const unsigned char> seed, const Consensus::Params&);
/** Check using the bootstrap/fixed seed (genesis and regtest convenience). */
bool CheckProofOfWork(const CBlockHeader& header, const Consensus::Params&);

/** Search up to max_tries nonces using a cache bound to seed. */
bool MineProofOfWork(CBlockHeader& header, std::span<const unsigned char> seed, const Consensus::Params&, uint64_t& max_tries, unsigned int threads = 0, bool use_full_memory = true);
/** Mine with the fixed/bootstrap seed (primarily regtest and genesis tooling). */
bool MineProofOfWork(CBlockHeader& header, const Consensus::Params&, uint64_t& max_tries, unsigned int threads = 0, bool use_full_memory = true);

/**
 * Check whether new_nbits is the permitted target for a header-sync step.
 * ASERT and no-retarget networks are checked exactly; legacy interval
 * retargets retain their bounded-transition check.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height,
                                   int64_t previous_time, int64_t current_time,
                                   uint32_t old_nbits, uint32_t new_nbits);

#endif // BITCOIN_POW_H
