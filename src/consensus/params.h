// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <consensus/amount.h>
#include <uint256.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <vector>

namespace Consensus {

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    struct ChainRegistryParams {
        /** Negative means the registry consensus rules are disabled. */
        int activation_height{-1};
        /** Minimum value permanently burned by a registration output. */
        CAmount minimum_registration_burn{0};
        /** Maximum number of registry state transitions accepted per block. */
        uint32_t maximum_operations{0};

        bool Enabled() const
        {
            return activation_height >= 0 &&
                   minimum_registration_burn > 0 &&
                   maximum_operations > 0;
        }
        bool IsActive(int height) const { return Enabled() && height >= activation_height; }
    };

    struct ASERTParams {
        /** Enable the per-block ASERTI3 difficulty adjustment algorithm. */
        bool enabled{false};
        /** Height and target of the fixed scheduling anchor. */
        int anchor_height{0};
        uint32_t anchor_bits{0};
        /** Timestamp of the block immediately preceding the anchor. */
        int64_t anchor_parent_time{0};
        /** Seconds of schedule drift required to double or halve difficulty. */
        int64_t half_life{2 * 24 * 60 * 60};
    };

    struct RandomXParams {
        /** Domain-separated key used before the first seeded epoch. */
        std::array<unsigned char, 32> bootstrap_key{};
        /** Number of blocks sharing one RandomX cache key. */
        uint32_t epoch_blocks{2048};
        /** Delay before a completed epoch becomes the cache-key source. */
        uint32_t epoch_lag{64};
        /** Keep the bootstrap key forever (used only by regtest). */
        bool fixed_seed{false};
    };

    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Proof of work parameters */
    uint256 powLimit;
    /** Per-block difficulty adjustment parameters. */
    ASERTParams asert;
    /** RandomX v2 cache-key schedule. The exact target remains encoded in nBits. */
    RandomXParams randomx;
    /** Child-chain registry activation and resource limits. */
    ChainRegistryParams chain_registry;
    bool fPowAllowMinDifficultyBlocks;
    /**
      * Enforce BIP94 timewarp attack mitigation. On testnet4 this also enforces
      * the block storm mitigation.
      */
    bool enforce_BIP94;
    /** Reject public-network headers whose timestamp moves backwards. */
    bool enforce_timestamp_monotonicity{false};
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a serialized Taproot witness satisfying
     * the P2TR Signet challenge.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
