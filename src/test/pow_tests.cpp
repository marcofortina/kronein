// Copyright (c) 2015-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <test/util/random.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <array>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    auto consensus{chainParams->GetConsensus()};
    consensus.asert.enabled = false;
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1d00ffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.
    unsigned int expected_nbits = 0x1d00d86aU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1,
                                              pindexLast.GetBlockTime(), pindexLast.GetBlockTime(),
                                              pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    auto consensus{chainParams->GetConsensus()};
    consensus.asert.enabled = false;
    int64_t nLastRetargetTime = 1789776000; // Synthetic retarget interval start
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1791831491; // Synthetic retarget interval end
    const unsigned int expected_nbits = UintToArith256(chainParams->GetConsensus().powLimit).GetCompact();
    pindexLast.nBits = expected_nbits;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1,
                                              pindexLast.GetBlockTime(), pindexLast.GetBlockTime(),
                                              pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    auto consensus{chainParams->GetConsensus()};
    consensus.asert.enabled = false;
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671;  // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1,
                                              pindexLast.GetBlockTime(), pindexLast.GetBlockTime(),
                                              pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits-1;
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1,
                                               pindexLast.GetBlockTime(), pindexLast.GetBlockTime(),
                                               pindexLast.nBits, invalid_nbits));
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    auto consensus{chainParams->GetConsensus()};
    consensus.asert.enabled = false;
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1,
                                              pindexLast.GetBlockTime(), pindexLast.GetBlockTime(),
                                              pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits+1;
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, pindexLast.nHeight + 1,
                                               pindexLast.GetBlockTime(), pindexLast.GetBlockTime(),
                                               pindexLast.nBits, invalid_nbits));
}

BOOST_AUTO_TEST_CASE(asert_reference_schedule)
{
    const auto chain_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& consensus{chain_params->GetConsensus()};
    const CBlock& genesis{chain_params->GenesisBlock()};
    const arith_uint256 pow_limit{UintToArith256(consensus.powLimit)};
    const arith_uint256 reference_target{pow_limit >> 8};

    BOOST_REQUIRE(consensus.asert.enabled);
    BOOST_CHECK_EQUAL(CalculateASERT(reference_target, consensus.nPowTargetSpacing,
                                    consensus.nPowTargetSpacing, 0, pow_limit,
                                    consensus.asert.half_life),
                      reference_target);
    BOOST_CHECK_EQUAL(CalculateASERT(reference_target, consensus.nPowTargetSpacing,
                                    consensus.nPowTargetSpacing + consensus.asert.half_life,
                                    0, pow_limit, consensus.asert.half_life),
                      reference_target * 2);
    BOOST_CHECK_EQUAL(CalculateASERT(reference_target, consensus.nPowTargetSpacing,
                                    consensus.nPowTargetSpacing - consensus.asert.half_life,
                                    0, pow_limit, consensus.asert.half_life),
                      reference_target >> 1);

    CBlockIndex previous{genesis};
    previous.nHeight = 0;
    CBlockHeader candidate;
    candidate.nTime = genesis.nTime + consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&previous, &candidate, consensus), genesis.nBits);
}

BOOST_AUTO_TEST_CASE(asert_hashrate_spike_and_recovery)
{
    const auto chain_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& consensus{chain_params->GetConsensus()};
    const CBlock& genesis{chain_params->GenesisBlock()};
    const arith_uint256 initial_target{arith_uint256{}.SetCompact(genesis.nBits)};

    CBlockIndex previous{genesis};
    previous.nHeight = consensus.asert.half_life / consensus.nPowTargetSpacing;
    // The chain is one half-life ahead of schedule: difficulty must double.
    previous.nTime = genesis.nTime;
    CBlockHeader candidate;
    candidate.nTime = previous.nTime + 1;
    const uint32_t spike_bits{GetNextWorkRequired(&previous, &candidate, consensus)};
    BOOST_CHECK_EQUAL(arith_uint256{}.SetCompact(spike_bits), initial_target >> 1);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, previous.nHeight + 1,
                                              previous.GetBlockTime(), candidate.GetBlockTime(),
                                              previous.nBits, spike_bits));
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, previous.nHeight + 1,
                                               previous.GetBlockTime(), candidate.GetBlockTime(),
                                               previous.nBits, spike_bits - 1));

    // Returning to the absolute schedule restores the original target without
    // retaining state or accumulated rounding error.
    previous.nTime = genesis.nTime + previous.nHeight * consensus.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&previous, &candidate, consensus), genesis.nBits);
}

BOOST_AUTO_TEST_CASE(asert_large_pow_limit_is_overflow_safe)
{
    const auto chain_params{CreateChainParams(*m_node.args, ChainType::SIGNET)};
    const auto& consensus{chain_params->GetConsensus()};
    const arith_uint256 pow_limit{UintToArith256(consensus.powLimit)};

    BOOST_CHECK_EQUAL(CalculateASERT(pow_limit, consensus.nPowTargetSpacing,
                                    consensus.nPowTargetSpacing, 0, pow_limit,
                                    consensus.asert.half_life),
                      pow_limit);
    BOOST_CHECK_EQUAL(CalculateASERT(pow_limit, consensus.nPowTargetSpacing,
                                    consensus.nPowTargetSpacing + consensus.asert.half_life,
                                    0, pow_limit, consensus.asert.half_life),
                      pow_limit);
    BOOST_CHECK_EQUAL(CalculateASERT(pow_limit, consensus.nPowTargetSpacing,
                                    consensus.nPowTargetSpacing - consensus.asert.half_life,
                                    0, pow_limit, consensus.asert.half_life),
                      pow_limit >> 1);
}

BOOST_AUTO_TEST_CASE(asert_published_vectors)
{
    struct Vector {
        uint32_t anchor_bits;
        int64_t height_diff;
        int64_t time_diff;
        uint32_t expected_bits;
    };
    // Selected boundary, ramp and non-monotonic-time cases from the published
    // BCHN ASERTI3-2d test-vector runs 4, 5, 6, 9, 10, 11 and 12.
    static constexpr std::array vectors{
        Vector{0x01010000, 1, 174000, 0x01020000},
        Vector{0x01010000, 2, 347400, 0x01040000},
        Vector{0x1d00ffff, 1, 0, 0x1d00fec5},
        Vector{0x1d00ffff, 289, 0, 0x1c7f62c0},
        Vector{0x1802aee8, 1, 1200, 0x1802aee8},
        Vector{0x1802aee8, 2, 1310, 0x1802ad91},
        Vector{0x1802aee8, 3, 1327, 0x1802abf8},
        Vector{0x1802aee8, 1, 900, 0x1802ae16},
        Vector{0x1802aee8, 3, 1500, 0x1802ac71},
        Vector{0x1802aee8, 1, 1500, 0x1802afbb},
        Vector{0x1802aee8, 3, 3300, 0x1802b166},
        Vector{0x1802aee8, 2, 1496, 0x1802ae12},
        Vector{0x1802aee8, 3, 1398, 0x1802ac28},
        Vector{0x1802aee8, 2, 1199, 0x1802ad44},
        Vector{0x1802aee8, 3, 1198, 0x1802ab9e},
    };

    arith_uint256 pow_limit;
    pow_limit.SetCompact(0x1d00ffff);
    for (const auto& vector : vectors) {
        arith_uint256 anchor_target;
        anchor_target.SetCompact(vector.anchor_bits);
        BOOST_CHECK_EQUAL(CalculateASERT(anchor_target, /*target_spacing=*/600,
                                         vector.time_diff, vector.height_diff,
                                         pow_limit, /*half_life=*/172800).GetCompact(),
                          vector.expected_bits);
    }
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWorkTarget(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWorkTarget(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWorkTarget(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWorkTarget(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWorkTarget(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // The overflow-safe retarget calculation must clamp a maximum target after
    // the largest permitted timespan adjustment.
    if (!consensus.fPowNoRetargeting && !consensus.enforce_BIP94) {
        CBlockIndex index;
        index.nBits = UintToArith256(consensus.powLimit).GetCompact();
        index.nTime = consensus.nPowTargetTimespan * 4;
        BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&index, 0, consensus), index.nBits);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

BOOST_AUTO_TEST_SUITE_END()
