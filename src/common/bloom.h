// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_BLOOM_H
#define BITCOIN_COMMON_BLOOM_H

#include <span.h>

#include <cstdint>
#include <vector>

/**
 * RollingBloomFilter is a probabilistic "keep track of most recently inserted" set.
 * Construct it with the number of items to keep track of, and a false-positive
 * rate. By default nTweak is set to a cryptographically secure random value.
 * Rather than clear(), the method
 * reset() is provided, which also changes nTweak to decrease the impact of
 * false-positives.
 *
 * contains(item) will always return true if item was one of the last N to 1.5*N
 * insert()'ed ... but may also return true for items that were not inserted.
 *
 * It needs around 1.8 bytes per element per factor 0.1 of false positive rate.
 * For example, if we want 1000 elements, we'd need:
 * - ~1800 bytes for a false positive rate of 0.1
 * - ~3600 bytes for a false positive rate of 0.01
 * - ~5400 bytes for a false positive rate of 0.001
 *
 * If we make these simplifying assumptions:
 * - logFpRate / log(0.5) doesn't get rounded or clamped in the nHashFuncs calculation
 * - nElements is even, so that nEntriesPerGeneration == nElements / 2
 *
 * Then we get a more accurate estimate for filter bytes:
 *
 *     3/(log(256)*log(2)) * log(1/fpRate) * nElements
 */
class CRollingBloomFilter
{
public:
    CRollingBloomFilter(unsigned int nElements, double nFPRate);

    void insert(std::span<const unsigned char> vKey);
    bool contains(std::span<const unsigned char> vKey) const;

    void reset();

private:
    int nEntriesPerGeneration;
    int nEntriesThisGeneration;
    int nGeneration;
    std::vector<uint64_t> data;
    unsigned int nTweak;
    int nHashFuncs;
};

#endif // BITCOIN_COMMON_BLOOM_H
