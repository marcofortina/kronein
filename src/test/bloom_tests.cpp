// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/bloom.h>

#include <random.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <vector>

#include <boost/test/unit_test.hpp>

namespace bloom_tests {
struct BloomTest : public BasicTestingSetup {
    std::vector<unsigned char> RandomData()
    {
        const uint256 random{m_rng.rand256()};
        return {random.begin(), random.end()};
    }
};
} // namespace bloom_tests

BOOST_FIXTURE_TEST_SUITE(bloom_tests, BloomTest)

BOOST_AUTO_TEST_CASE(rolling_bloom)
{
    SeedRandomForTest(SeedRand::ZEROS);

    // last-100-entry, 1% false positive:
    CRollingBloomFilter rb1(100, 0.01);

    // Overfill:
    static constexpr int DATA_SIZE{399};
    std::vector<unsigned char> data[DATA_SIZE];
    for (int i = 0; i < DATA_SIZE; ++i) {
        data[i] = RandomData();
        rb1.insert(data[i]);
    }
    // Last 100 guaranteed to be remembered:
    for (int i = 299; i < DATA_SIZE; ++i) {
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // false positive rate is 1%, so we should get about 100 hits if
    // testing 10,000 random keys.
    unsigned int hits{0};
    for (int i = 0; i < 10000; ++i) {
        if (rb1.contains(RandomData())) ++hits;
    }
    BOOST_CHECK_EQUAL(hits, 71U);

    BOOST_CHECK(rb1.contains(data[DATA_SIZE - 1]));
    rb1.reset();
    BOOST_CHECK(!rb1.contains(data[DATA_SIZE - 1]));

    for (int i = 0; i < DATA_SIZE; ++i) {
        if (i >= 100) BOOST_CHECK(rb1.contains(data[i - 100]));
        rb1.insert(data[i]);
        BOOST_CHECK(rb1.contains(data[i]));
    }

    for (int i = 0; i < 999; ++i) {
        const std::vector<unsigned char> value{RandomData()};
        rb1.insert(value);
        BOOST_CHECK(rb1.contains(value));
    }
    hits = 0;
    for (int i = 0; i < DATA_SIZE; ++i) {
        if (rb1.contains(data[i])) ++hits;
    }
    BOOST_CHECK_EQUAL(hits, 3U);

    // last-1000-entry, 0.1% false positive:
    CRollingBloomFilter rb2(1000, 0.001);
    for (int i = 0; i < DATA_SIZE; ++i) rb2.insert(data[i]);
    for (int i = 0; i < DATA_SIZE; ++i) BOOST_CHECK(rb2.contains(data[i]));
}

BOOST_AUTO_TEST_SUITE_END()
