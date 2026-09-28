// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_block_download.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <vector>

using namespace std::chrono_literals;

namespace {

std::vector<uint256> Hashes(uint64_t first, size_t count)
{
    std::vector<uint256> result;
    result.reserve(count);
    for (size_t i{0}; i < count; ++i) {
        uint64_t value{first + i};
        uint256 hash;
        for (size_t byte{0}; byte < sizeof(value); ++byte) {
            hash.begin()[byte] = static_cast<uint8_t>(value >> (byte * 8));
        }
        result.push_back(hash);
    }
    return result;
}

} // namespace

BOOST_AUTO_TEST_SUITE(child_block_download_tests)

BOOST_AUTO_TEST_CASE(admits_announcements_atomically)
{
    node::ChildBlockDownloadTracker tracker;
    const auto hashes{Hashes(1, 2)};
    BOOST_CHECK(
        tracker.Announce(1, hashes) ==
        node::ChildBlockDownloadError::NONE);
    BOOST_CHECK_EQUAL(tracker.CandidateCount(), 2U);
    BOOST_CHECK_EQUAL(tracker.AnnouncementCount(), 2U);
    BOOST_CHECK_EQUAL(tracker.PeerAnnouncementCount(1), 2U);

    BOOST_CHECK(
        tracker.Announce(1, hashes) ==
        node::ChildBlockDownloadError::NONE);
    BOOST_CHECK_EQUAL(tracker.AnnouncementCount(), 2U);

    const std::vector<uint256> invalid{uint256{3}, uint256{}};
    BOOST_CHECK(
        tracker.Announce(1, invalid) ==
        node::ChildBlockDownloadError::NULL_BLOCK_HASH);
    BOOST_CHECK_EQUAL(tracker.CandidateCount(), 2U);
    BOOST_CHECK_EQUAL(tracker.AnnouncementCount(), 2U);

    const std::vector<uint256> duplicate{uint256{3}, uint256{3}};
    BOOST_CHECK(
        tracker.Announce(1, duplicate) ==
        node::ChildBlockDownloadError::DUPLICATE_BLOCK_HASH);
    BOOST_CHECK_EQUAL(tracker.CandidateCount(), 2U);
}

BOOST_AUTO_TEST_CASE(enforces_peer_announcement_limit)
{
    node::ChildBlockDownloadTracker tracker;
    uint64_t next_hash{1};
    while (tracker.PeerAnnouncementCount(1) <
           node::MAX_CHILD_BLOCK_ANNOUNCEMENTS_PER_PEER) {
        const size_t remaining{
            node::MAX_CHILD_BLOCK_ANNOUNCEMENTS_PER_PEER -
            tracker.PeerAnnouncementCount(1)};
        const auto batch{
            Hashes(next_hash, std::min<size_t>(remaining, 16))};
        next_hash += batch.size();
        BOOST_REQUIRE(
            tracker.Announce(1, batch) ==
            node::ChildBlockDownloadError::NONE);
    }

    const auto rejected{Hashes(next_hash, 1)};
    BOOST_CHECK(
        tracker.Announce(1, rejected) ==
        node::ChildBlockDownloadError::PEER_ANNOUNCEMENT_LIMIT);
    BOOST_CHECK_EQUAL(
        tracker.CandidateCount(),
        node::MAX_CHILD_BLOCK_ANNOUNCEMENTS_PER_PEER);
}

BOOST_AUTO_TEST_CASE(enforces_global_limits)
{
    node::ChildBlockDownloadTracker candidates;
    uint64_t next_hash{1};
    for (node::ChildPeerId peer{1}; peer <= 16; ++peer) {
        for (size_t offset{0};
             offset < node::MAX_CHILD_BLOCK_ANNOUNCEMENTS_PER_PEER;
             offset += 16) {
            const auto batch{Hashes(next_hash, 16)};
            next_hash += batch.size();
            BOOST_REQUIRE(
                candidates.Announce(peer, batch) ==
                node::ChildBlockDownloadError::NONE);
        }
    }
    const auto extra_candidate{Hashes(next_hash, 1)};
    BOOST_CHECK(
        candidates.Announce(17, extra_candidate) ==
        node::ChildBlockDownloadError::GLOBAL_CANDIDATE_LIMIT);
    BOOST_CHECK_EQUAL(
        candidates.CandidateCount(), node::MAX_CHILD_BLOCK_CANDIDATES);

    node::ChildBlockDownloadTracker announcements;
    const auto shared_hashes{Hashes(1, 256)};
    for (node::ChildPeerId peer{1}; peer <= 32; ++peer) {
        for (size_t offset{0}; offset < shared_hashes.size(); offset += 16) {
            BOOST_REQUIRE(
                announcements.Announce(
                    peer, std::span{shared_hashes}.subspan(offset, 16)) ==
                node::ChildBlockDownloadError::NONE);
        }
    }
    BOOST_CHECK_EQUAL(
        announcements.AnnouncementCount(),
        node::MAX_CHILD_BLOCK_ANNOUNCEMENTS);
    BOOST_CHECK(
        announcements.Announce(
            33, std::span{shared_hashes}.first<1>()) ==
        node::ChildBlockDownloadError::GLOBAL_ANNOUNCEMENT_LIMIT);
}

BOOST_AUTO_TEST_CASE(bounds_and_matches_in_flight_requests)
{
    node::ChildBlockDownloadTracker tracker;
    const auto hashes{Hashes(1, 20)};
    BOOST_REQUIRE(
        tracker.Announce(1, std::span{hashes}.first<16>()) ==
        node::ChildBlockDownloadError::NONE);
    BOOST_REQUIRE(
        tracker.Announce(1, std::span{hashes}.subspan(16)) ==
        node::ChildBlockDownloadError::NONE);

    const auto requests{tracker.Schedule(1, 1s)};
    BOOST_CHECK_EQUAL(
        requests.size(), node::MAX_CHILD_BLOCKS_IN_FLIGHT_PER_PEER);
    BOOST_CHECK_EQUAL(
        tracker.InFlightCount(),
        node::MAX_CHILD_BLOCKS_IN_FLIGHT_PER_PEER);
    BOOST_CHECK(tracker.IsInFlight(requests.front()));

    BOOST_CHECK(
        tracker.ReceivedBlock(2, requests.front()) ==
        node::ChildBlockDownloadError::WRONG_PEER);
    BOOST_CHECK(tracker.IsInFlight(requests.front()));
    BOOST_CHECK(
        tracker.ReceivedBlock(1, uint256{42}) ==
        node::ChildBlockDownloadError::UNSOLICITED_BLOCK);
    BOOST_CHECK(
        tracker.ReceivedBlock(1, requests.front()) ==
        node::ChildBlockDownloadError::NONE);
    BOOST_CHECK(!tracker.IsInFlight(requests.front()));
    BOOST_CHECK_EQUAL(
        tracker.InFlightCount(),
        node::MAX_CHILD_BLOCKS_IN_FLIGHT_PER_PEER - 1);
}

BOOST_AUTO_TEST_CASE(retries_alternative_source_after_timeout)
{
    node::ChildBlockDownloadTracker tracker;
    const std::vector<uint256> hashes{uint256{1}};
    BOOST_REQUIRE(
        tracker.Announce(1, hashes) ==
        node::ChildBlockDownloadError::NONE);
    BOOST_REQUIRE(
        tracker.Announce(2, hashes) ==
        node::ChildBlockDownloadError::NONE);

    const auto first{tracker.Schedule(1, 1s)};
    BOOST_REQUIRE_EQUAL(first.size(), 1U);
    BOOST_CHECK(tracker.Schedule(2, 2s).empty());

    const auto expired{
        tracker.Expire(1s + node::CHILD_BLOCK_REQUEST_TIMEOUT)};
    BOOST_REQUIRE_EQUAL(expired.size(), 1U);
    BOOST_CHECK_EQUAL(expired.front().peer, 1);
    BOOST_CHECK(expired.front().block_hash == hashes.front());
    BOOST_CHECK_EQUAL(tracker.PeerAnnouncementCount(1), 0U);
    BOOST_CHECK_EQUAL(tracker.PeerAnnouncementCount(2), 1U);

    const auto retry{
        tracker.Schedule(2, 1s + node::CHILD_BLOCK_REQUEST_TIMEOUT)};
    BOOST_REQUIRE_EQUAL(retry.size(), 1U);
    BOOST_CHECK(retry.front() == hashes.front());
}

BOOST_AUTO_TEST_CASE(disconnect_releases_requests_and_candidates)
{
    node::ChildBlockDownloadTracker tracker;
    const std::vector<uint256> shared{uint256{1}};
    const std::vector<uint256> private_hash{uint256{2}};
    BOOST_REQUIRE(
        tracker.Announce(1, shared) ==
        node::ChildBlockDownloadError::NONE);
    BOOST_REQUIRE(
        tracker.Announce(2, shared) ==
        node::ChildBlockDownloadError::NONE);
    BOOST_REQUIRE(
        tracker.Announce(1, private_hash) ==
        node::ChildBlockDownloadError::NONE);
    BOOST_REQUIRE_EQUAL(tracker.Schedule(1, 1s).size(), 2U);

    tracker.DisconnectedPeer(1);
    BOOST_CHECK_EQUAL(tracker.InFlightCount(), 0U);
    BOOST_CHECK_EQUAL(tracker.PeerAnnouncementCount(1), 0U);
    BOOST_CHECK_EQUAL(tracker.CandidateCount(), 1U);
    BOOST_CHECK_EQUAL(tracker.AnnouncementCount(), 1U);

    const auto retry{tracker.Schedule(2, 2s)};
    BOOST_REQUIRE_EQUAL(retry.size(), 1U);
    BOOST_CHECK(retry.front() == shared.front());
    tracker.ForgetBlock(shared.front());
    BOOST_CHECK_EQUAL(tracker.CandidateCount(), 0U);
    BOOST_CHECK_EQUAL(tracker.InFlightCount(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
