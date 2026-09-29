// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_CHILD_BLOCK_DOWNLOAD_H
#define BITCOIN_NODE_CHILD_BLOCK_DOWNLOAD_H

#include <uint256.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <vector>

namespace node {

/** Identifier local to an isolated child-chain transport. */
using ChildPeerId = int64_t;

/** Monotonic timestamp supplied by the transport event loop. */
using ChildRequestTime = std::chrono::microseconds;

inline constexpr size_t MAX_CHILD_BLOCK_ANNOUNCEMENTS_PER_PEER{256};
inline constexpr size_t MAX_CHILD_BLOCK_ANNOUNCEMENTS{8192};
inline constexpr size_t MAX_CHILD_BLOCK_CANDIDATES{4096};
inline constexpr size_t MAX_CHILD_BLOCKS_IN_FLIGHT_PER_PEER{16};
inline constexpr size_t MAX_CHILD_BLOCKS_IN_FLIGHT{128};
inline constexpr ChildRequestTime CHILD_BLOCK_REQUEST_TIMEOUT{
    std::chrono::seconds{30}};

enum class ChildBlockDownloadError : uint8_t {
    NONE,
    EMPTY_ANNOUNCEMENT,
    TOO_MANY_HASHES,
    NULL_BLOCK_HASH,
    DUPLICATE_BLOCK_HASH,
    PEER_ANNOUNCEMENT_LIMIT,
    GLOBAL_ANNOUNCEMENT_LIMIT,
    GLOBAL_CANDIDATE_LIMIT,
    UNSOLICITED_BLOCK,
    WRONG_PEER,
};

struct ChildBlockRequest {
    ChildPeerId peer{0};
    uint256 block_hash;
};

/**
 * Bounded block download state for one child chain.
 *
 * The tracker is intentionally independent from the main-chain PeerManager.
 * It does not perform I/O and is expected to be owned by one child transport
 * event loop. Announcements are admitted atomically. A timed-out source is
 * removed, allowing an alternative announcing peer to be selected without
 * immediately retrying the peer that stalled.
 */
class ChildBlockDownloadTracker
{
private:
    struct InFlight {
        ChildPeerId peer{0};
        ChildRequestTime expiry{0};
    };

    struct Candidate {
        std::set<ChildPeerId> sources;
        std::optional<InFlight> in_flight;
        uint32_t priority{std::numeric_limits<uint32_t>::max()};
    };

    std::map<uint256, Candidate> m_candidates;
    std::map<ChildPeerId, std::set<uint256>> m_peer_announcements;
    std::map<ChildPeerId, size_t> m_peer_in_flight;
    size_t m_announcement_count{0};
    size_t m_in_flight_count{0};

    void RemoveSource(ChildPeerId peer, const uint256& block_hash);
    void EraseCandidate(const uint256& block_hash);

public:
    ChildBlockDownloadError Announce(
        ChildPeerId peer,
        std::span<const uint256> block_hashes);

    /** Prefer lower values when selecting otherwise eligible blocks. */
    bool SetPriority(const uint256& block_hash, uint32_t priority);

    /** Expire stalled requests and return them for peer accounting. */
    std::vector<ChildBlockRequest> Expire(ChildRequestTime now);

    /**
     * Select and mark requests for a peer, up to all configured limits.
     * Expire() must be called by the event loop before scheduling a new round.
     */
    std::vector<uint256> Schedule(ChildPeerId peer, ChildRequestTime now);

    /** Match a response to the peer that owns the in-flight request. */
    ChildBlockDownloadError ReceivedBlock(
        ChildPeerId peer,
        const uint256& block_hash);

    void ForgetBlock(const uint256& block_hash);
    void DisconnectedPeer(ChildPeerId peer);

    size_t CandidateCount() const { return m_candidates.size(); }
    size_t AnnouncementCount() const { return m_announcement_count; }
    size_t InFlightCount() const { return m_in_flight_count; }
    size_t PeerAnnouncementCount(ChildPeerId peer) const;
    size_t PeerInFlightCount(ChildPeerId peer) const;
    bool IsInFlight(const uint256& block_hash) const;
};

} // namespace node

#endif // BITCOIN_NODE_CHILD_BLOCK_DOWNLOAD_H
