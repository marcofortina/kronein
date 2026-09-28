// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/child_block_download.h>

#include <chainregistry/child_net.h>

#include <algorithm>
#include <set>

namespace node {

void ChildBlockDownloadTracker::RemoveSource(
    ChildPeerId peer,
    const uint256& block_hash)
{
    const auto candidate_it{m_candidates.find(block_hash)};
    if (candidate_it == m_candidates.end() ||
        candidate_it->second.sources.erase(peer) == 0) {
        return;
    }
    --m_announcement_count;

    const auto peer_it{m_peer_announcements.find(peer)};
    if (peer_it != m_peer_announcements.end()) {
        peer_it->second.erase(block_hash);
        if (peer_it->second.empty()) m_peer_announcements.erase(peer_it);
    }

    if (candidate_it->second.sources.empty() &&
        !candidate_it->second.in_flight) {
        m_candidates.erase(candidate_it);
    }
}

void ChildBlockDownloadTracker::EraseCandidate(const uint256& block_hash)
{
    const auto candidate_it{m_candidates.find(block_hash)};
    if (candidate_it == m_candidates.end()) return;

    if (candidate_it->second.in_flight) {
        const ChildPeerId peer{candidate_it->second.in_flight->peer};
        const auto in_flight_it{m_peer_in_flight.find(peer)};
        if (in_flight_it != m_peer_in_flight.end()) {
            if (--in_flight_it->second == 0) {
                m_peer_in_flight.erase(in_flight_it);
            }
        }
        --m_in_flight_count;
    }

    for (const ChildPeerId peer : candidate_it->second.sources) {
        const auto peer_it{m_peer_announcements.find(peer)};
        if (peer_it != m_peer_announcements.end()) {
            peer_it->second.erase(block_hash);
            if (peer_it->second.empty()) {
                m_peer_announcements.erase(peer_it);
            }
        }
        --m_announcement_count;
    }
    m_candidates.erase(candidate_it);
}

ChildBlockDownloadError ChildBlockDownloadTracker::Announce(
    ChildPeerId peer,
    std::span<const uint256> block_hashes)
{
    if (block_hashes.empty()) {
        return ChildBlockDownloadError::EMPTY_ANNOUNCEMENT;
    }
    if (block_hashes.size() >
        chainregistry::MAX_CHILD_BLOCK_REQUEST_HASHES) {
        return ChildBlockDownloadError::TOO_MANY_HASHES;
    }

    std::set<uint256> unique;
    size_t new_announcements{0};
    size_t new_candidates{0};
    for (const uint256& hash : block_hashes) {
        if (hash.IsNull()) {
            return ChildBlockDownloadError::NULL_BLOCK_HASH;
        }
        if (!unique.insert(hash).second) {
            return ChildBlockDownloadError::DUPLICATE_BLOCK_HASH;
        }
        const auto candidate_it{m_candidates.find(hash)};
        if (candidate_it == m_candidates.end()) {
            ++new_candidates;
            ++new_announcements;
        } else if (!candidate_it->second.sources.contains(peer)) {
            ++new_announcements;
        }
    }

    if (PeerAnnouncementCount(peer) + new_announcements >
        MAX_CHILD_BLOCK_ANNOUNCEMENTS_PER_PEER) {
        return ChildBlockDownloadError::PEER_ANNOUNCEMENT_LIMIT;
    }
    if (m_announcement_count + new_announcements >
        MAX_CHILD_BLOCK_ANNOUNCEMENTS) {
        return ChildBlockDownloadError::GLOBAL_ANNOUNCEMENT_LIMIT;
    }
    if (m_candidates.size() + new_candidates >
        MAX_CHILD_BLOCK_CANDIDATES) {
        return ChildBlockDownloadError::GLOBAL_CANDIDATE_LIMIT;
    }

    for (const uint256& hash : block_hashes) {
        auto& candidate{m_candidates[hash]};
        if (candidate.sources.insert(peer).second) {
            m_peer_announcements[peer].insert(hash);
            ++m_announcement_count;
        }
    }
    return ChildBlockDownloadError::NONE;
}

bool ChildBlockDownloadTracker::SetPriority(
    const uint256& block_hash,
    uint32_t priority)
{
    const auto it{m_candidates.find(block_hash)};
    if (it == m_candidates.end()) return false;
    it->second.priority = priority;
    return true;
}

std::vector<ChildBlockRequest> ChildBlockDownloadTracker::Expire(
    ChildRequestTime now)
{
    std::vector<ChildBlockRequest> expired;
    for (auto it = m_candidates.begin(); it != m_candidates.end();) {
        if (!it->second.in_flight || it->second.in_flight->expiry > now) {
            ++it;
            continue;
        }

        const uint256 hash{it->first};
        const ChildPeerId peer{it->second.in_flight->peer};
        expired.push_back({peer, hash});

        const auto in_flight_it{m_peer_in_flight.find(peer)};
        if (in_flight_it != m_peer_in_flight.end()) {
            if (--in_flight_it->second == 0) {
                m_peer_in_flight.erase(in_flight_it);
            }
        }
        --m_in_flight_count;
        it->second.in_flight.reset();

        // Do not immediately assign the same stalled peer again. A fresh
        // announcement can make it eligible after alternative sources fail.
        RemoveSource(peer, hash);
        it = m_candidates.upper_bound(hash);
    }
    return expired;
}

std::vector<uint256> ChildBlockDownloadTracker::Schedule(
    ChildPeerId peer,
    ChildRequestTime now)
{
    std::vector<uint256> result;
    const size_t peer_in_flight{PeerInFlightCount(peer)};
    const size_t peer_capacity{
        MAX_CHILD_BLOCKS_IN_FLIGHT_PER_PEER - peer_in_flight};
    const size_t global_capacity{
        MAX_CHILD_BLOCKS_IN_FLIGHT - m_in_flight_count};
    const size_t capacity{std::min({
        peer_capacity,
        global_capacity,
        static_cast<size_t>(
            chainregistry::MAX_CHILD_BLOCK_REQUEST_HASHES)})};
    if (capacity == 0) return result;

    std::vector<std::pair<uint32_t, uint256>> eligible;
    eligible.reserve(m_candidates.size());
    for (const auto& [hash, candidate] : m_candidates) {
        if (!candidate.in_flight && candidate.sources.contains(peer)) {
            eligible.emplace_back(candidate.priority, hash);
        }
    }
    std::sort(eligible.begin(), eligible.end());

    for (const auto& entry : eligible) {
        if (result.size() == capacity) break;
        const uint256& hash{entry.second};
        auto& candidate{m_candidates.at(hash)};
        candidate.in_flight = InFlight{
            peer,
            now + CHILD_BLOCK_REQUEST_TIMEOUT,
        };
        result.push_back(hash);
        ++m_peer_in_flight[peer];
        ++m_in_flight_count;
    }
    return result;
}

ChildBlockDownloadError ChildBlockDownloadTracker::ReceivedBlock(
    ChildPeerId peer,
    const uint256& block_hash)
{
    const auto candidate_it{m_candidates.find(block_hash)};
    if (candidate_it == m_candidates.end() ||
        !candidate_it->second.in_flight) {
        return ChildBlockDownloadError::UNSOLICITED_BLOCK;
    }
    if (candidate_it->second.in_flight->peer != peer) {
        return ChildBlockDownloadError::WRONG_PEER;
    }
    EraseCandidate(block_hash);
    return ChildBlockDownloadError::NONE;
}

void ChildBlockDownloadTracker::ForgetBlock(const uint256& block_hash)
{
    EraseCandidate(block_hash);
}

void ChildBlockDownloadTracker::DisconnectedPeer(ChildPeerId peer)
{
    std::vector<uint256> hashes;
    if (const auto peer_it{m_peer_announcements.find(peer)};
        peer_it != m_peer_announcements.end()) {
        hashes.assign(peer_it->second.begin(), peer_it->second.end());
    }

    for (const uint256& hash : hashes) {
        const auto candidate_it{m_candidates.find(hash)};
        if (candidate_it != m_candidates.end() &&
            candidate_it->second.in_flight &&
            candidate_it->second.in_flight->peer == peer) {
            const auto in_flight_it{m_peer_in_flight.find(peer)};
            if (in_flight_it != m_peer_in_flight.end()) {
                if (--in_flight_it->second == 0) {
                    m_peer_in_flight.erase(in_flight_it);
                }
            }
            --m_in_flight_count;
            candidate_it->second.in_flight.reset();
        }
        RemoveSource(peer, hash);
    }
    m_peer_in_flight.erase(peer);
}

size_t ChildBlockDownloadTracker::PeerAnnouncementCount(
    ChildPeerId peer) const
{
    const auto it{m_peer_announcements.find(peer)};
    return it == m_peer_announcements.end() ? 0 : it->second.size();
}

size_t ChildBlockDownloadTracker::PeerInFlightCount(ChildPeerId peer) const
{
    const auto it{m_peer_in_flight.find(peer)};
    return it == m_peer_in_flight.end() ? 0 : it->second;
}

bool ChildBlockDownloadTracker::IsInFlight(
    const uint256& block_hash) const
{
    const auto it{m_candidates.find(block_hash)};
    return it != m_candidates.end() && it->second.in_flight.has_value();
}

} // namespace node
