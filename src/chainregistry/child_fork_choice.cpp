// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_fork_choice.h>

#include <limits>
#include <map>
#include <set>
#include <vector>

namespace chainregistry {
namespace {

enum class VisitState : uint8_t {
    UNVISITED,
    VISITING,
    VISITED,
};

ChildForkChoiceResult ForkError(
    ChildForkChoiceError error,
    std::optional<uint256> failed_candidate = std::nullopt,
    std::optional<uint256> failed_main_block = std::nullopt)
{
    ChildForkChoiceResult result;
    result.error = error;
    result.failed_candidate = failed_candidate;
    result.failed_main_block = failed_main_block;
    return result;
}

bool BetterHead(const uint256& candidate_hash,
                const ChildForkScore& candidate,
                const uint256& current_hash,
                const ChildForkScore& current)
{
    if (candidate.cumulative_anchor_work != current.cumulative_anchor_work) {
        return candidate.cumulative_anchor_work >
               current.cumulative_anchor_work;
    }
    if (candidate.child_height != current.child_height) {
        return candidate.child_height > current.child_height;
    }
    return candidate_hash < current_hash;
}

bool WorsePruneCandidate(const uint256& candidate_hash,
                         const ChildForkScore& candidate,
                         const uint256& current_hash,
                         const ChildForkScore& current)
{
    if (candidate.eligible != current.eligible) return !candidate.eligible;
    if (candidate.cumulative_anchor_work != current.cumulative_anchor_work) {
        return candidate.cumulative_anchor_work <
               current.cumulative_anchor_work;
    }
    if (candidate.child_height != current.child_height) {
        return candidate.child_height < current.child_height;
    }
    return current_hash < candidate_hash;
}

} // namespace

ChildForkChoiceResult SelectChildFork(
    const uint256& child_genesis_hash,
    const std::vector<ChildForkCandidate>& candidates)
{
    if (child_genesis_hash.IsNull()) {
        return ForkError(ChildForkChoiceError::NULL_GENESIS);
    }

    std::map<uint256, const ChildForkCandidate*> by_hash;
    std::set<uint256> main_blocks;
    std::set<uint32_t> main_heights;
    for (const auto& candidate : candidates) {
        if (candidate.block_hash.IsNull()) {
            return ForkError(ChildForkChoiceError::NULL_BLOCK_HASH);
        }
        if (candidate.block_hash == child_genesis_hash) {
            return ForkError(
                ChildForkChoiceError::GENESIS_REDEFINED,
                candidate.block_hash);
        }
        if (!by_hash.emplace(candidate.block_hash, &candidate).second) {
            return ForkError(
                ChildForkChoiceError::DUPLICATE_BLOCK,
                candidate.block_hash);
        }
        for (const auto& anchor : candidate.anchors) {
            if (anchor.main_block_hash.IsNull()) {
                return ForkError(
                    ChildForkChoiceError::NULL_MAIN_BLOCK,
                    candidate.block_hash);
            }
            if (anchor.main_height == 0) {
                return ForkError(
                    ChildForkChoiceError::INVALID_MAIN_HEIGHT,
                    candidate.block_hash,
                    anchor.main_block_hash);
            }
            if (anchor.work == 0) {
                return ForkError(
                    ChildForkChoiceError::ZERO_MAIN_WORK,
                    candidate.block_hash,
                    anchor.main_block_hash);
            }
            if (!main_blocks.insert(anchor.main_block_hash).second) {
                return ForkError(
                    ChildForkChoiceError::DUPLICATE_MAIN_BLOCK,
                    candidate.block_hash,
                    anchor.main_block_hash);
            }
            if (!main_heights.insert(anchor.main_height).second) {
                return ForkError(
                    ChildForkChoiceError::DUPLICATE_MAIN_HEIGHT,
                    candidate.block_hash,
                    anchor.main_block_hash);
            }
        }
    }

    for (const auto& candidate : candidates) {
        if (candidate.parent_hash != child_genesis_hash &&
            !by_hash.contains(candidate.parent_hash)) {
            return ForkError(
                ChildForkChoiceError::UNKNOWN_PARENT,
                candidate.block_hash);
        }
    }

    ChildForkChoiceResult result;
    result.head = child_genesis_hash;
    std::map<uint256, VisitState> visits;

    const auto evaluate = [&](const auto& self,
                              const ChildForkCandidate& candidate)
        -> ChildForkChoiceError {
        VisitState& visit{visits[candidate.block_hash]};
        if (visit == VisitState::VISITED) return ChildForkChoiceError::NONE;
        if (visit == VisitState::VISITING) {
            result.failed_candidate = candidate.block_hash;
            return ChildForkChoiceError::CYCLIC_PARENT;
        }
        visit = VisitState::VISITING;

        ChildForkScore parent_score;
        if (candidate.parent_hash != child_genesis_hash) {
            const ChildForkCandidate& parent{*by_hash.at(candidate.parent_hash)};
            const auto error{self(self, parent)};
            if (error != ChildForkChoiceError::NONE) return error;
            parent_score = result.scores.at(candidate.parent_hash);
        }
        if (parent_score.child_height ==
            std::numeric_limits<uint32_t>::max()) {
            result.failed_candidate = candidate.block_hash;
            return ChildForkChoiceError::HEIGHT_OVERFLOW;
        }

        ChildForkScore score;
        score.child_height = parent_score.child_height + 1;
        if (candidate.parent_hash == child_genesis_hash ||
            parent_score.eligible) {
            for (const auto& anchor : candidate.anchors) {
                if (anchor.main_height <=
                    parent_score.activation_main_height) {
                    continue;
                }
                if (!score.eligible ||
                    anchor.main_height < score.activation_main_height) {
                    score.activation_main_height = anchor.main_height;
                }
                score.eligible = true;
                const arith_uint256 previous{score.own_anchor_work};
                score.own_anchor_work += anchor.work;
                if (score.own_anchor_work < previous) {
                    result.failed_candidate = candidate.block_hash;
                    result.failed_main_block = anchor.main_block_hash;
                    return ChildForkChoiceError::WORK_OVERFLOW;
                }
            }
        }
        if (score.eligible) {
            score.cumulative_anchor_work =
                parent_score.cumulative_anchor_work;
            const arith_uint256 previous{score.cumulative_anchor_work};
            score.cumulative_anchor_work += score.own_anchor_work;
            if (score.cumulative_anchor_work < previous) {
                result.failed_candidate = candidate.block_hash;
                return ChildForkChoiceError::WORK_OVERFLOW;
            }
        }
        result.scores.emplace(candidate.block_hash, score);
        visit = VisitState::VISITED;
        return ChildForkChoiceError::NONE;
    };

    for (const auto& [hash, candidate] : by_hash) {
        const auto error{evaluate(evaluate, *candidate)};
        if (error != ChildForkChoiceError::NONE) {
            result.error = error;
            return result;
        }
        const ChildForkScore& score{result.scores.at(hash)};
        if (score.eligible && BetterHead(
                hash, score, result.head, result.head_score)) {
            result.head = hash;
            result.head_score = score;
        }
    }
    return result;
}

ChildForkPruneResult SelectChildForkPruning(
    const uint256& child_genesis_hash,
    const std::vector<ChildForkPruneCandidate>& candidates,
    const ChildForkPruneLimits& limits)
{
    ChildForkPruneResult result;
    std::vector<ChildForkCandidate> fork_candidates;
    fork_candidates.reserve(candidates.size());
    std::map<uint256, const ChildForkPruneCandidate*> by_hash;
    for (const auto& candidate : candidates) {
        const uint256& hash{candidate.candidate.block_hash};
        if (!by_hash.emplace(hash, &candidate).second) {
            result.error = ChildForkPruneError::DUPLICATE_CANDIDATE;
            return result;
        }
        if ((candidate.prunable &&
             (candidate.side_candidate_bytes == 0 ||
              candidate.candidate_anchor_count == 0 ||
              candidate.candidate_anchor_bytes == 0)) ||
            (!candidate.prunable && candidate.side_candidate_bytes != 0)) {
            result.error = ChildForkPruneError::INVALID_ACCOUNTING;
            return result;
        }
        if ((candidate.prunable &&
             result.side_candidate_count ==
                 std::numeric_limits<uint64_t>::max()) ||
            candidate.side_candidate_bytes >
                std::numeric_limits<uint64_t>::max() -
                    result.side_candidate_bytes ||
            candidate.candidate_anchor_count >
                std::numeric_limits<uint64_t>::max() -
                    result.candidate_anchor_count ||
            candidate.candidate_anchor_bytes >
                std::numeric_limits<uint64_t>::max() -
                    result.candidate_anchor_bytes) {
            result.error = ChildForkPruneError::ACCOUNTING_OVERFLOW;
            return result;
        }
        if (candidate.prunable) ++result.side_candidate_count;
        result.side_candidate_bytes += candidate.side_candidate_bytes;
        result.candidate_anchor_count += candidate.candidate_anchor_count;
        result.candidate_anchor_bytes += candidate.candidate_anchor_bytes;
        fork_candidates.push_back(candidate.candidate);
    }

    result.fork_choice = SelectChildFork(child_genesis_hash, fork_candidates);
    if (!result.fork_choice.IsValid()) {
        result.error = ChildForkPruneError::INVALID_FORK_CHOICE;
        return result;
    }

    std::set<uint256> protected_candidates;
    uint256 protected_hash{result.fork_choice.head};
    while (protected_hash != child_genesis_hash) {
        const auto candidate{by_hash.find(protected_hash)};
        if (candidate == by_hash.end() ||
            !protected_candidates.insert(protected_hash).second) {
            result.error = ChildForkPruneError::INVALID_FORK_CHOICE;
            return result;
        }
        protected_hash = candidate->second->candidate.parent_hash;
    }

    std::map<uint256, uint64_t> retained_children;
    std::set<uint256> retained;
    for (const auto& [hash, candidate] : by_hash) {
        retained.insert(hash);
        if (candidate->candidate.parent_hash != child_genesis_hash) {
            ++retained_children[candidate->candidate.parent_hash];
        }
    }

    const auto over_limit = [&] {
        return result.side_candidate_count > limits.side_candidate_count ||
               result.side_candidate_bytes > limits.side_candidate_bytes ||
               result.candidate_anchor_count >
                   limits.candidate_anchor_count ||
               result.candidate_anchor_bytes >
                   limits.candidate_anchor_bytes;
    };
    while (over_limit()) {
        std::optional<uint256> worst;
        for (const uint256& hash : retained) {
            const auto& candidate{*by_hash.at(hash)};
            if (!candidate.prunable || protected_candidates.contains(hash) ||
                retained_children[hash] != 0) {
                continue;
            }
            if (!worst || WorsePruneCandidate(
                    hash,
                    result.fork_choice.scores.at(hash),
                    *worst,
                    result.fork_choice.scores.at(*worst))) {
                worst = hash;
            }
        }
        if (!worst) {
            result.error = ChildForkPruneError::LIMIT_UNSATISFIABLE;
            return result;
        }

        const auto& candidate{*by_hash.at(*worst)};
        if (result.side_candidate_count == 0 ||
            candidate.side_candidate_bytes > result.side_candidate_bytes ||
            candidate.candidate_anchor_count >
                result.candidate_anchor_count ||
            candidate.candidate_anchor_bytes >
                result.candidate_anchor_bytes) {
            result.error = ChildForkPruneError::INVALID_ACCOUNTING;
            return result;
        }
        --result.side_candidate_count;
        result.side_candidate_bytes -= candidate.side_candidate_bytes;
        result.candidate_anchor_count -= candidate.candidate_anchor_count;
        result.candidate_anchor_bytes -= candidate.candidate_anchor_bytes;
        retained.erase(*worst);
        if (candidate.candidate.parent_hash != child_genesis_hash) {
            auto& children{retained_children[candidate.candidate.parent_hash]};
            if (children == 0) {
                result.error = ChildForkPruneError::INVALID_ACCOUNTING;
                return result;
            }
            --children;
        }
        result.pruned.push_back(*worst);
    }
    return result;
}

} // namespace chainregistry
