// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_fork_choice.h>

#include <limits>
#include <map>
#include <set>

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

} // namespace chainregistry
