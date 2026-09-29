// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CHAINREGISTRY_CHILD_FORK_CHOICE_H
#define BITCOIN_CHAINREGISTRY_CHILD_FORK_CHOICE_H

#include <arith_uint256.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace chainregistry {

/** One active-main-chain vote for a child block candidate. */
struct ChildForkAnchor {
    uint256 main_block_hash;
    uint32_t main_height{0};
    arith_uint256 work;
};

/** A consensus-valid child block and all known active anchors for its hash. */
struct ChildForkCandidate {
    uint256 block_hash;
    uint256 parent_hash;
    std::vector<ChildForkAnchor> anchors;
};

struct ChildForkScore {
    bool eligible{false};
    uint32_t child_height{0};
    uint32_t activation_main_height{0};
    arith_uint256 own_anchor_work;
    arith_uint256 cumulative_anchor_work;
};

enum class ChildForkChoiceError : uint8_t {
    NONE,
    NULL_GENESIS,
    NULL_BLOCK_HASH,
    GENESIS_REDEFINED,
    DUPLICATE_BLOCK,
    UNKNOWN_PARENT,
    NULL_MAIN_BLOCK,
    INVALID_MAIN_HEIGHT,
    ZERO_MAIN_WORK,
    DUPLICATE_MAIN_BLOCK,
    DUPLICATE_MAIN_HEIGHT,
    CYCLIC_PARENT,
    HEIGHT_OVERFLOW,
    WORK_OVERFLOW,
};

struct ChildForkChoiceResult {
    ChildForkChoiceError error{ChildForkChoiceError::NONE};
    uint256 head;
    ChildForkScore head_score;
    std::map<uint256, ChildForkScore> scores;
    std::optional<uint256> failed_candidate;
    std::optional<uint256> failed_main_block;

    bool IsValid() const { return error == ChildForkChoiceError::NONE; }
};

/**
 * Select a child head from an unordered candidate DAG.
 *
 * Every active main block may contribute its proof-of-work to at most one
 * child candidate. Candidates without an active anchor remain in the DAG as
 * ineligible ancestors. A candidate becomes eligible at its earliest anchor
 * after its parent's activation height. All of its eligible anchors contribute
 * work once, and branch work is the sum along the child ancestry. Equal work
 * is resolved by greater child height and then the lower child block hash.
 */
ChildForkChoiceResult SelectChildFork(
    const uint256& child_genesis_hash,
    const std::vector<ChildForkCandidate>& candidates);

/** Storage accounting for one candidate considered by DAG pruning. */
struct ChildForkPruneCandidate {
    ChildForkCandidate candidate;
    uint64_t side_candidate_bytes{0};
    uint64_t candidate_anchor_count{0};
    uint64_t candidate_anchor_bytes{0};
    /** Canonical candidates are structural inputs and may never be pruned. */
    bool prunable{false};
};

struct ChildForkPruneLimits {
    uint64_t side_candidate_count{0};
    uint64_t side_candidate_bytes{0};
    uint64_t candidate_anchor_count{0};
    uint64_t candidate_anchor_bytes{0};
};

enum class ChildForkPruneError : uint8_t {
    NONE,
    INVALID_FORK_CHOICE,
    DUPLICATE_CANDIDATE,
    INVALID_ACCOUNTING,
    ACCOUNTING_OVERFLOW,
    LIMIT_UNSATISFIABLE,
};

struct ChildForkPruneResult {
    ChildForkPruneError error{ChildForkPruneError::NONE};
    ChildForkChoiceResult fork_choice;
    std::vector<uint256> pruned;
    uint64_t side_candidate_count{0};
    uint64_t side_candidate_bytes{0};
    uint64_t candidate_anchor_count{0};
    uint64_t candidate_anchor_bytes{0};

    bool IsValid() const { return error == ChildForkPruneError::NONE; }
};

/**
 * Select side-candidate leaves to remove until every storage limit is met.
 *
 * The selected head, its complete ancestry and every canonical candidate are
 * protected. Only non-protected leaves are removable, so the retained graph
 * is always parent-complete. The least competitive leaf is removed first:
 * ineligible candidates, then lower cumulative anchor work, lower child
 * height, and finally the numerically greater child hash.
 */
ChildForkPruneResult SelectChildForkPruning(
    const uint256& child_genesis_hash,
    const std::vector<ChildForkPruneCandidate>& candidates,
    const ChildForkPruneLimits& limits);

} // namespace chainregistry

#endif // BITCOIN_CHAINREGISTRY_CHILD_FORK_CHOICE_H
