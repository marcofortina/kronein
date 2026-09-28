// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_fork_choice.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace {

uint256 Hash(uint64_t value)
{
    return ArithToUint256(arith_uint256{value});
}

chainregistry::ChildForkAnchor Anchor(uint64_t hash,
                                      uint32_t height,
                                      uint64_t work)
{
    return {
        .main_block_hash = Hash(hash),
        .main_height = height,
        .work = arith_uint256{work},
    };
}

chainregistry::ChildForkCandidate Candidate(
    uint64_t hash,
    uint64_t parent,
    std::vector<chainregistry::ChildForkAnchor> anchors)
{
    return {
        .block_hash = Hash(hash),
        .parent_hash = Hash(parent),
        .anchors = std::move(anchors),
    };
}

chainregistry::ChildForkPruneCandidate PruneCandidate(
    uint64_t hash,
    uint64_t parent,
    std::vector<chainregistry::ChildForkAnchor> anchors,
    bool prunable = true,
    uint64_t bytes = 100,
    uint64_t anchor_count = 1,
    uint64_t anchor_bytes = 50)
{
    return {
        .candidate = Candidate(hash, parent, std::move(anchors)),
        .side_candidate_bytes = prunable ? bytes : 0,
        .candidate_anchor_count = anchor_count,
        .candidate_anchor_bytes = anchor_bytes,
        .prunable = prunable,
    };
}

} // namespace

BOOST_AUTO_TEST_SUITE(child_fork_choice_tests)

BOOST_AUTO_TEST_CASE(selects_most_anchored_work_independent_of_arrival_order)
{
    const uint256 genesis{Hash(1)};
    std::vector<chainregistry::ChildForkCandidate> candidates{
        Candidate(10, 1, {Anchor(101, 1, 5)}),
        Candidate(11, 1, {Anchor(102, 2, 4)}),
        Candidate(20, 10, {Anchor(103, 3, 3)}),
        Candidate(21, 11, {Anchor(104, 4, 5)}),
    };

    const auto selected{
        chainregistry::SelectChildFork(genesis, candidates)};
    BOOST_REQUIRE(selected.IsValid());
    BOOST_CHECK(selected.head == Hash(21));
    BOOST_CHECK_EQUAL(selected.head_score.child_height, 2U);
    BOOST_CHECK_EQUAL(selected.head_score.activation_main_height, 4U);
    BOOST_CHECK(selected.head_score.cumulative_anchor_work ==
                arith_uint256{9});

    std::reverse(candidates.begin(), candidates.end());
    const auto reversed{
        chainregistry::SelectChildFork(genesis, candidates)};
    BOOST_REQUIRE(reversed.IsValid());
    BOOST_CHECK(reversed.head == selected.head);
    BOOST_CHECK(reversed.head_score.cumulative_anchor_work ==
                selected.head_score.cumulative_anchor_work);
}

BOOST_AUTO_TEST_CASE(repeated_anchors_add_work_once_and_survive_late_reveal)
{
    const uint256 genesis{Hash(1)};
    const auto branch_a{Candidate(
        10,
        1,
        {Anchor(101, 1, 3), Anchor(103, 3, 5)})};
    const auto branch_b{Candidate(11, 1, {Anchor(102, 2, 7)})};

    const auto before_reveal{chainregistry::SelectChildFork(
        genesis, std::vector{branch_b})};
    BOOST_REQUIRE(before_reveal.IsValid());
    BOOST_CHECK(before_reveal.head == Hash(11));

    const auto after_reveal{chainregistry::SelectChildFork(
        genesis, std::vector{branch_b, branch_a})};
    BOOST_REQUIRE(after_reveal.IsValid());
    BOOST_CHECK(after_reveal.head == Hash(10));
    BOOST_CHECK(after_reveal.head_score.own_anchor_work ==
                arith_uint256{8});

    const auto after_main_reorg{chainregistry::SelectChildFork(
        genesis,
        std::vector{
            Candidate(10, 1, {Anchor(101, 1, 3)}),
            branch_b,
        })};
    BOOST_REQUIRE(after_main_reorg.IsValid());
    BOOST_CHECK(after_main_reorg.head == Hash(11));
}

BOOST_AUTO_TEST_CASE(ignores_anchors_not_after_parent_activation)
{
    const uint256 genesis{Hash(1)};
    const auto selected{chainregistry::SelectChildFork(
        genesis,
        {
            Candidate(10, 1, {Anchor(110, 10, 4)}),
            Candidate(
                20,
                10,
                {Anchor(109, 9, 100), Anchor(111, 11, 2)}),
            Candidate(30, 20, {Anchor(112, 12, 1)}),
        })};

    BOOST_REQUIRE(selected.IsValid());
    BOOST_CHECK(selected.head == Hash(30));
    BOOST_CHECK_EQUAL(selected.scores.at(Hash(20)).activation_main_height, 11U);
    BOOST_CHECK(selected.scores.at(Hash(20)).own_anchor_work ==
                arith_uint256{2});
    BOOST_CHECK(selected.head_score.cumulative_anchor_work ==
                arith_uint256{7});
}

BOOST_AUTO_TEST_CASE(retains_unanchored_ancestors_without_selecting_them)
{
    const uint256 genesis{Hash(1)};
    const auto selected{chainregistry::SelectChildFork(
        genesis,
        {
            Candidate(10, 1, {}),
            Candidate(20, 10, {Anchor(102, 2, 7)}),
            Candidate(11, 1, {Anchor(101, 1, 3)}),
        })};

    BOOST_REQUIRE(selected.IsValid());
    BOOST_CHECK(!selected.scores.at(Hash(10)).eligible);
    BOOST_CHECK(!selected.scores.at(Hash(20)).eligible);
    BOOST_CHECK(selected.head == Hash(11));
}

BOOST_AUTO_TEST_CASE(uses_height_then_hash_as_deterministic_tie_break)
{
    const uint256 genesis{Hash(1)};
    const auto height_tie{chainregistry::SelectChildFork(
        genesis,
        {
            Candidate(10, 1, {Anchor(101, 1, 5)}),
            Candidate(20, 10, {Anchor(102, 2, 5)}),
            Candidate(11, 1, {Anchor(103, 3, 10)}),
        })};
    BOOST_REQUIRE(height_tie.IsValid());
    BOOST_CHECK(height_tie.head == Hash(20));

    const auto hash_tie{chainregistry::SelectChildFork(
        genesis,
        {
            Candidate(12, 1, {Anchor(104, 4, 10)}),
            Candidate(11, 1, {Anchor(105, 5, 10)}),
        })};
    BOOST_REQUIRE(hash_tie.IsValid());
    BOOST_CHECK(hash_tie.head == Hash(11));
}

BOOST_AUTO_TEST_CASE(rejects_ambiguous_or_invalid_candidate_graphs)
{
    const uint256 genesis{Hash(1)};

    const auto duplicate_height{chainregistry::SelectChildFork(
        genesis,
        {
            Candidate(10, 1, {Anchor(101, 1, 1)}),
            Candidate(11, 1, {Anchor(102, 1, 1)}),
        })};
    BOOST_CHECK_EQUAL(
        static_cast<int>(duplicate_height.error),
        static_cast<int>(
            chainregistry::ChildForkChoiceError::DUPLICATE_MAIN_HEIGHT));

    const auto unknown_parent{chainregistry::SelectChildFork(
        genesis,
        {Candidate(10, 99, {Anchor(103, 2, 1)})})};
    BOOST_CHECK_EQUAL(
        static_cast<int>(unknown_parent.error),
        static_cast<int>(
            chainregistry::ChildForkChoiceError::UNKNOWN_PARENT));

    const auto cycle{chainregistry::SelectChildFork(
        genesis,
        {
            Candidate(10, 11, {Anchor(104, 3, 1)}),
            Candidate(11, 10, {Anchor(105, 4, 1)}),
        })};
    BOOST_CHECK_EQUAL(
        static_cast<int>(cycle.error),
        static_cast<int>(
            chainregistry::ChildForkChoiceError::CYCLIC_PARENT));
}

BOOST_AUTO_TEST_CASE(pruning_protects_selected_branch_and_removes_weakest_leaf)
{
    const uint256 genesis{Hash(1)};
    std::vector<chainregistry::ChildForkPruneCandidate> candidates{
        PruneCandidate(10, 1, {Anchor(101, 1, 5)}, false),
        PruneCandidate(20, 10, {Anchor(102, 2, 5)}),
        PruneCandidate(11, 1, {Anchor(103, 3, 3)}),
        PruneCandidate(12, 1, {}),
    };
    const chainregistry::ChildForkPruneLimits limits{
        .side_candidate_count = 2,
        .side_candidate_bytes = 1'000,
        .candidate_anchor_count = 10,
        .candidate_anchor_bytes = 1'000,
    };

    const auto result{chainregistry::SelectChildForkPruning(
        genesis, candidates, limits)};
    BOOST_REQUIRE(result.IsValid());
    BOOST_CHECK(result.fork_choice.head == Hash(20));
    BOOST_REQUIRE_EQUAL(result.pruned.size(), 1U);
    BOOST_CHECK(result.pruned.front() == Hash(12));
    BOOST_CHECK_EQUAL(result.side_candidate_count, 2U);

    std::reverse(candidates.begin(), candidates.end());
    const auto reversed{chainregistry::SelectChildForkPruning(
        genesis, candidates, limits)};
    BOOST_REQUIRE(reversed.IsValid());
    BOOST_CHECK(reversed.pruned == result.pruned);
}

BOOST_AUTO_TEST_CASE(pruning_removes_only_leaves_and_can_collapse_a_losing_branch)
{
    const uint256 genesis{Hash(1)};
    const auto result{chainregistry::SelectChildForkPruning(
        genesis,
        {
            PruneCandidate(10, 1, {Anchor(101, 1, 10)}, false),
            PruneCandidate(11, 1, {Anchor(102, 2, 1)}),
            PruneCandidate(21, 11, {Anchor(103, 3, 1)}),
            PruneCandidate(31, 21, {}),
        },
        {
            .side_candidate_count = 1,
            .side_candidate_bytes = 1'000,
            .candidate_anchor_count = 10,
            .candidate_anchor_bytes = 1'000,
        })};

    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE_EQUAL(result.pruned.size(), 2U);
    BOOST_CHECK(result.pruned[0] == Hash(31));
    BOOST_CHECK(result.pruned[1] == Hash(21));
    BOOST_CHECK_EQUAL(result.side_candidate_count, 1U);
}

BOOST_AUTO_TEST_CASE(pruning_honors_byte_and_anchor_budgets)
{
    const uint256 genesis{Hash(1)};
    const auto result{chainregistry::SelectChildForkPruning(
        genesis,
        {
            PruneCandidate(10, 1, {Anchor(101, 1, 10)}, false,
                           0, 2, 80),
            PruneCandidate(11, 1, {Anchor(102, 2, 1)}, true,
                           300, 3, 120),
            PruneCandidate(12, 1, {}, true, 200, 2, 100),
        },
        {
            .side_candidate_count = 10,
            .side_candidate_bytes = 300,
            .candidate_anchor_count = 5,
            .candidate_anchor_bytes = 200,
        })};

    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE_EQUAL(result.pruned.size(), 1U);
    BOOST_CHECK(result.pruned.front() == Hash(12));
    BOOST_CHECK_EQUAL(result.side_candidate_bytes, 300U);
    BOOST_CHECK_EQUAL(result.candidate_anchor_count, 5U);
    BOOST_CHECK_EQUAL(result.candidate_anchor_bytes, 200U);
}

BOOST_AUTO_TEST_CASE(pruning_fails_instead_of_discarding_the_selected_branch)
{
    const uint256 genesis{Hash(1)};
    const auto result{chainregistry::SelectChildForkPruning(
        genesis,
        {
            PruneCandidate(10, 1, {Anchor(101, 1, 5)}),
            PruneCandidate(20, 10, {Anchor(102, 2, 5)}),
        },
        {
            .side_candidate_count = 1,
            .side_candidate_bytes = 1'000,
            .candidate_anchor_count = 10,
            .candidate_anchor_bytes = 1'000,
        })};

    BOOST_CHECK_EQUAL(
        static_cast<int>(result.error),
        static_cast<int>(
            chainregistry::ChildForkPruneError::LIMIT_UNSATISFIABLE));
    BOOST_CHECK(result.pruned.empty());
}

BOOST_AUTO_TEST_SUITE_END()
