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

BOOST_AUTO_TEST_SUITE_END()
