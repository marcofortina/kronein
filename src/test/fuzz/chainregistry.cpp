// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_block.h>
#include <chainregistry/child_fork_choice.h>
#include <chainregistry/child_net.h>
#include <chainregistry/deposit_import.h>
#include <chainregistry/mainchain_lightclient.h>
#include <consensus/bmm.h>
#include <consensus/chainregistry.h>
#include <consensus/deposit_proof.h>
#include <node/child_chain_db.h>
#include <primitives/bmm.h>
#include <primitives/chainregistry.h>
#include <primitives/deposit.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <optional>
#include <vector>

namespace {

template <typename T>
void FuzzPersistenceRecord(FuzzedDataProvider& provider)
{
    const auto record{ConsumeDeserializable<T>(provider)};
    if (!record) return;

    DataStream encoded;
    encoded << *record;
    const std::vector<std::byte> bytes{
        encoded.begin(), encoded.end()};
    SpanReader reader{bytes};
    T decoded;
    reader >> decoded;
    assert(reader.empty());

    DataStream reencoded;
    reencoded << decoded;
    assert(std::ranges::equal(bytes, reencoded));
}

} // namespace

FUZZ_TARGET(chainregistry_script_parsers)
{
    const CScript script{buffer.begin(), buffer.end()};

    const auto operation{chainregistry::ParseOperationScript(script)};
    if (operation) {
        const auto roundtrip{chainregistry::ParseOperationScript(
            chainregistry::BuildOperationScript(*operation.operation))};
        assert(roundtrip);
        assert(roundtrip.operation == operation.operation);
    }

    const auto fund{chainregistry::ParseFundScript(script)};
    if (fund) {
        const auto roundtrip{chainregistry::ParseFundScript(
            chainregistry::BuildFundScript(*fund.fund))};
        assert(roundtrip);
        assert(roundtrip.fund == fund.fund);
    }

    const auto anchor{chainregistry::ParseBmmAnchorScript(script)};
    if (anchor) {
        const auto roundtrip{chainregistry::ParseBmmAnchorScript(
            chainregistry::BuildBmmAnchorScript(*anchor.anchor))};
        assert(roundtrip);
        assert(roundtrip.anchor == anchor.anchor);
    }

    const auto commitment{chainregistry::ParseRegistryCommitment(script)};
    if (commitment.root) {
        const auto roundtrip{chainregistry::ParseRegistryCommitment(
            chainregistry::BuildRegistryCommitment(*commitment.root))};
        assert(roundtrip.root == commitment.root);
    }
}

FUZZ_TARGET(chainregistry_transaction_parsers)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const auto mutable_tx{ConsumeDeserializable<CMutableTransaction>(
        provider, TX_BASE)};
    if (!mutable_tx) return;

    const CTransaction tx{*mutable_tx};
    (void)chainregistry::ExtractTransactionOperation(
        tx, ConsumeMoney(provider));
    (void)chainregistry::ExtractTransactionFunds(tx);
    (void)chainregistry::ExtractTransactionBmmAnchor(tx);
}

FUZZ_TARGET(chainregistry_proof_parsers)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const uint256 main_genesis{ConsumeUInt256(provider)};
    const std::optional<chainregistry::ChainId> child_chain{
        provider.ConsumeBool()
            ? std::optional{chainregistry::ChainId::FromUint256(
                  ConsumeUInt256(provider))}
            : std::nullopt};

    if (const auto proof{ConsumeDeserializable<chainregistry::DepositProof>(
            provider)}) {
        (void)chainregistry::ValidateDepositProofStructure(
            *proof, main_genesis, child_chain);
    }
    if (const auto proof{ConsumeDeserializable<chainregistry::BmmAnchorProof>(
            provider)}) {
        (void)chainregistry::ValidateBmmAnchorProofStructure(
            *proof, main_genesis, child_chain);
    }
}

FUZZ_TARGET(chainregistry_merkle_proofs)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const uint256 expected_root{ConsumeUInt256(provider)};
    const chainregistry::ChainId target{
        chainregistry::ChainId::FromUint256(ConsumeUInt256(provider))};

    if (const auto entry{
            ConsumeDeserializable<chainregistry::RegistryProofEntry>(provider)}) {
        (void)chainregistry::VerifyRegistryInclusion(
            entry->record, entry->proof, expected_root);
    }
    if (const auto proof{
            ConsumeDeserializable<chainregistry::RegistryNonInclusionProof>(
                provider)}) {
        (void)chainregistry::VerifyRegistryNonInclusion(
            target, *proof, expected_root);
    }
}

FUZZ_TARGET(child_wire_parsers)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const chainregistry::ChainId expected_chain{
        chainregistry::ChainId::FromUint256(ConsumeUInt256(provider))};
    const uint256 expected_genesis{ConsumeUInt256(provider)};
    const uint256 requested_block{ConsumeUInt256(provider)};

    if (const auto message{
            ConsumeDeserializable<chainregistry::ChildNetHello>(provider)}) {
        (void)chainregistry::ValidateChildNetHello(
            *message, expected_chain, expected_genesis);
    }
    if (const auto message{
            ConsumeDeserializable<chainregistry::ChildBlockHashes>(provider)}) {
        (void)chainregistry::ValidateChildBlockHashes(
            *message, expected_chain);
    }
    if (const auto message{
            ConsumeDeserializable<chainregistry::ChildBlockData>(provider)}) {
        (void)chainregistry::ValidateChildBlockData(
            *message, expected_chain, requested_block);
    }
    if (const auto message{
            ConsumeDeserializable<chainregistry::ChildTransactionData>(
                provider)}) {
        (void)chainregistry::ValidateChildTransactionData(
            *message, expected_chain);
    }
    if (const auto message{
            ConsumeDeserializable<chainregistry::ChildAddressRequest>(
                provider)}) {
        (void)chainregistry::ValidateChildAddressRequest(
            *message, expected_chain);
    }
    if (const auto message{
            ConsumeDeserializable<chainregistry::ChildAddresses>(provider)}) {
        (void)chainregistry::ValidateChildAddresses(
            *message, expected_chain);
    }
}

FUZZ_TARGET(child_persistence_records)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    CallOneOf(
        provider,
        [&] { FuzzPersistenceRecord<chainregistry::MainHeaderRecord>(provider); },
        [&] { FuzzPersistenceRecord<chainregistry::ImportedDeposit>(provider); },
        [&] { FuzzPersistenceRecord<chainregistry::DepositImportUndo>(provider); },
        [&] { FuzzPersistenceRecord<chainregistry::DepositSafeHalt>(provider); },
        [&] { FuzzPersistenceRecord<chainregistry::ReferenceChildBlockUndo>(provider); },
        [&] { FuzzPersistenceRecord<node::ChildBmmAnchorRecord>(provider); },
        [&] { FuzzPersistenceRecord<node::ChildBlockFilterRecord>(provider); },
        [&] { FuzzPersistenceRecord<node::ChildPendingBmmAnchorRecord>(provider); },
        [&] { FuzzPersistenceRecord<node::ChildCandidateRecord>(provider); },
        [&] { FuzzPersistenceRecord<node::ChildCandidateBmmAnchorRecord>(provider); },
        [&] { FuzzPersistenceRecord<node::ChildLocalProposalRecord>(provider); },
        [&] { FuzzPersistenceRecord<node::ChildChainDBState>(provider); });
}

FUZZ_TARGET(child_fork_choice)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const uint256 genesis{ConsumeUInt256(provider)};
    std::vector<chainregistry::ChildForkPruneCandidate> candidates;
    const size_t candidate_count{
        provider.ConsumeIntegralInRange<size_t>(0, 64)};
    candidates.reserve(candidate_count);
    for (size_t index{0}; index < candidate_count; ++index) {
        chainregistry::ChildForkCandidate candidate{
            .block_hash = ConsumeUInt256(provider),
            .parent_hash = ConsumeUInt256(provider),
            .anchors = {},
        };
        const size_t anchor_count{
            provider.ConsumeIntegralInRange<size_t>(0, 8)};
        candidate.anchors.reserve(anchor_count);
        for (size_t anchor{0}; anchor < anchor_count; ++anchor) {
            candidate.anchors.push_back({
                .main_block_hash = ConsumeUInt256(provider),
                .main_height = provider.ConsumeIntegral<uint32_t>(),
                .work = ConsumeArithUInt256(provider),
            });
        }
        const bool prunable{provider.ConsumeBool()};
        candidates.push_back({
            .candidate = std::move(candidate),
            .side_candidate_bytes = prunable
                ? provider.ConsumeIntegral<uint64_t>()
                : 0,
            .candidate_anchor_count =
                provider.ConsumeIntegral<uint64_t>(),
            .candidate_anchor_bytes =
                provider.ConsumeIntegral<uint64_t>(),
            .prunable = prunable,
        });
    }

    std::vector<chainregistry::ChildForkCandidate> fork_candidates;
    fork_candidates.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        fork_candidates.push_back(candidate.candidate);
    }
    const auto selected{
        chainregistry::SelectChildFork(genesis, fork_candidates)};
    if (selected.IsValid()) {
        std::reverse(fork_candidates.begin(), fork_candidates.end());
        const auto reversed{
            chainregistry::SelectChildFork(genesis, fork_candidates)};
        assert(reversed.IsValid());
        assert(reversed.head == selected.head);
        assert(reversed.head_score.child_height ==
               selected.head_score.child_height);
        assert(reversed.head_score.cumulative_anchor_work ==
               selected.head_score.cumulative_anchor_work);
    }

    const chainregistry::ChildForkPruneLimits limits{
        .side_candidate_count = provider.ConsumeIntegral<uint64_t>(),
        .side_candidate_bytes = provider.ConsumeIntegral<uint64_t>(),
        .candidate_anchor_count = provider.ConsumeIntegral<uint64_t>(),
        .candidate_anchor_bytes = provider.ConsumeIntegral<uint64_t>(),
    };
    const auto pruned{chainregistry::SelectChildForkPruning(
        genesis, candidates, limits)};
    if (pruned.IsValid()) {
        std::reverse(candidates.begin(), candidates.end());
        const auto reversed{chainregistry::SelectChildForkPruning(
            genesis, candidates, limits)};
        assert(reversed.IsValid());
        assert(reversed.fork_choice.head == pruned.fork_choice.head);
        assert(reversed.pruned == pruned.pruned);
    }
}
