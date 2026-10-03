// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chainregistry.h>

#include <consensus/merkle.h>
#include <primitives/block.h>
#include <primitives/bmm.h>
#include <primitives/deposit.h>
#include <primitives/transaction.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <span>
#include <vector>

using namespace util::hex_literals;

namespace {

std::array<unsigned char, 32> DealerAuthorityKey()
{
    return "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"_hex_u8;
}

CBlock Block(const uint256& previous, const CScript& commitment = {})
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.emplace_back(0, commitment);

    CBlock block;
    block.hashPrevBlock = previous;
    block.nTime = 1;
    block.nBits = 0x207fffff;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    return block;
}

DBParams Params(const fs::path& path, bool wipe = false)
{
    return {
        .path = path,
        .cache_bytes = 1 << 20,
        .wipe_data = wipe,
        .obfuscate = true,
    };
}

chainregistry::ChainRecord Record()
{
    std::array<unsigned char, 32> control{};
    control.fill(3);
    return {
        .record_version = chainregistry::CHAIN_RECORD_VERSION,
        .chain_id = chainregistry::ChainId{"1111111111111111111111111111111111111111111111111111111111111111"},
        .manifest_hash = chainregistry::ManifestHash{"2222222222222222222222222222222222222222222222222222222222222222"},
        .template_id = 1,
        .template_version = 1,
        .control_outpoint = COutPoint{Txid::FromUint256(uint256{std::span{control}}), 0},
        .metadata_hash = chainregistry::MetadataHash{"4444444444444444444444444444444444444444444444444444444444444444"},
        .status = chainregistry::ChainStatus::ACTIVE,
        .registered_height = 100,
        .updated_height = 100,
        .retired_height = 0,
    };
}

CTransactionRef BmmProposal(const chainregistry::ChainId& chain_id,
                            const uint256& child_block_hash,
                            unsigned char input_byte)
{
    std::array<unsigned char, 32> input{};
    input.fill(input_byte);
    CMutableTransaction proposal;
    proposal.vin.emplace_back(
        COutPoint{Txid::FromUint256(uint256{std::span{input}}), 0});
    proposal.vout.emplace_back(
        0,
        chainregistry::BuildBmmAnchorScript({
            .chain_id = chain_id,
            .child_block_hash = child_block_hash,
        }));
    return MakeTransactionRef(std::move(proposal));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(chainregistry_state_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(connect_disconnect_and_reload)
{
    constexpr uint256 genesis_hash{"0101010101010101010101010101010101010101010101010101010101010101"};
    const Consensus::Params::ChainRegistryParams registry_params{
        .activation_height = 2,
        .dealer_authority = {1, {DealerAuthorityKey()}},
        .maximum_operations = 4,
    };
    const fs::path path{m_args.GetDataDirBase() / "chainregistry_state"};

    CBlock block_one{Block(genesis_hash)};
    const uint256 block_one_hash{block_one.GetHash()};
    const chainregistry::ChainRegistry empty_registry;
    CBlock block_two{Block(block_one_hash, chainregistry::BuildRegistryCommitment(empty_registry.ComputeRoot()))};
    const uint256 block_two_hash{block_two.GetHash()};

    {
        node::ChainRegistryState state{registry_params, genesis_hash};
        BOOST_REQUIRE(state.Initialize(Params(path, /*wipe=*/true), genesis_hash, 0).IsValid());
        BOOST_CHECK(state.Enabled());
        BOOST_REQUIRE(state.ConnectBlock(block_one, 1, block_one_hash, /*sync=*/true).IsValid());
        const CBlock missing_commitment{Block(block_one_hash)};
        const auto invalid{state.ConnectBlock(missing_commitment, 2, missing_commitment.GetHash())};
        BOOST_CHECK(invalid.error == node::ChainRegistryStateError::INVALID_BLOCK);
        BOOST_CHECK(invalid.block_result.error == chainregistry::RegistryBlockError::MISSING_COMMITMENT);
        BOOST_CHECK(state.State().best_block == block_one_hash);
        BOOST_REQUIRE(state.ConnectBlock(block_two, 2, block_two_hash, /*sync=*/true).IsValid());
        BOOST_CHECK(state.State().best_block == block_two_hash);
        BOOST_CHECK_EQUAL(state.State().height, 2U);
        BOOST_CHECK_EQUAL(state.Registry().Size(), 0U);
    }

    {
        node::ChainRegistryState state{registry_params, genesis_hash};
        const auto mismatched{state.Initialize(Params(path), block_one_hash, 1)};
        BOOST_CHECK(mismatched.error ==
                    node::ChainRegistryStateError::DATABASE_TIP_MISMATCH);
        BOOST_REQUIRE(state.IsInitialized());
        BOOST_CHECK(state.State().best_block == block_two_hash);
        BOOST_CHECK(state.UndoParent(block_two_hash) == block_one_hash);
        const auto wrong_parent{state.DisconnectBlock(block_two_hash, {}, -1)};
        BOOST_CHECK(wrong_parent.error == node::ChainRegistryStateError::NON_SEQUENTIAL_BLOCK);
        const auto mismatched_parent{
            state.DisconnectBlock(block_two_hash, genesis_hash, 1)};
        BOOST_CHECK(mismatched_parent.error ==
                    node::ChainRegistryStateError::UNDO_FAILED);
        const auto wrong_tip{state.DisconnectBlock(block_one_hash, genesis_hash, 0)};
        BOOST_CHECK(wrong_tip.error == node::ChainRegistryStateError::NON_SEQUENTIAL_BLOCK);
        BOOST_REQUIRE(state.DisconnectBlock(block_two_hash, block_one_hash, 1, /*sync=*/true).IsValid());
        BOOST_CHECK(state.State().best_block == block_one_hash);
        BOOST_CHECK_EQUAL(state.State().height, 1U);
    }

    {
        node::ChainRegistryState state{registry_params, genesis_hash};
        BOOST_REQUIRE(state.Initialize(Params(path), block_one_hash, 1).IsValid());
        BOOST_REQUIRE(state.DisconnectBlock(block_one_hash, genesis_hash, 0, /*sync=*/true).IsValid());
        BOOST_CHECK(state.State().best_block == genesis_hash);
        BOOST_CHECK_EQUAL(state.State().height, 0U);
    }
}

BOOST_AUTO_TEST_CASE(initialization_guards)
{
    constexpr uint256 genesis_hash{"0202020202020202020202020202020202020202020202020202020202020202"};
    const Consensus::Params::ChainRegistryParams registry_params{
        .activation_height = 1,
        .dealer_authority = {1, {DealerAuthorityKey()}},
        .maximum_operations = 1,
    };
    const fs::path path{m_args.GetDataDirBase() / "chainregistry_state_guards"};

    node::ChainRegistryState active_without_db{registry_params, genesis_hash};
    const auto active_result{active_without_db.Initialize(Params(path, /*wipe=*/true), genesis_hash, 1)};
    BOOST_CHECK(active_result.error == node::ChainRegistryStateError::ACTIVE_STATE_REQUIRES_REINDEX);

    node::ChainRegistryState invalid_tip{registry_params, genesis_hash};
    const auto invalid_result{invalid_tip.Initialize(Params(path, /*wipe=*/true), {}, 0)};
    BOOST_CHECK(invalid_result.error == node::ChainRegistryStateError::INVALID_EXPECTED_TIP);

    const Consensus::Params::ChainRegistryParams disabled;
    node::ChainRegistryState disabled_state{disabled, genesis_hash};
    BOOST_REQUIRE(disabled_state.Initialize(Params(path), genesis_hash, 0).IsValid());
    BOOST_CHECK(!disabled_state.Enabled());
}

BOOST_AUTO_TEST_CASE(initialize_from_authenticated_snapshot)
{
    constexpr uint256 genesis_hash{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    constexpr uint256 snapshot_tip{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
    const Consensus::Params::ChainRegistryParams registry_params{
        .activation_height = 1,
        .dealer_authority = {1, {DealerAuthorityKey()}},
        .maximum_operations = 4,
    };
    const fs::path path{m_args.GetDataDirBase() / "chainregistry_state_snapshot"};

    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({Record()}).IsValid());
    const uint256 root{registry.ComputeRoot()};

    node::ChainRegistryState wrong_root{registry_params, genesis_hash};
    const auto wrong_root_result{wrong_root.InitializeFromSnapshot(
        Params(path, /*wipe=*/true), snapshot_tip, 100, registry, uint256{})};
    BOOST_CHECK(wrong_root_result.error == node::ChainRegistryStateError::SNAPSHOT_ROOT_MISMATCH);

    {
        node::ChainRegistryState state{registry_params, genesis_hash};
        BOOST_REQUIRE(state.InitializeFromSnapshot(
            Params(path, /*wipe=*/true), snapshot_tip, 100, registry, root).IsValid());
        BOOST_CHECK(state.State().best_block == snapshot_tip);
        BOOST_CHECK_EQUAL(state.State().height, 100U);
        BOOST_CHECK(state.State().registry_root == root);
        BOOST_CHECK_EQUAL(state.Registry().Size(), 1U);
    }
    {
        node::ChainRegistryState reloaded{registry_params, genesis_hash};
        BOOST_REQUIRE(reloaded.Initialize(Params(path), snapshot_tip, 100).IsValid());
        BOOST_CHECK(reloaded.Registry().ComputeRoot() == root);
    }
    {
        node::ChainRegistryState existing{registry_params, genesis_hash};
        const auto existing_result{existing.InitializeFromSnapshot(
            Params(path), snapshot_tip, 100, registry, root)};
        BOOST_CHECK(existing_result.error == node::ChainRegistryStateError::DATABASE_ALREADY_INITIALIZED);
    }
}

BOOST_AUTO_TEST_CASE(indexes_snapshot_descendant_deposit_and_reverts_it)
{
    constexpr uint256 genesis_hash{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    constexpr uint256 snapshot_tip{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
    const Consensus::Params::ChainRegistryParams registry_params{
        .activation_height = 1,
        .dealer_authority = {1, {DealerAuthorityKey()}},
        .maximum_operations = 4,
        .deposit_activation_height = 101,
        .minimum_deposit_amount = 1'000,
        .maximum_deposits = 4,
    };
    const fs::path path{m_args.GetDataDirBase() / "chainregistry_state_deposits"};

    const auto record{Record()};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());

    CBlock deposit_block{Block(
        snapshot_tip, chainregistry::BuildRegistryCommitment(registry.ComputeRoot()))};
    CMutableTransaction funding;
    funding.vin.emplace_back(COutPoint{
        Txid{"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}, 0});
    funding.vout.emplace_back(
        50'000,
        chainregistry::BuildFundScript({
            .chain_id = record.chain_id,
            .recipient_type = 1,
            .recipient = std::vector<unsigned char>(32, 0x42),
        }));
    deposit_block.vtx.push_back(MakeTransactionRef(std::move(funding)));
    deposit_block.hashMerkleRoot = BlockMerkleRoot(deposit_block);
    const uint256 deposit_block_hash{deposit_block.GetHash()};
    const COutPoint outpoint{deposit_block.vtx[1]->GetHash(), 0};
    const auto deposit_id{chainregistry::DeriveDepositId(genesis_hash, outpoint)};

    {
        node::ChainRegistryState state{registry_params, genesis_hash};
        BOOST_REQUIRE(state.InitializeFromSnapshot(
            Params(path, /*wipe=*/true),
            snapshot_tip,
            100,
            registry,
            registry.ComputeRoot()).IsValid());
        BOOST_CHECK_EQUAL(state.State().deposit_history_start_height, 101U);
        BOOST_CHECK_EQUAL(state.State().deposit_count, 0U);

        BOOST_REQUIRE(state.ConnectBlock(
            deposit_block, 101, deposit_block_hash, /*sync=*/true).IsValid());
        BOOST_CHECK_EQUAL(state.State().deposit_count, 1U);
        const auto indexed{state.FindDeposit(deposit_id)};
        BOOST_REQUIRE(indexed.has_value());
        BOOST_CHECK(indexed->outpoint == outpoint);
        BOOST_CHECK_EQUAL(indexed->transaction_index, 1U);
        BOOST_CHECK(indexed->registry_root == registry.ComputeRoot());
        BOOST_CHECK(chainregistry::VerifyRegistryInclusion(
            indexed->chain_record, indexed->registry_proof, indexed->registry_root));
        const auto built{
            node::BuildDepositProof(deposit_block, *indexed, genesis_hash)};
        BOOST_REQUIRE(built.IsValid());
        BOOST_CHECK(built.validation.deposit_id == deposit_id);
        BOOST_REQUIRE(built.validation.fund);
        BOOST_CHECK(built.validation.fund->amount == indexed->amount);
        BOOST_CHECK(built.validation.fund->fund == indexed->fund);
        BOOST_CHECK_EQUAL(built.proof.block_height, 101U);
        BOOST_CHECK(built.proof.block_header.GetHash() == deposit_block_hash);
        BOOST_CHECK_EQUAL(built.proof.transaction_index, 1U);

        CBlock wrong_block{deposit_block};
        ++wrong_block.nTime;
        BOOST_CHECK(
            node::BuildDepositProof(wrong_block, *indexed, genesis_hash)
                .error == node::DepositProofBuildError::BLOCK_MISMATCH);
        auto wrong_entry{*indexed};
        ++wrong_entry.transaction_index;
        BOOST_CHECK(
            node::BuildDepositProof(deposit_block, wrong_entry, genesis_hash)
                .error ==
            node::DepositProofBuildError::TRANSACTION_MISMATCH);
        wrong_entry = *indexed;
        wrong_entry.registry_root = {};
        BOOST_CHECK(
            node::BuildDepositProof(deposit_block, wrong_entry, genesis_hash)
                .error == node::DepositProofBuildError::PROOF_INVALID);
    }

    {
        node::ChainRegistryState state{registry_params, genesis_hash};
        BOOST_REQUIRE(state.Initialize(Params(path), deposit_block_hash, 101).IsValid());
        BOOST_REQUIRE(state.FindDeposit(deposit_id).has_value());
        BOOST_REQUIRE(state.DisconnectBlock(
            deposit_block_hash, snapshot_tip, 100, /*sync=*/true).IsValid());
        BOOST_CHECK_EQUAL(state.State().deposit_count, 0U);
        BOOST_CHECK(!state.FindDeposit(deposit_id).has_value());
    }
}

BOOST_AUTO_TEST_CASE(indexes_bmm_anchor_across_restart_and_reorg)
{
    constexpr uint256 genesis_hash{
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    constexpr uint256 snapshot_tip{
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"};
    constexpr uint256 child_block_hash{
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"};
    const Consensus::Params::ChainRegistryParams registry_params{
        .activation_height = 1,
        .dealer_authority = {1, {DealerAuthorityKey()}},
        .maximum_operations = 4,
        .bmm_activation_height = 101,
        .maximum_bmm_anchors = 1,
    };
    const fs::path path{m_args.GetDataDirBase() / "chainregistry_state_bmm"};

    const auto record{Record()};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());

    CBlock anchored{Block(
        snapshot_tip,
        chainregistry::BuildRegistryCommitment(registry.ComputeRoot()))};
    anchored.vtx.push_back(
        BmmProposal(record.chain_id, child_block_hash, 1));
    anchored.hashMerkleRoot = BlockMerkleRoot(anchored);
    const uint256 anchored_hash{anchored.GetHash()};
    const node::BmmAnchorId anchor_id{
        .chain_id = record.chain_id,
        .main_block_hash = anchored_hash,
    };

    {
        node::ChainRegistryState state{registry_params, genesis_hash};
        BOOST_REQUIRE(state.InitializeFromSnapshot(
                               Params(path, /*wipe=*/true),
                               snapshot_tip,
                               100,
                               registry,
                               registry.ComputeRoot())
                          .IsValid());
        BOOST_CHECK_EQUAL(state.State().anchor_history_start_height, 101U);

        CBlock duplicate{anchored};
        duplicate.vtx.push_back(
            BmmProposal(record.chain_id, child_block_hash, 2));
        duplicate.hashMerkleRoot = BlockMerkleRoot(duplicate);
        const auto rejected{state.ConnectBlock(
            duplicate, 101, duplicate.GetHash())};
        BOOST_CHECK(rejected.error ==
                    node::ChainRegistryStateError::INVALID_BLOCK);
        BOOST_CHECK(rejected.bmm_result.error ==
                    chainregistry::BmmBlockValidationError::DUPLICATE_CHAIN);
        BOOST_CHECK_EQUAL(state.State().anchor_count, 0U);

        const auto connected{state.ConnectBlock(
            anchored, 101, anchored_hash, /*sync=*/true)};
        BOOST_REQUIRE(connected.IsValid());
        BOOST_REQUIRE_EQUAL(connected.bmm_result.anchors.size(), 1U);
        BOOST_CHECK_EQUAL(state.State().anchor_count, 1U);
        const auto stored{state.FindAnchor(anchor_id)};
        BOOST_REQUIRE(stored.has_value());
        BOOST_CHECK(stored->anchor.child_block_hash == child_block_hash);
        BOOST_CHECK(stored->transaction_id == anchored.vtx[1]->GetHash());
        BOOST_CHECK_EQUAL(stored->transaction_index, 1U);
        const std::array target_hashes{child_block_hash};
        const auto lookup{state.FindAnchorsForChildBlocks(
            record.chain_id, target_hashes, /*lookup_limit=*/10)};
        BOOST_REQUIRE(lookup);
        BOOST_CHECK(lookup->complete);
        BOOST_REQUIRE_EQUAL(lookup->anchors.size(), 1U);
        BOOST_CHECK(lookup->anchors.front() == *stored);
        BOOST_CHECK_EQUAL(lookup->lookups, 1U);
        const auto bounded_lookup{state.FindAnchorsForChildBlocks(
            record.chain_id, target_hashes, /*lookup_limit=*/0)};
        BOOST_REQUIRE(bounded_lookup);
        BOOST_CHECK(!bounded_lookup->complete);
        BOOST_CHECK(bounded_lookup->anchors.empty());
        const auto built{
            node::BuildBmmAnchorProof(anchored, *stored, genesis_hash)};
        BOOST_REQUIRE(built.IsValid());
        BOOST_REQUIRE(built.validation.anchor);
        BOOST_CHECK(*built.validation.anchor == stored->anchor);
        BOOST_CHECK(built.validation.registry_root == stored->registry_root);
        BOOST_CHECK_EQUAL(built.proof.block_height, 101U);
        BOOST_CHECK(built.proof.block_header.GetHash() == anchored_hash);
        BOOST_CHECK_EQUAL(built.proof.transaction_index, 1U);

        CBlock wrong_block{anchored};
        ++wrong_block.nTime;
        BOOST_CHECK(
            node::BuildBmmAnchorProof(wrong_block, *stored, genesis_hash)
                .error == node::BmmAnchorProofBuildError::BLOCK_MISMATCH);
        auto wrong_entry{*stored};
        ++wrong_entry.transaction_index;
        BOOST_CHECK(
            node::BuildBmmAnchorProof(anchored, wrong_entry, genesis_hash)
                .error ==
            node::BmmAnchorProofBuildError::TRANSACTION_MISMATCH);
        wrong_entry = *stored;
        wrong_entry.registry_root = {};
        BOOST_CHECK(
            node::BuildBmmAnchorProof(anchored, wrong_entry, genesis_hash)
                .error == node::BmmAnchorProofBuildError::PROOF_INVALID);
    }

    {
        node::ChainRegistryState state{registry_params, genesis_hash};
        BOOST_REQUIRE(state.Initialize(Params(path), anchored_hash, 101).IsValid());
        BOOST_CHECK_EQUAL(state.State().anchor_count, 1U);
        BOOST_REQUIRE(state.FindAnchor(anchor_id).has_value());
        BOOST_REQUIRE(state.DisconnectBlock(
                               anchored_hash,
                               snapshot_tip,
                               100,
                               /*sync=*/true)
                          .IsValid());
        BOOST_CHECK_EQUAL(state.State().anchor_count, 0U);
        BOOST_CHECK(!state.FindAnchor(anchor_id).has_value());
    }

    {
        node::ChainRegistryState state{registry_params, genesis_hash};
        BOOST_REQUIRE(state.Initialize(Params(path), snapshot_tip, 100).IsValid());
        BOOST_CHECK_EQUAL(state.State().anchor_count, 0U);
        BOOST_CHECK(!state.FindAnchor(anchor_id).has_value());
    }
}

BOOST_AUTO_TEST_SUITE_END()
