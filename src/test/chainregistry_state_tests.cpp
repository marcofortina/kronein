// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chainregistry.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <span>

namespace {

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

} // namespace

BOOST_FIXTURE_TEST_SUITE(chainregistry_state_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(connect_disconnect_and_reload)
{
    constexpr uint256 genesis_hash{"0101010101010101010101010101010101010101010101010101010101010101"};
    const Consensus::Params::ChainRegistryParams registry_params{
        .activation_height = 2,
        .minimum_registration_burn = 1,
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
        BOOST_REQUIRE(state.Initialize(Params(path), block_two_hash, 2).IsValid());
        const auto wrong_parent{state.DisconnectBlock(block_two_hash, {}, -1)};
        BOOST_CHECK(wrong_parent.error == node::ChainRegistryStateError::NON_SEQUENTIAL_BLOCK);
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
        .minimum_registration_burn = 1,
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
        .minimum_registration_burn = 1,
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

BOOST_AUTO_TEST_SUITE_END()
