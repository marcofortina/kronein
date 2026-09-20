// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chainregistry_db.h>

#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <span>
#include <vector>

namespace {

chainregistry::ChainRecord Record(unsigned char id_byte,
                                  unsigned char control_byte,
                                  uint32_t height)
{
    std::array<unsigned char, 32> id{};
    id.fill(id_byte);
    std::array<unsigned char, 32> control{};
    control.fill(control_byte);
    return {
        .record_version = chainregistry::CHAIN_RECORD_VERSION,
        .chain_id = chainregistry::ChainId::FromUint256(uint256{std::span{id}}),
        .manifest_hash = chainregistry::ManifestHash{"2222222222222222222222222222222222222222222222222222222222222222"},
        .template_id = 1,
        .template_version = 1,
        .control_outpoint = COutPoint{Txid::FromUint256(uint256{std::span{control}}), 0},
        .metadata_hash = chainregistry::MetadataHash{"4444444444444444444444444444444444444444444444444444444444444444"},
        .status = chainregistry::ChainStatus::ACTIVE,
        .registered_height = height,
        .updated_height = height,
        .retired_height = 0,
    };
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(chainregistry_db_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(registry_db_connect_load_disconnect)
{
    const fs::path path{m_args.GetDataDirBase() / "chainregistry_db"};
    constexpr uint256 block_one{"1111111111111111111111111111111111111111111111111111111111111111"};
    constexpr uint256 block_two{"2222222222222222222222222222222222222222222222222222222222222222"};

    const auto original{Record(1, 11, 100)};
    auto updated{original};
    updated.control_outpoint = COutPoint{
        Txid{"abababababababababababababababababababababababababababababababab"}, 1};
    updated.metadata_hash = chainregistry::MetadataHash{
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"};
    updated.updated_height = 101;

    const chainregistry::RegistryBlockUndo register_undo{{chainregistry::RegistryUndo{
        .chain_id = original.chain_id,
        .had_previous = false,
        .previous = {},
    }}};
    const chainregistry::RegistryBlockUndo update_undo{{chainregistry::RegistryUndo{
        .chain_id = original.chain_id,
        .had_previous = true,
        .previous = original,
    }}};

    node::ChainRegistryDBState state_one;
    {
        node::ChainRegistryDB db{{
            .path = path,
            .cache_bytes = 1 << 20,
            .wipe_data = true,
            .obfuscate = true,
        }};
        chainregistry::ChainRegistry fresh;
        node::ChainRegistryDBState fresh_state;
        const auto fresh_result{db.Load(fresh, fresh_state)};
        BOOST_REQUIRE(fresh_result.IsValid());
        BOOST_CHECK(!fresh_result.initialized);
        BOOST_CHECK_EQUAL(fresh.Size(), 0U);
        BOOST_CHECK_EQUAL(fresh_state.registry_root.GetHex(), fresh.ComputeRoot().GetHex());

        BOOST_REQUIRE(fresh.LoadRecords({original}).IsValid());
        state_one = node::MakeChainRegistryDBState(block_one, 100, fresh);
        auto inconsistent{state_one};
        inconsistent.registry_root.SetNull();
        BOOST_CHECK(!db.WriteConnectedBlock(fresh, inconsistent, block_one, register_undo));
        BOOST_CHECK(!db.WriteConnectedBlock(fresh, state_one, block_two, register_undo));
        BOOST_REQUIRE(db.WriteConnectedBlock(fresh, state_one, block_one, register_undo, true));

        chainregistry::ChainRecord stored_record;
        BOOST_REQUIRE(db.ReadRecord(original.chain_id, stored_record));
        BOOST_CHECK(stored_record == original);

        chainregistry::RegistryBlockUndo stored_undo;
        BOOST_REQUIRE(db.ReadUndo(block_one, stored_undo));
        BOOST_CHECK(stored_undo == register_undo);
    }

    node::ChainRegistryDBState state_two;
    {
        node::ChainRegistryDB db{{
            .path = path,
            .cache_bytes = 1 << 20,
            .obfuscate = true,
        }};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        const auto load_result{db.Load(loaded, loaded_state)};
        BOOST_REQUIRE_MESSAGE(load_result.IsValid(), static_cast<int>(load_result.error));
        BOOST_CHECK(load_result.initialized);
        BOOST_CHECK(loaded_state == state_one);
        BOOST_CHECK_EQUAL(loaded.ComputeRoot().GetHex(), state_one.registry_root.GetHex());

        BOOST_REQUIRE(loaded.LoadRecords({updated}).IsValid());
        state_two = node::MakeChainRegistryDBState(block_two, 101, loaded);
        BOOST_REQUIRE(db.WriteConnectedBlock(loaded, state_two, block_two, update_undo, true));
    }

    {
        node::ChainRegistryDB db{{
            .path = path,
            .cache_bytes = 1 << 20,
            .obfuscate = true,
        }};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        BOOST_REQUIRE(db.Load(loaded, loaded_state).IsValid());
        BOOST_CHECK(loaded_state == state_two);
        BOOST_REQUIRE(loaded.UndoBlock(update_undo));
        BOOST_CHECK_EQUAL(loaded.ComputeRoot().GetHex(), state_one.registry_root.GetHex());
        BOOST_REQUIRE(db.WriteDisconnectedBlock(loaded, state_one, block_two, update_undo, true));

        chainregistry::RegistryBlockUndo erased_undo;
        BOOST_CHECK(!db.ReadUndo(block_two, erased_undo));
        BOOST_REQUIRE(db.ReadUndo(block_one, erased_undo));
        BOOST_CHECK(erased_undo == register_undo);
    }

    {
        node::ChainRegistryDB db{{
            .path = path,
            .cache_bytes = 1 << 20,
            .obfuscate = true,
        }};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        BOOST_REQUIRE(db.Load(loaded, loaded_state).IsValid());
        BOOST_CHECK(loaded_state == state_one);
        BOOST_CHECK_EQUAL(loaded.Size(), 1U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
