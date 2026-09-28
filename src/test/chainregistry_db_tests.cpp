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

constexpr uint256 MAIN_GENESIS{
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
constexpr uint256 OTHER_GENESIS{
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"};

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

node::DepositIndexEntry Deposit(const chainregistry::ChainRegistry& registry,
                                const chainregistry::ChainRecord& record,
                                const uint256& block_hash,
                                uint32_t block_height,
                                unsigned char transaction_byte = 0xbb,
                                uint32_t transaction_index = 3)
{
    std::array<unsigned char, 32> transaction{};
    transaction.fill(transaction_byte);
    const COutPoint outpoint{
        Txid::FromUint256(uint256{std::span{transaction}}), 2};
    const auto proof{registry.GetInclusionProof(record.chain_id)};
    BOOST_REQUIRE(proof.has_value());
    return {
        .deposit_id = chainregistry::DeriveDepositId(MAIN_GENESIS, outpoint),
        .outpoint = outpoint,
        .amount = 50'000,
        .fund = {
            .chain_id = record.chain_id,
            .recipient_type = 1,
            .recipient = std::vector<unsigned char>(32, 0x42),
        },
        .block_hash = block_hash,
        .block_height = block_height,
        .transaction_index = transaction_index,
        .registry_root = registry.ComputeRoot(),
        .chain_record = record,
        .registry_proof = *proof,
    };
}

node::BmmAnchorIndexEntry Anchor(const chainregistry::ChainRegistry& registry,
                                 const chainregistry::ChainRecord& record,
                                 const uint256& block_hash,
                                 uint32_t block_height)
{
    const auto proof{registry.GetInclusionProof(record.chain_id)};
    BOOST_REQUIRE(proof.has_value());
    return {
        .id = {
            .chain_id = record.chain_id,
            .main_block_hash = block_hash,
        },
        .anchor = {
            .chain_id = record.chain_id,
            .child_block_hash = uint256{
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
        },
        .block_height = block_height,
        .transaction_id = Txid{
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
        .transaction_index = 2,
        .output_index = 0,
        .registry_root = registry.ComputeRoot(),
        .chain_record = record,
        .registry_proof = *proof,
    };
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(chainregistry_db_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(registry_db_connect_load_disconnect)
{
    const fs::path path{m_args.GetDataDirBase() / "chainregistry_db"};
    constexpr uint256 block_zero{"0101010101010101010101010101010101010101010101010101010101010101"};
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
    const node::ChainRegistryDBUndo register_db_undo{
        .registry = register_undo,
        .deposits = {},
        .anchors = {},
    };
    const node::ChainRegistryDBUndo update_db_undo{
        .registry = update_undo,
        .deposits = {},
        .anchors = {},
    };

    node::ChainRegistryDBState state_one;
    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .wipe_data = true,
                                     .obfuscate = true,
                                 },
                                 MAIN_GENESIS};
        chainregistry::ChainRegistry fresh;
        node::ChainRegistryDBState fresh_state;
        const auto fresh_result{db.Load(fresh, fresh_state)};
        BOOST_REQUIRE(fresh_result.IsValid());
        BOOST_CHECK(!fresh_result.initialized);
        BOOST_CHECK_EQUAL(fresh.Size(), 0U);
        BOOST_CHECK_EQUAL(fresh_state.registry_root.GetHex(), fresh.ComputeRoot().GetHex());
        BOOST_REQUIRE(db.WriteInitialState(
            fresh, node::MakeChainRegistryDBState(block_zero, 99, fresh), /*sync=*/true));

        BOOST_REQUIRE(fresh.LoadRecords({original}).IsValid());
        state_one = node::MakeChainRegistryDBState(block_one, 100, fresh);
        auto inconsistent{state_one};
        inconsistent.registry_root.SetNull();
        BOOST_CHECK(!db.WriteConnectedBlock(fresh, inconsistent, block_one, register_db_undo));
        BOOST_CHECK(!db.WriteConnectedBlock(fresh, state_one, block_two, register_db_undo));
        BOOST_REQUIRE(db.WriteConnectedBlock(
            fresh, state_one, block_one, register_db_undo, {}, {}, /*sync=*/true));

        chainregistry::ChainRecord stored_record;
        BOOST_REQUIRE(db.ReadRecord(original.chain_id, stored_record));
        BOOST_CHECK(stored_record == original);

        node::ChainRegistryDBUndo stored_undo;
        BOOST_REQUIRE(db.ReadUndo(block_one, stored_undo));
        BOOST_CHECK(stored_undo == register_db_undo);
    }

    node::ChainRegistryDBState state_two;
    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .obfuscate = true,
                                 },
                                 MAIN_GENESIS};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        const auto load_result{db.Load(loaded, loaded_state)};
        BOOST_REQUIRE_MESSAGE(load_result.IsValid(), static_cast<int>(load_result.error));
        BOOST_CHECK(load_result.initialized);
        BOOST_CHECK(loaded_state == state_one);
        BOOST_CHECK_EQUAL(loaded.ComputeRoot().GetHex(), state_one.registry_root.GetHex());

        BOOST_REQUIRE(loaded.LoadRecords({updated}).IsValid());
        state_two = node::MakeChainRegistryDBState(block_two, 101, loaded);
        BOOST_REQUIRE(db.WriteConnectedBlock(
            loaded, state_two, block_two, update_db_undo, {}, {}, /*sync=*/true));
    }

    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .obfuscate = true,
                                 },
                                 MAIN_GENESIS};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        BOOST_REQUIRE(db.Load(loaded, loaded_state).IsValid());
        BOOST_CHECK(loaded_state == state_two);
        BOOST_REQUIRE(loaded.UndoBlock(update_undo));
        BOOST_CHECK_EQUAL(loaded.ComputeRoot().GetHex(), state_one.registry_root.GetHex());
        BOOST_REQUIRE(db.WriteDisconnectedBlock(
            loaded, state_one, block_two, update_db_undo, /*sync=*/true));

        node::ChainRegistryDBUndo erased_undo;
        BOOST_CHECK(!db.ReadUndo(block_two, erased_undo));
        BOOST_REQUIRE(db.ReadUndo(block_one, erased_undo));
        BOOST_CHECK(erased_undo == register_db_undo);
    }

    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .obfuscate = true,
                                 },
                                 MAIN_GENESIS};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        BOOST_REQUIRE(db.Load(loaded, loaded_state).IsValid());
        BOOST_CHECK(loaded_state == state_one);
        BOOST_CHECK_EQUAL(loaded.Size(), 1U);

        BOOST_REQUIRE(db.EraseUndo({&block_one, 1}, /*sync=*/true));
        node::ChainRegistryDBUndo erased_undo;
        BOOST_CHECK(!db.ReadUndo(block_one, erased_undo));

        chainregistry::ChainRegistry reloaded;
        node::ChainRegistryDBState reloaded_state;
        BOOST_REQUIRE(db.Load(reloaded, reloaded_state).IsValid());
        BOOST_CHECK(reloaded_state == state_one);
        BOOST_CHECK_EQUAL(reloaded.ComputeRoot().GetHex(), state_one.registry_root.GetHex());
    }
}

BOOST_AUTO_TEST_CASE(deposit_index_connect_load_disconnect)
{
    const fs::path path{m_args.GetDataDirBase() / "chainregistry_deposit_db"};
    constexpr uint256 parent_hash{"1010101010101010101010101010101010101010101010101010101010101010"};
    constexpr uint256 block_hash{"2020202020202020202020202020202020202020202020202020202020202020"};

    const auto record{Record(3, 13, 50)};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());
    const auto deposit{Deposit(registry, record, block_hash, 100)};
    const node::ChainRegistryDBUndo undo{
        .registry = {},
        .deposits = {deposit.deposit_id},
        .anchors = {},
    };
    const auto parent_state{node::MakeChainRegistryDBState(parent_hash, 99, registry)};
    const auto connected_state{
        node::MakeChainRegistryDBState(block_hash, 100, registry, 0, 1)};

    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .wipe_data = true,
                                     .obfuscate = true,
                                 },
                                 MAIN_GENESIS};
        BOOST_REQUIRE(db.WriteInitialState(registry, parent_state, /*sync=*/true));

        auto invalid{deposit};
        invalid.deposit_id = chainregistry::DepositId{
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        const node::ChainRegistryDBUndo invalid_undo{
            .registry = {},
            .deposits = {invalid.deposit_id},
            .anchors = {},
        };
        BOOST_CHECK(!db.WriteConnectedBlock(
            registry, connected_state, block_hash, invalid_undo, {&invalid, 1}));

        const std::array duplicate{deposit, deposit};
        const node::ChainRegistryDBUndo duplicate_undo{
            .registry = {},
            .deposits = {deposit.deposit_id, deposit.deposit_id},
            .anchors = {},
        };
        const auto duplicate_state{
            node::MakeChainRegistryDBState(block_hash, 100, registry, 0, 2)};
        BOOST_CHECK(!db.WriteConnectedBlock(
            registry, duplicate_state, block_hash, duplicate_undo, duplicate));

        BOOST_REQUIRE(db.WriteConnectedBlock(
            registry, connected_state, block_hash, undo, {&deposit, 1}, {}, /*sync=*/true));
        const auto stored{db.ReadDeposit(deposit.deposit_id)};
        BOOST_REQUIRE(stored.has_value());
        BOOST_CHECK(*stored == deposit);
        const auto lookup{db.ReadDepositsForChild(
            record.chain_id, /*lookup_limit=*/1)};
        BOOST_REQUIRE(lookup);
        BOOST_CHECK(lookup->complete);
        BOOST_CHECK_EQUAL(lookup->lookups, 1U);
        BOOST_REQUIRE_EQUAL(lookup->deposits.size(), 1U);
        BOOST_CHECK(lookup->deposits.front() == deposit);
    }

    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .obfuscate = true,
                                 },
                                 OTHER_GENESIS};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        const auto result{db.Load(loaded, loaded_state)};
        BOOST_CHECK(result.error == node::ChainRegistryDBLoadError::INVALID_DEPOSIT);
    }

    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .obfuscate = true,
                                 },
                                 MAIN_GENESIS};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        BOOST_REQUIRE(db.Load(loaded, loaded_state).IsValid());
        BOOST_CHECK(loaded_state == connected_state);
        BOOST_CHECK_EQUAL(loaded_state.deposit_count, 1U);
        const auto stored{db.ReadDeposit(deposit.deposit_id)};
        BOOST_REQUIRE(stored.has_value());
        BOOST_CHECK(*stored == deposit);

        BOOST_REQUIRE(db.WriteDisconnectedBlock(
            loaded, parent_state, block_hash, undo, /*sync=*/true));
        BOOST_CHECK(!db.ReadDeposit(deposit.deposit_id).has_value());
        const auto lookup{db.ReadDepositsForChild(
            record.chain_id, /*lookup_limit=*/1)};
        BOOST_REQUIRE(lookup);
        BOOST_CHECK(lookup->complete);
        BOOST_CHECK_EQUAL(lookup->lookups, 0U);
        BOOST_CHECK(lookup->deposits.empty());
    }

    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .obfuscate = true,
                                 },
                                 MAIN_GENESIS};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        BOOST_REQUIRE(db.Load(loaded, loaded_state).IsValid());
        BOOST_CHECK(loaded_state == parent_state);
        BOOST_CHECK_EQUAL(loaded_state.deposit_count, 0U);
    }
}

BOOST_AUTO_TEST_CASE(deposit_child_lookup_is_bounded)
{
    const fs::path path{
        m_args.GetDataDirBase() / "chainregistry_deposit_child_lookup_db"};
    constexpr uint256 parent_hash{
        "5151515151515151515151515151515151515151515151515151515151515151"};
    constexpr uint256 block_hash{
        "6161616161616161616161616161616161616161616161616161616161616161"};

    const auto record{Record(7, 17, 50)};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());
    const auto first{Deposit(
        registry, record, block_hash, 100, /*transaction_byte=*/0x71,
        /*transaction_index=*/2)};
    const auto second{Deposit(
        registry, record, block_hash, 100, /*transaction_byte=*/0x72,
        /*transaction_index=*/3)};
    const std::array deposits{first, second};
    const node::ChainRegistryDBUndo undo{
        .registry = {},
        .deposits = {first.deposit_id, second.deposit_id},
        .anchors = {},
    };
    const auto parent_state{
        node::MakeChainRegistryDBState(parent_hash, 99, registry)};
    const auto state{node::MakeChainRegistryDBState(
        block_hash, 100, registry, 0, deposits.size())};

    node::ChainRegistryDB db{{
                                 .path = path,
                                 .cache_bytes = 1 << 20,
                                 .wipe_data = true,
                                 .obfuscate = true,
                             },
                             MAIN_GENESIS};
    BOOST_REQUIRE(db.WriteInitialState(registry, parent_state, /*sync=*/true));
    BOOST_REQUIRE(db.WriteConnectedBlock(
        registry, state, block_hash, undo, deposits, {}, /*sync=*/true));

    const auto bounded{db.ReadDepositsForChild(
        record.chain_id, /*lookup_limit=*/1)};
    BOOST_REQUIRE(bounded);
    BOOST_CHECK(!bounded->complete);
    BOOST_CHECK_EQUAL(bounded->lookups, 1U);
    BOOST_REQUIRE_EQUAL(bounded->deposits.size(), 1U);

    const auto complete{db.ReadDepositsForChild(
        record.chain_id, /*lookup_limit=*/2)};
    BOOST_REQUIRE(complete);
    BOOST_CHECK(complete->complete);
    BOOST_CHECK_EQUAL(complete->lookups, 2U);
    BOOST_REQUIRE_EQUAL(complete->deposits.size(), 2U);
    BOOST_CHECK(complete->deposits[0] == first);
    BOOST_CHECK(complete->deposits[1] == second);

    const auto other_chain{Record(8, 18, 50).chain_id};
    const auto empty{db.ReadDepositsForChild(
        other_chain, /*lookup_limit=*/2)};
    BOOST_REQUIRE(empty);
    BOOST_CHECK(empty->complete);
    BOOST_CHECK_EQUAL(empty->lookups, 0U);
    BOOST_CHECK(empty->deposits.empty());
}

BOOST_AUTO_TEST_CASE(bmm_anchor_index_connect_load_disconnect)
{
    const fs::path path{m_args.GetDataDirBase() / "chainregistry_anchor_db"};
    constexpr uint256 parent_hash{
        "3131313131313131313131313131313131313131313131313131313131313131"};
    constexpr uint256 block_hash{
        "4141414141414141414141414141414141414141414141414141414141414141"};

    const auto record{Record(5, 15, 50)};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());
    const auto anchor{Anchor(registry, record, block_hash, 100)};
    const node::ChainRegistryDBUndo undo{
        .registry = {},
        .deposits = {},
        .anchors = {anchor.id},
    };
    const auto parent_state{
        node::MakeChainRegistryDBState(parent_hash, 99, registry)};
    const auto connected_state{node::MakeChainRegistryDBState(
        block_hash, 100, registry, 0, 0, 0, 1)};

    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .wipe_data = true,
                                     .obfuscate = true,
                                 },
                                 MAIN_GENESIS};
        BOOST_REQUIRE(
            db.WriteInitialState(registry, parent_state, /*sync=*/true));

        auto invalid{anchor};
        invalid.chain_record.chain_id = chainregistry::ChainId{
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        BOOST_CHECK(!db.WriteConnectedBlock(
            registry,
            connected_state,
            block_hash,
            undo,
            {},
            {&invalid, 1}));

        const std::array duplicate{anchor, anchor};
        const node::ChainRegistryDBUndo duplicate_undo{
            .registry = {},
            .deposits = {},
            .anchors = {anchor.id, anchor.id},
        };
        const auto duplicate_state{node::MakeChainRegistryDBState(
            block_hash, 100, registry, 0, 0, 0, 2)};
        BOOST_CHECK(!db.WriteConnectedBlock(
            registry,
            duplicate_state,
            block_hash,
            duplicate_undo,
            {},
            duplicate));

        BOOST_REQUIRE(db.WriteConnectedBlock(
            registry,
            connected_state,
            block_hash,
            undo,
            {},
            {&anchor, 1},
            /*sync=*/true));
        const auto stored{db.ReadAnchor(anchor.id)};
        BOOST_REQUIRE(stored.has_value());
        BOOST_CHECK(*stored == anchor);
        const std::array child_hashes{anchor.anchor.child_block_hash};
        const auto lookup{db.ReadAnchorsForChildBlocks(
            record.chain_id, child_hashes, /*lookup_limit=*/1)};
        BOOST_REQUIRE(lookup);
        BOOST_CHECK(lookup->complete);
        BOOST_CHECK_EQUAL(lookup->lookups, 1U);
        BOOST_REQUIRE_EQUAL(lookup->anchors.size(), 1U);
        BOOST_CHECK(lookup->anchors.front() == anchor);
    }

    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .obfuscate = true,
                                 },
                                 MAIN_GENESIS};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        BOOST_REQUIRE(db.Load(loaded, loaded_state).IsValid());
        BOOST_CHECK(loaded_state == connected_state);
        BOOST_CHECK_EQUAL(loaded_state.anchor_count, 1U);
        const auto stored{db.ReadAnchor(anchor.id)};
        BOOST_REQUIRE(stored.has_value());
        BOOST_CHECK(*stored == anchor);

        BOOST_REQUIRE(db.WriteDisconnectedBlock(
            loaded, parent_state, block_hash, undo, /*sync=*/true));
        BOOST_CHECK(!db.ReadAnchor(anchor.id).has_value());
        const std::array child_hashes{anchor.anchor.child_block_hash};
        const auto lookup{db.ReadAnchorsForChildBlocks(
            record.chain_id, child_hashes, /*lookup_limit=*/1)};
        BOOST_REQUIRE(lookup);
        BOOST_CHECK(lookup->complete);
        BOOST_CHECK_EQUAL(lookup->lookups, 0U);
        BOOST_CHECK(lookup->anchors.empty());
    }

    {
        node::ChainRegistryDB db{{
                                     .path = path,
                                     .cache_bytes = 1 << 20,
                                     .obfuscate = true,
                                 },
                                 MAIN_GENESIS};
        chainregistry::ChainRegistry loaded;
        node::ChainRegistryDBState loaded_state;
        BOOST_REQUIRE(db.Load(loaded, loaded_state).IsValid());
        BOOST_CHECK(loaded_state == parent_state);
        BOOST_CHECK_EQUAL(loaded_state.anchor_count, 0U);
    }
}

BOOST_AUTO_TEST_CASE(bmm_anchor_child_lookup_is_bounded)
{
    const fs::path path{
        m_args.GetDataDirBase() / "chainregistry_anchor_lookup_db"};
    constexpr uint256 parent_hash{
        "5151515151515151515151515151515151515151515151515151515151515151"};
    constexpr uint256 block_one{
        "6161616161616161616161616161616161616161616161616161616161616161"};
    constexpr uint256 block_two{
        "7171717171717171717171717171717171717171717171717171717171717171"};

    const auto record{Record(6, 16, 50)};
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());
    const auto anchor_one{Anchor(registry, record, block_one, 100)};
    const auto anchor_two{Anchor(registry, record, block_two, 101)};
    const node::ChainRegistryDBUndo undo_one{
        .registry = {},
        .deposits = {},
        .anchors = {anchor_one.id},
    };
    const node::ChainRegistryDBUndo undo_two{
        .registry = {},
        .deposits = {},
        .anchors = {anchor_two.id},
    };
    const auto parent_state{
        node::MakeChainRegistryDBState(parent_hash, 99, registry)};
    const auto state_one{node::MakeChainRegistryDBState(
        block_one, 100, registry, 0, 0, 0, 1)};
    const auto state_two{node::MakeChainRegistryDBState(
        block_two, 101, registry, 0, 0, 0, 2)};

    node::ChainRegistryDB db{{
                                 .path = path,
                                 .cache_bytes = 1 << 20,
                                 .wipe_data = true,
                                 .obfuscate = true,
                             },
                             MAIN_GENESIS};
    BOOST_REQUIRE(db.WriteInitialState(registry, parent_state, /*sync=*/true));
    BOOST_REQUIRE(db.WriteConnectedBlock(
        registry, state_one, block_one, undo_one, {}, {&anchor_one, 1},
        /*sync=*/true));
    BOOST_REQUIRE(db.WriteConnectedBlock(
        registry, state_two, block_two, undo_two, {}, {&anchor_two, 1},
        /*sync=*/true));

    const std::array child_hashes{anchor_one.anchor.child_block_hash};
    const auto bounded{db.ReadAnchorsForChildBlocks(
        record.chain_id, child_hashes, /*lookup_limit=*/1)};
    BOOST_REQUIRE(bounded);
    BOOST_CHECK(!bounded->complete);
    BOOST_CHECK_EQUAL(bounded->lookups, 1U);
    BOOST_REQUIRE_EQUAL(bounded->anchors.size(), 1U);

    const auto complete{db.ReadAnchorsForChildBlocks(
        record.chain_id, child_hashes, /*lookup_limit=*/2)};
    BOOST_REQUIRE(complete);
    BOOST_CHECK(complete->complete);
    BOOST_CHECK_EQUAL(complete->lookups, 2U);
    BOOST_REQUIRE_EQUAL(complete->anchors.size(), 2U);
    BOOST_CHECK_EQUAL(complete->anchors[0].block_height, 101U);
    BOOST_CHECK_EQUAL(complete->anchors[1].block_height, 100U);
}

BOOST_AUTO_TEST_SUITE_END()
