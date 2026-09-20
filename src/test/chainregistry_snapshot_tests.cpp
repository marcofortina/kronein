// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/utxo_snapshot.h>

#include <consensus/merkle.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>

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

std::pair<node::RegistrySnapshot, CBlock> Snapshot()
{
    node::RegistrySnapshot snapshot;
    snapshot.records = {Record(1, 11, 100), Record(2, 22, 101)};

    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords(snapshot.records).IsValid());
    snapshot.registry_root = registry.ComputeRoot();

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.emplace_back(0, chainregistry::BuildRegistryCommitment(snapshot.registry_root));

    CMutableTransaction transaction;
    transaction.vin.emplace_back(COutPoint{Txid{"abababababababababababababababababababababababababababababababab"}, 0});
    transaction.vout.emplace_back(1, CScript{} << OP_TRUE);

    CBlock block;
    block.nVersion = 1;
    block.nTime = 1;
    block.nBits = 0x207fffff;
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(transaction)};
    block.hashMerkleRoot = BlockMerkleRoot(block);

    snapshot.base_blockhash = block.GetHash();
    snapshot.coinbase = std::move(coinbase);
    snapshot.coinbase_merkle_branch = TransactionMerklePath(block, /*position=*/0);
    return {std::move(snapshot), std::move(block)};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(chainregistry_snapshot_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(authenticated_registry_snapshot)
{
    auto [snapshot, block]{Snapshot()};
    auto result{node::ValidateRegistrySnapshot(snapshot, block)};
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(result->Size(), 2U);
    BOOST_CHECK(result->ComputeRoot() == snapshot.registry_root);

    DataStream stream;
    stream << snapshot;
    node::RegistrySnapshot decoded;
    stream >> decoded;
    BOOST_CHECK(stream.empty());
    auto decoded_result{node::ValidateRegistrySnapshot(decoded, block)};
    BOOST_REQUIRE(decoded_result);
    BOOST_CHECK(decoded_result->ComputeRoot() == snapshot.registry_root);
}

BOOST_AUTO_TEST_CASE(rejects_tampered_registry_snapshot)
{
    auto [snapshot, block]{Snapshot()};

    auto tampered{snapshot};
    tampered.base_blockhash.SetNull();
    BOOST_CHECK(!node::ValidateRegistrySnapshot(tampered, block));

    tampered = snapshot;
    tampered.registry_root.SetNull();
    BOOST_CHECK(!node::ValidateRegistrySnapshot(tampered, block));

    tampered = snapshot;
    tampered.records[0].metadata_hash = chainregistry::MetadataHash{
        "5555555555555555555555555555555555555555555555555555555555555555"};
    BOOST_CHECK(!node::ValidateRegistrySnapshot(tampered, block));

    tampered = snapshot;
    std::swap(tampered.records[0], tampered.records[1]);
    BOOST_CHECK(!node::ValidateRegistrySnapshot(tampered, block));

    tampered = snapshot;
    tampered.coinbase_merkle_branch[0].SetNull();
    BOOST_CHECK(!node::ValidateRegistrySnapshot(tampered, block));

    tampered = snapshot;
    tampered.coinbase.vin[0].prevout = COutPoint{Txid{
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}, 0};
    BOOST_CHECK(!node::ValidateRegistrySnapshot(tampered, block));
}

BOOST_AUTO_TEST_SUITE_END()
