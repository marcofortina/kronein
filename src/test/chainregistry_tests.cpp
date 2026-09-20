// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <primitives/chainregistry.h>

#include <primitives/transaction.h>
#include <streams.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <span>

BOOST_AUTO_TEST_SUITE(chainregistry_tests)

BOOST_AUTO_TEST_CASE(identifier_serialization)
{
    constexpr chainregistry::ChainId id{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};

    DataStream stream;
    stream << id;
    BOOST_CHECK_EQUAL(HexStr(stream), "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
    BOOST_CHECK_EQUAL(GetSerializeSize(id), 32U);

    chainregistry::ChainId decoded;
    stream >> decoded;
    BOOST_CHECK_EQUAL(decoded.GetHex(), id.GetHex());
    BOOST_CHECK(stream.empty());

    BOOST_CHECK(chainregistry::ChainId::FromHex(id.GetHex()).has_value());
    BOOST_CHECK(!chainregistry::ChainId::FromHex("not-a-chain-id").has_value());
}

BOOST_AUTO_TEST_CASE(chain_spec_hash_vectors)
{
    const auto empty_hash{chainregistry::ComputeChainSpecHash({})};
    BOOST_CHECK_EQUAL(empty_hash.GetHex(), "c101f132eaa2d6c2e3a48a6f0bc62bd56c8c4d7914f2cf582f8fd280773a90f6");

    const auto spec{ParseHex("00010280ff")};
    const auto spec_hash{chainregistry::ComputeChainSpecHash(std::as_bytes(std::span{spec}))};
    BOOST_CHECK_EQUAL(spec_hash.GetHex(), "a2481fdd4ec32e117d82875318d90b258b1764207fc3ab9b7d4d68a4f3c7d075");
}

BOOST_AUTO_TEST_CASE(chain_and_deposit_id_vectors)
{
    constexpr uint256 main_genesis{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};
    constexpr Txid registration_txid{"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"};
    const COutPoint outpoint{registration_txid, 7};
    const auto spec{ParseHex("00010280ff")};
    const auto spec_hash{chainregistry::ComputeChainSpecHash(std::as_bytes(std::span{spec}))};

    const auto chain_id{chainregistry::DeriveChainId(main_genesis, outpoint, spec_hash)};
    BOOST_CHECK_EQUAL(chain_id.GetHex(), "c9bd6705826629a273ee585dffded40c00b412ea430f4f11feb72e37f579c04a");

    const auto deposit_id{chainregistry::DeriveDepositId(main_genesis, outpoint)};
    BOOST_CHECK_EQUAL(deposit_id.GetHex(), "91137e119abaf4b95682b6da69684853cfc2699a4cce79b5262d1f5f20f959eb");

    BOOST_CHECK(chain_id.ToUint256() != deposit_id.ToUint256());
}

BOOST_AUTO_TEST_CASE(identifiers_commit_to_network_and_outpoint)
{
    constexpr uint256 main_a{"0000000000000000000000000000000000000000000000000000000000000001"};
    constexpr uint256 main_b{"0000000000000000000000000000000000000000000000000000000000000002"};
    constexpr Txid txid{"0000000000000000000000000000000000000000000000000000000000000003"};
    constexpr chainregistry::ChainSpecHash spec_hash{"0000000000000000000000000000000000000000000000000000000000000004"};

    const auto chain_a{chainregistry::DeriveChainId(main_a, COutPoint{txid, 0}, spec_hash)};
    const auto chain_other_network{chainregistry::DeriveChainId(main_b, COutPoint{txid, 0}, spec_hash)};
    const auto chain_other_vout{chainregistry::DeriveChainId(main_a, COutPoint{txid, 1}, spec_hash)};

    BOOST_CHECK(chain_a != chain_other_network);
    BOOST_CHECK(chain_a != chain_other_vout);

    const auto deposit_a{chainregistry::DeriveDepositId(main_a, COutPoint{txid, 0})};
    const auto deposit_other_network{chainregistry::DeriveDepositId(main_b, COutPoint{txid, 0})};
    const auto deposit_other_vout{chainregistry::DeriveDepositId(main_a, COutPoint{txid, 1})};

    BOOST_CHECK(deposit_a != deposit_other_network);
    BOOST_CHECK(deposit_a != deposit_other_vout);
}

BOOST_AUTO_TEST_SUITE_END()
