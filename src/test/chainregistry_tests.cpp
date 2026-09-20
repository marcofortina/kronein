// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <primitives/chainregistry.h>

#include <primitives/transaction.h>
#include <streams.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace {

chainregistry::ChainManifest ValidManifest()
{
    chainregistry::ChainSpec spec;
    spec.template_id = 1;
    spec.template_version = 2;
    spec.consensus_parameters = ParseHex("aabbcc");
    return {
        .spec = std::move(spec),
        .child_genesis_hash = uint256{"1111111111111111111111111111111111111111111111111111111111111111"},
        .initial_metadata_hash = chainregistry::MetadataHash{"2222222222222222222222222222222222222222222222222222222222222222"},
    };
}

chainregistry::RegistryOperation ValidRegistration(uint32_t anchor_input = 0, uint32_t control_output = 1)
{
    return chainregistry::RegisterChain{
        .anchor_input = anchor_input,
        .control_output = control_output,
        .manifest = ValidManifest(),
    };
}

CScript TaprootScript(unsigned char byte = 1)
{
    return CScript{} << OP_1 << std::vector<unsigned char>(32, byte);
}

CMutableTransaction ValidRegistrationTx(CAmount burn = 1'000)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{
        Txid{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, 0});
    tx.vout.emplace_back(burn, chainregistry::BuildOperationScript(ValidRegistration()));
    tx.vout.emplace_back(0, TaprootScript());
    return tx;
}

} // namespace

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
    const auto empty_hash{chainregistry::ComputeChainSpecHash(std::span<const std::byte>{})};
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

BOOST_AUTO_TEST_CASE(chain_spec_and_manifest_vectors)
{
    const auto manifest{ValidManifest()};

    DataStream spec_stream;
    spec_stream << manifest.spec;
    BOOST_CHECK_EQUAL(HexStr(spec_stream), "0100010000000200000003aabbcc01");
    BOOST_CHECK_EQUAL(chainregistry::ComputeChainSpecHash(manifest.spec).GetHex(),
                      "eceae475c8ab5b799405beb707bad137cad5674029b37feb6537608186d13159");

    DataStream manifest_stream;
    manifest_stream << manifest;
    BOOST_CHECK_EQUAL(
        HexStr(manifest_stream),
        "0100010000000200000003aabbcc01"
        "1111111111111111111111111111111111111111111111111111111111111111"
        "2222222222222222222222222222222222222222222222222222222222222222");
    BOOST_CHECK_EQUAL(chainregistry::ComputeManifestHash(manifest).GetHex(),
                      "26a669a5688af69900bf6ce34d43d62b376dfdb9dfa1fcc505d385aae723ba9b");
}

BOOST_AUTO_TEST_CASE(manifest_validation)
{
    auto manifest{ValidManifest()};
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::NONE);

    manifest.spec.protocol_version++;
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::UNSUPPORTED_PROTOCOL_VERSION);
    manifest = ValidManifest();
    manifest.spec.template_id = 0;
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::INVALID_TEMPLATE_ID);
    manifest = ValidManifest();
    manifest.spec.template_version = 0;
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::INVALID_TEMPLATE_VERSION);
    manifest = ValidManifest();
    manifest.spec.consensus_parameters.resize(chainregistry::MAX_CONSENSUS_PARAMETERS_SIZE + 1);
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::CONSENSUS_PARAMETERS_TOO_LARGE);
    manifest = ValidManifest();
    manifest.spec.anchoring_policy = static_cast<chainregistry::AnchoringPolicy>(255);
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::UNKNOWN_ANCHORING_POLICY);
    manifest = ValidManifest();
    manifest.child_genesis_hash.SetNull();
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::NULL_GENESIS);
    manifest = ValidManifest();
    manifest.initial_metadata_hash = {};
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::NULL_METADATA_HASH);
}

BOOST_AUTO_TEST_CASE(operation_script_vectors_and_roundtrip)
{
    const chainregistry::RegistryOperation registration{chainregistry::RegisterChain{
        .anchor_input = 0,
        .control_output = 1,
        .manifest = ValidManifest(),
    }};
    const chainregistry::RegistryOperation update{chainregistry::UpdateChain{
        .chain_id = chainregistry::ChainId{"3333333333333333333333333333333333333333333333333333333333333333"},
        .control_output = 2,
        .metadata_hash = chainregistry::MetadataHash{"4444444444444444444444444444444444444444444444444444444444444444"},
    }};
    const chainregistry::RegistryOperation retirement{chainregistry::RetireChain{
        .chain_id = chainregistry::ChainId{"5555555555555555555555555555555555555555555555555555555555555555"},
    }};

    const std::vector<std::pair<chainregistry::RegistryOperation, std::string_view>> vectors{
        {registration,
         "6a4c5d4b524547010100000000010000000100010000000200000003aabbcc01"
         "1111111111111111111111111111111111111111111111111111111111111111"
         "2222222222222222222222222222222222222222222222222222222222222222"},
        {update,
         "6a4a4b52454701023333333333333333333333333333333333333333333333333333333333333333"
         "020000004444444444444444444444444444444444444444444444444444444444444444"},
        {retirement,
         "6a264b52454701035555555555555555555555555555555555555555555555555555555555555555"},
    };

    for (const auto& [operation, expected_hex] : vectors) {
        const CScript script{chainregistry::BuildOperationScript(operation)};
        BOOST_CHECK(script.IsUnspendable());
        BOOST_CHECK_EQUAL(HexStr(script), expected_hex);

        const auto parsed{chainregistry::ParseOperationScript(script)};
        BOOST_REQUIRE(parsed);
        BOOST_CHECK(*parsed.operation == operation);
    }
}

BOOST_AUTO_TEST_CASE(operation_validation)
{
    chainregistry::RegistryOperation operation{chainregistry::RegisterChain{
        .anchor_input = std::numeric_limits<uint32_t>::max(),
        .control_output = 0,
        .manifest = ValidManifest(),
    }};
    BOOST_CHECK(chainregistry::ValidateOperation(operation) == chainregistry::OperationValidationError::INVALID_ANCHOR_INPUT);

    auto& registration{std::get<chainregistry::RegisterChain>(operation)};
    registration.anchor_input = 0;
    registration.control_output = std::numeric_limits<uint32_t>::max();
    BOOST_CHECK(chainregistry::ValidateOperation(operation) == chainregistry::OperationValidationError::INVALID_CONTROL_OUTPUT);
    registration.control_output = 0;
    registration.manifest.child_genesis_hash.SetNull();
    BOOST_CHECK(chainregistry::ValidateOperation(operation) == chainregistry::OperationValidationError::INVALID_MANIFEST);

    operation = chainregistry::UpdateChain{};
    BOOST_CHECK(chainregistry::ValidateOperation(operation) == chainregistry::OperationValidationError::NULL_CHAIN_ID);
    operation = chainregistry::RetireChain{};
    BOOST_CHECK(chainregistry::ValidateOperation(operation) == chainregistry::OperationValidationError::NULL_CHAIN_ID);
}

BOOST_AUTO_TEST_CASE(operation_parser_rejects_invalid_envelopes)
{
    BOOST_CHECK(chainregistry::ParseOperationScript(CScript{}).error == chainregistry::OperationParseError::NOT_REGISTRY);
    BOOST_CHECK(chainregistry::ParseOperationScript(CScript{} << OP_RETURN).error == chainregistry::OperationParseError::NOT_REGISTRY);
    BOOST_CHECK(chainregistry::ParseOperationScript(CScript{} << OP_RETURN << ParseHex("abcd")).error == chainregistry::OperationParseError::NOT_REGISTRY);

    const auto bad_version{CScript{} << OP_RETURN << ParseHex("4b5245470203")};
    BOOST_CHECK(chainregistry::ParseOperationScript(bad_version).error == chainregistry::OperationParseError::UNSUPPORTED_ENVELOPE_VERSION);
    const auto unknown_type{CScript{} << OP_RETURN << ParseHex("4b52454701ff")};
    BOOST_CHECK(chainregistry::ParseOperationScript(unknown_type).error == chainregistry::OperationParseError::UNKNOWN_OPERATION_TYPE);
    const auto short_payload{CScript{} << OP_RETURN << ParseHex("4b5245470101")};
    BOOST_CHECK(chainregistry::ParseOperationScript(short_payload).error == chainregistry::OperationParseError::INVALID_PAYLOAD);

    auto oversized{ParseHex("4b524547")};
    oversized.resize(chainregistry::MAX_REGISTRY_DATA_SIZE + 1);
    BOOST_CHECK(chainregistry::ParseOperationScript(CScript{} << OP_RETURN << oversized).error == chainregistry::OperationParseError::DATA_TOO_LARGE);

    const auto retirement_data{ParseHex(
        "4b524547010355555555555555555555555555555555555555555555555555555555555555555500")};
    BOOST_CHECK(chainregistry::ParseOperationScript(CScript{} << OP_RETURN << retirement_data).error == chainregistry::OperationParseError::TRAILING_DATA);

    const auto canonical_retirement{ParseHex(
        "4b52454701035555555555555555555555555555555555555555555555555555555555555555555555")};
    const auto malformed{CScript{} << OP_RETURN << canonical_retirement << OP_0};
    BOOST_CHECK(chainregistry::ParseOperationScript(malformed).error == chainregistry::OperationParseError::MALFORMED_SCRIPT);

    CScript noncanonical;
    noncanonical << OP_RETURN;
    noncanonical.push_back(OP_PUSHDATA1);
    noncanonical.push_back(static_cast<unsigned char>(canonical_retirement.size()));
    noncanonical.insert(noncanonical.end(), canonical_retirement.begin(), canonical_retirement.end());
    BOOST_CHECK(chainregistry::ParseOperationScript(noncanonical).error == chainregistry::OperationParseError::NON_CANONICAL_SCRIPT);

    const chainregistry::RegistryOperation invalid{chainregistry::RetireChain{}};
    BOOST_CHECK(chainregistry::ParseOperationScript(chainregistry::BuildOperationScript(invalid)).error == chainregistry::OperationParseError::INVALID_OPERATION);
}

BOOST_AUTO_TEST_CASE(transaction_operation_extraction)
{
    CMutableTransaction plain_tx;
    plain_tx.vout.emplace_back(0, CScript{} << OP_RETURN << ParseHex("abcd"));
    auto result{chainregistry::ExtractTransactionOperation(CTransaction{plain_tx}, 1'000)};
    BOOST_CHECK(result.IsValid());
    BOOST_CHECK(!result.operation.has_value());

    const CMutableTransaction registration_tx{ValidRegistrationTx()};
    result = chainregistry::ExtractTransactionOperation(CTransaction{registration_tx}, 1'000);
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.operation.has_value());
    BOOST_CHECK_EQUAL(result.operation->registry_output, 0U);
    BOOST_CHECK(std::holds_alternative<chainregistry::RegisterChain>(result.operation->operation));

    CMutableTransaction update_tx;
    update_tx.vout.emplace_back(0, chainregistry::BuildOperationScript(chainregistry::UpdateChain{
        .chain_id = chainregistry::ChainId{"3333333333333333333333333333333333333333333333333333333333333333"},
        .control_output = 1,
        .metadata_hash = chainregistry::MetadataHash{"4444444444444444444444444444444444444444444444444444444444444444"},
    }));
    update_tx.vout.emplace_back(0, TaprootScript(2));
    result = chainregistry::ExtractTransactionOperation(CTransaction{update_tx}, 1'000);
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.operation.has_value());
    BOOST_CHECK(std::holds_alternative<chainregistry::UpdateChain>(result.operation->operation));

    CMutableTransaction retire_tx;
    retire_tx.vout.emplace_back(0, chainregistry::BuildOperationScript(chainregistry::RetireChain{
        .chain_id = chainregistry::ChainId{"5555555555555555555555555555555555555555555555555555555555555555"},
    }));
    result = chainregistry::ExtractTransactionOperation(CTransaction{retire_tx}, 1'000);
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.operation.has_value());
    BOOST_CHECK(std::holds_alternative<chainregistry::RetireChain>(result.operation->operation));
}

BOOST_AUTO_TEST_CASE(transaction_operation_rejects_invalid_context)
{
    CMutableTransaction tx{ValidRegistrationTx()};
    tx.vout[0].nValue = 999;
    auto result{chainregistry::ExtractTransactionOperation(CTransaction{tx}, 1'000)};
    BOOST_CHECK(result.error == chainregistry::TxOperationError::INSUFFICIENT_REGISTRATION_BURN);

    tx = ValidRegistrationTx();
    tx.vout[0].scriptPubKey = chainregistry::BuildOperationScript(ValidRegistration(1, 1));
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx}, 1'000);
    BOOST_CHECK(result.error == chainregistry::TxOperationError::INVALID_ANCHOR_INPUT);

    tx = ValidRegistrationTx();
    tx.vin[0].prevout.SetNull();
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx}, 1'000);
    BOOST_CHECK(result.error == chainregistry::TxOperationError::NULL_ANCHOR_PREVOUT);

    tx = ValidRegistrationTx();
    tx.vout[0].scriptPubKey = chainregistry::BuildOperationScript(ValidRegistration(0, 2));
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx}, 1'000);
    BOOST_CHECK(result.error == chainregistry::TxOperationError::INVALID_CONTROL_OUTPUT);

    tx = ValidRegistrationTx();
    tx.vout[0].scriptPubKey = chainregistry::BuildOperationScript(ValidRegistration(0, 0));
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx}, 1'000);
    BOOST_CHECK(result.error == chainregistry::TxOperationError::CONTROL_OUTPUT_COLLISION);

    tx = ValidRegistrationTx();
    tx.vout[1].scriptPubKey = CScript{} << OP_RETURN;
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx}, 1'000);
    BOOST_CHECK(result.error == chainregistry::TxOperationError::CONTROL_OUTPUT_NOT_P2TR);

    tx = ValidRegistrationTx();
    tx.vout[0].scriptPubKey = CScript{} << OP_RETURN << ParseHex("4b524547");
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx}, 1'000);
    BOOST_CHECK(result.error == chainregistry::TxOperationError::INVALID_ENVELOPE);
    BOOST_CHECK(result.parse_error == chainregistry::OperationParseError::INVALID_PAYLOAD);
}

BOOST_AUTO_TEST_CASE(transaction_operation_rejects_multiple_and_unexpected_value)
{
    CMutableTransaction tx{ValidRegistrationTx()};
    tx.vout[0].scriptPubKey = chainregistry::BuildOperationScript(ValidRegistration(0, 2));
    tx.vout[1] = CTxOut{0, chainregistry::BuildOperationScript(chainregistry::RetireChain{
        .chain_id = chainregistry::ChainId{"5555555555555555555555555555555555555555555555555555555555555555"},
    })};
    tx.vout.emplace_back(0, TaprootScript());
    auto result{chainregistry::ExtractTransactionOperation(CTransaction{tx}, 1'000)};
    BOOST_CHECK(result.error == chainregistry::TxOperationError::MULTIPLE_OPERATIONS);

    CMutableTransaction update_tx;
    update_tx.vout.emplace_back(1, chainregistry::BuildOperationScript(chainregistry::UpdateChain{
        .chain_id = chainregistry::ChainId{"3333333333333333333333333333333333333333333333333333333333333333"},
        .control_output = 1,
        .metadata_hash = chainregistry::MetadataHash{"4444444444444444444444444444444444444444444444444444444444444444"},
    }));
    update_tx.vout.emplace_back(0, TaprootScript());
    result = chainregistry::ExtractTransactionOperation(CTransaction{update_tx}, 1'000);
    BOOST_CHECK(result.error == chainregistry::TxOperationError::UNEXPECTED_OPERATION_VALUE);

    CMutableTransaction retire_tx;
    retire_tx.vout.emplace_back(1, chainregistry::BuildOperationScript(chainregistry::RetireChain{
        .chain_id = chainregistry::ChainId{"5555555555555555555555555555555555555555555555555555555555555555"},
    }));
    result = chainregistry::ExtractTransactionOperation(CTransaction{retire_tx}, 1'000);
    BOOST_CHECK(result.error == chainregistry::TxOperationError::UNEXPECTED_OPERATION_VALUE);
}

BOOST_AUTO_TEST_SUITE_END()
