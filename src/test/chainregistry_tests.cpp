// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/chainregistry.h>
#include <key.h>
#include <primitives/block.h>
#include <primitives/chainregistry.h>

#include <primitives/transaction.h>
#include <streams.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
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
        .default_fee_recipient = {
            .recipient_type = 1,
            .recipient = ParseHex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"),
        },
    };
}

chainregistry::DealerId TestDealerId(unsigned char byte = 1)
{
    std::array<unsigned char, 32> data{};
    data.fill(byte);
    return chainregistry::DealerId::FromUint256(uint256{std::span{data}});
}

COutPoint TestDealerControl(unsigned char byte = 1)
{
    std::array<unsigned char, 32> data{};
    data.fill(static_cast<unsigned char>(0x80U + byte));
    return COutPoint{Txid::FromUint256(uint256{std::span{data}}), 0};
}

const CKey& TestAuthorityPrivateKey()
{
    static const CKey key{[] {
        std::array<unsigned char, 32> secret{};
        secret.back() = 1;
        CKey result;
        result.Set(secret.begin(), secret.end(), true);
        return result;
    }()};
    return key;
}

const chainregistry::DealerAuthority& TestAuthorityKey()
{
    static const auto authority{[] {
        const XOnlyPubKey pubkey{TestAuthorityPrivateKey().GetPubKey()};
        chainregistry::DealerAuthority result{.threshold = 1, .keys = {{}}};
        std::copy(pubkey.begin(), pubkey.end(), result.keys[0].begin());
        return result;
    }()};
    return authority;
}

template <typename Operation>
Operation SignAdminOperation(Operation operation, const uint256& main_genesis)
{
    chainregistry::RegistryOperation variant{operation};
    const auto digest{chainregistry::ComputeDealerAuthorityHash(main_genesis, variant)};
    BOOST_REQUIRE(digest.has_value());
    operation.authority_signatures.signers = 1;
    operation.authority_signatures.signatures.resize(1);
    BOOST_REQUIRE(TestAuthorityPrivateKey().SignSchnorr(
        *digest, operation.authority_signatures.signatures[0], nullptr, uint256{}));
    return operation;
}

CMutableTransaction OperationTx(const chainregistry::RegistryOperation& operation,
                                std::optional<CScript> control = std::nullopt)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{
        Txid{"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}, 0});
    tx.vout.emplace_back(0, chainregistry::BuildOperationScript(operation));
    if (control) tx.vout.emplace_back(0, *control);
    return tx;
}

chainregistry::RegistryOperation ValidRegistration(uint32_t anchor_input = 0,
                                                   uint32_t control_output = 1,
                                                   unsigned char dealer_byte = 1)
{
    return chainregistry::RegisterChain{
        .anchor_input = anchor_input,
        .control_output = control_output,
        .dealer_id = TestDealerId(dealer_byte),
        .dealer_control_output = 2,
        .dealer_payment_output = 3,
        .manifest = ValidManifest(),
    };
}

CScript TaprootScript(unsigned char byte = 1)
{
    return CScript{} << OP_1 << std::vector<unsigned char>(32, byte);
}

CMutableTransaction ValidRegistrationTx(CAmount operation_value = 0)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{
        Txid{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, 0});
    tx.vin.emplace_back(TestDealerControl());
    tx.vout.emplace_back(operation_value, chainregistry::BuildOperationScript(ValidRegistration()));
    tx.vout.emplace_back(0, TaprootScript());
    tx.vout.emplace_back(0, TaprootScript(0x41));
    tx.vout.emplace_back(1'000, TaprootScript(0x81));
    return tx;
}

CMutableTransaction RegistrationTx(const Txid& anchor_txid,
                                   uint32_t anchor_vout,
                                   unsigned char control_byte,
                                   CAmount operation_value = 0)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{anchor_txid, anchor_vout});
    tx.vin.emplace_back(TestDealerControl(control_byte));
    tx.vout.emplace_back(operation_value,
                         chainregistry::BuildOperationScript(
                             ValidRegistration(0, 1, control_byte)));
    tx.vout.emplace_back(0, TaprootScript(control_byte));
    tx.vout.emplace_back(0, TaprootScript(static_cast<unsigned char>(0x40U + control_byte)));
    tx.vout.emplace_back(1'000, TaprootScript(static_cast<unsigned char>(0x80U + control_byte)));
    return tx;
}

void SeedDealers(chainregistry::ChainRegistry& registry, unsigned count = 32)
{
    std::vector<chainregistry::DealerRecord> dealers;
    dealers.reserve(count);
    for (unsigned index{1}; index <= count; ++index) {
        const auto byte{static_cast<unsigned char>(index)};
        dealers.push_back(chainregistry::DealerRecord{
            .dealer_id = TestDealerId(byte),
            .control_outpoint = TestDealerControl(byte),
            .payout_script = TaprootScript(static_cast<unsigned char>(0x80U + byte)),
            .remaining_licenses = 1,
            .status = chainregistry::DealerStatus::ACTIVE,
            .authorized_height = 1,
            .updated_height = 1,
        });
    }
    BOOST_REQUIRE(registry.LoadState({}, std::move(dealers), 0).IsValid());
}

CMutableTransaction UpdateTx(const chainregistry::ChainRecord& record,
                             const chainregistry::MetadataHash& metadata_hash,
                             unsigned char control_byte)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(record.control_outpoint);
    tx.vout.emplace_back(0, chainregistry::BuildOperationScript(chainregistry::UpdateChain{
        .chain_id = record.chain_id,
        .control_output = 1,
        .metadata_hash = metadata_hash,
    }));
    tx.vout.emplace_back(0, TaprootScript(control_byte));
    return tx;
}

CMutableTransaction RetireTx(const chainregistry::ChainRecord& record)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(record.control_outpoint);
    tx.vout.emplace_back(0, chainregistry::BuildOperationScript(chainregistry::RetireChain{
        .chain_id = record.chain_id,
    }));
    return tx;
}

CMutableTransaction CoinbaseTx(std::optional<uint256> registry_root = std::nullopt)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{});
    tx.vout.emplace_back(0, TaprootScript(0));
    if (registry_root) tx.vout.emplace_back(0, chainregistry::BuildRegistryCommitment(*registry_root));
    return tx;
}

CBlock RegistryBlock(const CMutableTransaction& coinbase, std::vector<CMutableTransaction> transactions)
{
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(coinbase));
    for (auto& tx : transactions) block.vtx.push_back(MakeTransactionRef(std::move(tx)));
    return block;
}

} // namespace

struct ChainRegistryTestingSetup {
    ECC_Context ecc_context;
};

BOOST_FIXTURE_TEST_SUITE(chainregistry_tests, ChainRegistryTestingSetup)

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
        "2222222222222222222222222222222222222222222222222222222222222222"
        "010020"
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");
    BOOST_CHECK_EQUAL(chainregistry::ComputeManifestHash(manifest).GetHex(),
                      "d20e2bbc2b6025668c0142b3d82fb4fb1d9f4dfda9316271c18893b245ef12f0");
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
    manifest = ValidManifest();
    manifest.default_fee_recipient.recipient_type = 0;
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::INVALID_FEE_RECIPIENT_TYPE);
    manifest = ValidManifest();
    manifest.default_fee_recipient.recipient.clear();
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::INVALID_FEE_RECIPIENT_SIZE);
    manifest.default_fee_recipient.recipient.resize(
        chainregistry::MAX_FEE_RECIPIENT_SIZE + 1);
    BOOST_CHECK(chainregistry::ValidateManifest(manifest) == chainregistry::ManifestValidationError::INVALID_FEE_RECIPIENT_SIZE);
}

BOOST_AUTO_TEST_CASE(operation_script_vectors_and_roundtrip)
{
    const chainregistry::RegistryOperation registration{chainregistry::RegisterChain{
        .anchor_input = 0,
        .control_output = 1,
        .dealer_id = TestDealerId(),
        .dealer_control_output = 2,
        .dealer_payment_output = 3,
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
    chainregistry::AuthorizeDealer authorization{
        .authority_sequence = 1,
        .authorization_nonce = uint256{
            "6666666666666666666666666666666666666666666666666666666666666666"},
        .control_output = 1,
        .payout_script = ParseHex(
            "51207777777777777777777777777777777777777777777777777777777777777777"),
        .initial_licenses = 10,
    };
    const auto authority_key{ParseHex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")};
    std::copy(authority_key.begin(), authority_key.end(), authorization.control_key.begin());
    authorization.authority_signatures = {1, {{}}};
    authorization.authority_signatures.signatures[0].fill(0x88);
    chainregistry::UpdateDealer dealer_update{
        .authority_sequence = 2,
        .dealer_id = TestDealerId(),
        .added_licenses = 3,
        .payout_script = {},
    };
    dealer_update.authority_signatures = {1, {{}}};
    dealer_update.authority_signatures.signatures[0].fill(0x99);
    chainregistry::RevokeDealer dealer_revocation{
        .authority_sequence = 3,
        .dealer_id = TestDealerId(),
    };
    dealer_revocation.authority_signatures = {1, {{}}};
    dealer_revocation.authority_signatures.signatures[0].fill(0xaa);

    const std::vector<std::pair<chainregistry::RegistryOperation, std::string_view>> vectors{
        {registration,
         "6a4ca84b52454701010000000001000000"
         "0101010101010101010101010101010101010101010101010101010101010101"
         "02000000030000000100010000000200000003aabbcc01"
         "1111111111111111111111111111111111111111111111111111111111111111"
         "2222222222222222222222222222222222222222222222222222222222222222"
         "010020"
         "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"},
        {update,
         "6a4a4b52454701023333333333333333333333333333333333333333333333333333333333333333"
         "020000004444444444444444444444444444444444444444444444444444444444444444"},
        {retirement,
         "6a264b52454701035555555555555555555555555555555555555555555555555555555555555555"},
        {authorization,
         "6a4cba4b52454702040100000000000000"
         "6666666666666666666666666666666666666666666666666666666666666666"
         "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
         "010000002251207777777777777777777777777777777777777777777777777777777777777777"
         "0a00000001"
         "8888888888888888888888888888888888888888888888888888888888888888"
         "8888888888888888888888888888888888888888888888888888888888888888"},
        {dealer_update,
         "6a4c744b52454702050200000000000000"
         "0101010101010101010101010101010101010101010101010101010101010101"
         "030000000001"
         "9999999999999999999999999999999999999999999999999999999999999999"
         "9999999999999999999999999999999999999999999999999999999999999999"},
        {dealer_revocation,
         "6a4c6f4b52454702060300000000000000"
         "0101010101010101010101010101010101010101010101010101010101010101"
         "01"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
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
        .dealer_id = TestDealerId(),
        .dealer_control_output = 1,
        .dealer_payment_output = 2,
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
    auto result{chainregistry::ExtractTransactionOperation(CTransaction{plain_tx})};
    BOOST_CHECK(result.IsValid());
    BOOST_CHECK(!result.operation.has_value());

    const CMutableTransaction registration_tx{ValidRegistrationTx()};
    result = chainregistry::ExtractTransactionOperation(CTransaction{registration_tx});
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
    result = chainregistry::ExtractTransactionOperation(CTransaction{update_tx});
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.operation.has_value());
    BOOST_CHECK(std::holds_alternative<chainregistry::UpdateChain>(result.operation->operation));

    CMutableTransaction retire_tx;
    retire_tx.vout.emplace_back(0, chainregistry::BuildOperationScript(chainregistry::RetireChain{
        .chain_id = chainregistry::ChainId{"5555555555555555555555555555555555555555555555555555555555555555"},
    }));
    result = chainregistry::ExtractTransactionOperation(CTransaction{retire_tx});
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.operation.has_value());
    BOOST_CHECK(std::holds_alternative<chainregistry::RetireChain>(result.operation->operation));
}

BOOST_AUTO_TEST_CASE(transaction_operation_rejects_invalid_context)
{
    CMutableTransaction tx{ValidRegistrationTx()};
    tx.vout[0].nValue = 999;
    auto result{chainregistry::ExtractTransactionOperation(CTransaction{tx})};
    BOOST_CHECK(result.error == chainregistry::TxOperationError::UNEXPECTED_OPERATION_VALUE);

    tx = ValidRegistrationTx();
    tx.vout[0].scriptPubKey = chainregistry::BuildOperationScript(ValidRegistration(2, 1));
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::INVALID_ANCHOR_INPUT);

    tx = ValidRegistrationTx();
    tx.vin[0].prevout.SetNull();
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::NULL_ANCHOR_PREVOUT);

    tx = ValidRegistrationTx();
    tx.vout[0].scriptPubKey = chainregistry::BuildOperationScript(ValidRegistration(0, 4));
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::INVALID_CONTROL_OUTPUT);

    tx = ValidRegistrationTx();
    tx.vout[0].scriptPubKey = chainregistry::BuildOperationScript(ValidRegistration(0, 0));
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::CONTROL_OUTPUT_COLLISION);

    tx = ValidRegistrationTx();
    tx.vout[1].scriptPubKey = CScript{} << OP_RETURN;
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::CONTROL_OUTPUT_NOT_P2TR);

    tx = ValidRegistrationTx();
    tx.vout[2].scriptPubKey = CScript{} << OP_RETURN;
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::CONTROL_OUTPUT_NOT_P2TR);

    tx = ValidRegistrationTx();
    tx.vout[3].nValue = 0;
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::INVALID_DEALER_PAYMENT);

    tx = ValidRegistrationTx();
    auto registration{std::get<chainregistry::RegisterChain>(ValidRegistration())};
    registration.dealer_payment_output = registration.dealer_control_output;
    tx.vout[0].scriptPubKey = chainregistry::BuildOperationScript(registration);
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::OUTPUT_COLLISION);

    tx = ValidRegistrationTx();
    registration = std::get<chainregistry::RegisterChain>(ValidRegistration());
    registration.dealer_payment_output = static_cast<uint32_t>(tx.vout.size());
    tx.vout[0].scriptPubKey = chainregistry::BuildOperationScript(registration);
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::INVALID_DEALER_PAYMENT);

    tx = ValidRegistrationTx();
    tx.vout[0].scriptPubKey = CScript{} << OP_RETURN << ParseHex("4b524547");
    result = chainregistry::ExtractTransactionOperation(CTransaction{tx});
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
    auto result{chainregistry::ExtractTransactionOperation(CTransaction{tx})};
    BOOST_CHECK(result.error == chainregistry::TxOperationError::MULTIPLE_OPERATIONS);

    CMutableTransaction update_tx;
    update_tx.vout.emplace_back(1, chainregistry::BuildOperationScript(chainregistry::UpdateChain{
        .chain_id = chainregistry::ChainId{"3333333333333333333333333333333333333333333333333333333333333333"},
        .control_output = 1,
        .metadata_hash = chainregistry::MetadataHash{"4444444444444444444444444444444444444444444444444444444444444444"},
    }));
    update_tx.vout.emplace_back(0, TaprootScript());
    result = chainregistry::ExtractTransactionOperation(CTransaction{update_tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::UNEXPECTED_OPERATION_VALUE);

    CMutableTransaction retire_tx;
    retire_tx.vout.emplace_back(1, chainregistry::BuildOperationScript(chainregistry::RetireChain{
        .chain_id = chainregistry::ChainId{"5555555555555555555555555555555555555555555555555555555555555555"},
    }));
    result = chainregistry::ExtractTransactionOperation(CTransaction{retire_tx});
    BOOST_CHECK(result.error == chainregistry::TxOperationError::UNEXPECTED_OPERATION_VALUE);
}

BOOST_AUTO_TEST_CASE(registry_record_hash_vectors)
{
    const chainregistry::ChainRecord record{
        .record_version = chainregistry::CHAIN_RECORD_VERSION,
        .chain_id = chainregistry::ChainId{"1111111111111111111111111111111111111111111111111111111111111111"},
        .manifest_hash = chainregistry::ManifestHash{"2222222222222222222222222222222222222222222222222222222222222222"},
        .template_id = 1,
        .template_version = 2,
        .control_outpoint = COutPoint{
            Txid{"3333333333333333333333333333333333333333333333333333333333333333"}, 4},
        .metadata_hash = chainregistry::MetadataHash{"4444444444444444444444444444444444444444444444444444444444444444"},
        .status = chainregistry::ChainStatus::ACTIVE,
        .registered_height = 100,
        .updated_height = 101,
        .retired_height = 0,
    };
    DataStream stream;
    stream << record;
    BOOST_CHECK_EQUAL(
        HexStr(stream),
        "01"
        "1111111111111111111111111111111111111111111111111111111111111111"
        "2222222222222222222222222222222222222222222222222222222222222222"
        "0100000002000000"
        "333333333333333333333333333333333333333333333333333333333333333304000000"
        "4444444444444444444444444444444444444444444444444444444444444444"
        "01640000006500000000000000");
    const uint256 leaf{chainregistry::ComputeRegistryLeafHash(record)};
    BOOST_CHECK_EQUAL(leaf.GetHex(),
                      "d9ff06f866121978c5358460276b39fbb5244a4edf3589c868d3da5172001c56");
    BOOST_CHECK_EQUAL(chainregistry::ComputeRegistryRootFromLeaves({leaf}).GetHex(),
                      "a32e93c64b78afae08ea32edac25f9c44dcce59a651c5744bec325ec107c8f1e");

    chainregistry::ChainRegistry registry;
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(),
                      "a50abeda09f86c49411f03598c9f3786d93807d11ed4a0d9695f0a88e5172421");

    const chainregistry::RegistryUndo undo{
        .has_chain = true,
        .chain_id = record.chain_id,
        .chain_had_previous = true,
        .previous_chain = record,
        .has_dealer = false,
        .dealer_id = {},
        .dealer_had_previous = false,
        .previous_dealer = {},
        .previous_authority_sequence = 0,
    };
    DataStream undo_stream;
    undo_stream << undo;
    chainregistry::RegistryUndo decoded;
    undo_stream >> decoded;
    BOOST_CHECK(decoded == undo);
    BOOST_CHECK(undo_stream.empty());
}

BOOST_AUTO_TEST_CASE(registry_commitment_vectors_and_roundtrip)
{
    constexpr uint256 root{"1111111111111111111111111111111111111111111111111111111111111111"};
    const CScript script{chainregistry::BuildRegistryCommitment(root)};
    BOOST_CHECK_EQUAL(
        HexStr(script),
        "6a254b52525402"
        "1111111111111111111111111111111111111111111111111111111111111111");
    BOOST_CHECK(script.IsUnspendable());

    const auto parsed{chainregistry::ParseRegistryCommitment(script)};
    BOOST_REQUIRE(parsed);
    BOOST_CHECK_EQUAL(parsed.root->GetHex(), root.GetHex());

    CMutableTransaction tx;
    tx.vout.emplace_back(0, CScript{} << OP_RETURN << ParseHex("abcd"));
    tx.vout.emplace_back(0, script);
    const auto extracted{chainregistry::ExtractRegistryCommitment(CTransaction{tx})};
    BOOST_REQUIRE(extracted.IsValid());
    BOOST_REQUIRE(extracted.output_index.has_value());
    BOOST_REQUIRE(extracted.root.has_value());
    BOOST_CHECK_EQUAL(*extracted.output_index, 1U);
    BOOST_CHECK_EQUAL(extracted.root->GetHex(), root.GetHex());
}

BOOST_AUTO_TEST_CASE(registry_commitment_rejects_invalid_encodings)
{
    constexpr uint256 root{"1111111111111111111111111111111111111111111111111111111111111111"};
    const auto canonical_data{ParseHex(
        "4b52525402"
        "1111111111111111111111111111111111111111111111111111111111111111")};

    BOOST_CHECK(chainregistry::ParseRegistryCommitment(CScript{}).error == chainregistry::CommitmentParseError::NOT_COMMITMENT);
    BOOST_CHECK(chainregistry::ParseRegistryCommitment(CScript{} << OP_RETURN << ParseHex("abcd")).error == chainregistry::CommitmentParseError::NOT_COMMITMENT);
    BOOST_CHECK(chainregistry::ParseRegistryCommitment(CScript{} << OP_RETURN << ParseHex("4b52525402")).error == chainregistry::CommitmentParseError::INVALID_LENGTH);

    auto bad_version{canonical_data};
    bad_version[4] = 1;
    BOOST_CHECK(chainregistry::ParseRegistryCommitment(CScript{} << OP_RETURN << bad_version).error == chainregistry::CommitmentParseError::UNSUPPORTED_VERSION);

    const auto malformed{CScript{} << OP_RETURN << canonical_data << OP_0};
    BOOST_CHECK(chainregistry::ParseRegistryCommitment(malformed).error == chainregistry::CommitmentParseError::MALFORMED_SCRIPT);

    CScript noncanonical;
    noncanonical << OP_RETURN;
    noncanonical.push_back(OP_PUSHDATA1);
    noncanonical.push_back(static_cast<unsigned char>(canonical_data.size()));
    noncanonical.insert(noncanonical.end(), canonical_data.begin(), canonical_data.end());
    BOOST_CHECK(chainregistry::ParseRegistryCommitment(noncanonical).error == chainregistry::CommitmentParseError::NON_CANONICAL_SCRIPT);

    CMutableTransaction nonzero_tx;
    nonzero_tx.vout.emplace_back(1, chainregistry::BuildRegistryCommitment(root));
    auto extracted{chainregistry::ExtractRegistryCommitment(CTransaction{nonzero_tx})};
    BOOST_CHECK(extracted.error == chainregistry::CommitmentTxError::NONZERO_VALUE);

    CMutableTransaction duplicate_tx;
    duplicate_tx.vout.emplace_back(0, chainregistry::BuildRegistryCommitment(root));
    duplicate_tx.vout.emplace_back(0, chainregistry::BuildRegistryCommitment(root));
    extracted = chainregistry::ExtractRegistryCommitment(CTransaction{duplicate_tx});
    BOOST_CHECK(extracted.error == chainregistry::CommitmentTxError::MULTIPLE_COMMITMENTS);

    CMutableTransaction invalid_tx;
    invalid_tx.vout.emplace_back(0, CScript{} << OP_RETURN << ParseHex("4b52525402"));
    extracted = chainregistry::ExtractRegistryCommitment(CTransaction{invalid_tx});
    BOOST_CHECK(extracted.error == chainregistry::CommitmentTxError::INVALID_COMMITMENT);
    BOOST_CHECK(extracted.parse_error == chainregistry::CommitmentParseError::INVALID_LENGTH);
}

BOOST_AUTO_TEST_CASE(registry_lifecycle_and_undo)
{
    constexpr uint256 main_genesis{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    const CMutableTransaction registration_tx{RegistrationTx(
        Txid{"0101010101010101010101010101010101010101010101010101010101010101"}, 7, 1)};

    chainregistry::ChainRegistry registry;
    SeedDealers(registry);
    const uint256 empty_root{registry.ComputeRoot()};
    auto result{registry.ApplyTransaction(CTransaction{registration_tx}, 100, main_genesis, TestAuthorityKey())};
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.HasOperation());
    BOOST_REQUIRE(result.undo.has_value());
    BOOST_CHECK_EQUAL(registry.Size(), 1U);
    BOOST_CHECK(registry.ComputeRoot() != empty_root);

    const chainregistry::ChainId chain_id{*result.chain_id};
    const chainregistry::ChainRecord* record{registry.Find(chain_id)};
    BOOST_REQUIRE(record != nullptr);
    BOOST_CHECK(record->status == chainregistry::ChainStatus::ACTIVE);
    BOOST_CHECK_EQUAL(record->template_id, 1U);
    BOOST_CHECK_EQUAL(record->template_version, 2U);
    BOOST_CHECK_EQUAL(record->registered_height, 100U);
    BOOST_CHECK_EQUAL(record->updated_height, 100U);
    BOOST_CHECK_EQUAL(record->control_outpoint.hash.GetHex(), CTransaction{registration_tx}.GetHash().GetHex());

    const uint256 registered_root{registry.ComputeRoot()};
    const chainregistry::RegistryUndo registration_undo{*result.undo};
    const auto metadata{chainregistry::MetadataHash{"abababababababababababababababababababababababababababababababab"}};
    const CMutableTransaction update_tx{UpdateTx(*record, metadata, 2)};
    result = registry.ApplyTransaction(CTransaction{update_tx}, 101, main_genesis, TestAuthorityKey());
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.undo.has_value());
    const chainregistry::RegistryUndo update_undo{*result.undo};

    record = registry.Find(chain_id);
    BOOST_REQUIRE(record != nullptr);
    BOOST_CHECK(record->metadata_hash == metadata);
    BOOST_CHECK_EQUAL(record->updated_height, 101U);
    BOOST_CHECK(registry.ComputeRoot() != registered_root);

    const CMutableTransaction retire_tx{RetireTx(*record)};
    result = registry.ApplyTransaction(CTransaction{retire_tx}, 102, main_genesis, TestAuthorityKey());
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.undo.has_value());
    const chainregistry::RegistryUndo retire_undo{*result.undo};
    record = registry.Find(chain_id);
    BOOST_REQUIRE(record != nullptr);
    BOOST_CHECK(record->status == chainregistry::ChainStatus::RETIRED);
    BOOST_CHECK_EQUAL(record->retired_height, 102U);

    const CMutableTransaction update_after_retire{UpdateTx(*record, metadata, 3)};
    const auto retired_result{registry.ApplyTransaction(CTransaction{update_after_retire}, 103, main_genesis, TestAuthorityKey())};
    BOOST_CHECK(retired_result.error == chainregistry::RegistryError::RETIRED_CHAIN);

    BOOST_REQUIRE(registry.Undo(retire_undo));
    BOOST_REQUIRE(registry.Undo(update_undo));
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), registered_root.GetHex());
    BOOST_REQUIRE(registry.Undo(registration_undo));
    BOOST_CHECK_EQUAL(registry.Size(), 0U);
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), empty_root.GetHex());
}

BOOST_AUTO_TEST_CASE(dealer_authorization_sale_update_revoke_and_undo)
{
    constexpr uint256 main_genesis{
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    std::array<unsigned char, 32> dealer_secret{};
    dealer_secret.back() = 2;
    CKey dealer_key;
    dealer_key.Set(dealer_secret.begin(), dealer_secret.end(), true);
    const XOnlyPubKey dealer_xonly{dealer_key.GetPubKey()};
    const CScript dealer_control_script{CScript{} << OP_1 << std::vector<unsigned char>{
        dealer_xonly.begin(), dealer_xonly.end()}};
    const CScript initial_payout{TaprootScript(0x51)};
    const CScript rotated_payout{TaprootScript(0x52)};

    chainregistry::AuthorizeDealer authorization{
        .authority_sequence = 1,
        .authorization_nonce = uint256{
            "0101010101010101010101010101010101010101010101010101010101010101"},
        .control_output = 1,
        .payout_script = {initial_payout.begin(), initial_payout.end()},
        .initial_licenses = 10,
    };
    std::copy(dealer_xonly.begin(), dealer_xonly.end(), authorization.control_key.begin());
    const auto authority_digest{chainregistry::ComputeDealerAuthorityHash(
        main_genesis, chainregistry::RegistryOperation{authorization})};
    BOOST_REQUIRE(authority_digest.has_value());
    BOOST_CHECK_EQUAL(
        HexStr(std::span{authority_digest->begin(), authority_digest->size()}),
        "28c3eeebcf6d5a51128f2ccaa6407976f2638e1b41977c5698abe0b1276e491d");
    auto authorization_with_signature{authorization};
    authorization_with_signature.authority_signatures = {1, {{}}};
    authorization_with_signature.authority_signatures.signatures[0].fill(0x42);
    BOOST_CHECK(chainregistry::ComputeDealerAuthorityHash(
                    main_genesis,
                    chainregistry::RegistryOperation{authorization_with_signature}) ==
                authority_digest);
    authorization = SignAdminOperation(authorization, main_genesis);
    const CMutableTransaction authorization_tx{OperationTx(
        authorization, dealer_control_script)};

    chainregistry::ChainRegistry registry;
    const uint256 empty_root{registry.ComputeRoot()};
    const auto authorized{registry.ApplyTransaction(
        CTransaction{authorization_tx}, 10, main_genesis, TestAuthorityKey())};
    BOOST_REQUIRE(authorized.IsValid());
    BOOST_REQUIRE(authorized.dealer_id.has_value());
    BOOST_REQUIRE(authorized.undo.has_value());
    BOOST_CHECK_EQUAL(registry.AuthoritySequence(), 1U);
    const chainregistry::DealerId dealer_id{*authorized.dealer_id};
    const auto* dealer{registry.FindDealer(dealer_id)};
    BOOST_REQUIRE(dealer);
    BOOST_CHECK_EQUAL(dealer->remaining_licenses, 10U);
    BOOST_CHECK(dealer->payout_script == initial_payout);
    BOOST_CHECK(dealer->control_outpoint == COutPoint(authorization_tx.GetHash(), 1));

    auto replay_tx{authorization_tx};
    replay_tx.vin[0].prevout.n = 1;
    const auto replayed{registry.ApplyTransaction(
        CTransaction{replay_tx}, 11, main_genesis, TestAuthorityKey())};
    BOOST_CHECK(replayed.error == chainregistry::RegistryError::INVALID_AUTHORITY_SEQUENCE);

    auto bad_signature{authorization};
    bad_signature.authority_sequence = 2;
    bad_signature.authority_signatures.signatures[0][0] ^= 1;
    const auto invalid_signature{registry.ApplyTransaction(
        CTransaction{OperationTx(bad_signature, dealer_control_script)},
        11, main_genesis, TestAuthorityKey())};
    BOOST_CHECK(invalid_signature.error == chainregistry::RegistryError::INVALID_AUTHORITY_SIGNATURE);

    auto update{SignAdminOperation(chainregistry::UpdateDealer{
        .authority_sequence = 2,
        .dealer_id = dealer_id,
        .added_licenses = 3,
        .payout_script = {rotated_payout.begin(), rotated_payout.end()},
    }, main_genesis)};
    const auto updated{registry.ApplyTransaction(
        CTransaction{OperationTx(update)}, 12, main_genesis, TestAuthorityKey())};
    BOOST_REQUIRE(updated.IsValid());
    BOOST_REQUIRE(updated.undo.has_value());
    dealer = registry.FindDealer(dealer_id);
    BOOST_REQUIRE(dealer);
    BOOST_CHECK_EQUAL(dealer->remaining_licenses, 13U);
    BOOST_CHECK(dealer->payout_script == rotated_payout);
    BOOST_CHECK_EQUAL(registry.AuthoritySequence(), 2U);

    CMutableTransaction sale{RegistrationTx(
        Txid{"0202020202020202020202020202020202020202020202020202020202020202"},
        0, 7)};
    auto sale_operation{std::get<chainregistry::RegisterChain>(
        chainregistry::ExtractTransactionOperation(CTransaction{sale}).operation->operation)};
    sale_operation.dealer_id = dealer_id;
    sale.vin[1].prevout = dealer->control_outpoint;
    sale.vout[0].scriptPubKey = chainregistry::BuildOperationScript(sale_operation);
    sale.vout[3].scriptPubKey = rotated_payout;
    const auto sold{registry.ApplyTransaction(
        CTransaction{sale}, 13, main_genesis, TestAuthorityKey())};
    BOOST_REQUIRE(sold.IsValid());
    BOOST_REQUIRE(sold.chain_id.has_value());
    BOOST_REQUIRE(sold.undo.has_value());
    dealer = registry.FindDealer(dealer_id);
    BOOST_REQUIRE(dealer);
    BOOST_CHECK_EQUAL(dealer->remaining_licenses, 12U);
    BOOST_CHECK(dealer->control_outpoint == COutPoint(sale.GetHash(), 2));

    const uint256 pre_corrupt_undo_root{registry.ComputeRoot()};
    auto mismatched_dealer{*dealer};
    mismatched_dealer.dealer_id = TestDealerId(0x7f);
    const chainregistry::RegistryUndo corrupt_undo{
        .has_chain = true,
        .chain_id = *sold.chain_id,
        .chain_had_previous = false,
        .previous_chain = {},
        .has_dealer = true,
        .dealer_id = dealer_id,
        .dealer_had_previous = true,
        .previous_dealer = mismatched_dealer,
        .previous_authority_sequence = registry.AuthoritySequence(),
    };
    BOOST_CHECK(!registry.Undo(corrupt_undo));
    BOOST_CHECK(registry.ComputeRoot() == pre_corrupt_undo_root);
    BOOST_REQUIRE(registry.Find(*sold.chain_id));
    BOOST_REQUIRE(registry.FindDealer(dealer_id));

    const auto revocation{SignAdminOperation(chainregistry::RevokeDealer{
        .authority_sequence = 3,
        .dealer_id = dealer_id,
    }, main_genesis)};
    const auto revoked{registry.ApplyTransaction(
        CTransaction{OperationTx(revocation)}, 14, main_genesis, TestAuthorityKey())};
    BOOST_REQUIRE(revoked.IsValid());
    BOOST_REQUIRE(revoked.undo.has_value());
    dealer = registry.FindDealer(dealer_id);
    BOOST_REQUIRE(dealer);
    BOOST_CHECK(dealer->status == chainregistry::DealerStatus::REVOKED);
    BOOST_CHECK_EQUAL(registry.AuthoritySequence(), 3U);

    CMutableTransaction forbidden_sale{sale};
    forbidden_sale.vin[0].prevout.n = 1;
    forbidden_sale.vin[1].prevout = dealer->control_outpoint;
    const auto forbidden{registry.ApplyTransaction(
        CTransaction{forbidden_sale}, 15, main_genesis, TestAuthorityKey())};
    BOOST_CHECK(forbidden.error == chainregistry::RegistryError::REVOKED_DEALER);

    BOOST_REQUIRE(registry.Undo(*revoked.undo));
    BOOST_REQUIRE(registry.Undo(*sold.undo));
    BOOST_REQUIRE(registry.Undo(*updated.undo));
    BOOST_REQUIRE(registry.Undo(*authorized.undo));
    BOOST_CHECK_EQUAL(registry.DealerSize(), 0U);
    BOOST_CHECK_EQUAL(registry.Size(), 0U);
    BOOST_CHECK_EQUAL(registry.AuthoritySequence(), 0U);
    BOOST_CHECK(registry.ComputeRoot() == empty_root);
}

BOOST_AUTO_TEST_CASE(registry_rejects_unauthorized_control_spends)
{
    constexpr uint256 main_genesis{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    const CMutableTransaction registration_tx{RegistrationTx(
        Txid{"0101010101010101010101010101010101010101010101010101010101010101"}, 7, 1)};
    chainregistry::ChainRegistry registry;
    SeedDealers(registry);
    const auto registered{registry.ApplyTransaction(CTransaction{registration_tx}, 100, main_genesis, TestAuthorityKey())};
    BOOST_REQUIRE(registered.IsValid());
    const chainregistry::ChainRecord* record{registry.Find(*registered.chain_id)};
    BOOST_REQUIRE(record != nullptr);
    const uint256 root{registry.ComputeRoot()};

    CMutableTransaction silent_spend;
    silent_spend.vin.emplace_back(record->control_outpoint);
    silent_spend.vout.emplace_back(0, TaprootScript(2));
    auto result{registry.ApplyTransaction(CTransaction{silent_spend}, 101, main_genesis, TestAuthorityKey())};
    BOOST_CHECK(result.error == chainregistry::RegistryError::CONTROL_SPEND_WITHOUT_OPERATION);
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), root.GetHex());

    CMutableTransaction wrong_control{UpdateTx(*record,
        chainregistry::MetadataHash{"abababababababababababababababababababababababababababababababab"}, 2)};
    wrong_control.vin[0].prevout = COutPoint{
        Txid{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}, 0};
    result = registry.ApplyTransaction(CTransaction{wrong_control}, 101, main_genesis, TestAuthorityKey());
    BOOST_CHECK(result.error == chainregistry::RegistryError::WRONG_CONTROL_OUTPOINT);

    const CMutableTransaction anchor_spend{RegistrationTx(
        record->control_outpoint.hash, record->control_outpoint.n, 2)};
    result = registry.ApplyTransaction(CTransaction{anchor_spend}, 101, main_genesis, TestAuthorityKey());
    BOOST_CHECK(result.error == chainregistry::RegistryError::WRONG_CONTROL_OUTPOINT);
}

BOOST_AUTO_TEST_CASE(registry_ordering_and_duplicate_identity)
{
    constexpr uint256 main_genesis{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    const CMutableTransaction tx_a{RegistrationTx(
        Txid{"0101010101010101010101010101010101010101010101010101010101010101"}, 0, 1)};
    const CMutableTransaction tx_b{RegistrationTx(
        Txid{"0202020202020202020202020202020202020202020202020202020202020202"}, 0, 2)};

    chainregistry::ChainRegistry first;
    SeedDealers(first);
    BOOST_REQUIRE(first.ApplyTransaction(CTransaction{tx_a}, 100, main_genesis, TestAuthorityKey()).IsValid());
    BOOST_REQUIRE(first.ApplyTransaction(CTransaction{tx_b}, 100, main_genesis, TestAuthorityKey()).IsValid());

    chainregistry::ChainRegistry second;
    SeedDealers(second);
    BOOST_REQUIRE(second.ApplyTransaction(CTransaction{tx_b}, 100, main_genesis, TestAuthorityKey()).IsValid());
    BOOST_REQUIRE(second.ApplyTransaction(CTransaction{tx_a}, 100, main_genesis, TestAuthorityKey()).IsValid());
    BOOST_CHECK_EQUAL(first.ComputeRoot().GetHex(), second.ComputeRoot().GetHex());

    const auto duplicate{first.ApplyTransaction(CTransaction{tx_a}, 101, main_genesis, TestAuthorityKey())};
    BOOST_CHECK(duplicate.error == chainregistry::RegistryError::DUPLICATE_CHAIN_ID);
}

BOOST_AUTO_TEST_CASE(registry_rejects_ambiguous_and_unknown_updates)
{
    constexpr uint256 main_genesis{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    const CMutableTransaction tx_a{RegistrationTx(
        Txid{"0101010101010101010101010101010101010101010101010101010101010101"}, 0, 1)};
    const CMutableTransaction tx_b{RegistrationTx(
        Txid{"0202020202020202020202020202020202020202020202020202020202020202"}, 0, 2)};
    chainregistry::ChainRegistry registry;
    SeedDealers(registry);
    const auto result_a{registry.ApplyTransaction(CTransaction{tx_a}, 100, main_genesis, TestAuthorityKey())};
    const auto result_b{registry.ApplyTransaction(CTransaction{tx_b}, 100, main_genesis, TestAuthorityKey())};
    BOOST_REQUIRE(result_a.IsValid());
    BOOST_REQUIRE(result_b.IsValid());
    const auto* record_a{registry.Find(*result_a.chain_id)};
    const auto* record_b{registry.Find(*result_b.chain_id)};
    BOOST_REQUIRE(record_a != nullptr);
    BOOST_REQUIRE(record_b != nullptr);
    const uint256 root{registry.ComputeRoot()};

    CMutableTransaction multi_control{UpdateTx(
        *record_a,
        chainregistry::MetadataHash{"abababababababababababababababababababababababababababababababab"},
        3)};
    multi_control.vin.emplace_back(record_b->control_outpoint);
    auto result{registry.ApplyTransaction(CTransaction{multi_control}, 101, main_genesis, TestAuthorityKey())};
    BOOST_CHECK(result.error == chainregistry::RegistryError::MULTIPLE_CONTROL_OUTPOINTS);

    CMutableTransaction duplicate_control{UpdateTx(
        *record_a,
        chainregistry::MetadataHash{"abababababababababababababababababababababababababababababababab"},
        3)};
    duplicate_control.vin.emplace_back(record_a->control_outpoint);
    result = registry.ApplyTransaction(CTransaction{duplicate_control}, 101, main_genesis, TestAuthorityKey());
    BOOST_CHECK(result.error == chainregistry::RegistryError::MULTIPLE_CONTROL_OUTPOINTS);

    CMutableTransaction unknown_update;
    unknown_update.vout.emplace_back(0, chainregistry::BuildOperationScript(chainregistry::UpdateChain{
        .chain_id = chainregistry::ChainId{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
        .control_output = 1,
        .metadata_hash = chainregistry::MetadataHash{"abababababababababababababababababababababababababababababababab"},
    }));
    unknown_update.vout.emplace_back(0, TaprootScript(4));
    result = registry.ApplyTransaction(CTransaction{unknown_update}, 101, main_genesis, TestAuthorityKey());
    BOOST_CHECK(result.error == chainregistry::RegistryError::UNKNOWN_CHAIN);
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), root.GetHex());
}

BOOST_AUTO_TEST_CASE(registry_block_transition_and_undo)
{
    constexpr uint256 main_genesis{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    const CMutableTransaction registration_tx{RegistrationTx(
        Txid{"0101010101010101010101010101010101010101010101010101010101010101"}, 0, 1)};

    chainregistry::ChainRegistry preview;
    SeedDealers(preview);
    BOOST_REQUIRE(preview.ApplyTransaction(CTransaction{registration_tx}, 100, main_genesis, TestAuthorityKey()).IsValid());
    const uint256 expected_root{preview.ComputeRoot()};

    const CBlock block{RegistryBlock(CoinbaseTx(expected_root), {registration_tx})};
    chainregistry::ChainRegistry registry;
    SeedDealers(registry);
    const uint256 empty_root{registry.ComputeRoot()};
    const auto result{registry.ApplyBlock(
        block,
        100,
        main_genesis,
        TestAuthorityKey(),
        10,
        chainregistry::CommitmentRequirement::REQUIRED)};
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE(result.undo.has_value());
    BOOST_CHECK_EQUAL(result.computed_root.GetHex(), expected_root.GetHex());
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), expected_root.GetHex());
    BOOST_CHECK_EQUAL(result.undo->operations.size(), 1U);

    DataStream stream;
    stream << *result.undo;
    chainregistry::RegistryBlockUndo decoded;
    stream >> decoded;
    BOOST_CHECK(decoded == *result.undo);
    BOOST_CHECK(stream.empty());

    BOOST_REQUIRE(registry.UndoBlock(*result.undo));
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), empty_root.GetHex());

    const CBlock optional_block{RegistryBlock(CoinbaseTx(), {registration_tx})};
    const auto optional_result{registry.ApplyBlock(
        optional_block,
        100,
        main_genesis,
        TestAuthorityKey(),
        10,
        chainregistry::CommitmentRequirement::OPTIONAL)};
    BOOST_REQUIRE(optional_result.IsValid());
    BOOST_REQUIRE(optional_result.undo.has_value());
    BOOST_REQUIRE(registry.UndoBlock(*optional_result.undo));
}

BOOST_AUTO_TEST_CASE(registry_block_failures_are_atomic)
{
    constexpr uint256 main_genesis{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    const CMutableTransaction registration_tx{RegistrationTx(
        Txid{"0101010101010101010101010101010101010101010101010101010101010101"}, 0, 1)};
    chainregistry::ChainRegistry registry;
    SeedDealers(registry);
    const uint256 empty_root{registry.ComputeRoot()};

    auto result{registry.ApplyBlock(
        RegistryBlock(CoinbaseTx(), {registration_tx}),
        100,
        main_genesis,
        TestAuthorityKey(),
        10,
        chainregistry::CommitmentRequirement::REQUIRED)};
    BOOST_CHECK(result.error == chainregistry::RegistryBlockError::MISSING_COMMITMENT);
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), empty_root.GetHex());

    result = registry.ApplyBlock(
        RegistryBlock(CoinbaseTx(uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}), {registration_tx}),
        100,
        main_genesis,
        TestAuthorityKey(),
        10,
        chainregistry::CommitmentRequirement::REQUIRED);
    BOOST_CHECK(result.error == chainregistry::RegistryBlockError::COMMITMENT_MISMATCH);
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), empty_root.GetHex());

    result = registry.ApplyBlock(
        RegistryBlock(CoinbaseTx(), {registration_tx}),
        100,
        main_genesis,
        TestAuthorityKey(),
        0,
        chainregistry::CommitmentRequirement::OPTIONAL);
    BOOST_CHECK(result.error == chainregistry::RegistryBlockError::TOO_MANY_OPERATIONS);
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), empty_root.GetHex());

    result = registry.ApplyBlock(
        RegistryBlock(CoinbaseTx(), {registration_tx, registration_tx}),
        100,
        main_genesis,
        TestAuthorityKey(),
        10,
        chainregistry::CommitmentRequirement::OPTIONAL);
    BOOST_CHECK(result.error == chainregistry::RegistryBlockError::TRANSACTION_TRANSITION);
    BOOST_CHECK(result.tx_index == 2U);
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), empty_root.GetHex());

    CMutableTransaction non_coinbase_commitment;
    non_coinbase_commitment.vout.emplace_back(0, chainregistry::BuildRegistryCommitment(empty_root));
    result = registry.ApplyBlock(
        RegistryBlock(CoinbaseTx(), {non_coinbase_commitment}),
        100,
        main_genesis,
        TestAuthorityKey(),
        10,
        chainregistry::CommitmentRequirement::OPTIONAL);
    BOOST_CHECK(result.error == chainregistry::RegistryBlockError::NON_COINBASE_COMMITMENT);

    CMutableTransaction operation_coinbase{CoinbaseTx()};
    operation_coinbase.vout.emplace_back(0, chainregistry::BuildOperationScript(chainregistry::RetireChain{
        .chain_id = chainregistry::ChainId{"5555555555555555555555555555555555555555555555555555555555555555"},
    }));
    result = registry.ApplyBlock(
        RegistryBlock(operation_coinbase, {}),
        100,
        main_genesis,
        TestAuthorityKey(),
        10,
        chainregistry::CommitmentRequirement::OPTIONAL);
    BOOST_CHECK(result.error == chainregistry::RegistryBlockError::COINBASE_OPERATION);
    BOOST_CHECK_EQUAL(registry.ComputeRoot().GetHex(), empty_root.GetHex());
}

BOOST_AUTO_TEST_CASE(registry_inclusion_and_non_inclusion_proofs)
{
    constexpr uint256 main_genesis{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    chainregistry::ChainRegistry registry;
    SeedDealers(registry);
    for (unsigned char i{1}; i <= 3; ++i) {
        std::array<unsigned char, 32> anchor_bytes{};
        anchor_bytes.fill(i);
        const CMutableTransaction tx{RegistrationTx(Txid::FromUint256(uint256{std::span{anchor_bytes}}), 0, i)};
        BOOST_REQUIRE(registry.ApplyTransaction(CTransaction{tx}, 100, main_genesis, TestAuthorityKey()).IsValid());
    }
    const uint256 root{registry.ComputeRoot()};

    for (const auto& [chain_id, record] : registry.Records()) {
        const auto proof{registry.GetInclusionProof(chain_id)};
        BOOST_REQUIRE(proof.has_value());
        BOOST_CHECK(chainregistry::VerifyRegistryInclusion(record, *proof, root));
    }

    const auto& first_record{registry.Records().begin()->second};
    auto inclusion{*registry.GetInclusionProof(first_record.chain_id)};
    BOOST_REQUIRE(!inclusion.siblings.empty());
    inclusion.siblings[0].SetNull();
    BOOST_CHECK(!chainregistry::VerifyRegistryInclusion(first_record, inclusion, root));
    inclusion = *registry.GetInclusionProof(first_record.chain_id);
    inclusion.leaf_count++;
    BOOST_CHECK(!chainregistry::VerifyRegistryInclusion(first_record, inclusion, root));

    chainregistry::ChainRegistry empty;
    const chainregistry::ChainId absent{"8080808080808080808080808080808080808080808080808080808080808080"};
    const auto empty_proof{empty.GetNonInclusionProof(absent)};
    BOOST_REQUIRE(empty_proof.has_value());
    BOOST_CHECK(chainregistry::VerifyRegistryNonInclusion(absent, *empty_proof, empty.ComputeRoot()));

    const chainregistry::ChainId below{"0000000000000000000000000000000000000000000000000000000000000000"};
    const auto below_proof{registry.GetNonInclusionProof(below)};
    BOOST_REQUIRE(below_proof.has_value());
    BOOST_CHECK(!below_proof->has_left);
    BOOST_CHECK(below_proof->has_right);
    BOOST_CHECK(chainregistry::VerifyRegistryNonInclusion(below, *below_proof, root));

    const chainregistry::ChainId above{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    const auto above_proof{registry.GetNonInclusionProof(above)};
    BOOST_REQUIRE(above_proof.has_value());
    BOOST_CHECK(above_proof->has_left);
    BOOST_CHECK(!above_proof->has_right);
    BOOST_CHECK(chainregistry::VerifyRegistryNonInclusion(above, *above_proof, root));

    auto left_it{registry.Records().begin()};
    const auto right_it{std::next(left_it)};
    std::array<unsigned char, 32> between_bytes;
    std::copy(left_it->first.ToUint256().begin(), left_it->first.ToUint256().end(), between_bytes.begin());
    for (size_t i{between_bytes.size()}; i-- > 0;) {
        if (++between_bytes[i] != 0) break;
    }
    const chainregistry::ChainId between{chainregistry::ChainId::FromUint256(uint256{std::span{between_bytes}})};
    BOOST_REQUIRE(left_it->first < between);
    BOOST_REQUIRE(between < right_it->first);
    const auto between_proof{registry.GetNonInclusionProof(between)};
    BOOST_REQUIRE(between_proof.has_value());
    BOOST_CHECK(between_proof->has_left);
    BOOST_CHECK(between_proof->has_right);
    BOOST_CHECK(chainregistry::VerifyRegistryNonInclusion(between, *between_proof, root));
    BOOST_CHECK(!registry.GetNonInclusionProof(left_it->first).has_value());

    DataStream stream;
    stream << *between_proof;
    chainregistry::RegistryNonInclusionProof decoded;
    stream >> decoded;
    BOOST_CHECK(decoded == *between_proof);
    BOOST_CHECK(chainregistry::VerifyRegistryNonInclusion(between, decoded, root));

    decoded.left.proof.leaf_count++;
    BOOST_CHECK(!chainregistry::VerifyRegistryNonInclusion(between, decoded, root));
}

BOOST_AUTO_TEST_CASE(registry_record_validation_and_atomic_loading)
{
    constexpr uint256 main_genesis{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    chainregistry::ChainRegistry source;
    SeedDealers(source);
    const CMutableTransaction tx_a{RegistrationTx(
        Txid{"0101010101010101010101010101010101010101010101010101010101010101"}, 0, 1)};
    const CMutableTransaction tx_b{RegistrationTx(
        Txid{"0202020202020202020202020202020202020202020202020202020202020202"}, 0, 2)};
    BOOST_REQUIRE(source.ApplyTransaction(CTransaction{tx_a}, 100, main_genesis, TestAuthorityKey()).IsValid());
    BOOST_REQUIRE(source.ApplyTransaction(CTransaction{tx_b}, 101, main_genesis, TestAuthorityKey()).IsValid());

    std::vector<chainregistry::ChainRecord> records;
    for (const auto& entry : source.Records()) records.push_back(entry.second);
    std::vector<chainregistry::DealerRecord> dealers;
    for (const auto& entry : source.Dealers()) dealers.push_back(entry.second);
    BOOST_REQUIRE_EQUAL(records.size(), 2U);
    BOOST_CHECK(chainregistry::ValidateChainRecord(records[0]) == chainregistry::RecordValidationError::NONE);

    chainregistry::ChainRegistry loaded;
    BOOST_REQUIRE(loaded.LoadState(records, dealers, source.AuthoritySequence()).IsValid());
    BOOST_CHECK_EQUAL(loaded.ComputeRoot().GetHex(), source.ComputeRoot().GetHex());
    const uint256 loaded_root{loaded.ComputeRoot()};

    auto invalid{records[0]};
    invalid.record_version++;
    auto load_result{loaded.LoadRecords({invalid})};
    BOOST_CHECK(load_result.error == chainregistry::RegistryLoadError::INVALID_RECORD);
    BOOST_CHECK(load_result.record_error == chainregistry::RecordValidationError::UNSUPPORTED_VERSION);
    BOOST_CHECK_EQUAL(loaded.ComputeRoot().GetHex(), loaded_root.GetHex());

    invalid = records[0];
    invalid.status = static_cast<chainregistry::ChainStatus>(255);
    BOOST_CHECK(chainregistry::ValidateChainRecord(invalid) == chainregistry::RecordValidationError::UNKNOWN_STATUS);
    invalid = records[0];
    invalid.updated_height = invalid.registered_height - 1;
    BOOST_CHECK(chainregistry::ValidateChainRecord(invalid) == chainregistry::RecordValidationError::INVALID_HEIGHTS);
    invalid = records[0];
    invalid.retired_height = invalid.updated_height;
    BOOST_CHECK(chainregistry::ValidateChainRecord(invalid) == chainregistry::RecordValidationError::INVALID_HEIGHTS);

    load_result = loaded.LoadRecords({records[0], records[0]});
    BOOST_CHECK(load_result.error == chainregistry::RegistryLoadError::DUPLICATE_CHAIN_ID);
    BOOST_CHECK_EQUAL(loaded.ComputeRoot().GetHex(), loaded_root.GetHex());

    auto control_collision{records};
    control_collision[1].control_outpoint = control_collision[0].control_outpoint;
    load_result = loaded.LoadRecords(std::move(control_collision));
    BOOST_CHECK(load_result.error == chainregistry::RegistryLoadError::DUPLICATE_ACTIVE_CONTROL);
    BOOST_CHECK_EQUAL(loaded.ComputeRoot().GetHex(), loaded_root.GetHex());
}

BOOST_AUTO_TEST_CASE(registry_root_is_deterministic_across_load_order)
{
    constexpr uint256 main_genesis{
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    chainregistry::ChainRegistry source;
    SeedDealers(source);
    for (uint32_t index{0}; index < 32; ++index) {
        std::array<unsigned char, 32> anchor_bytes;
        anchor_bytes.fill(static_cast<unsigned char>(index + 1));
        const CMutableTransaction registration{RegistrationTx(
            Txid::FromUint256(uint256{std::span{anchor_bytes}}),
            index,
            static_cast<unsigned char>(index + 1))};
        BOOST_REQUIRE(source.ApplyTransaction(
            CTransaction{registration},
            100 + index,
            main_genesis,
            TestAuthorityKey()).IsValid());
    }

    std::vector<chainregistry::ChainRecord> records;
    records.reserve(source.Size());
    for (const auto& [_, record] : source.Records()) {
        records.push_back(record);
    }
    std::vector<chainregistry::DealerRecord> dealers;
    for (const auto& [_, dealer] : source.Dealers()) dealers.push_back(dealer);
    const uint256 expected_root{source.ComputeRoot()};

    for (size_t permutation{0}; permutation < 64; ++permutation) {
        auto shuffled{records};
        std::rotate(
            shuffled.begin(),
            shuffled.begin() + permutation % shuffled.size(),
            shuffled.end());
        if (permutation % 2 != 0) {
            std::reverse(shuffled.begin(), shuffled.end());
        }

        chainregistry::ChainRegistry loaded;
        BOOST_REQUIRE(loaded.LoadState(
            std::move(shuffled), dealers, source.AuthoritySequence()).IsValid());
        BOOST_CHECK(loaded.ComputeRoot() == expected_root);
        for (const auto& [chain_id, record] : loaded.Records()) {
            const auto proof{loaded.GetInclusionProof(chain_id)};
            BOOST_REQUIRE(proof.has_value());
            BOOST_CHECK(chainregistry::VerifyRegistryInclusion(
                record, *proof, expected_root));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
