// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/deposit.h>

#include <consensus/chainregistry.h>
#include <primitives/block.h>
#include <primitives/deposit.h>
#include <primitives/transaction.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <vector>

namespace {

constexpr chainregistry::ChainId ACTIVE_CHAIN{
    "1111111111111111111111111111111111111111111111111111111111111111"};
constexpr chainregistry::ChainId RETIRED_CHAIN{
    "2222222222222222222222222222222222222222222222222222222222222222"};
constexpr chainregistry::ChainId UNKNOWN_CHAIN{
    "3333333333333333333333333333333333333333333333333333333333333333"};
constexpr uint256 MAIN_GENESIS{
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

chainregistry::ChainRecord Record(const chainregistry::ChainId& chain_id,
                                  const Txid& control_txid,
                                  chainregistry::ChainStatus status)
{
    return {
        .record_version = chainregistry::CHAIN_RECORD_VERSION,
        .chain_id = chain_id,
        .manifest_hash = chainregistry::ManifestHash{
            "4444444444444444444444444444444444444444444444444444444444444444"},
        .template_id = 1,
        .template_version = 1,
        .control_outpoint = COutPoint{control_txid, 0},
        .metadata_hash = chainregistry::MetadataHash{
            "5555555555555555555555555555555555555555555555555555555555555555"},
        .status = status,
        .registered_height = 10,
        .updated_height = status == chainregistry::ChainStatus::ACTIVE ? 10U : 20U,
        .retired_height = status == chainregistry::ChainStatus::ACTIVE ? 0U : 20U,
    };
}

chainregistry::ChainRegistry Registry()
{
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({
        Record(ACTIVE_CHAIN,
               Txid{"0101010101010101010101010101010101010101010101010101010101010101"},
               chainregistry::ChainStatus::ACTIVE),
        Record(RETIRED_CHAIN,
               Txid{"0202020202020202020202020202020202020202020202020202020202020202"},
               chainregistry::ChainStatus::RETIRED),
    }).IsValid());
    return registry;
}

chainregistry::FundChain Fund(const chainregistry::ChainId& chain_id, unsigned char recipient)
{
    return {
        .chain_id = chain_id,
        .recipient_type = 1,
        .recipient = std::vector<unsigned char>(32, recipient),
    };
}

CMutableTransaction FundingTx(const chainregistry::ChainId& chain_id,
                              CAmount amount,
                              unsigned char recipient = 1)
{
    CMutableTransaction transaction;
    transaction.vin.emplace_back(COutPoint{
        Txid{"abababababababababababababababababababababababababababababababab"}, 0});
    transaction.vout.emplace_back(amount, chainregistry::BuildFundScript(Fund(chain_id, recipient)));
    return transaction;
}

CBlock Block(std::vector<CMutableTransaction> transactions)
{
    CBlock block;
    for (auto& transaction : transactions) {
        block.vtx.push_back(MakeTransactionRef(std::move(transaction)));
    }
    return block;
}

CMutableTransaction Coinbase(const uint256& registry_root)
{
    CMutableTransaction transaction;
    transaction.vin.emplace_back(COutPoint{});
    transaction.vout.emplace_back(0, chainregistry::BuildRegistryCommitment(registry_root));
    return transaction;
}

chainregistry::ChainManifest Manifest()
{
    chainregistry::ChainSpec spec;
    spec.template_id = 1;
    spec.template_version = 1;
    spec.consensus_parameters = {0xaa, 0xbb};
    return {
        .spec = std::move(spec),
        .child_genesis_hash = uint256{
            "6666666666666666666666666666666666666666666666666666666666666666"},
        .initial_metadata_hash = chainregistry::MetadataHash{
            "7777777777777777777777777777777777777777777777777777777777777777"},
        .default_fee_recipient = {
            .recipient_type = 1,
            .recipient = std::vector<unsigned char>(32, 2),
        },
    };
}

} // namespace

BOOST_AUTO_TEST_SUITE(deposit_validation_tests)

BOOST_AUTO_TEST_CASE(validates_active_chain_deposits)
{
    CMutableTransaction transaction{FundingTx(ACTIVE_CHAIN, 1'000)};
    transaction.vout.emplace_back(2'000, chainregistry::BuildFundScript(Fund(ACTIVE_CHAIN, 2)));
    const CBlock block{Block({transaction})};

    const auto result{chainregistry::ValidateBlockDeposits(
        block, Registry(), MAIN_GENESIS, {.minimum_amount = 1'000, .maximum_deposits = 2})};
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE_EQUAL(result.deposits.size(), 2U);
    BOOST_CHECK_EQUAL(result.total_amount, 3'000);
    BOOST_CHECK_EQUAL(result.deposits[0].transaction_index, 0U);
    BOOST_CHECK_EQUAL(result.deposits[1].transaction_index, 0U);
    BOOST_CHECK_EQUAL(result.deposits[0].outpoint.n, 0U);
    BOOST_CHECK_EQUAL(result.deposits[1].outpoint.n, 1U);
    BOOST_CHECK(result.deposits[0].deposit_id == chainregistry::DeriveDepositId(
        MAIN_GENESIS, result.deposits[0].outpoint));
    BOOST_CHECK(!result.transaction.has_value());
    BOOST_CHECK(!result.output_index.has_value());
    BOOST_CHECK(!result.chain_id.has_value());
}

BOOST_AUTO_TEST_CASE(rejects_unknown_retired_and_small_deposits)
{
    const auto registry{Registry()};
    const chainregistry::DepositValidationParams params{
        .minimum_amount = 1'000,
        .maximum_deposits = 4,
    };

    auto result{chainregistry::ValidateBlockDeposits(
        Block({FundingTx(UNKNOWN_CHAIN, 1'000)}), registry, MAIN_GENESIS, params)};
    BOOST_CHECK(result.error == chainregistry::BlockDepositsError::UNKNOWN_CHAIN);
    BOOST_REQUIRE(result.chain_id);
    BOOST_CHECK(*result.chain_id == UNKNOWN_CHAIN);

    result = chainregistry::ValidateBlockDeposits(
        Block({FundingTx(RETIRED_CHAIN, 1'000)}), registry, MAIN_GENESIS, params);
    BOOST_CHECK(result.error == chainregistry::BlockDepositsError::INACTIVE_CHAIN);

    result = chainregistry::ValidateBlockDeposits(
        Block({FundingTx(ACTIVE_CHAIN, 999)}), registry, MAIN_GENESIS, params);
    BOOST_CHECK(result.error == chainregistry::BlockDepositsError::AMOUNT_BELOW_MINIMUM);
}

BOOST_AUTO_TEST_CASE(enforces_block_limits_and_uniqueness)
{
    const auto registry{Registry()};
    CMutableTransaction two_funds{FundingTx(ACTIVE_CHAIN, 1'000)};
    two_funds.vout.emplace_back(1'000, chainregistry::BuildFundScript(Fund(ACTIVE_CHAIN, 2)));
    auto result{chainregistry::ValidateBlockDeposits(
        Block({two_funds}),
        registry,
        MAIN_GENESIS,
        {.minimum_amount = 1, .maximum_deposits = 1})};
    BOOST_CHECK(result.error == chainregistry::BlockDepositsError::TOO_MANY_DEPOSITS);

    const CMutableTransaction duplicate{FundingTx(ACTIVE_CHAIN, 1'000)};
    result = chainregistry::ValidateBlockDeposits(
        Block({duplicate, duplicate}),
        registry,
        MAIN_GENESIS,
        {.minimum_amount = 1, .maximum_deposits = 2});
    BOOST_CHECK(result.error == chainregistry::BlockDepositsError::DUPLICATE_DEPOSIT_ID);

    result = chainregistry::ValidateBlockDeposits(
        Block({FundingTx(ACTIVE_CHAIN, MAX_MONEY, 1), FundingTx(ACTIVE_CHAIN, MAX_MONEY, 2)}),
        registry,
        MAIN_GENESIS,
        {.minimum_amount = 1, .maximum_deposits = 2});
    BOOST_CHECK(result.error == chainregistry::BlockDepositsError::TOTAL_AMOUNT_OUT_OF_RANGE);
}

BOOST_AUTO_TEST_CASE(rejects_malformed_transaction_envelope)
{
    CMutableTransaction transaction{FundingTx(ACTIVE_CHAIN, 1'000)};
    auto script{transaction.vout[0].scriptPubKey};
    CScript::const_iterator cursor{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    BOOST_REQUIRE(script.GetOp(cursor, opcode));
    BOOST_REQUIRE(script.GetOp(cursor, opcode, data));
    data.push_back(0);
    transaction.vout[0].scriptPubKey = CScript{} << OP_RETURN << data;

    const auto result{chainregistry::ValidateBlockDeposits(
        Block({transaction}),
        Registry(),
        MAIN_GENESIS,
        {.minimum_amount = 1, .maximum_deposits = 1})};
    BOOST_CHECK(result.error == chainregistry::BlockDepositsError::INVALID_TRANSACTION);
    BOOST_CHECK(result.transaction_error == chainregistry::TxFundsError::INVALID_ENVELOPE);
    BOOST_CHECK(result.parse_error == chainregistry::FundParseError::TRAILING_DATA);
}

BOOST_AUTO_TEST_CASE(registry_block_validation_uses_final_registry_state)
{
    const COutPoint anchor{
        Txid{"8888888888888888888888888888888888888888888888888888888888888888"}, 3};
    const auto manifest{Manifest()};
    const chainregistry::ChainId chain_id{chainregistry::DeriveChainId(
        MAIN_GENESIS, anchor, chainregistry::ComputeChainSpecHash(manifest.spec))};

    CMutableTransaction registration;
    registration.vin.emplace_back(anchor);
    registration.vout.emplace_back(1'000, chainregistry::BuildOperationScript(
        chainregistry::RegisterChain{
            .anchor_input = 0,
            .control_output = 1,
            .manifest = manifest,
        }));
    registration.vout.emplace_back(0, CScript{} << OP_1 << std::vector<unsigned char>(32, 1));

    chainregistry::ChainRegistry expected;
    BOOST_REQUIRE(expected.ApplyTransaction(CTransaction{registration}, 50, MAIN_GENESIS, 1'000).IsValid());
    CBlock register_and_fund{Block({Coinbase(expected.ComputeRoot()), registration,
                                    FundingTx(chain_id, 2'000)})};

    chainregistry::ChainRegistry registry;
    const auto registered{registry.ApplyBlock(
        register_and_fund,
        50,
        MAIN_GENESIS,
        1'000,
        4,
        chainregistry::CommitmentRequirement::REQUIRED,
        chainregistry::DepositValidationParams{.minimum_amount = 1'000, .maximum_deposits = 4})};
    BOOST_REQUIRE(registered.IsValid());
    BOOST_REQUIRE_EQUAL(registered.deposits.deposits.size(), 1U);
    BOOST_CHECK(registered.deposits.deposits[0].fund.chain_id == chain_id);
    BOOST_REQUIRE(registry.Find(chain_id));

    const chainregistry::ChainRecord record{*registry.Find(chain_id)};
    CMutableTransaction retirement;
    retirement.vin.emplace_back(record.control_outpoint);
    retirement.vout.emplace_back(0, chainregistry::BuildOperationScript(
        chainregistry::RetireChain{.chain_id = chain_id}));
    chainregistry::ChainRegistry retired_state{registry};
    BOOST_REQUIRE(retired_state.ApplyTransaction(CTransaction{retirement}, 51, MAIN_GENESIS, 1'000).IsValid());
    const CBlock retire_and_fund{Block({Coinbase(retired_state.ComputeRoot()),
                                       FundingTx(chain_id, 2'000), retirement})};

    const uint256 root_before{registry.ComputeRoot()};
    const auto retired{registry.ApplyBlock(
        retire_and_fund,
        51,
        MAIN_GENESIS,
        1'000,
        4,
        chainregistry::CommitmentRequirement::REQUIRED,
        chainregistry::DepositValidationParams{.minimum_amount = 1'000, .maximum_deposits = 4})};
    BOOST_CHECK(retired.error == chainregistry::RegistryBlockError::INVALID_DEPOSITS);
    BOOST_CHECK(retired.deposits.error == chainregistry::BlockDepositsError::INACTIVE_CHAIN);
    BOOST_CHECK(registry.ComputeRoot() == root_before);
    BOOST_REQUIRE(registry.Find(chain_id));
    BOOST_CHECK(registry.Find(chain_id)->status == chainregistry::ChainStatus::ACTIVE);
}

BOOST_AUTO_TEST_SUITE_END()
