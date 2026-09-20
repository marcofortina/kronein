// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/deposit.h>

#include <consensus/chainregistry.h>
#include <primitives/block.h>
#include <primitives/deposit.h>
#include <primitives/transaction.h>

#include <boost/test/unit_test.hpp>

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

BOOST_AUTO_TEST_SUITE_END()
