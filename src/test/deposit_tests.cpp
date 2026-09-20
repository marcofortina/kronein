// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <primitives/deposit.h>

#include <primitives/transaction.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

chainregistry::FundChain ValidFund()
{
    return {
        .chain_id = chainregistry::ChainId{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},
        .recipient_type = 0x1234,
        .recipient = {0xaa, 0xbb, 0xcc},
    };
}

std::vector<unsigned char> FundData(const CScript& script)
{
    auto cursor{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    BOOST_REQUIRE(script.GetOp(cursor, opcode));
    BOOST_REQUIRE_EQUAL(opcode, OP_RETURN);
    BOOST_REQUIRE(script.GetOp(cursor, opcode, data));
    BOOST_REQUIRE(cursor == script.end());
    return data;
}

} // namespace

BOOST_AUTO_TEST_SUITE(deposit_tests)

BOOST_AUTO_TEST_CASE(fund_script_vector_and_roundtrip)
{
    const auto fund{ValidFund()};
    const CScript script{chainregistry::BuildFundScript(fund)};
    BOOST_CHECK_EQUAL(
        HexStr(script),
        "6a2b4b464e4401"
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        "341203aabbcc");

    const auto parsed{chainregistry::ParseFundScript(script)};
    BOOST_REQUIRE(parsed);
    BOOST_CHECK(*parsed.fund == fund);
    BOOST_CHECK(chainregistry::ValidateFund(*parsed.fund) == chainregistry::FundValidationError::NONE);
}

BOOST_AUTO_TEST_CASE(fund_validation)
{
    auto fund{ValidFund()};
    fund.chain_id = {};
    BOOST_CHECK(chainregistry::ValidateFund(fund) == chainregistry::FundValidationError::NULL_CHAIN_ID);

    fund = ValidFund();
    fund.recipient_type = 0;
    BOOST_CHECK(chainregistry::ValidateFund(fund) == chainregistry::FundValidationError::INVALID_RECIPIENT_TYPE);

    fund = ValidFund();
    fund.recipient.clear();
    BOOST_CHECK(chainregistry::ValidateFund(fund) == chainregistry::FundValidationError::EMPTY_RECIPIENT);

    fund = ValidFund();
    fund.recipient.resize(chainregistry::MAX_CHILD_RECIPIENT_SIZE + 1);
    BOOST_CHECK(chainregistry::ValidateFund(fund) == chainregistry::FundValidationError::RECIPIENT_TOO_LARGE);
    BOOST_CHECK(chainregistry::ParseFundScript(chainregistry::BuildFundScript(fund)).error ==
                chainregistry::FundParseError::DATA_TOO_LARGE);
}

BOOST_AUTO_TEST_CASE(rejects_malformed_fund_scripts)
{
    const CScript canonical{chainregistry::BuildFundScript(ValidFund())};

    BOOST_CHECK(chainregistry::ParseFundScript(CScript{} << OP_TRUE).error ==
                chainregistry::FundParseError::NOT_FUND);
    BOOST_CHECK(chainregistry::ParseFundScript(CScript{} << OP_RETURN << std::vector<unsigned char>{'n', 'o'}).error ==
                chainregistry::FundParseError::NOT_FUND);
    const std::vector<unsigned char> magic{chainregistry::FUND_MAGIC.begin(), chainregistry::FUND_MAGIC.end()};
    BOOST_CHECK(chainregistry::ParseFundScript(CScript{} << OP_RETURN << magic).error ==
                chainregistry::FundParseError::INVALID_PAYLOAD);

    auto data{FundData(canonical)};
    data[chainregistry::FUND_MAGIC.size()]++;
    BOOST_CHECK(chainregistry::ParseFundScript(CScript{} << OP_RETURN << data).error ==
                chainregistry::FundParseError::UNSUPPORTED_ENVELOPE_VERSION);

    data = FundData(canonical);
    data.push_back(0);
    BOOST_CHECK(chainregistry::ParseFundScript(CScript{} << OP_RETURN << data).error ==
                chainregistry::FundParseError::TRAILING_DATA);

    CScript noncanonical;
    noncanonical << OP_RETURN << OP_PUSHDATA1;
    noncanonical.push_back(static_cast<unsigned char>(FundData(canonical).size()));
    const auto canonical_data{FundData(canonical)};
    noncanonical.insert(noncanonical.end(), canonical_data.begin(), canonical_data.end());
    BOOST_CHECK(chainregistry::ParseFundScript(noncanonical).error ==
                chainregistry::FundParseError::NON_CANONICAL_SCRIPT);

    CScript extra_opcode{canonical};
    extra_opcode << OP_TRUE;
    BOOST_CHECK(chainregistry::ParseFundScript(extra_opcode).error ==
                chainregistry::FundParseError::MALFORMED_SCRIPT);
}

BOOST_AUTO_TEST_CASE(transaction_funds)
{
    auto second{ValidFund()};
    second.chain_id = chainregistry::ChainId{
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    second.recipient_type = 7;
    second.recipient.assign(32, 0x55);

    CMutableTransaction tx;
    tx.vout.emplace_back(0, CScript{} << OP_RETURN << std::vector<unsigned char>{'n', 'o'});
    tx.vout.emplace_back(50'000, chainregistry::BuildFundScript(ValidFund()));
    tx.vout.emplace_back(75'000, chainregistry::BuildFundScript(second));

    auto result{chainregistry::ExtractTransactionFunds(CTransaction{tx})};
    BOOST_REQUIRE(result.IsValid());
    BOOST_REQUIRE_EQUAL(result.funds.size(), 2U);
    BOOST_CHECK_EQUAL(result.funds[0].output_index, 1U);
    BOOST_CHECK_EQUAL(result.funds[0].amount, 50'000);
    BOOST_CHECK(result.funds[0].fund == ValidFund());
    BOOST_CHECK_EQUAL(result.funds[1].output_index, 2U);
    BOOST_CHECK_EQUAL(result.funds[1].amount, 75'000);
    BOOST_CHECK(result.funds[1].fund == second);

    tx.vout[1].nValue = 0;
    result = chainregistry::ExtractTransactionFunds(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxFundsError::INVALID_AMOUNT);

    tx.vout[1].nValue = 50'000;
    auto malformed{FundData(tx.vout[2].scriptPubKey)};
    malformed.push_back(0);
    tx.vout[2].scriptPubKey = CScript{} << OP_RETURN << malformed;
    result = chainregistry::ExtractTransactionFunds(CTransaction{tx});
    BOOST_CHECK(result.error == chainregistry::TxFundsError::INVALID_ENVELOPE);
    BOOST_CHECK(result.parse_error == chainregistry::FundParseError::TRAILING_DATA);
    BOOST_CHECK(result.funds.empty());
}

BOOST_AUTO_TEST_SUITE_END()
