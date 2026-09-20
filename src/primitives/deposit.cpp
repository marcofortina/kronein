// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <primitives/deposit.h>

#include <primitives/transaction.h>
#include <streams.h>

#include <algorithm>
#include <ios>
#include <span>
#include <utility>
#include <vector>

namespace chainregistry {

static_assert(MAX_CHILD_RECIPIENT_SIZE <= 252);
static_assert(MAX_FUND_DATA_SIZE == FUND_MAGIC.size() + 1 + ChainId::size() + 2 + 1 + MAX_CHILD_RECIPIENT_SIZE);

FundValidationError ValidateFund(const FundChain& fund)
{
    if (fund.chain_id.IsNull()) return FundValidationError::NULL_CHAIN_ID;
    if (fund.recipient_type == 0) return FundValidationError::INVALID_RECIPIENT_TYPE;
    if (fund.recipient.empty()) return FundValidationError::EMPTY_RECIPIENT;
    if (fund.recipient.size() > MAX_CHILD_RECIPIENT_SIZE) {
        return FundValidationError::RECIPIENT_TOO_LARGE;
    }
    return FundValidationError::NONE;
}

CScript BuildFundScript(const FundChain& fund)
{
    std::vector<unsigned char> data{FUND_MAGIC.begin(), FUND_MAGIC.end()};
    VectorWriter writer{data, data.size()};
    writer << FUND_ENVELOPE_VERSION << fund;
    return CScript{} << OP_RETURN << data;
}

FundParseResult ParseFundScript(const CScript& script)
{
    auto cursor{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(cursor, opcode) || opcode != OP_RETURN) {
        return {FundParseError::NOT_FUND, std::nullopt};
    }
    if (!script.GetOp(cursor, opcode, data)) {
        return {FundParseError::NOT_FUND, std::nullopt};
    }
    if (data.size() < FUND_MAGIC.size() ||
        !std::equal(FUND_MAGIC.begin(), FUND_MAGIC.end(), data.begin())) {
        return {FundParseError::NOT_FUND, std::nullopt};
    }
    if (opcode > OP_PUSHDATA4 || cursor != script.end()) {
        return {FundParseError::MALFORMED_SCRIPT, std::nullopt};
    }
    if (data.size() > MAX_FUND_DATA_SIZE) {
        return {FundParseError::DATA_TOO_LARGE, std::nullopt};
    }
    if (script != (CScript{} << OP_RETURN << data)) {
        return {FundParseError::NON_CANONICAL_SCRIPT, std::nullopt};
    }

    try {
        SpanReader reader{std::span{data}.subspan(FUND_MAGIC.size())};
        uint8_t envelope_version;
        FundChain fund;
        reader >> envelope_version;
        if (envelope_version != FUND_ENVELOPE_VERSION) {
            return {FundParseError::UNSUPPORTED_ENVELOPE_VERSION, std::nullopt};
        }
        reader >> fund;
        if (!reader.empty()) return {FundParseError::TRAILING_DATA, std::nullopt};
        if (ValidateFund(fund) != FundValidationError::NONE) {
            return {FundParseError::INVALID_FUND, std::nullopt};
        }
        return {FundParseError::NONE, std::move(fund)};
    } catch (const std::ios_base::failure&) {
        return {FundParseError::INVALID_PAYLOAD, std::nullopt};
    }
}

TxFundsResult ExtractTransactionFunds(const CTransaction& tx)
{
    std::vector<FundOutput> funds;
    for (size_t output_index{0}; output_index < tx.vout.size(); ++output_index) {
        const auto parsed{ParseFundScript(tx.vout[output_index].scriptPubKey)};
        if (parsed.error == FundParseError::NOT_FUND) continue;
        if (!parsed) {
            return {TxFundsError::INVALID_ENVELOPE, parsed.error, {}};
        }
        if (tx.vout[output_index].nValue <= 0 || !MoneyRange(tx.vout[output_index].nValue)) {
            return {TxFundsError::INVALID_AMOUNT, FundParseError::NONE, {}};
        }
        funds.push_back(FundOutput{
            .output_index = static_cast<uint32_t>(output_index),
            .amount = tx.vout[output_index].nValue,
            .fund = *parsed.fund,
        });
    }
    return {TxFundsError::NONE, FundParseError::NONE, std::move(funds)};
}

} // namespace chainregistry
