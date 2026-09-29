// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PRIMITIVES_DEPOSIT_H
#define BITCOIN_PRIMITIVES_DEPOSIT_H

#include <consensus/amount.h>
#include <primitives/chainregistry.h>
#include <script/script.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

class CTransaction;

namespace chainregistry {

inline constexpr std::array<unsigned char, 4> FUND_MAGIC{'K', 'F', 'N', 'D'};
inline constexpr uint8_t FUND_ENVELOPE_VERSION{1};
inline constexpr size_t MAX_CHILD_RECIPIENT_SIZE{64};
inline constexpr size_t MAX_FUND_DATA_SIZE{104};

/**
 * Irreversible main-chain burn authorizing value import on one child chain.
 * recipient_type is interpreted by the registered template and
 * template_version; recipient contains the canonical raw destination bytes.
 */
struct FundChain {
    ChainId chain_id;
    uint16_t recipient_type{0};
    std::vector<unsigned char> recipient;

    SERIALIZE_METHODS(FundChain, obj)
    {
        READWRITE(obj.chain_id, obj.recipient_type, obj.recipient);
    }

    friend bool operator==(const FundChain&, const FundChain&) = default;
};

enum class FundValidationError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    INVALID_RECIPIENT_TYPE,
    EMPTY_RECIPIENT,
    RECIPIENT_TOO_LARGE,
};

enum class FundParseError : uint8_t {
    NONE,
    NOT_FUND,
    MALFORMED_SCRIPT,
    DATA_TOO_LARGE,
    NON_CANONICAL_SCRIPT,
    UNSUPPORTED_ENVELOPE_VERSION,
    INVALID_PAYLOAD,
    TRAILING_DATA,
    INVALID_FUND,
};

struct FundParseResult {
    FundParseError error{FundParseError::NOT_FUND};
    std::optional<FundChain> fund;

    explicit operator bool() const { return error == FundParseError::NONE && fund.has_value(); }
};

enum class TxFundsError : uint8_t {
    NONE,
    INVALID_ENVELOPE,
    INVALID_AMOUNT,
};

struct FundOutput {
    uint32_t output_index{0};
    CAmount amount{0};
    FundChain fund;

    friend bool operator==(const FundOutput&, const FundOutput&) = default;
};

struct TxFundsResult {
    TxFundsError error{TxFundsError::NONE};
    FundParseError parse_error{FundParseError::NONE};
    std::vector<FundOutput> funds;

    bool IsValid() const { return error == TxFundsError::NONE; }
};

FundValidationError ValidateFund(const FundChain& fund);

/** Serialize a FUND_CHAIN output without validating the payload. */
CScript BuildFundScript(const FundChain& fund);
/** Parse and validate a canonical, provably unspendable FUND_CHAIN output. */
FundParseResult ParseFundScript(const CScript& script);

/**
 * Extract all FUND_CHAIN outputs from a transaction. A transaction may fund
 * multiple children or recipients through distinct output indexes. Any
 * recognizable but malformed envelope invalidates the complete result.
 */
TxFundsResult ExtractTransactionFunds(const CTransaction& tx);

} // namespace chainregistry

#endif // BITCOIN_PRIMITIVES_DEPOSIT_H
