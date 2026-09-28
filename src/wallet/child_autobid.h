// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_CHILD_AUTOBID_H
#define BITCOIN_WALLET_CHILD_AUTOBID_H

#include <consensus/amount.h>
#include <primitives/chainregistry.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace wallet {

class CWallet;
struct WalletContext;

inline constexpr uint32_t CHILD_AUTO_BID_POLICY_VERSION{1};
inline constexpr uint32_t MIN_CHILD_AUTO_BID_INTERVAL{60};
inline constexpr uint32_t MAX_CHILD_AUTO_BID_INTERVAL{24 * 60 * 60};

/** Explicit wallet spending limits for automatic BMM anchor publication. */
struct ChildAutoBidPolicy {
    uint32_t version{CHILD_AUTO_BID_POLICY_VERSION};
    CAmount fee_rate_per_kvb{0};
    CAmount max_bid{0};
    CAmount daily_budget{0};
    uint32_t min_interval{0};

    SERIALIZE_METHODS(ChildAutoBidPolicy, obj)
    {
        READWRITE(obj.version,
                  obj.fee_rate_per_kvb,
                  obj.max_bid,
                  obj.daily_budget,
                  obj.min_interval);
    }

    friend bool operator==(const ChildAutoBidPolicy&,
                           const ChildAutoBidPolicy&) = default;
};

bool IsValidChildAutoBidPolicy(const ChildAutoBidPolicy& policy);

enum class ChildAutoBidStatus : uint8_t {
    SUBMITTED,
    DISABLED,
    BMM_INACTIVE,
    CHILD_UNAVAILABLE,
    NO_PROPOSAL,
    DUPLICATE_ANCHOR,
    INTERVAL_LIMIT,
    DAILY_BUDGET_EXCEEDED,
    WALLET_LOCKED,
    CREATE_FAILED,
    BID_LIMIT_EXCEEDED,
    SIGNING_FAILED,
    BROADCAST_FAILED,
};

std::string_view ChildAutoBidStatusString(ChildAutoBidStatus status);

struct ChildAutoBidResult {
    ChildAutoBidStatus status{ChildAutoBidStatus::DISABLED};
    chainregistry::ChainId chain_id;
    uint256 child_block_hash;
    Txid txid;
    CAmount security_bid{0};
    CAmount daily_spent{0};
    std::string error;

    bool Submitted() const { return status == ChildAutoBidStatus::SUBMITTED; }
};

/** Evaluate limits and publish one anchor for the oldest eligible proposal. */
ChildAutoBidResult RunChildAutoBid(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id);

/** Scheduled best-effort processing for all explicit wallet policies. */
void MaybeSendChildAutoBids(WalletContext& context);

} // namespace wallet

#endif // BITCOIN_WALLET_CHILD_AUTOBID_H
