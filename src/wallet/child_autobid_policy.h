// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_CHILD_AUTOBID_POLICY_H
#define BITCOIN_WALLET_CHILD_AUTOBID_POLICY_H

#include <consensus/amount.h>
#include <serialize.h>

#include <cstdint>

namespace wallet {

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

} // namespace wallet

#endif // BITCOIN_WALLET_CHILD_AUTOBID_POLICY_H
