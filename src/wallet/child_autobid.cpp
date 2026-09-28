// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/child_autobid.h>

namespace wallet {

bool IsValidChildAutoBidPolicy(const ChildAutoBidPolicy& policy)
{
    return policy.version == CHILD_AUTO_BID_POLICY_VERSION &&
           policy.fee_rate_per_kvb > 0 &&
           MoneyRange(policy.fee_rate_per_kvb) &&
           policy.max_bid > 0 && MoneyRange(policy.max_bid) &&
           policy.daily_budget >= policy.max_bid &&
           MoneyRange(policy.daily_budget) &&
           policy.min_interval >= MIN_CHILD_AUTO_BID_INTERVAL &&
           policy.min_interval <= MAX_CHILD_AUTO_BID_INTERVAL;
}

} // namespace wallet
