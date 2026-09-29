// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_CHILD_AUTOBID_H
#define BITCOIN_WALLET_CHILD_AUTOBID_H

#include <primitives/chainregistry.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <wallet/child_autobid_policy.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace wallet {

class CWallet;
struct WalletContext;

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
