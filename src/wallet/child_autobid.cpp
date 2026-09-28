// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/child_autobid.h>

#include <common/messages.h>
#include <consensus/consensus.h>
#include <interfaces/chain.h>
#include <node/types.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/bmm.h>
#include <psbt.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <optional>

namespace wallet {
namespace {

constexpr std::string_view AUTO_BID_TAG{"__child_autobid"};
constexpr int64_t AUTO_BID_BUDGET_WINDOW{24 * 60 * 60};

struct AutoBidHistory {
    bool duplicate{false};
    CAmount daily_spent{0};
    std::optional<int64_t> last_bid_time;
};

bool IsActiveWalletTransaction(const CWalletTx& transaction)
{
    return !transaction.isAbandoned() &&
           !transaction.isBlockConflicted() &&
           !transaction.isMempoolConflicted();
}

AutoBidHistory ReadAutoBidHistory(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id,
    const uint256& child_block_hash,
    int64_t now)
{
    LOCK(wallet.cs_wallet);
    AutoBidHistory result;
    const std::string tag_prefix{chain_id.GetHex() + ":"};
    for (const auto& [txid, wallet_tx] : wallet.mapWallet) {
        if (!IsActiveWalletTransaction(wallet_tx)) continue;
        const auto extracted{
            chainregistry::ExtractTransactionBmmAnchor(*wallet_tx.tx)};
        if (!extracted.IsValid() || !extracted.anchor ||
            extracted.anchor->chain_id != chain_id) {
            continue;
        }
        if (extracted.anchor->child_block_hash == child_block_hash) {
            result.duplicate = true;
        }

        const auto automatic{wallet_tx.mapValue.find(std::string{AUTO_BID_TAG})};
        if (automatic == wallet_tx.mapValue.end() ||
            !automatic->second.starts_with(tag_prefix)) {
            continue;
        }

        const int64_t transaction_time{wallet_tx.GetTxTime()};
        if (!result.last_bid_time ||
            transaction_time > *result.last_bid_time) {
            result.last_bid_time = transaction_time;
        }
        if (transaction_time < now - AUTO_BID_BUDGET_WINDOW) continue;

        const CAmount debit{wallet.GetDebit(*wallet_tx.tx)};
        const CAmount fee{debit - wallet_tx.tx->GetValueOut()};
        if (fee > 0 && MoneyRange(fee) &&
            fee <= MAX_MONEY - result.daily_spent) {
            result.daily_spent += fee;
        }
    }
    return result;
}

ChildAutoBidResult Result(
    ChildAutoBidStatus status,
    const chainregistry::ChainId& chain_id,
    std::string error = {})
{
    return ChildAutoBidResult{
        .status = status,
        .chain_id = chain_id,
        .child_block_hash = {},
        .txid = {},
        .security_bid = 0,
        .daily_spent = 0,
        .error = std::move(error),
    };
}

} // namespace

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

std::string_view ChildAutoBidStatusString(ChildAutoBidStatus status)
{
    switch (status) {
    case ChildAutoBidStatus::SUBMITTED: return "submitted";
    case ChildAutoBidStatus::DISABLED: return "disabled";
    case ChildAutoBidStatus::BMM_INACTIVE: return "bmm_inactive";
    case ChildAutoBidStatus::CHILD_UNAVAILABLE: return "child_unavailable";
    case ChildAutoBidStatus::NO_PROPOSAL: return "no_proposal";
    case ChildAutoBidStatus::DUPLICATE_ANCHOR: return "duplicate_anchor";
    case ChildAutoBidStatus::INTERVAL_LIMIT: return "interval_limit";
    case ChildAutoBidStatus::DAILY_BUDGET_EXCEEDED: return "daily_budget_exceeded";
    case ChildAutoBidStatus::WALLET_LOCKED: return "wallet_locked";
    case ChildAutoBidStatus::CREATE_FAILED: return "create_failed";
    case ChildAutoBidStatus::BID_LIMIT_EXCEEDED: return "bid_limit_exceeded";
    case ChildAutoBidStatus::SIGNING_FAILED: return "signing_failed";
    case ChildAutoBidStatus::BROADCAST_FAILED: return "broadcast_failed";
    }
    return "unknown";
}

ChildAutoBidResult RunChildAutoBid(
    CWallet& wallet,
    const chainregistry::ChainId& chain_id)
{
    LOCK(wallet.m_child_autobid_mutex);
    const auto policy{wallet.GetChildAutoBidPolicy(chain_id)};
    if (!policy) return Result(ChildAutoBidStatus::DISABLED, chain_id);

    wallet.BlockUntilSyncedToCurrentChain();
    const auto registry{wallet.chain().getChainRegistrySnapshot(chain_id)};
    if (!registry.enabled || !registry.bmm_enabled ||
        !registry.active_for_next_block ||
        !registry.bmm_active_for_next_block || !registry.record ||
        registry.record->status != chainregistry::ChainStatus::ACTIVE) {
        return Result(ChildAutoBidStatus::BMM_INACTIVE, chain_id);
    }

    const auto child{wallet.chain().getChildBmmState(chain_id)};
    if (!child.IsValid()) {
        return Result(ChildAutoBidStatus::CHILD_UNAVAILABLE, chain_id);
    }
    const interfaces::ChildBmmProposal* candidate{nullptr};
    for (const auto& proposal : child.proposals) {
        if (proposal.previous_block_hash == child.best_block &&
            proposal.anchor_count == 0) {
            candidate = &proposal;
            break;
        }
    }
    if (!candidate) {
        return Result(ChildAutoBidStatus::NO_PROPOSAL, chain_id);
    }

    ChildAutoBidResult result;
    result.chain_id = chain_id;
    result.child_block_hash = candidate->block_hash;
    if (wallet.chain().hasBmmAnchorInMempool(
            chain_id, candidate->block_hash)) {
        result.status = ChildAutoBidStatus::DUPLICATE_ANCHOR;
        return result;
    }
    const int64_t now{Now<NodeSeconds>().time_since_epoch().count()};
    const AutoBidHistory history{
        ReadAutoBidHistory(wallet, chain_id, candidate->block_hash, now)};
    result.daily_spent = history.daily_spent;
    if (history.duplicate) {
        result.status = ChildAutoBidStatus::DUPLICATE_ANCHOR;
        return result;
    }
    if (history.last_bid_time &&
        now - *history.last_bid_time < policy->min_interval) {
        result.status = ChildAutoBidStatus::INTERVAL_LIMIT;
        return result;
    }
    if (history.daily_spent >= policy->daily_budget) {
        result.status = ChildAutoBidStatus::DAILY_BUDGET_EXCEEDED;
        return result;
    }
    if (wallet.IsLocked()) {
        result.status = ChildAutoBidStatus::WALLET_LOCKED;
        return result;
    }

    const chainregistry::BmmAnchor anchor{
        .chain_id = chain_id,
        .child_block_hash = candidate->block_hash,
    };
    const CScript anchor_script{chainregistry::BuildBmmAnchorScript(anchor)};
    const std::vector<CRecipient> recipients{
        CRecipient{CNoDestination{anchor_script}, 0, false}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    coin_control.fOverrideFeeRate = true;
    coin_control.m_feerate = CFeeRate{policy->fee_rate_per_kvb};
    const int64_t maximum_vsize{std::min<int64_t>(
        MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR,
        policy->max_bid * 1000 / policy->fee_rate_per_kvb)};
    coin_control.m_max_tx_weight = static_cast<int>(
        maximum_vsize * WITNESS_SCALE_FACTOR);

    CMutableTransaction raw_transaction;
    auto funded{FundTransaction(
        wallet,
        raw_transaction,
        recipients,
        /*change_pos=*/1,
        /*lockUnspents=*/false,
        coin_control)};
    if (!funded) {
        result.status = ChildAutoBidStatus::CREATE_FAILED;
        result.error = util::ErrorString(funded).original;
        return result;
    }
    if (funded->tx->vout.empty() || funded->tx->vout[0].nValue != 0 ||
        funded->tx->vout[0].scriptPubKey != anchor_script) {
        result.status = ChildAutoBidStatus::CREATE_FAILED;
        result.error = "wallet changed reserved BMM anchor output";
        return result;
    }
    result.security_bid = funded->fee;
    if (funded->fee <= 0 || funded->fee > policy->max_bid ||
        funded->fee > policy->daily_budget - history.daily_spent) {
        result.status = ChildAutoBidStatus::BID_LIMIT_EXCEEDED;
        return result;
    }

    PartiallySignedTransaction psbt{CMutableTransaction{*funded->tx}};
    bool complete{false};
    if (const auto error{wallet.FillPSBT(
            psbt,
            {.sign = true, .finalize = true, .bip32_derivs = false},
            complete)}) {
        result.status = ChildAutoBidStatus::SIGNING_FAILED;
        result.error = common::PSBTErrorString(*error).original;
        return result;
    }
    if (!complete) {
        result.status = ChildAutoBidStatus::SIGNING_FAILED;
        result.error = "wallet could not sign every BMM anchor input";
        return result;
    }

    CMutableTransaction final_transaction;
    if (!FinalizeAndExtractPSBT(psbt, final_transaction)) {
        result.status = ChildAutoBidStatus::SIGNING_FAILED;
        result.error = "wallet could not finalize the BMM anchor transaction";
        return result;
    }
    const CTransactionRef transaction{
        MakeTransactionRef(std::move(final_transaction))};
    std::string broadcast_error;
    if (!wallet.chain().broadcastTransaction(
            transaction,
            policy->max_bid,
            node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
            broadcast_error)) {
        result.status = ChildAutoBidStatus::BROADCAST_FAILED;
        result.error = std::move(broadcast_error);
        return result;
    }

    wallet.CommitTransaction(
        transaction,
        {{std::string{AUTO_BID_TAG},
          chain_id.GetHex() + ":" + candidate->block_hash.GetHex()}},
        /*orderForm=*/{});
    result.status = ChildAutoBidStatus::SUBMITTED;
    result.txid = transaction->GetHash();
    result.daily_spent += result.security_bid;
    return result;
}

void MaybeSendChildAutoBids(WalletContext& context)
{
    for (const auto& wallet : GetWallets(context)) {
        for (const auto& entry : wallet->GetChildAutoBidPolicies()) {
            const auto& chain_id{entry.first};
            const auto result{RunChildAutoBid(*wallet, chain_id)};
            if (result.Submitted()) {
                wallet->WalletLogPrintf(
                    "Published automatic BMM anchor %s for child block %s "
                    "with security bid %d\n",
                    result.txid.ToString(),
                    result.child_block_hash.ToString(),
                    result.security_bid);
            } else if (result.status == ChildAutoBidStatus::CREATE_FAILED ||
                       result.status == ChildAutoBidStatus::BID_LIMIT_EXCEEDED ||
                       result.status == ChildAutoBidStatus::SIGNING_FAILED ||
                       result.status == ChildAutoBidStatus::BROADCAST_FAILED) {
                wallet->WalletLogPrintf(
                    "Automatic BMM bid for child %s stopped with status %s: %s\n",
                    chain_id.ToString(),
                    ChildAutoBidStatusString(result.status),
                    result.error);
            }
        }
    }
}

} // namespace wallet
