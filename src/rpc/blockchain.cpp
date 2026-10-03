// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/blockchain.h>

#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <chainregistry/child_import.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/bmm.h>
#include <consensus/chainregistry.h>
#include <consensus/deposit_proof.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <flatfile.h>
#include <hash.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <interfaces/mining.h>
#include <kernel/coinstats.h>
#include <logging/timer.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/chainregistry.h>
#include <node/chain_manager.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/utxo_snapshot.h>
#include <node/warnings.h>
#include <primitives/block.h>
#include <primitives/deposit.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/syserror.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <cstdint>

#include <condition_variable>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using kernel::CCoinsStats;
using kernel::CoinStatsHashType;

using interfaces::BlockRef;
using interfaces::Mining;
using node::BlockManager;
using node::NodeContext;
using node::SnapshotMetadata;
using util::MakeUnorderedList;

static chainregistry::ChainId ParseChainId(std::string_view value)
{
    const auto chain_id{chainregistry::ChainId::FromHex(value)};
    if (!chain_id || chain_id->IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "chain_id must be exactly 32 non-null bytes encoded as hexadecimal");
    }
    return *chain_id;
}

static node::ChainManagerView CheckedLoadedChildChainView(
    node::ChainManagerView view)
{
    switch (view.error) {
    case node::ChainManagerViewError::NONE:
        return view;
    case node::ChainManagerViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    case node::ChainManagerViewError::HEIGHT_OUT_OF_RANGE:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child chain view error");
}

static node::ChainManagerView GetLoadedChildChainView(
    const std::any& context,
    std::string_view chain_id,
    std::optional<int> height = std::nullopt)
{
    return CheckedLoadedChildChainView(
        EnsureAnyChildChainman(context).GetChainView(
            ParseChainId(chain_id), height));
}

static node::ChainManagerWaitResult WaitForLoadedChildTip(
    const std::any& context,
    std::string_view chain_id,
    std::optional<uint256> current_tip,
    std::optional<std::chrono::milliseconds> timeout)
{
    auto result{EnsureAnyChildChainman(context).WaitForTipChanged(
        ParseChainId(chain_id), current_tip, timeout)};
    result.view = CheckedLoadedChildChainView(std::move(result.view));
    return result;
}

static UniValue ChildTipWaitResult(const node::ChainManagerView& view)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("hash", view.entry.tip.GetHex());
    result.pushKV("height", view.entry.height);
    result.pushKV("chain_id", view.entry.chain_id.GetHex());
    return result;
}

node::ChainManagerBlockView GetLoadedChildBlockView(
    const std::any& context,
    std::string_view chain_id,
    const uint256& block_hash)
{
    const auto view{EnsureAnyChildChainman(context).GetBlockView(
        ParseChainId(chain_id), block_hash)};
    switch (view.error) {
    case node::ChainManagerBlockViewError::NONE:
        return view;
    case node::ChainManagerBlockViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerBlockViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerBlockViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    case node::ChainManagerBlockViewError::BLOCK_NOT_FOUND:
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Child block not found");
    case node::ChainManagerBlockViewError::HEIGHT_OUT_OF_RANGE:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Child block height out of range");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child block view error");
}

static node::ChainManagerBlockView GetLoadedChildTipBlockView(
    const std::any& context,
    std::string_view chain_id)
{
    const auto view{EnsureAnyChildChainman(context).GetTipBlockView(
        ParseChainId(chain_id))};
    switch (view.error) {
    case node::ChainManagerBlockViewError::NONE:
        return view;
    case node::ChainManagerBlockViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerBlockViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerBlockViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    case node::ChainManagerBlockViewError::BLOCK_NOT_FOUND:
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "loaded child chain tip is unavailable");
    case node::ChainManagerBlockViewError::HEIGHT_OUT_OF_RANGE:
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "loaded child chain tip height is unavailable");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child tip view error");
}

static node::ChainManagerActiveBlocksView GetLoadedChildActiveBlockViews(
    const std::any& context,
    std::string_view chain_id,
    std::span<const uint256> block_hashes)
{
    const auto view{EnsureAnyChildChainman(context).GetActiveBlockViews(
        ParseChainId(chain_id), block_hashes)};
    switch (view.error) {
    case node::ChainManagerActiveBlocksViewError::NONE:
        return view;
    case node::ChainManagerActiveBlocksViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerActiveBlocksViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerActiveBlocksViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    case node::ChainManagerActiveBlocksViewError::BLOCK_NOT_FOUND:
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Child block not found");
    case node::ChainManagerActiveBlocksViewError::BLOCK_NOT_ACTIVE:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Child block is not in active chain");
    case node::ChainManagerActiveBlocksViewError::VIRTUAL_GENESIS:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "virtual child genesis has no serialized block or undo data");
    case node::ChainManagerActiveBlocksViewError::DATA_UNAVAILABLE:
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "child block or undo data is unavailable");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled active child blocks view error");
}

static node::ChainManagerCoinView GetLoadedChildCoinView(
    const std::any& context,
    std::string_view chain_id,
    const COutPoint& outpoint,
    bool include_mempool = false)
{
    const auto view{EnsureAnyChildChainman(context).GetCoinView(
        ParseChainId(chain_id), outpoint, include_mempool)};
    switch (view.error) {
    case node::ChainManagerCoinViewError::NONE:
        return view;
    case node::ChainManagerCoinViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerCoinViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerCoinViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child coin view error");
}

static node::ChainManagerTipsView GetLoadedChildChainTipsView(
    const std::any& context,
    std::string_view chain_id)
{
    const auto view{EnsureAnyChildChainman(context).GetChainTipsView(
        ParseChainId(chain_id))};
    switch (view.error) {
    case node::ChainManagerTipsViewError::NONE:
        return view;
    case node::ChainManagerTipsViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerTipsViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerTipsViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    case node::ChainManagerTipsViewError::DATA_UNAVAILABLE:
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "child chain DAG data is unavailable");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child chain tips view error");
}

static node::ChainManagerUTXOStatsView GetLoadedChildUTXOStatsView(
    const std::any& context,
    std::string_view chain_id,
    kernel::CoinStatsHashType hash_type,
    const std::function<void()>& interruption_point)
{
    const auto view{EnsureAnyChildChainman(context).GetUTXOStatsView(
        ParseChainId(chain_id), hash_type, interruption_point)};
    switch (view.error) {
    case node::ChainManagerUTXOStatsViewError::NONE:
        return view;
    case node::ChainManagerUTXOStatsViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerUTXOStatsViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerUTXOStatsViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    case node::ChainManagerUTXOStatsViewError::DATA_UNAVAILABLE:
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "child chain UTXO data is unavailable");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child UTXO statistics view error");
}

static node::ChainManagerUTXOScanView ScanLoadedChildUTXOSet(
    const std::any& context,
    const chainregistry::ChainId& chain_id,
    const std::set<CScript>& needles,
    std::atomic<int>& progress,
    const std::atomic<bool>& should_abort,
    const std::function<void()>& interruption_point)
{
    auto view{EnsureAnyChildChainman(context).ScanUTXOSet(
        chain_id, needles, progress, should_abort, interruption_point)};
    switch (view.error) {
    case node::ChainManagerUTXOStatsViewError::NONE:
        return view;
    case node::ChainManagerUTXOStatsViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerUTXOStatsViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerUTXOStatsViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    case node::ChainManagerUTXOStatsViewError::DATA_UNAVAILABLE:
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "child chain UTXO data is unavailable");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child UTXO scan view error");
}

static node::ChainManagerVerifyResult VerifyLoadedChildChain(
    const std::any& context,
    std::string_view chain_id,
    int64_t current_time)
{
    const auto result{EnsureAnyChildChainman(context).VerifyChain(
        ParseChainId(chain_id), current_time)};
    switch (result.error) {
    case node::ChainManagerVerifyError::NONE:
        return result;
    case node::ChainManagerVerifyError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerVerifyError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerVerifyError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unhandled child chain verification error");
}

struct PreparedUTXOSnapshot {
    std::unique_ptr<CCoinsViewCursor> cursor;
    CCoinsStats stats;
    const CBlockIndex* tip;
    std::optional<node::RegistrySnapshot> registry;
};

PreparedUTXOSnapshot
PrepareUTXOSnapshot(
    Chainstate& chainstate,
    const std::function<void()>& interruption_point = {})
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

UniValue WriteUTXOSnapshot(
    Chainstate& chainstate,
    CCoinsViewCursor* pcursor,
    CCoinsStats* maybe_stats,
    const CBlockIndex* tip,
    const std::optional<node::RegistrySnapshot>& registry_snapshot,
    AutoFile&& afile,
    const fs::path& path,
    const fs::path& temppath,
    const std::function<void()>& interruption_point = {});

/* Calculate the difficulty for a given block index.
 */
double GetDifficulty(const CBlockIndex& blockindex)
{
    int nShift = (blockindex.nBits >> 24) & 0xff;
    double dDiff =
        (double)0x0000ffff / (double)(blockindex.nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

static int ComputeNextBlockAndDepth(const CBlockIndex& tip, const CBlockIndex& blockindex, const CBlockIndex*& next)
{
    next = tip.GetAncestor(blockindex.nHeight + 1);
    if (next && next->pprev == &blockindex) {
        return tip.nHeight - blockindex.nHeight + 1;
    }
    next = nullptr;
    return &blockindex == &tip ? 1 : -1;
}

static const CBlockIndex* ParseHashOrHeight(const UniValue& param, ChainstateManager& chainman)
{
    LOCK(::cs_main);
    CChain& active_chain = chainman.ActiveChain();

    if (param.isNum()) {
        const int height{param.getInt<int>()};
        if (height < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d is negative", height));
        }
        const int current_tip{active_chain.Height()};
        if (height > current_tip) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d after current tip %d", height, current_tip));
        }

        return active_chain[height];
    } else {
        const uint256 hash{ParseHashV(param, "hash_or_height")};
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);

        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        return pindex;
    }
}

UniValue blockheaderToJSON(const CBlockIndex& tip, const CBlockIndex& blockindex, const uint256 pow_limit)
{
    // Serialize passed information without accessing chain state of the active chain!
    AssertLockNotHeld(cs_main); // For performance reasons

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", blockindex.GetBlockHash().GetHex());
    const CBlockIndex* pnext;
    int confirmations = ComputeNextBlockAndDepth(tip, blockindex, pnext);
    result.pushKV("confirmations", confirmations);
    result.pushKV("height", blockindex.nHeight);
    result.pushKV("version", blockindex.nVersion);
    result.pushKV("versionHex", strprintf("%08x", blockindex.nVersion));
    result.pushKV("merkleroot", blockindex.hashMerkleRoot.GetHex());
    result.pushKV("time", blockindex.nTime);
    result.pushKV("mediantime", blockindex.GetMedianTimePast());
    result.pushKV("nonce", blockindex.nNonce);
    result.pushKV("bits", strprintf("%08x", blockindex.nBits));
    result.pushKV("target", GetTarget(blockindex, pow_limit).GetHex());
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex.nChainWork.GetHex());
    result.pushKV("nTx", blockindex.nTx);

    if (blockindex.pprev)
        result.pushKV("previousblockhash", blockindex.pprev->GetBlockHash().GetHex());
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

UniValue childBlockHeaderToJSON(const node::ChainManagerBlockView& view)
{
    const auto& child{view.block};
    const CBlockHeader* header{child.block
        ? static_cast<const CBlockHeader*>(&*child.block)
        : nullptr};
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", view.entry.chain_id.GetHex());
    result.pushKV("hash", child.block_hash.GetHex());
    result.pushKV("confirmations", child.confirmations);
    result.pushKV("height", child.height);
    result.pushKV("version", header ? header->nVersion : 0);
    result.pushKV("versionHex", strprintf("%08x", header ? header->nVersion : 0));
    result.pushKV("merkleroot", header ? header->hashMerkleRoot.GetHex() : uint256{}.GetHex());
    result.pushKV("time", child.time);
    result.pushKV("mediantime", child.median_time);
    result.pushKV("nonce", header ? header->nNonce : 0);
    result.pushKV("bits", strprintf("%08x", header ? header->nBits : 0));
    result.pushKV("target", uint256{}.GetHex());
    result.pushKV("difficulty", 0.0);
    result.pushKV("chainwork", child.fork_score.cumulative_anchor_work.GetHex());
    result.pushKV("nTx", child.block ? child.block->vtx.size() : 0);
    result.pushKV("virtual", child.virtual_genesis);
    result.pushKV("bmm_eligible", child.fork_score.eligible);
    result.pushKV("bmm_activation_main_height", child.fork_score.activation_main_height);
    result.pushKV("bmm_own_work", child.fork_score.own_anchor_work.GetHex());
    result.pushKV("bmm_cumulative_work", child.fork_score.cumulative_anchor_work.GetHex());
    if (header && !header->hashPrevBlock.IsNull()) {
        result.pushKV("previousblockhash", header->hashPrevBlock.GetHex());
    }
    if (child.next_block_hash) {
        result.pushKV("nextblockhash", child.next_block_hash->GetHex());
    }
    return result;
}

UniValue childBlockchainInfoToJSON(const node::ChainManagerBlockView& view)
{
    const auto& entry{view.entry};
    const auto& tip{view.block};
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain", "child");
    result.pushKV("chain_id", entry.chain_id.GetHex());
    result.pushKV("genesis_hash", entry.genesis_hash.GetHex());
    result.pushKV("template_id", entry.template_id);
    result.pushKV("template_version", entry.template_version);
    result.pushKV("context_state",
                  entry.failed ? "failed" :
                  entry.safe_halt ? "safe_halt" : "loaded");
    result.pushKV("blocks", entry.height);
    result.pushKV("headers", entry.height);
    result.pushKV("bestblockhash", entry.tip.GetHex());
    result.pushKV("bits", strprintf("%08x", 0));
    result.pushKV("target", uint256{}.GetHex());
    result.pushKV("difficulty", 0.0);
    result.pushKV("time", tip.time);
    result.pushKV("mediantime", tip.median_time);
    result.pushKV("verificationprogress", 1.0);
    result.pushKV("initialblockdownload", false);
    result.pushKV("chainwork", tip.fork_score.cumulative_anchor_work.GetHex());
    result.pushKV("pruned", false);
    result.pushKV("safe_halt", entry.safe_halt);
    result.pushKV("network_sync_available", true);
    result.pushKV("main_height", entry.main_height);
    result.pushKV("main_tip", entry.main_tip.GetHex());
    result.pushKV("bmm_anchor_count", entry.anchor_count);
    result.pushKV("pending_bmm_anchor_count", entry.pending_anchor_count);
    result.pushKV("pending_bmm_anchor_bytes", entry.pending_anchor_bytes);
    result.pushKV("pending_bmm_anchor_limit", node::MAX_CHILD_PENDING_BMM_ANCHORS);
    result.pushKV("pending_bmm_anchor_bytes_limit", node::MAX_CHILD_PENDING_BMM_BYTES);
    result.pushKV("side_candidate_count", entry.side_candidate_count);
    result.pushKV("side_candidate_bytes", entry.side_candidate_bytes);
    result.pushKV("side_candidate_limit", node::MAX_CHILD_SIDE_CANDIDATES);
    result.pushKV("side_candidate_bytes_limit", node::MAX_CHILD_SIDE_CANDIDATE_BYTES);
    result.pushKV("candidate_bmm_anchor_count", entry.candidate_anchor_count);
    result.pushKV("candidate_bmm_anchor_bytes", entry.candidate_anchor_bytes);
    result.pushKV("candidate_bmm_anchor_limit", node::MAX_CHILD_CANDIDATE_BMM_ANCHORS);
    result.pushKV("candidate_bmm_anchor_bytes_limit", node::MAX_CHILD_CANDIDATE_BMM_BYTES);
    result.pushKV("bmm_eligible", tip.fork_score.eligible);
    result.pushKV("bmm_activation_main_height",
                  tip.fork_score.activation_main_height);
    result.pushKV("bmm_own_work", tip.fork_score.own_anchor_work.GetHex());
    result.pushKV("bmm_cumulative_work",
                  tip.fork_score.cumulative_anchor_work.GetHex());
    UniValue warnings{UniValue::VARR};
    if (entry.safe_halt) {
        warnings.push_back("Child chain is in SAFE_HALT");
    } else if (entry.failed) {
        warnings.push_back("Child chain runtime has failed");
    }
    result.pushKV("warnings", std::move(warnings));
    return result;
}

UniValue childChainTipsToJSON(const node::ChainManagerTipsView& view)
{
    UniValue result{UniValue::VARR};
    result.reserve(view.tips.size());
    for (const auto& tip : view.tips) {
        UniValue object{UniValue::VOBJ};
        object.pushKV("chain_id", view.entry.chain_id.GetHex());
        object.pushKV("height", tip.height);
        object.pushKV("hash", tip.block_hash.GetHex());
        object.pushKV("branchlen", tip.branch_length);
        object.pushKV("status",
                      tip.active ? "active" :
                      tip.fork_score.eligible ? "valid-fork" :
                      "bmm-ineligible");
        object.pushKV("bmm_eligible", tip.fork_score.eligible);
        object.pushKV("bmm_activation_main_height",
                      tip.fork_score.activation_main_height);
        object.pushKV("bmm_own_work",
                      tip.fork_score.own_anchor_work.GetHex());
        object.pushKV("bmm_cumulative_work",
                      tip.fork_score.cumulative_anchor_work.GetHex());
        result.push_back(std::move(object));
    }
    return result;
}

UniValue coinbaseTxToJSON(const CTransaction& coinbase_tx);

UniValue childBlockToJSON(const node::ChainManagerBlockView& view,
                          TxVerbosity verbosity)
{
    CHECK_NONFATAL(view.block.block);
    const CBlock& block{*view.block.block};
    UniValue result{childBlockHeaderToJSON(view)};
    result.pushKV("strippedsize", ::GetSerializeSize(TX_BASE(block)));
    result.pushKV("size", ::GetSerializeSize(TX_WITH_WITNESS(block)));
    result.pushKV("weight", ::GetBlockWeight(block));
    CHECK_NONFATAL(!block.vtx.empty());
    result.pushKV("coinbase_tx", coinbaseTxToJSON(*block.vtx[0]));

    UniValue transactions{UniValue::VARR};
    transactions.reserve(block.vtx.size());
    for (const auto& transaction : block.vtx) {
        if (verbosity == TxVerbosity::SHOW_TXID) {
            transactions.push_back(transaction->GetHash().GetHex());
            continue;
        }
        UniValue encoded{UniValue::VOBJ};
        TxToUniv(
            *transaction,
            view.block.block_hash,
            encoded,
            /*include_hex=*/true,
            /*txundo=*/nullptr,
            verbosity);
        transactions.push_back(std::move(encoded));
    }
    result.pushKV("tx", std::move(transactions));
    return result;
}

/** Serialize coinbase transaction metadata */
UniValue coinbaseTxToJSON(const CTransaction& coinbase_tx)
{
    CHECK_NONFATAL(!coinbase_tx.vin.empty());
    const CTxIn& vin_0{coinbase_tx.vin[0]};
    UniValue coinbase_tx_obj(UniValue::VOBJ);
    coinbase_tx_obj.pushKV("version", coinbase_tx.version);
    coinbase_tx_obj.pushKV("locktime", coinbase_tx.nLockTime);
    coinbase_tx_obj.pushKV("sequence", vin_0.nSequence);
    coinbase_tx_obj.pushKV("coinbase", HexStr(vin_0.scriptSig));
    const auto& witness_stack{vin_0.scriptWitness.stack};
    if (!witness_stack.empty()) {
        CHECK_NONFATAL(witness_stack.size() == 1);
        coinbase_tx_obj.pushKV("witness", HexStr(witness_stack[0]));
    }
    return coinbase_tx_obj;
}

UniValue blockToJSON(BlockManager& blockman, const CBlock& block, const CBlockIndex& tip, const CBlockIndex& blockindex, TxVerbosity verbosity, const uint256 pow_limit)
{
    UniValue result = blockheaderToJSON(tip, blockindex, pow_limit);

    result.pushKV("strippedsize", ::GetSerializeSize(TX_BASE(block)));
    result.pushKV("size", ::GetSerializeSize(TX_WITH_WITNESS(block)));
    result.pushKV("weight", ::GetBlockWeight(block));

    CHECK_NONFATAL(!block.vtx.empty());
    result.pushKV("coinbase_tx", coinbaseTxToJSON(*block.vtx[0]));

    UniValue txs(UniValue::VARR);
    txs.reserve(block.vtx.size());

    switch (verbosity) {
        case TxVerbosity::SHOW_TXID:
            for (const CTransactionRef& tx : block.vtx) {
                txs.push_back(tx->GetHash().GetHex());
            }
            break;

        case TxVerbosity::SHOW_DETAILS:
        case TxVerbosity::SHOW_DETAILS_AND_PREVOUT:
            CBlockUndo blockUndo;
            const bool is_not_pruned{WITH_LOCK(::cs_main, return !blockman.IsBlockPruned(blockindex))};
            bool have_undo{is_not_pruned && WITH_LOCK(::cs_main, return blockindex.nStatus & BLOCK_HAVE_UNDO)};
            if (have_undo && !blockman.ReadBlockUndo(blockUndo, blockindex)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Undo data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event.");
            }
            for (size_t i = 0; i < block.vtx.size(); ++i) {
                const CTransactionRef& tx = block.vtx.at(i);
                // coinbase transaction (i.e. i == 0) doesn't have undo data
                const CTxUndo* txundo = (have_undo && i > 0) ? &blockUndo.vtxundo.at(i - 1) : nullptr;
                UniValue objTx(UniValue::VOBJ);
                TxToUniv(*tx, /*block_hash=*/uint256(), /*entry=*/objTx, /*include_hex=*/true, txundo, verbosity);
                txs.push_back(std::move(objTx));
            }
            break;
    }

    result.pushKV("tx", std::move(txs));

    return result;
}

static RPCHelpMan getblockcount()
{
    return RPCHelpMan{
        "getblockcount",
        "Returns the height of the most-work fully-validated chain.\n"
                "The genesis block has height 0. Omit chain_id for the main chain.\n",
                {
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "The current block count"},
                RPCExamples{
                    HelpExampleCli("getblockcount", "")
            + HelpExampleRpc("getblockcount", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        return GetLoadedChildChainView(request.context, *chain_id).entry.height;
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Height();
},
    };
}

static RPCHelpMan getbestblockhash()
{
    return RPCHelpMan{
        "getbestblockhash",
        "Returns the hash of the best (tip) block in the selected fully-validated chain.\n"
                "Omit chain_id for the main chain.\n",
                {
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "the block hash, hex-encoded"},
                RPCExamples{
                    HelpExampleCli("getbestblockhash", "")
            + HelpExampleRpc("getbestblockhash", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        return GetLoadedChildChainView(request.context, *chain_id)
            .entry.tip.GetHex();
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Tip()->GetBlockHash().GetHex();
},
    };
}

static RPCHelpMan waitfornewblock()
{
    return RPCHelpMan{
        "waitfornewblock",
        "Waits for any new block and returns useful info about it.\n"
                "Omit chain_id for the main chain.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (kronein-cli -rpcclienttimeout=0)",
                {
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                    {"current_tip", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Method waits for the chain tip to differ from this."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                        {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitfornewblock", "1000")
            + HelpExampleCli("waitfornewblock", "1000 \"current_tip\" \"chain_id\"")
            + HelpExampleRpc("waitfornewblock", "1000")
            + HelpExampleRpc("waitfornewblock", "1000, \"current_tip\", \"chain_id\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;
    if (!request.params[0].isNull())
        timeout = request.params[0].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        const std::optional<uint256> current_tip{request.params[1].isNull()
            ? std::nullopt
            : std::optional<uint256>{
                  ParseHashV(request.params[1], "current_tip")}};
        return ChildTipWaitResult(
            WaitForLoadedChildTip(
                request.context,
                *chain_id,
                current_tip,
                timeout == 0
                    ? std::nullopt
                    : std::optional<std::chrono::milliseconds>{timeout})
                .view);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    // If the caller provided a current_tip value, pass it to waitTipChanged().
    //
    // If the caller did not provide a current tip hash, call getTip() to get
    // one and wait for the tip to be different from this value. This mode is
    // less reliable because if the tip changed between waitfornewblock calls,
    // it will need to change a second time before this call returns.
    BlockRef current_block{CHECK_NONFATAL(miner.getTip()).value()};

    uint256 tip_hash{request.params[1].isNull()
        ? current_block.hash
        : ParseHashV(request.params[1], "current_tip")};

    // If the user provided an invalid current_tip then this call immediately
    // returns the current tip.
    std::optional<BlockRef> block = timeout ? miner.waitTipChanged(tip_hash, std::chrono::milliseconds(timeout)) :
                                              miner.waitTipChanged(tip_hash);

    // Return current block upon shutdown
    if (block) current_block = *block;

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", current_block.hash.GetHex());
    ret.pushKV("height", current_block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblock()
{
    return RPCHelpMan{
        "waitforblock",
        "Waits for a specific new block and returns useful info about it.\n"
                "Omit chain_id for the main chain.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (kronein-cli -rpcclienttimeout=0)",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Block hash to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                        {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\" 1000")
            + HelpExampleCli("waitforblock", "\"childblockhash\" 1000 \"chain_id\"")
            + HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
            + HelpExampleRpc("waitforblock", "\"childblockhash\", 1000, \"chain_id\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    if (!request.params[1].isNull())
        timeout = request.params[1].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        auto current{GetLoadedChildChainView(request.context, *chain_id)};
        const auto deadline{
            std::chrono::steady_clock::now() + 1ms * timeout};
        while (current.entry.tip != hash) {
            std::optional<std::chrono::milliseconds> remaining;
            if (timeout) {
                const auto now{std::chrono::steady_clock::now()};
                if (now >= deadline) break;
                remaining = std::chrono::ceil<std::chrono::milliseconds>(
                    deadline - now);
            }
            auto waited{WaitForLoadedChildTip(
                request.context,
                *chain_id,
                current.entry.tip,
                remaining)};
            current = std::move(waited.view);
            if (waited.interrupted) break;
        }
        return ChildTipWaitResult(current);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    // Abort if RPC came out of warmup too early
    BlockRef current_block{CHECK_NONFATAL(miner.getTip()).value()};

    const auto deadline{std::chrono::steady_clock::now() + 1ms * timeout};
    while (current_block.hash != hash) {
        std::optional<BlockRef> block;
        if (timeout) {
            auto now{std::chrono::steady_clock::now()};
            if (now >= deadline) break;
            const MillisecondsDouble remaining{deadline - now};
            block = miner.waitTipChanged(current_block.hash, remaining);
        } else {
            block = miner.waitTipChanged(current_block.hash);
        }
        // Return current block upon shutdown
        if (!block) break;
        current_block = *block;
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", current_block.hash.GetHex());
    ret.pushKV("height", current_block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblockheight()
{
    return RPCHelpMan{
        "waitforblockheight",
        "Waits for (at least) block height and returns the height and hash\n"
                "of the current tip.\n"
                "Omit chain_id for the main chain.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (kronein-cli -rpcclienttimeout=0)",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                        {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblockheight", "100 1000")
            + HelpExampleCli("waitforblockheight", "100 1000 \"chain_id\"")
            + HelpExampleRpc("waitforblockheight", "100, 1000")
            + HelpExampleRpc("waitforblockheight", "100, 1000, \"chain_id\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    int height = request.params[0].getInt<int>();

    if (!request.params[1].isNull())
        timeout = request.params[1].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        auto current{GetLoadedChildChainView(request.context, *chain_id)};
        const auto deadline{
            std::chrono::steady_clock::now() + 1ms * timeout};
        while (static_cast<int64_t>(current.entry.height) < height) {
            std::optional<std::chrono::milliseconds> remaining;
            if (timeout) {
                const auto now{std::chrono::steady_clock::now()};
                if (now >= deadline) break;
                remaining = std::chrono::ceil<std::chrono::milliseconds>(
                    deadline - now);
            }
            auto waited{WaitForLoadedChildTip(
                request.context,
                *chain_id,
                current.entry.tip,
                remaining)};
            current = std::move(waited.view);
            if (waited.interrupted) break;
        }
        return ChildTipWaitResult(current);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    // Abort if RPC came out of warmup too early
    BlockRef current_block{CHECK_NONFATAL(miner.getTip()).value()};

    const auto deadline{std::chrono::steady_clock::now() + 1ms * timeout};

    while (current_block.height < height) {
        std::optional<BlockRef> block;
        if (timeout) {
            auto now{std::chrono::steady_clock::now()};
            if (now >= deadline) break;
            const MillisecondsDouble remaining{deadline - now};
            block = miner.waitTipChanged(current_block.hash, remaining);
        } else {
            block = miner.waitTipChanged(current_block.hash);
        }
        // Return current block on shutdown
        if (!block) break;
        current_block = *block;
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", current_block.hash.GetHex());
    ret.pushKV("height", current_block.height);
    return ret;
},
    };
}

static RPCHelpMan syncwithvalidationinterfacequeue()
{
    return RPCHelpMan{
        "syncwithvalidationinterfacequeue",
        "Waits for the validation interface queue to catch up on everything that was there when we entered this function.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("syncwithvalidationinterfacequeue","")
            + HelpExampleRpc("syncwithvalidationinterfacequeue","")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    CHECK_NONFATAL(node.validation_signals)->SyncWithValidationInterfaceQueue();
    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getdifficulty()
{
    return RPCHelpMan{
        "getdifficulty",
        "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"
        "Omit chain_id for the main chain. BMM child chains have no independent proof-of-work target and return 0.\n",
                {
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "the proof-of-work difficulty as a multiple of the minimum difficulty, or zero for a BMM child chain."},
                RPCExamples{
                    HelpExampleCli("getdifficulty", "")
            + HelpExampleCli("getdifficulty", "\"chain_id\"")
            + HelpExampleRpc("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "\"chain_id\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        GetLoadedChildTipBlockView(request.context, *chain_id);
        return 0.0;
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return GetDifficulty(*CHECK_NONFATAL(chainman.ActiveChain().Tip()));
},
    };
}

static RPCHelpMan getblockfrompeer()
{
    return RPCHelpMan{
        "getblockfrompeer",
        "Attempt to fetch block from a given peer.\n\n"
        "We must have the header for this block, e.g. using submitheader.\n"
        "The block will not have any undo data which can limit the usage of the block data in a context where the undo data is needed.\n"
        "Subsequent calls for the same block may cause the response from the previous peer to be ignored.\n"
        "Peers generally ignore requests for a stale block that they never fully verified, or one that is more than a month old.\n"
        "When a peer does not respond with a block, we will disconnect.\n"
        "Note: The block could be re-pruned as soon as it is received.\n\n"
        "Returns an empty JSON object if the request was successfully scheduled.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash to try to fetch"},
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to fetch it from (see getpeerinfo for peer IDs)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "", {}},
        RPCExamples{
            HelpExampleCli("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
            + HelpExampleRpc("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    PeerManager& peerman = EnsurePeerman(node);

    const uint256& block_hash{ParseHashV(request.params[0], "blockhash")};
    const NodeId peer_id{request.params[1].getInt<int64_t>()};

    const CBlockIndex* const index = WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(block_hash););

    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block header missing");
    }

    // Fetching blocks before the node has syncing past their height can prevent block files from
    // being pruned, so we avoid it if the node is in prune mode.
    if (chainman.m_blockman.IsPruneMode() && index->nHeight > WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()->nHeight)) {
        throw JSONRPCError(RPC_MISC_ERROR, "In prune mode, only blocks that the node has already synced previously can be fetched from a peer");
    }

    const bool block_has_data = WITH_LOCK(::cs_main, return index->nStatus & BLOCK_HAVE_DATA);
    if (block_has_data) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block already downloaded");
    }

    if (const auto res{peerman.FetchBlock(peer_id, *index)}; !res) {
        throw JSONRPCError(RPC_MISC_ERROR, res.error());
    }
    return UniValue::VOBJ;
},
    };
}

static RPCHelpMan getblockhash()
{
    return RPCHelpMan{
        "getblockhash",
        "Returns hash of block in the selected best block chain at the provided height.\n"
                "Omit chain_id for the main chain.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The height index"},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "The block hash"},
                RPCExamples{
                    HelpExampleCli("getblockhash", "1000")
            + HelpExampleRpc("getblockhash", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int nHeight = self.Arg<int>("height");
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        return GetLoadedChildChainView(
                   request.context, *chain_id, nHeight)
            .block_hash->GetHex();
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();

    if (nHeight < 0 || nHeight > active_chain.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    const CBlockIndex* pblockindex = active_chain[nHeight];
    return pblockindex->GetBlockHash().GetHex();
},
    };
}

static RPCHelpMan getblockheader()
{
    return RPCHelpMan{
        "getblockheader",
        "If verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
                "If verbose is true, returns an Object with information about blockheader <hash>.\n"
                "Omit chain_id for the main chain. A child genesis is a virtual descriptor and only has a verbose representation.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{true}, "true for a json object, false for the hex-encoded data"},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                {
                    RPCResult{"for verbose = true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                            {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                            {RPCResult::Type::NUM, "height", "The block height or index"},
                            {RPCResult::Type::NUM, "version", "The block version"},
                            {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                            {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                            {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM, "nonce", "The nonce"},
                            {RPCResult::Type::STR_HEX, "bits", "nBits: compact representation of the block difficulty target"},
                            {RPCResult::Type::STR_HEX, "target", "The difficulty target"},
                            {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                            {RPCResult::Type::STR_HEX, "chainwork", "Expected main-chain work; for a child, cumulative active BMM anchor work"},
                            {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                            {RPCResult::Type::BOOL, "virtual", /*optional=*/true, "Whether this is the non-serialized child genesis descriptor"},
                            {RPCResult::Type::BOOL, "bmm_eligible", /*optional=*/true, "Whether this child block is eligible for BMM fork choice"},
                            {RPCResult::Type::NUM, "bmm_activation_main_height", /*optional=*/true, "Earliest active main height anchoring the child block after its parent"},
                            {RPCResult::Type::STR_HEX, "bmm_own_work", /*optional=*/true, "Active main-chain anchor work committed directly to this child block"},
                            {RPCResult::Type::STR_HEX, "bmm_cumulative_work", /*optional=*/true, "Cumulative BMM work along this child branch"},
                            {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                            {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                        }},
                    RPCResult{"for verbose=false",
                        RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                },
                RPCExamples{
                    HelpExampleCli("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "hash"));

    bool fVerbose = true;
    if (!request.params[1].isNull())
        fVerbose = request.params[1].get_bool();

    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        const auto view{GetLoadedChildBlockView(
            request.context, *chain_id, hash)};
        if (!fVerbose) {
            if (view.block.virtual_genesis) {
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "The child genesis is a virtual descriptor and has no serialized block header");
            }
            CHECK_NONFATAL(view.block.block);
            DataStream stream;
            stream << static_cast<const CBlockHeader&>(*view.block.block);
            return HexStr(stream);
        }
        return childBlockHeaderToJSON(view);
    }

    const CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();
    }

    if (!pblockindex) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    if (!fVerbose)
    {
        DataStream ssBlock{};
        ssBlock << pblockindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock);
        return strHex;
    }

    return blockheaderToJSON(*tip, *pblockindex, chainman.GetConsensus().powLimit);
},
    };
}

void CheckBlockDataAvailability(BlockManager& blockman, const CBlockIndex& blockindex, bool check_for_undo)
{
    AssertLockHeld(cs_main);
    uint32_t flag = check_for_undo ? BLOCK_HAVE_UNDO : BLOCK_HAVE_DATA;
    if (!(blockindex.nStatus & flag)) {
        if (blockman.IsBlockPruned(blockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("%s not available (pruned data)", check_for_undo ? "Undo data" : "Block"));
        }
        if (check_for_undo) {
            throw JSONRPCError(RPC_MISC_ERROR, "Undo data not available");
        }
        throw JSONRPCError(RPC_MISC_ERROR, "Block not available (not fully downloaded)");
    }
}

static CBlock GetBlockChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    CBlock block;
    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/false);
    }

    if (!blockman.ReadBlock(block, blockindex)) {
        // Block not found on disk. This shouldn't normally happen unless the block was
        // pruned right after we released the lock above.
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    return block;
}

static std::vector<std::byte> GetRawBlockChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    FlatFilePos pos{};
    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/false);
        pos = blockindex.GetBlockPos();
    }

    if (auto data{blockman.ReadRawBlock(pos)}) return std::move(*data);
    // Block not found on disk. This shouldn't normally happen unless the block was
    // pruned right after we released the lock above.
    throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
}

static CBlockUndo GetUndoChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    CBlockUndo blockUndo;

    // The Genesis block does not have undo data
    if (blockindex.nHeight == 0) return blockUndo;

    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/true);
    }

    if (!blockman.ReadBlockUndo(blockUndo, blockindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Can't read undo data from disk");
    }

    return blockUndo;
}

const RPCResult getblock_vin{
    RPCResult::Type::ARR, "vin", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::ELISION, "", "The same output as verbosity = 2"},
            {RPCResult::Type::OBJ, "prevout", "(Only if undo information is available)",
            {
                {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                {RPCResult::Type::NUM, "height", "The height of the prevout"},
                {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Kronein address (only if a well-defined address exists)"},
                    {RPCResult::Type::STR, "type", "The type (one of: " + GetAllOutputTypes() + ")"},
                }},
            }},
        }},
    }
};

static RPCHelpMan getblock()
{
    return RPCHelpMan{
        "getblock",
        "If verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
                "If verbosity is 1, returns an Object with information about block <hash>.\n"
                "If verbosity is 2, returns an Object with information about block <hash> and information about each transaction.\n"
                "If verbosity is 3, returns an Object with information about block <hash> and information about each transaction, including prevout information for inputs (only for unpruned blocks in the current best chain).\n"
                "Omit chain_id for the main chain. A child genesis is a virtual descriptor and has no serialized block.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbosity", RPCArg::Type::NUM, RPCArg::Default{1}, "0 for hex-encoded data, 1 for a JSON object, 2 for JSON object with transaction data, and 3 for JSON object with transaction data including prevout information for inputs"},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                {
                    RPCResult{"for verbosity = 0",
                RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                    RPCResult{"for verbosity = 1",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                    {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
                    {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                    {RPCResult::Type::NUM, "size", "The block size"},
                    {RPCResult::Type::NUM, "strippedsize", "The block size excluding witness data"},
                    {RPCResult::Type::NUM, "weight", "The block weight as defined in BIP 141"},
                    {RPCResult::Type::OBJ, "coinbase_tx", "Coinbase transaction metadata",
                    {
                        {RPCResult::Type::NUM, "version", "The coinbase transaction version"},
                        {RPCResult::Type::NUM, "locktime", "The coinbase transaction's locktime (nLockTime)"},
                        {RPCResult::Type::NUM, "sequence", "The coinbase input's sequence number (nSequence)"},
                        {RPCResult::Type::STR_HEX, "coinbase", "The coinbase input's script"},
                        {RPCResult::Type::STR_HEX, "witness", /*optional=*/true, "The coinbase input's first (and only) witness stack element, if present"},
                    }},
                    {RPCResult::Type::NUM, "height", "The block height or index"},
                    {RPCResult::Type::NUM, "version", "The block version"},
                    {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                    {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                    {RPCResult::Type::ARR, "tx", "The transaction ids",
                        {{RPCResult::Type::STR_HEX, "", "The transaction id"}}},
                    {RPCResult::Type::NUM_TIME, "time",       "The block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM, "nonce", "The nonce"},
                    {RPCResult::Type::STR_HEX, "bits", "nBits: compact representation of the block difficulty target"},
                    {RPCResult::Type::STR_HEX, "target", "The difficulty target"},
                    {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                    {RPCResult::Type::STR_HEX, "chainwork", "Expected main-chain work; for a child, cumulative active BMM anchor work"},
                    {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                    {RPCResult::Type::BOOL, "virtual", /*optional=*/true, "Whether this is the non-serialized child genesis descriptor"},
                    {RPCResult::Type::BOOL, "bmm_eligible", /*optional=*/true, "Whether this child block is eligible for BMM fork choice"},
                    {RPCResult::Type::NUM, "bmm_activation_main_height", /*optional=*/true, "Earliest active main height anchoring the child block after its parent"},
                    {RPCResult::Type::STR_HEX, "bmm_own_work", /*optional=*/true, "Active main-chain anchor work committed directly to this child block"},
                    {RPCResult::Type::STR_HEX, "bmm_cumulative_work", /*optional=*/true, "Cumulative BMM work along this child branch"},
                    {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                    {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                }},
                    RPCResult{"for verbosity = 2",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 \"tx\" result"},
                            {RPCResult::Type::NUM, "fee", /*optional=*/true, "The transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                        }},
                    }},
                }},
                    RPCResult{"for verbosity = 3",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 2"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            getblock_vin,
                        }},
                    }},
                }},
        },
                RPCExamples{
                    HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    int verbosity{ParseVerbosity(request.params[1], /*default_verbosity=*/1)};

    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        const auto view{GetLoadedChildBlockView(
            request.context, *chain_id, hash)};
        if (view.block.virtual_genesis) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "The child genesis is a virtual descriptor and has no serialized block");
        }
        CHECK_NONFATAL(view.block.block);
        if (verbosity <= 0) {
            DataStream stream;
            stream << TX_WITH_WITNESS(*view.block.block);
            return HexStr(stream);
        }
        const TxVerbosity transaction_verbosity{
            verbosity == 1 ? TxVerbosity::SHOW_TXID
                           : verbosity == 2 ? TxVerbosity::SHOW_DETAILS
                                            : TxVerbosity::SHOW_DETAILS_AND_PREVOUT};
        return childBlockToJSON(view, transaction_verbosity);
    }

    const CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();

        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    const std::vector<std::byte> block_data{GetRawBlockChecked(chainman.m_blockman, *pblockindex)};

    if (verbosity <= 0) {
        return HexStr(block_data);
    }

    CBlock block{};
    SpanReader{block_data} >> TX_WITH_WITNESS(block);

    TxVerbosity tx_verbosity;
    if (verbosity == 1) {
        tx_verbosity = TxVerbosity::SHOW_TXID;
    } else if (verbosity == 2) {
        tx_verbosity = TxVerbosity::SHOW_DETAILS;
    } else {
        tx_verbosity = TxVerbosity::SHOW_DETAILS_AND_PREVOUT;
    }

    return blockToJSON(chainman.m_blockman, block, *tip, *pblockindex, tx_verbosity, chainman.GetConsensus().powLimit);
},
    };
}

//! Return height of highest block that has been pruned, or std::nullopt if no blocks have been pruned
std::optional<int> GetPruneHeight(const BlockManager& blockman, const CChain& chain) {
    AssertLockHeld(::cs_main);

    // Search for the last block missing block data or undo data. Don't let the
    // search consider the genesis block, because the genesis block does not
    // have undo data, but should not be considered pruned.
    const CBlockIndex* first_block{chain[1]};
    const CBlockIndex* chain_tip{chain.Tip()};

    // If there are no blocks after the genesis block, or no blocks at all, nothing is pruned.
    if (!first_block || !chain_tip) return std::nullopt;

    // If the chain tip is pruned, everything is pruned.
    if ((chain_tip->nStatus & BLOCK_HAVE_MASK) != BLOCK_HAVE_MASK) return chain_tip->nHeight;

    const auto& first_unpruned{blockman.GetFirstBlock(*chain_tip, /*status_mask=*/BLOCK_HAVE_MASK, first_block)};
    if (&first_unpruned == first_block) {
        // All blocks between first_block and chain_tip have data, so nothing is pruned.
        return std::nullopt;
    }

    // Block before the first unpruned block is the last pruned block.
    return CHECK_NONFATAL(first_unpruned.pprev)->nHeight;
}

static RPCHelpMan pruneblockchain()
{
    return RPCHelpMan{"pruneblockchain",
                "Attempts to delete block and undo data up to a specified height or timestamp, if eligible for pruning.\n"
                "Requires `-prune` to be enabled at startup. While pruned data may be re-fetched in some cases (e.g., via `getblockfrompeer`), local deletion is irreversible.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block height to prune up to. May be set to a discrete height, or to a " + UNIX_EPOCH_TIME + "\n"
            "                  to prune blocks whose block time is at least 2 hours older than the provided timestamp."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Height of the last block pruned"},
                RPCExamples{
                    HelpExampleCli("pruneblockchain", "1000")
            + HelpExampleRpc("pruneblockchain", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    if (!chainman.m_blockman.IsPruneMode()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Cannot prune blocks because node is not in prune mode.");
    }

    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    CChain& active_chain = active_chainstate.m_chain;

    int heightParam = request.params[0].getInt<int>();
    if (heightParam < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative block height.");
    }

    // Height value more than a billion is too high to be a block height, and
    // too low to be a block time (corresponds to timestamp from Sep 2001).
    if (heightParam > 1000000000) {
        // Add a 2 hour buffer to include blocks which might have had old timestamps
        const CBlockIndex* pindex = active_chain.FindEarliestAtLeast(heightParam - TIMESTAMP_WINDOW, 0);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not find block with at least the specified timestamp.");
        }
        heightParam = pindex->nHeight;
    }

    unsigned int height = (unsigned int) heightParam;
    unsigned int chainHeight = (unsigned int) active_chain.Height();
    if (chainHeight < chainman.GetParams().PruneAfterHeight()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Blockchain is too short for pruning.");
    } else if (height > chainHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Blockchain is shorter than the attempted prune height.");
    } else if (height > chainHeight - MIN_BLOCKS_TO_KEEP) {
        LogDebug(BCLog::RPC, "Attempt to prune blocks close to the tip.  Retaining the minimum number of blocks.\n");
        height = chainHeight - MIN_BLOCKS_TO_KEEP;
    }

    PruneBlockFilesManual(active_chainstate, height);
    return GetPruneHeight(chainman.m_blockman, active_chain).value_or(-1);
},
    };
}

CoinStatsHashType ParseHashType(std::string_view hash_type_input)
{
    if (hash_type_input == "muhash") {
        return CoinStatsHashType::MUHASH;
    } else if (hash_type_input == "none") {
        return CoinStatsHashType::NONE;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("'%s' is not a valid hash_type", hash_type_input));
    }
}

/**
 * Calculate statistics about the unspent transaction output set
 *
 * @param[in] index_requested Signals if the coinstatsindex should be used (when available).
 */
static std::optional<kernel::CCoinsStats> GetUTXOStats(CCoinsView* view, node::BlockManager& blockman,
                                                       kernel::CoinStatsHashType hash_type,
                                                       const std::function<void()>& interruption_point = {},
                                                       const CBlockIndex* pindex = nullptr,
                                                       bool index_requested = true)
{
    // Use CoinStatsIndex if it is requested and available and a hash_type of Muhash or None was requested
    if ((hash_type == kernel::CoinStatsHashType::MUHASH || hash_type == kernel::CoinStatsHashType::NONE) && g_coin_stats_index && index_requested) {
        if (pindex) {
            return g_coin_stats_index->LookUpStats(*pindex);
        } else {
            CBlockIndex& block_index = *CHECK_NONFATAL(WITH_LOCK(::cs_main, return blockman.LookupBlockIndex(view->GetBestBlock())));
            return g_coin_stats_index->LookUpStats(block_index);
        }
    }

    // If the coinstats index isn't requested or is otherwise not usable, the
    // pindex should either be null or equal to the view's best block. This is
    // because without the coinstats index we can only get coinstats about the
    // best block.
    CHECK_NONFATAL(!pindex || pindex->GetBlockHash() == view->GetBestBlock());

    return kernel::ComputeUTXOStats(hash_type, view, blockman, interruption_point);
}

static RPCHelpMan gettxoutsetinfo()
{
    return RPCHelpMan{
        "gettxoutsetinfo",
        "Returns statistics about the unspent transaction output set.\n"
                "Note this call may take some time if you are not using coinstatsindex.\n"
                "When chain_id is omitted, this operates on the main chain. Child-chain statistics are calculated from the current locally loaded tip.\n",
                {
                    {"hash_type", RPCArg::Type::STR, RPCArg::Default{"muhash"}, "Which UTXO set hash should be calculated. Options: 'muhash', 'none'."},
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"the current best block"}, "The block hash or height of the target height (historical values require main-chain coinstatsindex; a child target must equal its current tip).",
                     RPCArgOptions{
                         .skip_type_check = true,
                         .type_str = {"", "string or numeric"},
                     }},
                    {"use_index", RPCArg::Type::BOOL, RPCArg::Default{true}, "Use main-chain coinstatsindex, if available. Child-chain requests always calculate the current snapshot."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "height", "The block height (index) of the returned statistics"},
                        {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at which these statistics are calculated"},
                        {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs"},
                        {RPCResult::Type::NUM, "bogosize", "Database-independent, meaningless metric indicating the UTXO set size"},
                        {RPCResult::Type::STR_HEX, "muhash", /*optional=*/true, "The MuHash (only present if 'muhash' hash_type is chosen)"},
                        {RPCResult::Type::NUM, "transactions", /*optional=*/true, "The number of transactions with unspent outputs (not available when coinstatsindex is used)"},
                        {RPCResult::Type::NUM, "disk_size", /*optional=*/true, "The estimated size of the chainstate on disk (not available when coinstatsindex is used)"},
                        {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of coins in the UTXO set"},
                        {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
                        {RPCResult::Type::STR_AMOUNT, "total_unspendable_amount", /*optional=*/true, "The total amount of coins permanently excluded from the UTXO set (only available if coinstatsindex is used)"},
                        {RPCResult::Type::OBJ, "block_info", /*optional=*/true, "Info on amounts in the block at this block height (only available if coinstatsindex is used)",
                        {
                            {RPCResult::Type::STR_AMOUNT, "prevout_spent", "Total amount of all prevouts spent in this block"},
                            {RPCResult::Type::STR_AMOUNT, "coinbase", "Coinbase subsidy amount of this block"},
                            {RPCResult::Type::STR_AMOUNT, "new_outputs_ex_coinbase", "Total amount of new outputs created by this block"},
                            {RPCResult::Type::STR_AMOUNT, "unspendable", "Total amount of unspendable outputs created in this block"},
                            {RPCResult::Type::OBJ, "unspendables", "Detailed view of the unspendable categories",
                            {
                                {RPCResult::Type::STR_AMOUNT, "genesis_block", "The unspendable amount of the Genesis block subsidy"},
                                {RPCResult::Type::STR_AMOUNT, "scripts", "Amounts sent to scripts that are unspendable (for example OP_RETURN outputs)"},
                                {RPCResult::Type::STR_AMOUNT, "unclaimed_rewards", "Fee rewards that miners did not claim in their coinbase transaction"},
                            }}
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("gettxoutsetinfo", "") +
                    HelpExampleCli("gettxoutsetinfo", R"("none")") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" 1000)") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" '"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"')") +
                    HelpExampleCli("-named gettxoutsetinfo", R"(hash_type='muhash' use_index='false')") +
                    HelpExampleRpc("gettxoutsetinfo", "") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none")") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", 1000)") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09")")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);

    const CBlockIndex* pindex{nullptr};
    const CoinStatsHashType hash_type{ParseHashType(self.Arg<std::string_view>("hash_type"))};
    bool index_requested = request.params[2].isNull() || request.params[2].get_bool();

    NodeContext& node = EnsureAnyNodeContext(request.context);
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        const auto view{GetLoadedChildUTXOStatsView(
            request.context, *chain_id, hash_type,
            node.rpc_interruption_point)};
        const CCoinsStats& stats{view.stats};
        if (!request.params[1].isNull()) {
            const bool matches_tip{request.params[1].isNum()
                    ? request.params[1].getInt<int>() == stats.nHeight
                    : ParseHashV(request.params[1], "hash_or_height") ==
                          stats.hashBlock};
            if (!matches_tip) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "Child UTXO statistics are available only for the current tip");
            }
        }
        ret.pushKV("height", stats.nHeight);
        ret.pushKV("bestblock", stats.hashBlock.GetHex());
        ret.pushKV("txouts", stats.nTransactionOutputs);
        ret.pushKV("bogosize", stats.nBogoSize);
        if (hash_type == CoinStatsHashType::MUHASH) {
            ret.pushKV("muhash", stats.muhash.GetHex());
        }
        CHECK_NONFATAL(stats.total_amount.has_value());
        ret.pushKV("total_amount", ValueFromAmount(*stats.total_amount));
        ret.pushKV("transactions", stats.nTransactions);
        ret.pushKV("disk_size", stats.nDiskSize);
        ret.pushKV("chain_id", view.entry.chain_id.GetHex());
        return ret;
    }

    ChainstateManager& chainman = EnsureChainman(node);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    active_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);

    CCoinsView* coins_view;
    BlockManager* blockman;
    {
        LOCK(::cs_main);
        coins_view = &active_chainstate.CoinsDB();
        blockman = &active_chainstate.m_blockman;
    }

    if (!request.params[1].isNull()) {
        if (!g_coin_stats_index) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Querying specific block heights requires coinstatsindex");
        }

        if (!index_requested) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot set use_index to false when querying for a specific block");
        }
        pindex = ParseHashOrHeight(request.params[1], chainman);
    }

    if (index_requested && g_coin_stats_index) {
        if (!g_coin_stats_index->BlockUntilSyncedToCurrentChain()) {
            const IndexSummary summary{g_coin_stats_index->GetSummary()};

            // If a specific block was requested and the index has already synced past that height, we can return the
            // data already even though the index is not fully synced yet.
            if (pindex && pindex->nHeight > summary.best_block_height) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to get data because coinstatsindex is still syncing. Current height: %d", summary.best_block_height));
            }
        }
    }

    const std::optional<CCoinsStats> maybe_stats = GetUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex, index_requested);
    if (maybe_stats.has_value()) {
        const CCoinsStats& stats = maybe_stats.value();
        ret.pushKV("height", stats.nHeight);
        ret.pushKV("bestblock", stats.hashBlock.GetHex());
        ret.pushKV("txouts", stats.nTransactionOutputs);
        ret.pushKV("bogosize", stats.nBogoSize);
        if (hash_type == CoinStatsHashType::MUHASH) {
            ret.pushKV("muhash", stats.muhash.GetHex());
        }
        CHECK_NONFATAL(stats.total_amount.has_value());
        ret.pushKV("total_amount", ValueFromAmount(stats.total_amount.value()));
        if (!stats.index_used) {
            ret.pushKV("transactions", stats.nTransactions);
            ret.pushKV("disk_size", stats.nDiskSize);
        } else {
            CCoinsStats prev_stats{};
            if (stats.nHeight > 0) {
                const CBlockIndex& block_index = *CHECK_NONFATAL(WITH_LOCK(::cs_main, return blockman->LookupBlockIndex(stats.hashBlock)));
                const std::optional<CCoinsStats> maybe_prev_stats = GetUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, block_index.pprev, index_requested);
                if (!maybe_prev_stats) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
                }
                prev_stats = maybe_prev_stats.value();
            }

            CAmount block_total_unspendable_amount = stats.total_unspendables_genesis_block +
                                                     stats.total_unspendables_scripts +
                                                     stats.total_unspendables_unclaimed_rewards;
            CAmount prev_block_total_unspendable_amount = prev_stats.total_unspendables_genesis_block +
                                                          prev_stats.total_unspendables_scripts +
                                                          prev_stats.total_unspendables_unclaimed_rewards;

            ret.pushKV("total_unspendable_amount", ValueFromAmount(block_total_unspendable_amount));

            UniValue block_info(UniValue::VOBJ);
            // These per-block values should fit uint64 under normal circumstances
            arith_uint256 diff_prevout = stats.total_prevout_spent_amount - prev_stats.total_prevout_spent_amount;
            arith_uint256 diff_coinbase = stats.total_coinbase_amount - prev_stats.total_coinbase_amount;
            arith_uint256 diff_outputs = stats.total_new_outputs_ex_coinbase_amount - prev_stats.total_new_outputs_ex_coinbase_amount;
            CAmount prevout_amount = static_cast<CAmount>(diff_prevout.GetLow64());
            CAmount coinbase_amount = static_cast<CAmount>(diff_coinbase.GetLow64());
            CAmount outputs_amount = static_cast<CAmount>(diff_outputs.GetLow64());
            block_info.pushKV("prevout_spent", ValueFromAmount(prevout_amount));
            block_info.pushKV("coinbase", ValueFromAmount(coinbase_amount));
            block_info.pushKV("new_outputs_ex_coinbase", ValueFromAmount(outputs_amount));
            block_info.pushKV("unspendable", ValueFromAmount(block_total_unspendable_amount - prev_block_total_unspendable_amount));

            UniValue unspendables(UniValue::VOBJ);
            unspendables.pushKV("genesis_block", ValueFromAmount(stats.total_unspendables_genesis_block - prev_stats.total_unspendables_genesis_block));
            unspendables.pushKV("scripts", ValueFromAmount(stats.total_unspendables_scripts - prev_stats.total_unspendables_scripts));
            unspendables.pushKV("unclaimed_rewards", ValueFromAmount(stats.total_unspendables_unclaimed_rewards - prev_stats.total_unspendables_unclaimed_rewards));
            block_info.pushKV("unspendables", std::move(unspendables));

            ret.pushKV("block_info", std::move(block_info));
        }
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
    }
    return ret;
},
    };
}

static RPCHelpMan gettxout()
{
    return RPCHelpMan{
        "gettxout",
        "Returns details about an unspent transaction output.\n"
        "When chain_id is omitted, this operates on the main chain.\n",
        {
            {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
            {"n", RPCArg::Type::NUM, RPCArg::Optional::NO, "vout number"},
            {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to include the selected chain's mempool. An unspent output that is spent in the mempool won't appear."},
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full non-null child-chain identifier"},
        },
        {
            RPCResult{"If the UTXO was not found", RPCResult::Type::NONE, "", ""},
            RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                {RPCResult::Type::STR_AMOUNT, "value", "The transaction value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "", {
                    {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg pubkeyhash"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Kronein address (only if a well-defined address exists)"},
                }},
                {RPCResult::Type::BOOL, "coinbase", "Coinbase or not"},
            }},
        },
        RPCExamples{
            "\nGet unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nView the details\n"
            + HelpExampleCli("gettxout", "\"txid\" 1") +
            HelpExampleCli("gettxout", "\"txid\" 1 true \"chain_id\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("gettxout", "\"txid\", 1") +
            HelpExampleRpc("gettxout", "\"txid\", 1, true, \"chain_id\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    auto hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};
    COutPoint out{hash, request.params[1].getInt<uint32_t>()};
    bool fMempool = true;
    if (!request.params[2].isNull())
        fMempool = request.params[2].get_bool();

    UniValue ret(UniValue::VOBJ);
    if (!request.params[3].isNull()) {
        const auto view{GetLoadedChildCoinView(
            request.context, request.params[3].get_str(), out, fMempool)};
        if (!view.coin) return UniValue::VNULL;
        if (!view.mempool && view.coin->nHeight > view.entry.height) {
            throw JSONRPCError(
                RPC_INTERNAL_ERROR,
                "child UTXO confirmation height exceeds the active tip");
        }
        ret.pushKV("chain_id", view.entry.chain_id.GetHex());
        ret.pushKV("bestblock", view.entry.tip.GetHex());
        ret.pushKV("confirmations", view.mempool ? 0 :
                   view.entry.height - view.coin->nHeight + 1);
        ret.pushKV("value", ValueFromAmount(view.coin->out.nValue));
        UniValue o(UniValue::VOBJ);
        ScriptToUniv(view.coin->out.scriptPubKey, /*out=*/o,
                     /*include_hex=*/true, /*include_address=*/true);
        ret.pushKV("scriptPubKey", std::move(o));
        ret.pushKV("coinbase", static_cast<bool>(view.coin->fCoinBase));
        return ret;
    }

    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    Chainstate& active_chainstate = chainman.ActiveChainstate();
    CCoinsViewCache* coins_view = &active_chainstate.CoinsTip();

    std::optional<Coin> coin;
    if (fMempool) {
        const CTxMemPool& mempool = EnsureMemPool(node);
        LOCK(mempool.cs);
        CCoinsViewMemPool view(coins_view, mempool);
        if (!mempool.isSpent(out)) coin = view.GetCoin(out);
    } else {
        coin = coins_view->GetCoin(out);
    }
    if (!coin) return UniValue::VNULL;

    const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(coins_view->GetBestBlock());
    ret.pushKV("bestblock", pindex->GetBlockHash().GetHex());
    if (coin->nHeight == MEMPOOL_HEIGHT) {
        ret.pushKV("confirmations", 0);
    } else {
        ret.pushKV("confirmations", pindex->nHeight - coin->nHeight + 1);
    }
    ret.pushKV("value", ValueFromAmount(coin->out.nValue));
    UniValue o(UniValue::VOBJ);
    ScriptToUniv(coin->out.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
    ret.pushKV("scriptPubKey", std::move(o));
    ret.pushKV("coinbase", static_cast<bool>(coin->fCoinBase));

    return ret;
},
    };
}

static RPCHelpMan verifychain()
{
    return RPCHelpMan{
        "verifychain",
        "Verifies blockchain database.\n"
        "When chain_id is omitted, this operates on the main chain. Child-chain verification always performs an exhaustive, non-mutating rebuild of persisted headers, blocks, undo, imports, DAG and UTXO state; checklevel and nblocks are accepted for API compatibility but do not weaken that verification.\n",
                {
                    {"checklevel", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, range=0-4", DEFAULT_CHECKLEVEL)},
                        strprintf("How thorough the block verification is:\n%s", MakeUnorderedList(CHECKLEVEL_DOC))},
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, 0=all", DEFAULT_CHECKBLOCKS)}, "The number of blocks to check."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Verification finished successfully. If false, check debug.log for reason."},
                RPCExamples{
                    HelpExampleCli("verifychain", "")
            + HelpExampleRpc("verifychain", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int check_level{request.params[0].isNull() ? DEFAULT_CHECKLEVEL : request.params[0].getInt<int>()};
    const int check_depth{request.params[1].isNull() ? DEFAULT_CHECKBLOCKS : request.params[1].getInt<int>()};

    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        return VerifyLoadedChildChain(
                   request.context,
                   *chain_id,
                   Now<NodeSeconds>().time_since_epoch().count())
            .verified;
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);

    Chainstate& active_chainstate = chainman.ActiveChainstate();
    return CVerifyDB(chainman.GetNotifications()).VerifyDB(
               active_chainstate, chainman.GetParams().GetConsensus(), active_chainstate.CoinsTip(), check_level, check_depth) == VerifyDBResult::SUCCESS;
},
    };
}

// used by rest.cpp:rest_chaininfo, so cannot be static
RPCHelpMan getblockchaininfo()
{
    return RPCHelpMan{"getblockchaininfo",
        "Returns an object containing various state info regarding blockchain processing.\n"
        "Omit chain_id for the main chain. Child results describe the locally loaded runtime and its isolated P2P synchronization state.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "chain", "current main network name (" LIST_CHAIN_NAMES ") or 'child'"},
                {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
                {RPCResult::Type::STR_HEX, "genesis_hash", /*optional=*/true, "Child genesis descriptor hash; present only for child results"},
                {RPCResult::Type::NUM, "template_id", /*optional=*/true, "Child template identifier"},
                {RPCResult::Type::NUM, "template_version", /*optional=*/true, "Child template version"},
                {RPCResult::Type::STR, "context_state", /*optional=*/true, "Child runtime state: loaded, safe_halt, or failed"},
                {RPCResult::Type::NUM, "blocks", "the height of the most-work fully-validated chain. The genesis block has height 0"},
                {RPCResult::Type::NUM, "headers", "the current number of validated headers; equals blocks for a child runtime without header-only synchronization"},
                {RPCResult::Type::STR, "bestblockhash", "the hash of the currently best block"},
                {RPCResult::Type::STR_HEX, "bits", "nBits: compact representation of the block difficulty target; zero for a BMM child"},
                {RPCResult::Type::STR_HEX, "target", "The difficulty target; zero for a BMM child"},
                {RPCResult::Type::NUM, "difficulty", "the current difficulty; zero for a BMM child"},
                {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::NUM, "verificationprogress", "estimate of verification progress [0..1]; one for all locally accepted child data"},
                {RPCResult::Type::BOOL, "initialblockdownload", "(debug information) estimate of whether this node is in Initial Block Download mode; false for child runtimes"},
                {RPCResult::Type::STR_HEX, "chainwork", "total PoW on main or cumulative active BMM anchor work on a child, in hexadecimal"},
                {RPCResult::Type::NUM, "size_on_disk", /*optional=*/true, "the estimated size of the main-chain block and undo files on disk; currently unavailable for child runtimes"},
                {RPCResult::Type::BOOL, "pruned", "if the blocks are subject to pruning"},
                {RPCResult::Type::NUM, "pruneheight", /*optional=*/true, "the first block unpruned, all previous blocks were pruned (only present if pruning is enabled)"},
                {RPCResult::Type::BOOL, "automatic_pruning", /*optional=*/true, "whether automatic pruning is enabled (only present if pruning is enabled)"},
                {RPCResult::Type::NUM, "prune_target_size", /*optional=*/true, "the target size used by pruning (only present if automatic pruning is enabled)"},
                {RPCResult::Type::STR_HEX, "signet_challenge", /*optional=*/true, "the P2TR block challenge scriptPubKey, in hexadecimal (only present if the current network is a signet)"},
                {RPCResult::Type::BOOL, "safe_halt", /*optional=*/true, "Whether the child runtime is fail-closed after an invalidated imported deposit"},
                {RPCResult::Type::BOOL, "network_sync_available", /*optional=*/true, "Whether child P2P synchronization is implemented"},
                {RPCResult::Type::NUM, "main_height", /*optional=*/true, "Height of the active main-chain tip tracked by the child runtime"},
                {RPCResult::Type::STR_HEX, "main_tip", /*optional=*/true, "Active main-chain tip tracked by the child runtime"},
                {RPCResult::Type::NUM, "bmm_anchor_count", /*optional=*/true, "Canonical child blocks with persisted BMM anchors"},
                {RPCResult::Type::NUM, "pending_bmm_anchor_count", /*optional=*/true, "Authenticated BMM anchors waiting for child block data"},
                {RPCResult::Type::NUM, "pending_bmm_anchor_bytes", /*optional=*/true, "Serialized bytes used by pending BMM anchors"},
                {RPCResult::Type::NUM, "pending_bmm_anchor_limit", /*optional=*/true, "Maximum pending BMM anchor records"},
                {RPCResult::Type::NUM, "pending_bmm_anchor_bytes_limit", /*optional=*/true, "Maximum serialized bytes for pending BMM anchors"},
                {RPCResult::Type::NUM, "side_candidate_count", /*optional=*/true, "Validated non-canonical child candidates retained in the fork DAG"},
                {RPCResult::Type::NUM, "side_candidate_bytes", /*optional=*/true, "Serialized bytes used by retained non-canonical candidates"},
                {RPCResult::Type::NUM, "side_candidate_limit", /*optional=*/true, "Maximum retained non-canonical child candidates"},
                {RPCResult::Type::NUM, "side_candidate_bytes_limit", /*optional=*/true, "Maximum serialized bytes for retained non-canonical candidates"},
                {RPCResult::Type::NUM, "candidate_bmm_anchor_count", /*optional=*/true, "BMM anchors retained for non-canonical candidates"},
                {RPCResult::Type::NUM, "candidate_bmm_anchor_bytes", /*optional=*/true, "Serialized bytes used by non-canonical candidate anchors"},
                {RPCResult::Type::NUM, "candidate_bmm_anchor_limit", /*optional=*/true, "Maximum BMM anchors retained for non-canonical candidates"},
                {RPCResult::Type::NUM, "candidate_bmm_anchor_bytes_limit", /*optional=*/true, "Maximum serialized bytes for non-canonical candidate anchors"},
                {RPCResult::Type::BOOL, "bmm_eligible", /*optional=*/true, "Whether the active child tip is eligible for BMM fork choice"},
                {RPCResult::Type::NUM, "bmm_activation_main_height", /*optional=*/true, "Earliest active main height anchoring the child tip after its parent"},
                {RPCResult::Type::STR_HEX, "bmm_own_work", /*optional=*/true, "Active main-chain work committed directly to the child tip"},
                {RPCResult::Type::STR_HEX, "bmm_cumulative_work", /*optional=*/true, "Cumulative BMM work along the active child branch"},
                {RPCResult::Type::ARR, "warnings", "any network and blockchain warnings",
                    {
                        {RPCResult::Type::STR, "", "warning"},
                    }
                },
            }},
        RPCExamples{
            HelpExampleCli("getblockchaininfo", "")
            + HelpExampleCli("getblockchaininfo", "\"chain_id\"")
            + HelpExampleRpc("getblockchaininfo", "")
            + HelpExampleRpc("getblockchaininfo", "\"chain_id\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        return childBlockchainInfoToJSON(
            GetLoadedChildTipBlockView(request.context, *chain_id));
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();

    const CBlockIndex& tip{*CHECK_NONFATAL(active_chainstate.m_chain.Tip())};
    const int height{tip.nHeight};
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());
    obj.pushKV("blocks", height);
    obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);
    obj.pushKV("bestblockhash", tip.GetBlockHash().GetHex());
    obj.pushKV("bits", strprintf("%08x", tip.nBits));
    obj.pushKV("target", GetTarget(tip, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("difficulty", GetDifficulty(tip));
    obj.pushKV("time", tip.GetBlockTime());
    obj.pushKV("mediantime", tip.GetMedianTimePast());
    obj.pushKV("verificationprogress", chainman.GuessVerificationProgress(&tip));
    obj.pushKV("initialblockdownload", chainman.IsInitialBlockDownload());
    obj.pushKV("chainwork", tip.nChainWork.GetHex());
    obj.pushKV("size_on_disk", chainman.m_blockman.CalculateCurrentUsage());
    obj.pushKV("pruned", chainman.m_blockman.IsPruneMode());
    if (chainman.m_blockman.IsPruneMode()) {
        const auto prune_height{GetPruneHeight(chainman.m_blockman, active_chainstate.m_chain)};
        obj.pushKV("pruneheight", prune_height ? prune_height.value() + 1 : 0);

        const bool automatic_pruning{chainman.m_blockman.GetPruneTarget() != BlockManager::PRUNE_TARGET_MANUAL};
        obj.pushKV("automatic_pruning",  automatic_pruning);
        if (automatic_pruning) {
            obj.pushKV("prune_target_size", chainman.m_blockman.GetPruneTarget());
        }
    }
    if (chainman.GetParams().GetChainType() == ChainType::SIGNET) {
        const std::vector<uint8_t>& signet_challenge =
            chainman.GetParams().GetConsensus().signet_challenge;
        obj.pushKV("signet_challenge", HexStr(signet_challenge));
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    obj.pushKV("warnings", node::GetWarningsForRpc(*CHECK_NONFATAL(node.warnings)));
    return obj;
},
    };
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight
{
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
          return (a->nHeight > b->nHeight);

        return a < b;
    }
};

static RPCHelpMan getchaintips()
{
    return RPCHelpMan{"getchaintips",
                "Return information about all known tips in the block tree,"
                " including the selected chain as well as orphaned branches.\n"
                "Omit chain_id for the main chain. Child results include fully validated BMM candidates retained in the local DAG.\n",
                {
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
                            {RPCResult::Type::NUM, "height", "height of the chain tip"},
                            {RPCResult::Type::STR_HEX, "hash", "block hash of the tip"},
                            {RPCResult::Type::NUM, "branchlen", "zero for main chain, otherwise length of branch connecting the tip to the main chain"},
                            {RPCResult::Type::STR, "status", "status of the chain, \"active\" for the main chain\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the selected active chain, which is certainly valid\n"
            "6.  \"bmm-ineligible\"        Child branch is fully validated but lacks an eligible anchor path on the active main chain"},
                            {RPCResult::Type::BOOL, "bmm_eligible", /*optional=*/true, "Whether this child tip is eligible for BMM fork choice"},
                            {RPCResult::Type::NUM, "bmm_activation_main_height", /*optional=*/true, "Earliest active main height anchoring this child tip after its parent"},
                            {RPCResult::Type::STR_HEX, "bmm_own_work", /*optional=*/true, "Active main-chain work committed directly to this child tip"},
                            {RPCResult::Type::STR_HEX, "bmm_cumulative_work", /*optional=*/true, "Cumulative BMM work along this child branch"},
                        }}}},
                RPCExamples{
                    HelpExampleCli("getchaintips", "")
            + HelpExampleCli("getchaintips", "\"chain_id\"")
            + HelpExampleRpc("getchaintips", "")
            + HelpExampleRpc("getchaintips", "\"chain_id\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        return childChainTipsToJSON(
            GetLoadedChildChainTipsView(request.context, *chain_id));
    }
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();

    /*
     * Idea: The set of chain tips is the active chain tip, plus orphan blocks which do not have another orphan building off of them.
     * Algorithm:
     *  - Make one pass through BlockIndex(), picking out the orphan blocks, and also storing a set of the orphan block's pprev pointers.
     *  - Iterate through the orphan blocks. If the block isn't pointed to by another orphan, it is a chain tip.
     *  - Add the active chain tip
     */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    std::set<const CBlockIndex*> setOrphans;
    std::set<const CBlockIndex*> setPrevs;

    for (const auto& [_, block_index] : chainman.BlockIndex()) {
        if (!active_chain.Contains(&block_index)) {
            setOrphans.insert(&block_index);
            setPrevs.insert(block_index.pprev);
        }
    }

    for (std::set<const CBlockIndex*>::iterator it = setOrphans.begin(); it != setOrphans.end(); ++it) {
        if (setPrevs.erase(*it) == 0) {
            setTips.insert(*it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(active_chain.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block : setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height", block->nHeight);
        obj.pushKV("hash", block->phashBlock->GetHex());

        const int branchLen = block->nHeight - active_chain.FindFork(block)->nHeight;
        obj.pushKV("branchlen", branchLen);

        std::string status;
        if (active_chain.Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_VALID) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (!block->HaveNumChainTxs()) {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.pushKV("status", status);

        res.push_back(std::move(obj));
    }

    return res;
},
    };
}

static RPCHelpMan preciousblock()
{
    return RPCHelpMan{
        "preciousblock",
        "Treats a block as if it were received before others with the same work.\n"
                "\nA later preciousblock call can override the effect of an earlier one.\n"
                "\nThe effects of preciousblock are not retained across restarts.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as precious"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("preciousblock", "\"blockhash\"")
            + HelpExampleRpc("preciousblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));
    CBlockIndex* pblockindex;

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    BlockValidationState state;
    chainman.ActiveChainstate().PreciousBlock(state, pblockindex);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }

    return UniValue::VNULL;
},
    };
}

void InvalidateBlock(ChainstateManager& chainman, const uint256 block_hash) {
    BlockValidationState state;
    CBlockIndex* pblockindex;
    {
        LOCK(chainman.GetMutex());
        pblockindex = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }
    chainman.ActiveChainstate().InvalidateBlock(state, pblockindex);

    if (state.IsValid()) {
        chainman.ActiveChainstate().ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }
}

static RPCHelpMan invalidateblock()
{
    return RPCHelpMan{
        "invalidateblock",
        "Permanently marks a block as invalid, as if it violated a consensus rule.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as invalid"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("invalidateblock", "\"blockhash\"")
            + HelpExampleRpc("invalidateblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    InvalidateBlock(chainman, hash);

    return UniValue::VNULL;
},
    };
}

void ReconsiderBlock(ChainstateManager& chainman, uint256 block_hash) {
    {
        LOCK(chainman.GetMutex());
        CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        chainman.ActiveChainstate().ResetBlockFailureFlags(pblockindex);
        chainman.RecalculateBestHeader();
    }

    BlockValidationState state;
    chainman.ActiveChainstate().ActivateBestChain(state);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }
}

static RPCHelpMan reconsiderblock()
{
    return RPCHelpMan{
        "reconsiderblock",
        "Removes invalidity status of a block, its ancestors and its descendants, reconsider them for activation.\n"
                "This can be used to undo the effects of invalidateblock.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to reconsider"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("reconsiderblock", "\"blockhash\"")
            + HelpExampleRpc("reconsiderblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    ReconsiderBlock(chainman, hash);

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getchaintxstats()
{
    return RPCHelpMan{
        "getchaintxstats",
        "Compute statistics about the total number and rate of transactions in the chain.\n"
        "Omit chain_id for the main chain. Child-chain statistics cover the active local child branch.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{"one month"}, "Size of the window in number of blocks"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "The hash of the block that ends the window."},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM_TIME, "time", "The timestamp for the final block in the window, expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM, "txcount", /*optional=*/true,
                         "The total number of transactions in the chain up to that point, if known. "
                         "It may be unknown when using assumeutxo."},
                        {RPCResult::Type::STR_HEX, "window_final_block_hash", "The hash of the final block in the window"},
                        {RPCResult::Type::NUM, "window_final_block_height", "The height of the final block in the window."},
                        {RPCResult::Type::NUM, "window_block_count", "Size of the window in number of blocks"},
                        {RPCResult::Type::NUM, "window_interval", /*optional=*/true, "The elapsed time in the window in seconds. Only returned if \"window_block_count\" is > 0"},
                        {RPCResult::Type::NUM, "window_tx_count", /*optional=*/true,
                         "The number of transactions in the window. "
                         "Only returned if \"window_block_count\" is > 0 and if txcount exists for the start and end of the window."},
                        {RPCResult::Type::NUM, "txrate", /*optional=*/true,
                         "The average rate of transactions per second in the window. "
                         "Only returned if \"window_interval\" is > 0 and if window_tx_count exists."},
                        {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
                    }},
                RPCExamples{
                    HelpExampleCli("getchaintxstats", "")
            + HelpExampleCli("getchaintxstats", "0 \"blockhash\" \"chain_id\"")
            + HelpExampleRpc("getchaintxstats", "2016")
            + HelpExampleRpc("getchaintxstats", "0, null, \"chain_id\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    int blockcount = 30 * 24 * 60 * 60 / chainman.GetParams().GetConsensus().nPowTargetSpacing; // By default: 1 month

    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        const auto final_view{request.params[1].isNull()
            ? GetLoadedChildTipBlockView(request.context, *chain_id)
            : GetLoadedChildBlockView(
                  request.context,
                  *chain_id,
                  ParseHashV(request.params[1], "blockhash"))};
        if (!final_view.block.active) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Block is not in active child chain");
        }
        if (request.params[0].isNull()) {
            blockcount = std::max(
                0,
                std::min(blockcount, final_view.block.height - 1));
        } else {
            blockcount = request.params[0].getInt<int>();
            if (blockcount < 0 ||
                (blockcount > 0 && blockcount >= final_view.block.height)) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "Invalid block count: should be between 0 and the block's height - 1");
            }
        }

        const auto past_chain_view{GetLoadedChildChainView(
            request.context,
            *chain_id,
            final_view.block.height - blockcount)};
        CHECK_NONFATAL(past_chain_view.block_hash);
        const auto past_view{GetLoadedChildBlockView(
            request.context, *chain_id, *past_chain_view.block_hash)};
        const int64_t time_diff{
            final_view.block.median_time - past_view.block.median_time};

        UniValue result{UniValue::VOBJ};
        result.pushKV("time", final_view.block.time);
        result.pushKV("txcount", final_view.block.chain_tx_count);
        result.pushKV(
            "window_final_block_hash",
            final_view.block.block_hash.GetHex());
        result.pushKV("window_final_block_height", final_view.block.height);
        result.pushKV("window_block_count", blockcount);
        result.pushKV("chain_id", final_view.entry.chain_id.GetHex());
        if (blockcount > 0) {
            result.pushKV("window_interval", time_diff);
            const uint64_t window_tx_count{
                final_view.block.chain_tx_count -
                past_view.block.chain_tx_count};
            result.pushKV("window_tx_count", window_tx_count);
            if (time_diff > 0) {
                result.pushKV(
                    "txrate", double(window_tx_count) / time_diff);
            }
        }
        return result;
    }

    const CBlockIndex* pindex;

    if (request.params[1].isNull()) {
        LOCK(cs_main);
        pindex = chainman.ActiveChain().Tip();
    } else {
        uint256 hash(ParseHashV(request.params[1], "blockhash"));
        LOCK(cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        if (!chainman.ActiveChain().Contains(pindex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
        }
    }

    CHECK_NONFATAL(pindex != nullptr);

    if (request.params[0].isNull()) {
        blockcount = std::max(0, std::min(blockcount, pindex->nHeight - 1));
    } else {
        blockcount = request.params[0].getInt<int>();

        if (blockcount < 0 || (blockcount > 0 && blockcount >= pindex->nHeight)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count: should be between 0 and the block's height - 1");
        }
    }

    const CBlockIndex& past_block{*CHECK_NONFATAL(pindex->GetAncestor(pindex->nHeight - blockcount))};
    const int64_t nTimeDiff{pindex->GetMedianTimePast() - past_block.GetMedianTimePast()};

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("time", pindex->nTime);
    if (pindex->m_chain_tx_count) {
        ret.pushKV("txcount", pindex->m_chain_tx_count);
    }
    ret.pushKV("window_final_block_hash", pindex->GetBlockHash().GetHex());
    ret.pushKV("window_final_block_height", pindex->nHeight);
    ret.pushKV("window_block_count", blockcount);
    if (blockcount > 0) {
        ret.pushKV("window_interval", nTimeDiff);
        if (pindex->m_chain_tx_count != 0 && past_block.m_chain_tx_count != 0) {
            const auto window_tx_count = pindex->m_chain_tx_count - past_block.m_chain_tx_count;
            ret.pushKV("window_tx_count", window_tx_count);
            if (nTimeDiff > 0) {
                ret.pushKV("txrate", double(window_tx_count) / nTimeDiff);
            }
        }
    }

    return ret;
},
    };
}

template<typename T>
static T CalculateTruncatedMedian(std::vector<T>& scores)
{
    size_t size = scores.size();
    if (size == 0) {
        return 0;
    }

    std::sort(scores.begin(), scores.end());
    if (size % 2 == 0) {
        return (scores[size / 2 - 1] + scores[size / 2]) / 2;
    } else {
        return scores[size / 2];
    }
}

void CalculatePercentilesByWeight(CAmount result[NUM_GETBLOCKSTATS_PERCENTILES], std::vector<std::pair<CAmount, int64_t>>& scores, int64_t total_weight)
{
    if (scores.empty()) {
        return;
    }

    std::sort(scores.begin(), scores.end());

    // 10th, 25th, 50th, 75th, and 90th percentile weight units.
    const double weights[NUM_GETBLOCKSTATS_PERCENTILES] = {
        total_weight / 10.0, total_weight / 4.0, total_weight / 2.0, (total_weight * 3.0) / 4.0, (total_weight * 9.0) / 10.0
    };

    int64_t next_percentile_index = 0;
    int64_t cumulative_weight = 0;
    for (const auto& element : scores) {
        cumulative_weight += element.second;
        while (next_percentile_index < NUM_GETBLOCKSTATS_PERCENTILES && cumulative_weight >= weights[next_percentile_index]) {
            result[next_percentile_index] = element.first;
            ++next_percentile_index;
        }
    }

    // Fill any remaining percentiles with the last value.
    for (int64_t i = next_percentile_index; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        result[i] = scores.back().first;
    }
}

template<typename T>
static inline bool SetHasKeys(const std::set<T>& set) {return false;}
template<typename T, typename Tk, typename... Args>
static inline bool SetHasKeys(const std::set<T>& set, const Tk& key, const Args&... args)
{
    return (set.contains(key)) || SetHasKeys(set, args...);
}

// outpoint (needed for the utxo index) + nHeight + fCoinBase
static constexpr size_t PER_UTXO_OVERHEAD = sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool);

static RPCHelpMan getblockstats()
{
    return RPCHelpMan{
        "getblockstats",
        "Compute per block statistics for a given window. All amounts are in satoshis.\n"
                "It won't work for some heights with pruning.\n",
                {
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block hash or height of the target block",
                     RPCArgOptions{
                         .skip_type_check = true,
                         .type_str = {"", "string or numeric"},
                     }},
                    {"stats", RPCArg::Type::ARR, RPCArg::DefaultHint{"all values"}, "Values to plot (see result below)",
                        {
                            {"height", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                            {"time", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                        },
                        RPCArgOptions{.oneline_description="stats"}},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "avgfee", /*optional=*/true, "Average fee in the block"},
                {RPCResult::Type::NUM, "avgfeerate", /*optional=*/true, "Average feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "avgtxsize", /*optional=*/true, "Average transaction size"},
                {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash (to check for potential reorgs)"},
                {RPCResult::Type::ARR_FIXED, "feerate_percentiles", /*optional=*/true, "Feerates at the 10th, 25th, 50th, 75th, and 90th percentile weight unit (in satoshis per virtual byte)",
                {
                    {RPCResult::Type::NUM, "10th_percentile_feerate", "The 10th percentile feerate"},
                    {RPCResult::Type::NUM, "25th_percentile_feerate", "The 25th percentile feerate"},
                    {RPCResult::Type::NUM, "50th_percentile_feerate", "The 50th percentile feerate"},
                    {RPCResult::Type::NUM, "75th_percentile_feerate", "The 75th percentile feerate"},
                    {RPCResult::Type::NUM, "90th_percentile_feerate", "The 90th percentile feerate"},
                }},
                {RPCResult::Type::NUM, "height", /*optional=*/true, "The height of the block"},
                {RPCResult::Type::NUM, "ins", /*optional=*/true, "The number of inputs (excluding coinbase)"},
                {RPCResult::Type::NUM, "maxfee", /*optional=*/true, "Maximum fee in the block"},
                {RPCResult::Type::NUM, "maxfeerate", /*optional=*/true, "Maximum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "maxtxsize", /*optional=*/true, "Maximum transaction size"},
                {RPCResult::Type::NUM, "medianfee", /*optional=*/true, "Truncated median fee in the block"},
                {RPCResult::Type::NUM, "mediantime", /*optional=*/true, "The block median time past"},
                {RPCResult::Type::NUM, "mediantxsize", /*optional=*/true, "Truncated median transaction size"},
                {RPCResult::Type::NUM, "minfee", /*optional=*/true, "Minimum fee in the block"},
                {RPCResult::Type::NUM, "minfeerate", /*optional=*/true, "Minimum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "mintxsize", /*optional=*/true, "Minimum transaction size"},
                {RPCResult::Type::NUM, "outs", /*optional=*/true, "The number of outputs"},
                {RPCResult::Type::NUM, "subsidy", /*optional=*/true, "The block subsidy"},
                {RPCResult::Type::NUM, "swtotal_size", /*optional=*/true, "Total size of all segwit transactions"},
                {RPCResult::Type::NUM, "swtotal_weight", /*optional=*/true, "Total weight of all segwit transactions"},
                {RPCResult::Type::NUM, "swtxs", /*optional=*/true, "The number of segwit transactions"},
                {RPCResult::Type::NUM, "time", /*optional=*/true, "The block time"},
                {RPCResult::Type::NUM, "total_out", /*optional=*/true, "Total amount in all outputs (excluding coinbase and thus reward [ie subsidy + totalfee])"},
                {RPCResult::Type::NUM, "total_size", /*optional=*/true, "Total size of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "total_weight", /*optional=*/true, "Total weight of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "totalfee", /*optional=*/true, "The fee total"},
                {RPCResult::Type::NUM, "txs", /*optional=*/true, "The number of transactions (including coinbase)"},
                {RPCResult::Type::NUM, "utxo_increase", /*optional=*/true, "The increase/decrease in the number of unspent outputs (not discounting op_return and similar)"},
                {RPCResult::Type::NUM, "utxo_size_inc", /*optional=*/true, "The increase/decrease in size for the utxo index (not discounting op_return and similar)"},
                {RPCResult::Type::NUM, "utxo_increase_actual", /*optional=*/true, "The increase/decrease in the number of unspent outputs, not counting unspendables"},
                {RPCResult::Type::NUM, "utxo_size_inc_actual", /*optional=*/true, "The increase/decrease in size for the utxo index, not counting unspendables"},
                {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Child-chain identifier; present only for child results"},
            }},
                RPCExamples{
                    HelpExampleCli("getblockstats", R"('"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"' '["minfeerate","avgfeerate"]')") +
                    HelpExampleCli("getblockstats", R"(1000 '["minfeerate","avgfeerate"]')") +
                    HelpExampleRpc("getblockstats", R"("00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09", ["minfeerate","avgfeerate"])") +
                    HelpExampleRpc("getblockstats", R"(1000, ["minfeerate","avgfeerate"])") +
                    HelpExampleCli("getblockstats", R"('"childblockhash"' '[]' '"chain_id"')")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::set<std::string> stats;
    if (!request.params[1].isNull()) {
        const UniValue stats_univalue = request.params[1].get_array();
        for (unsigned int i = 0; i < stats_univalue.size(); i++) {
            const std::string stat = stats_univalue[i].get_str();
            stats.insert(stat);
        }
    }

    CBlock block;
    CBlockUndo blockUndo;
    uint256 block_hash;
    int block_height{0};
    int64_t block_time{0};
    int64_t median_time{0};
    CAmount subsidy{0};
    std::optional<chainregistry::ChainId> child_chain_id;
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        child_chain_id = ParseChainId(*chain_id);
        uint256 requested_hash;
        if (request.params[0].isNum()) {
            const auto chain_view{GetLoadedChildChainView(
                request.context, *chain_id, request.params[0].getInt<int>())};
            CHECK_NONFATAL(chain_view.block_hash);
            requested_hash = *chain_view.block_hash;
        } else {
            requested_hash = ParseHashV(request.params[0], "hash_or_height");
        }
        const auto view{GetLoadedChildBlockView(
            request.context, *chain_id, requested_hash)};
        if (view.block.virtual_genesis || !view.block.block || !view.block.undo) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "Block statistics are unavailable for the virtual child genesis");
        }
        block = *view.block.block;
        blockUndo = view.block.undo->coins;
        block_hash = view.block.block_hash;
        block_height = view.block.height;
        block_time = view.block.time;
        median_time = view.block.median_time;
    } else {
        ChainstateManager& chainman{EnsureAnyChainman(request.context)};
        const CBlockIndex& pindex{
            *CHECK_NONFATAL(ParseHashOrHeight(request.params[0], chainman))};
        block = GetBlockChecked(chainman.m_blockman, pindex);
        blockUndo = GetUndoChecked(chainman.m_blockman, pindex);
        block_hash = pindex.GetBlockHash();
        block_height = pindex.nHeight;
        block_time = pindex.GetBlockTime();
        median_time = pindex.GetMedianTimePast();
        subsidy = GetBlockSubsidy(
            pindex.nHeight, chainman.GetParams().GetConsensus());
    }

    const bool do_all = stats.size() == 0; // Calculate everything if nothing selected (default)
    const bool do_mediantxsize = do_all || stats.contains("mediantxsize");
    const bool do_medianfee = do_all || stats.contains("medianfee");
    const bool do_feerate_percentiles = do_all || stats.contains("feerate_percentiles");
    const bool loop_inputs = do_all || do_medianfee || do_feerate_percentiles ||
        SetHasKeys(stats, "utxo_increase", "utxo_increase_actual", "utxo_size_inc", "utxo_size_inc_actual", "totalfee", "avgfee", "avgfeerate", "minfee", "maxfee", "minfeerate", "maxfeerate");
    const bool loop_outputs = do_all || loop_inputs || stats.contains("total_out");
    const bool do_calculate_size = do_mediantxsize ||
        SetHasKeys(stats, "total_size", "avgtxsize", "mintxsize", "maxtxsize", "swtotal_size");
    const bool do_calculate_weight = do_all || SetHasKeys(stats, "total_weight", "avgfeerate", "swtotal_weight", "avgfeerate", "feerate_percentiles", "minfeerate", "maxfeerate");
    const bool do_calculate_sw = do_all || SetHasKeys(stats, "swtxs", "swtotal_size", "swtotal_weight");

    CAmount maxfee = 0;
    CAmount maxfeerate = 0;
    CAmount minfee = MAX_MONEY;
    CAmount minfeerate = MAX_MONEY;
    CAmount total_out = 0;
    CAmount totalfee = 0;
    int64_t inputs = 0;
    int64_t maxtxsize = 0;
    int64_t mintxsize = MAX_BLOCK_SERIALIZED_SIZE;
    int64_t outputs = 0;
    int64_t swtotal_size = 0;
    int64_t swtotal_weight = 0;
    int64_t swtxs = 0;
    int64_t total_size = 0;
    int64_t total_weight = 0;
    int64_t utxos = 0;
    int64_t utxo_size_inc = 0;
    int64_t utxo_size_inc_actual = 0;
    std::vector<CAmount> fee_array;
    std::vector<std::pair<CAmount, int64_t>> feerate_array;
    std::vector<int64_t> txsize_array;

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx.at(i);
        outputs += tx->vout.size();

        CAmount tx_total_out = 0;
        if (loop_outputs) {
            for (const CTxOut& out : tx->vout) {
                tx_total_out += out.nValue;

                uint64_t out_size{GetSerializeSize(out) + PER_UTXO_OVERHEAD};
                utxo_size_inc += out_size;

                // The genesis block does not change the UTXO set counts.
                if (block_height == 0) continue;
                // Skip unspendable outputs since they are not included in the UTXO set
                if (out.scriptPubKey.IsUnspendable()) continue;

                ++utxos;
                utxo_size_inc_actual += out_size;
            }
        }

        if (tx->IsCoinBase()) {
            continue;
        }

        inputs += tx->vin.size(); // Don't count coinbase's fake input
        total_out += tx_total_out; // Don't count coinbase reward

        int64_t tx_size = 0;
        if (do_calculate_size) {

            tx_size = tx->ComputeTotalSize();
            if (do_mediantxsize) {
                txsize_array.push_back(tx_size);
            }
            maxtxsize = std::max(maxtxsize, tx_size);
            mintxsize = std::min(mintxsize, tx_size);
            total_size += tx_size;
        }

        int64_t weight = 0;
        if (do_calculate_weight) {
            weight = GetTransactionWeight(*tx);
            total_weight += weight;
        }

        if (do_calculate_sw && tx->HasWitness()) {
            ++swtxs;
            swtotal_size += tx_size;
            swtotal_weight += weight;
        }

        if (loop_inputs) {
            CAmount tx_total_in{child_chain_id &&
                    chainregistry::IsReferenceChildImport(*tx)
                ? tx_total_out
                : 0};
            const auto& txundo = blockUndo.vtxundo.at(i - 1);
            for (const Coin& coin: txundo.vprevout) {
                const CTxOut& prevoutput = coin.out;

                tx_total_in += prevoutput.nValue;
                uint64_t prevout_size{GetSerializeSize(prevoutput) + PER_UTXO_OVERHEAD};
                utxo_size_inc -= prevout_size;
                utxo_size_inc_actual -= prevout_size;
            }

            CAmount txfee = tx_total_in - tx_total_out;
            CHECK_NONFATAL(MoneyRange(txfee));
            if (do_medianfee) {
                fee_array.push_back(txfee);
            }
            maxfee = std::max(maxfee, txfee);
            minfee = std::min(minfee, txfee);
            totalfee += txfee;

            // New feerate uses satoshis per virtual byte instead of per serialized byte
            CAmount feerate = weight ? (txfee * WITNESS_SCALE_FACTOR) / weight : 0;
            if (do_feerate_percentiles) {
                feerate_array.emplace_back(feerate, weight);
            }
            maxfeerate = std::max(maxfeerate, feerate);
            minfeerate = std::min(minfeerate, feerate);
        }
    }

    CAmount feerate_percentiles[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    CalculatePercentilesByWeight(feerate_percentiles, feerate_array, total_weight);

    UniValue feerates_res(UniValue::VARR);
    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        feerates_res.push_back(feerate_percentiles[i]);
    }

    UniValue ret_all(UniValue::VOBJ);
    ret_all.pushKV("avgfee", (block.vtx.size() > 1) ? totalfee / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("avgfeerate", total_weight ? (totalfee * WITNESS_SCALE_FACTOR) / total_weight : 0); // Unit: sat/vbyte
    ret_all.pushKV("avgtxsize", (block.vtx.size() > 1) ? total_size / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("blockhash", block_hash.GetHex());
    ret_all.pushKV("feerate_percentiles", std::move(feerates_res));
    ret_all.pushKV("height", block_height);
    ret_all.pushKV("ins", inputs);
    ret_all.pushKV("maxfee", maxfee);
    ret_all.pushKV("maxfeerate", maxfeerate);
    ret_all.pushKV("maxtxsize", maxtxsize);
    ret_all.pushKV("medianfee", CalculateTruncatedMedian(fee_array));
    ret_all.pushKV("mediantime", median_time);
    ret_all.pushKV("mediantxsize", CalculateTruncatedMedian(txsize_array));
    ret_all.pushKV("minfee", (minfee == MAX_MONEY) ? 0 : minfee);
    ret_all.pushKV("minfeerate", (minfeerate == MAX_MONEY) ? 0 : minfeerate);
    ret_all.pushKV("mintxsize", mintxsize == MAX_BLOCK_SERIALIZED_SIZE ? 0 : mintxsize);
    ret_all.pushKV("outs", outputs);
    ret_all.pushKV("subsidy", subsidy);
    ret_all.pushKV("swtotal_size", swtotal_size);
    ret_all.pushKV("swtotal_weight", swtotal_weight);
    ret_all.pushKV("swtxs", swtxs);
    ret_all.pushKV("time", block_time);
    ret_all.pushKV("total_out", total_out);
    ret_all.pushKV("total_size", total_size);
    ret_all.pushKV("total_weight", total_weight);
    ret_all.pushKV("totalfee", totalfee);
    ret_all.pushKV("txs", block.vtx.size());
    ret_all.pushKV("utxo_increase", outputs - inputs);
    ret_all.pushKV("utxo_size_inc", utxo_size_inc);
    ret_all.pushKV("utxo_increase_actual", utxos - inputs);
    ret_all.pushKV("utxo_size_inc_actual", utxo_size_inc_actual);
    if (child_chain_id) {
        ret_all.pushKV("chain_id", child_chain_id->GetHex());
    }

    if (do_all) {
        return ret_all;
    }

    UniValue ret(UniValue::VOBJ);
    for (const std::string& stat : stats) {
        const UniValue& value = ret_all[stat];
        if (value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid selected statistic '%s'", stat));
        }
        ret.pushKV(stat, value);
    }
    if (child_chain_id) {
        ret.pushKV("chain_id", child_chain_id->GetHex());
    }
    return ret;
},
    };
}

namespace {
//! Search for a given set of pubkey scripts
bool FindScriptPubKey(std::atomic<int>& scan_progress, const std::atomic<bool>& should_abort, int64_t& count, CCoinsViewCursor* cursor, const std::set<CScript>& needles, std::map<COutPoint, Coin>& out_results, std::function<void()>& interruption_point)
{
    scan_progress = 0;
    count = 0;
    while (cursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (!cursor->GetKey(key) || !cursor->GetValue(coin)) return false;
        if (++count % 8192 == 0) {
            interruption_point();
            if (should_abort) {
                // allow to abort the scan via the abort reference
                return false;
            }
        }
        if (count % 256 == 0) {
            // update progress reference every 256 item
            uint32_t high = 0x100 * *UCharCast(key.hash.begin()) + *(UCharCast(key.hash.begin()) + 1);
            scan_progress = (int)(high * 100.0 / 65536.0 + 0.5);
        }
        if (needles.contains(coin.out.scriptPubKey)) {
            out_results.emplace(key, coin);
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}
} // namespace

/** RAII object to prevent concurrency issue when scanning the txout set */
static std::atomic<int> g_scan_progress;
static std::atomic<bool> g_should_abort_scan;
static GlobalMutex g_scan_mutex;
static bool g_scan_in_progress GUARDED_BY(g_scan_mutex){false};
static std::optional<chainregistry::ChainId> g_scan_child_chain
    GUARDED_BY(g_scan_mutex);

static bool ScanInProgressFor(
    const std::optional<chainregistry::ChainId>& child_chain)
{
    LOCK(g_scan_mutex);
    return g_scan_in_progress && g_scan_child_chain == child_chain;
}

static bool AbortScanFor(
    const std::optional<chainregistry::ChainId>& child_chain)
{
    LOCK(g_scan_mutex);
    if (!g_scan_in_progress || g_scan_child_chain != child_chain) return false;
    g_should_abort_scan = true;
    return true;
}

class CoinsViewScanReserver
{
private:
    const std::optional<chainregistry::ChainId> m_child_chain;
    bool m_could_reserve{false};
public:
    explicit CoinsViewScanReserver(
        std::optional<chainregistry::ChainId> child_chain)
        : m_child_chain{std::move(child_chain)}
    {
    }

    bool reserve() {
        LOCK(g_scan_mutex);
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scan_in_progress) return false;
        CHECK_NONFATAL(g_scan_progress == 0);
        g_scan_in_progress = true;
        g_scan_child_chain = m_child_chain;
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver() {
        if (m_could_reserve) {
            LOCK(g_scan_mutex);
            g_scan_in_progress = false;
            g_scan_child_chain.reset();
            g_scan_progress = 0;
        }
    }
};

static const auto scan_action_arg_desc = RPCArg{
    "action", RPCArg::Type::STR, RPCArg::Optional::NO, "The action to execute\n"
        "\"start\" for starting a scan\n"
        "\"abort\" for aborting the current scan (returns true when abort was successful)\n"
        "\"status\" for progress report (in %) of the current scan"
};

static const auto output_descriptor_obj = RPCArg{
    "", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with output descriptor and metadata",
    {
        {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
        {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "The range of HD chain indexes to explore (either end or [begin,end])"},
    }
};

static const auto scan_objects_arg_desc = RPCArg{
    "scanobjects", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of scan objects. Required for \"start\" action\n"
        "Every scan object is either a string descriptor or an object:",
    {
        {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
        output_descriptor_obj,
    },
    RPCArgOptions{.oneline_description="[scanobjects,...]"},
};

static const auto scan_result_abort = RPCResult{
    "when action=='abort'", RPCResult::Type::BOOL, "success",
    "True if scan will be aborted (not necessarily before this RPC returns), or false if there is no scan to abort"
};
static const auto scan_result_status_none = RPCResult{
    "when action=='status' and no scan is in progress - possibly already completed", RPCResult::Type::NONE, "", ""
};
static const auto scan_result_status_some = RPCResult{
    "when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "",
    {
        {RPCResult::Type::NUM, "progress", "Approximate percent complete"},
        {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for the main chain"},
    }
};


static RPCHelpMan scantxoutset()
{
    const std::string EXAMPLE_DESCRIPTOR_RAW = "raw(512050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)";

    return RPCHelpMan{
        "scantxoutset",
        "Scans the unspent transaction output set for entries that match certain output descriptors.\n"
        "Examples of output descriptors are:\n"
        "    addr(<address>)                     Taproot or pay-to-anchor output for the specified address\n"
        "    raw(<hex script>)                   Native output script or OP_RETURN data output\n"
        "    tr(<pubkey>)                        P2TR\n"
        "    tr(<pubkey>,{pk(<pubkey>)})         P2TR with single fallback pubkey in tapscript\n"
        "    rawtr(<pubkey>)                     P2TR with the specified key as output key rather than inner\n"
        "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
        "or more path elements separated by \"/\", and optionally ending in \"/*\" (unhardened), or \"/*'\" or \"/*h\" (hardened) to specify all\n"
        "unhardened or hardened child keys.\n"
        "In the latter case, a range needs to be specified by below if different from 1000.\n"
        "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n"
        "Omit chain_id to scan the main chain, or provide a loaded child-chain identifier\n"
        "to scan that child's isolated UTXO set. Scan status and abort are chain-scoped.\n",
        {
            scan_action_arg_desc,
            scan_objects_arg_desc,
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
        },
        {
            RPCResult{"when action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::BOOL, "success", "Whether the scan was completed"},
                {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs scanned"},
                {RPCResult::Type::NUM, "height", "The block height at which the scan was done"},
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for the main chain"},
                {RPCResult::Type::ARR, "unspents", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                        {RPCResult::Type::NUM, "vout", "The vout value"},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The output script"},
                        {RPCResult::Type::STR, "desc", "A specialized descriptor for the matched output script"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the unspent output"},
                        {RPCResult::Type::BOOL, "coinbase", "Whether this is a coinbase output"},
                        {RPCResult::Type::NUM, "height", "Height of the unspent transaction output"},
                        {RPCResult::Type::STR_HEX, "blockhash", "Blockhash of the unspent transaction output"},
                        {RPCResult::Type::NUM, "confirmations", "Number of confirmations of the unspent transaction output when the scan was done"},
                    }},
                }},
                {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of all found unspent outputs in " + CURRENCY_UNIT},
            }},
            scan_result_abort,
            scan_result_status_some,
            scan_result_status_none,
        },
        RPCExamples{
            HelpExampleCli("scantxoutset", "start \'[\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]\'") +
            HelpExampleCli("scantxoutset", "start \'[\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]\' chain_id") +
            HelpExampleCli("scantxoutset", "status") +
            HelpExampleCli("scantxoutset", "abort") +
            HelpExampleRpc("scantxoutset", "\"start\", [\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]") +
            HelpExampleRpc("scantxoutset", "\"status\"") +
            HelpExampleRpc("scantxoutset", "\"abort\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VOBJ);
    const auto action{self.Arg<std::string_view>("action")};
    std::optional<chainregistry::ChainId> child_chain;
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        child_chain = ParseChainId(*chain_id);
    }
    if (action == "status") {
        if (!ScanInProgressFor(child_chain)) return UniValue::VNULL;
        result.pushKV("progress", g_scan_progress.load());
        if (child_chain) result.pushKV("chain_id", child_chain->GetHex());
        return result;
    } else if (action == "abort") {
        return AbortScanFor(child_chain);
    } else if (action == "start") {
        CoinsViewScanReserver reserver{child_chain};
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }

        if (request.params[1].isNull()) {
            throw JSONRPCError(RPC_MISC_ERROR, "scanobjects argument is required for the start action");
        }

        std::set<CScript> needles;
        std::map<CScript, std::string> descriptors;
        CAmount total_in = 0;

        // loop through the scan objects
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            auto scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (CScript& script : scripts) {
                auto descriptor{InferDescriptor(script, provider)};
                if (!descriptor) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor produced a non-native output script");
                }
                needles.emplace(script);
                descriptors.emplace(std::move(script), descriptor->ToString());
            }
        }

        // Scan the unspent transaction output set for inputs
        UniValue unspents(UniValue::VARR);
        std::map<COutPoint, Coin> coins;
        std::map<int, uint256> block_hashes;
        g_should_abort_scan = false;
        int64_t count = 0;
        int tip_height{0};
        uint256 tip_hash;
        bool scan_completed{false};
        NodeContext& node = EnsureAnyNodeContext(request.context);
        if (child_chain) {
            auto child_scan{ScanLoadedChildUTXOSet(
                request.context,
                *child_chain,
                needles,
                g_scan_progress,
                g_should_abort_scan,
                node.rpc_interruption_point)};
            scan_completed = child_scan.completed;
            count = child_scan.scanned;
            tip_height = child_scan.entry.height;
            tip_hash = child_scan.entry.tip;
            coins = std::move(child_scan.matches);
            block_hashes = std::move(child_scan.block_hashes);
        } else {
            std::unique_ptr<CCoinsViewCursor> pcursor;
            const CBlockIndex* tip;
            ChainstateManager& chainman = EnsureChainman(node);
            {
                LOCK(cs_main);
                Chainstate& active_chainstate = chainman.ActiveChainstate();
                active_chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);
                pcursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
                tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
            }
            scan_completed = FindScriptPubKey(
                g_scan_progress,
                g_should_abort_scan,
                count,
                pcursor.get(),
                needles,
                coins,
                node.rpc_interruption_point);
            tip_height = tip->nHeight;
            tip_hash = tip->GetBlockHash();
            for (const auto& [_, coin] : coins) {
                const CBlockIndex* coin_block{tip->GetAncestor(coin.nHeight)};
                if (!coin_block) {
                    throw JSONRPCError(
                        RPC_INTERNAL_ERROR,
                        "UTXO scan returned a coin outside the selected chain");
                }
                block_hashes.emplace(
                    coin.nHeight, coin_block->GetBlockHash());
            }
        }
        result.pushKV("success", scan_completed);
        result.pushKV("txouts", count);
        result.pushKV("height", tip_height);
        result.pushKV("bestblock", tip_hash.GetHex());
        if (child_chain) result.pushKV("chain_id", child_chain->GetHex());

        for (const auto& it : coins) {
            const COutPoint& outpoint = it.first;
            const Coin& coin = it.second;
            const CTxOut& txo = coin.out;
            total_in += txo.nValue;

            UniValue unspent(UniValue::VOBJ);
            unspent.pushKV("txid", outpoint.hash.GetHex());
            unspent.pushKV("vout", outpoint.n);
            unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey));
            unspent.pushKV("desc", descriptors[txo.scriptPubKey]);
            unspent.pushKV("amount", ValueFromAmount(txo.nValue));
            unspent.pushKV("coinbase", coin.IsCoinBase());
            unspent.pushKV("height", coin.nHeight);
            unspent.pushKV("blockhash", block_hashes.at(coin.nHeight).GetHex());
            unspent.pushKV("confirmations", tip_height - coin.nHeight + 1);

            unspents.push_back(std::move(unspent));
        }
        result.pushKV("unspents", std::move(unspents));
        result.pushKV("total_amount", ValueFromAmount(total_in));
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", action));
    }
    return result;
},
    };
}

/** RAII object to prevent concurrency issue when scanning blockfilters */
static std::atomic<int> g_scanfilter_progress;
static std::atomic<int> g_scanfilter_progress_height;
static std::atomic<bool> g_scanfilter_should_abort_scan;
static GlobalMutex g_scanfilter_mutex;
static bool g_scanfilter_in_progress GUARDED_BY(g_scanfilter_mutex){false};
static std::optional<chainregistry::ChainId> g_scanfilter_child_chain
    GUARDED_BY(g_scanfilter_mutex);

static bool BlockFilterScanInProgressFor(
    const std::optional<chainregistry::ChainId>& child_chain)
{
    LOCK(g_scanfilter_mutex);
    return g_scanfilter_in_progress &&
           g_scanfilter_child_chain == child_chain;
}

static bool AbortBlockFilterScanFor(
    const std::optional<chainregistry::ChainId>& child_chain)
{
    LOCK(g_scanfilter_mutex);
    if (!g_scanfilter_in_progress ||
        g_scanfilter_child_chain != child_chain) {
        return false;
    }
    g_scanfilter_should_abort_scan = true;
    return true;
}

class BlockFiltersScanReserver
{
private:
    const std::optional<chainregistry::ChainId> m_child_chain;
    bool m_could_reserve{false};
public:
    explicit BlockFiltersScanReserver(
        std::optional<chainregistry::ChainId> child_chain)
        : m_child_chain{std::move(child_chain)}
    {
    }

    bool reserve() {
        LOCK(g_scanfilter_mutex);
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scanfilter_in_progress) return false;
        g_scanfilter_in_progress = true;
        g_scanfilter_child_chain = m_child_chain;
        m_could_reserve = true;
        return true;
    }

    ~BlockFiltersScanReserver() {
        if (m_could_reserve) {
            LOCK(g_scanfilter_mutex);
            g_scanfilter_in_progress = false;
            g_scanfilter_child_chain.reset();
            g_scanfilter_progress = 0;
            g_scanfilter_progress_height = 0;
        }
    }
};

static bool CheckBlockFilterMatches(BlockManager& blockman, const CBlockIndex& blockindex, const GCSFilter::ElementSet& needles)
{
    const CBlock block{GetBlockChecked(blockman, blockindex)};
    const CBlockUndo block_undo{GetUndoChecked(blockman, blockindex)};

    // Check if any of the outputs match the scriptPubKey
    for (const auto& tx : block.vtx) {
        if (std::any_of(tx->vout.cbegin(), tx->vout.cend(), [&](const auto& txout) {
                return needles.contains(std::vector<unsigned char>(txout.scriptPubKey.begin(), txout.scriptPubKey.end()));
            })) {
            return true;
        }
    }
    // Check if any of the inputs match the scriptPubKey
    for (const auto& txundo : block_undo.vtxundo) {
        if (std::any_of(txundo.vprevout.cbegin(), txundo.vprevout.cend(), [&](const auto& coin) {
                return needles.contains(std::vector<unsigned char>(coin.out.scriptPubKey.begin(), coin.out.scriptPubKey.end()));
            })) {
            return true;
        }
    }

    return false;
}

static RPCHelpMan scanblocks()
{
    return RPCHelpMan{
        "scanblocks",
        "Return relevant blockhashes for given descriptors (the main chain requires blockfilterindex).\n"
        "This call may take several minutes. Make sure to use no RPC timeout (kronein-cli -rpcclienttimeout=0).\n"
        "Omit chain_id for the main chain, or provide a loaded child-chain identifier to scan its persisted basic filters.\n"
        "Scan status and abort are chain-scoped.",
        {
            scan_action_arg_desc,
            scan_objects_arg_desc,
            RPCArg{"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Height to start to scan from"},
            RPCArg{"stop_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"chain tip"}, "Height to stop to scan"},
            RPCArg{"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
            RPCArg{"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"filter_false_positives", RPCArg::Type::BOOL, RPCArg::Default{false}, "Filter false positives (slower and may fail on pruned nodes). Otherwise they may occur at a rate of 1/M"},
                },
                RPCArgOptions{.oneline_description="options"}},
            RPCArg{"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
        },
        {
            scan_result_status_none,
            RPCResult{"When action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "from_height", "The height we started the scan from"},
                {RPCResult::Type::NUM, "to_height", "The height we ended the scan at"},
                {RPCResult::Type::ARR, "relevant_blocks", "Blocks that may have matched a scanobject.", {
                    {RPCResult::Type::STR_HEX, "blockhash", "A relevant blockhash"},
                }},
                {RPCResult::Type::BOOL, "completed", "true if the scan process was not aborted"},
                {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for the main chain"},
            }},
            RPCResult{"when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "progress", "Approximate percent complete"},
                    {RPCResult::Type::NUM, "current_height", "Height of the block currently being scanned"},
                    {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for the main chain"},
                },
            },
            scan_result_abort,
        },
        RPCExamples{
            HelpExampleCli("scanblocks", "start '[\"addr(rkne1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqql5kcyk)\"]' 300000") +
            HelpExampleCli("scanblocks", "start '[\"addr(rkne1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqql5kcyk)\"]' 100 150 basic") +
            HelpExampleCli("scanblocks", "status") +
            HelpExampleRpc("scanblocks", "\"start\", [\"addr(rkne1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqql5kcyk)\"], 300000") +
            HelpExampleRpc("scanblocks", "\"start\", [\"addr(rkne1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqql5kcyk)\"], 100, 150, \"basic\"") +
            HelpExampleRpc("scanblocks", "\"status\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);
    auto action{self.Arg<std::string_view>("action")};
    std::optional<chainregistry::ChainId> child_chain;
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        child_chain = ParseChainId(*chain_id);
    }
    if (action == "status") {
        if (!BlockFilterScanInProgressFor(child_chain)) return NullUniValue;
        ret.pushKV("progress", g_scanfilter_progress.load());
        ret.pushKV("current_height", g_scanfilter_progress_height.load());
        if (child_chain) ret.pushKV("chain_id", child_chain->GetHex());
        return ret;
    } else if (action == "abort") {
        return AbortBlockFilterScanFor(child_chain);
    } else if (action == "start") {
        BlockFiltersScanReserver reserver{child_chain};
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }
        auto filtertype_name{self.Arg<std::string_view>("filtertype")};

        BlockFilterType filtertype;
        if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
        }

        UniValue options{request.params[5].isNull() ? UniValue::VOBJ : request.params[5]};
        bool filter_false_positives{options.exists("filter_false_positives") ? options["filter_false_positives"].get_bool() : false};

        BlockFilterIndex* index{nullptr};
        if (child_chain && filtertype != BlockFilterType::BASIC) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               "Unknown child filtertype");
        }
        if (!child_chain) index = GetBlockFilterIndex(filtertype);
        if (!child_chain && !index) {
            throw JSONRPCError(RPC_MISC_ERROR, tfm::format("Index is not enabled for filtertype %s", filtertype_name));
        }

        NodeContext& node = EnsureAnyNodeContext(request.context);
        ChainstateManager& chainman = EnsureChainman(node);

        // set the start-height
        const CBlockIndex* start_index = nullptr;
        const CBlockIndex* stop_block = nullptr;
        if (!child_chain) {
            LOCK(cs_main);
            CChain& active_chain = chainman.ActiveChain();
            start_index = active_chain.Genesis();
            stop_block = active_chain.Tip(); // If no stop block is provided, stop at the chain tip.
            if (!request.params[2].isNull()) {
                start_index = active_chain[request.params[2].getInt<int>()];
                if (!start_index) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid start_height");
                }
            }
            if (!request.params[3].isNull()) {
                stop_block = active_chain[request.params[3].getInt<int>()];
                if (!stop_block || stop_block->nHeight < start_index->nHeight) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid stop_height");
                }
            }
        }

        // loop through the scan objects, add scripts to the needle_set
        GCSFilter::ElementSet needle_set;
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            std::vector<CScript> scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (const CScript& script : scripts) {
                needle_set.emplace(script.begin(), script.end());
            }
        }

        if (child_chain) {
            const int start_height{request.params[2].isNull()
                    ? 0
                    : request.params[2].getInt<int>()};
            const std::optional<int> stop_height{request.params[3].isNull()
                    ? std::nullopt
                    : std::optional<int>{request.params[3].getInt<int>()}};
            g_scanfilter_should_abort_scan = false;
            g_scanfilter_progress = 0;
            g_scanfilter_progress_height = start_height;
            const auto scan{EnsureAnyChildChainman(request.context)
                .ScanBlockFilters(
                    *child_chain,
                    start_height,
                    stop_height,
                    needle_set,
                    filter_false_positives,
                    g_scanfilter_progress,
                    g_scanfilter_progress_height,
                    g_scanfilter_should_abort_scan,
                    [&node] { node.rpc_interruption_point(); })};
            switch (scan.error) {
            case node::ChainManagerBlockFilterScanError::NONE:
                break;
            case node::ChainManagerBlockFilterScanError::NULL_CHAIN_ID:
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "chain_id must not be null");
            case node::ChainManagerBlockFilterScanError::UNKNOWN_CHAIN:
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "child chain is not configured locally");
            case node::ChainManagerBlockFilterScanError::CHAIN_NOT_LOADED:
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "child chain is not loaded");
            case node::ChainManagerBlockFilterScanError::HEIGHT_OUT_OF_RANGE:
                throw JSONRPCError(
                    RPC_MISC_ERROR,
                    "Invalid start_height or stop_height");
            case node::ChainManagerBlockFilterScanError::DATA_UNAVAILABLE:
                throw JSONRPCError(
                    RPC_INTERNAL_ERROR,
                    "Child block filter data is unavailable");
            }
            UniValue blocks{UniValue::VARR};
            for (const uint256& hash : scan.scan.relevant_blocks) {
                blocks.push_back(hash.GetHex());
            }
            ret.pushKV("from_height", start_height);
            ret.pushKV("to_height", scan.scan.last_scanned_height);
            ret.pushKV("relevant_blocks", std::move(blocks));
            ret.pushKV("completed", scan.scan.completed);
            ret.pushKV("chain_id", child_chain->GetHex());
            return ret;
        }

        CHECK_NONFATAL(index);
        CHECK_NONFATAL(start_index);
        CHECK_NONFATAL(stop_block);
        UniValue blocks(UniValue::VARR);
        const int amount_per_chunk = 10000;
        std::vector<BlockFilter> filters;
        int start_block_height = start_index->nHeight; // for progress reporting
        const int total_blocks_to_process = stop_block->nHeight - start_block_height;

        g_scanfilter_should_abort_scan = false;
        g_scanfilter_progress = 0;
        g_scanfilter_progress_height = start_block_height;
        bool completed = true;

        const CBlockIndex* end_range = nullptr;
        do {
            node.rpc_interruption_point(); // allow a clean shutdown
            if (g_scanfilter_should_abort_scan) {
                completed = false;
                break;
            }

            // split the lookup range in chunks if we are deeper than 'amount_per_chunk' blocks from the stopping block
            int start_block = !end_range ? start_index->nHeight : start_index->nHeight + 1; // to not include the previous round 'end_range' block
            end_range = (start_block + amount_per_chunk < stop_block->nHeight) ?
                    WITH_LOCK(::cs_main, return chainman.ActiveChain()[start_block + amount_per_chunk]) :
                    stop_block;

            if (index->LookupFilterRange(start_block, end_range, filters)) {
                for (const BlockFilter& filter : filters) {
                    // compare the elements-set with each filter
                    if (filter.GetFilter().MatchAny(needle_set)) {
                        if (filter_false_positives) {
                            // Double check the filter matches by scanning the block
                            const CBlockIndex& blockindex = *CHECK_NONFATAL(WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(filter.GetBlockHash())));

                            if (!CheckBlockFilterMatches(chainman.m_blockman, blockindex, needle_set)) {
                                continue;
                            }
                        }

                        blocks.push_back(filter.GetBlockHash().GetHex());
                    }
                }
            }
            start_index = end_range;

            // update progress
            int blocks_processed = end_range->nHeight - start_block_height;
            if (total_blocks_to_process > 0) { // avoid division by zero
                g_scanfilter_progress = (int)(100.0 / total_blocks_to_process * blocks_processed);
            } else {
                g_scanfilter_progress = 100;
            }
            g_scanfilter_progress_height = end_range->nHeight;

        // Finish if we reached the stop block
        } while (start_index != stop_block);

        ret.pushKV("from_height", start_block_height);
        ret.pushKV("to_height", start_index->nHeight); // start_index is always the last scanned block here
        ret.pushKV("relevant_blocks", std::move(blocks));
        ret.pushKV("completed", completed);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, tfm::format("Invalid action '%s'", action));
    }
    return ret;
},
    };
}

static RPCHelpMan getdescriptoractivity()
{
    return RPCHelpMan{
        "getdescriptoractivity",
        "Get spend and receive activity associated with a set of descriptors for a set of blocks. "
        "This command pairs well with the `relevant_blocks` output of `scanblocks()`.\n"
        "Omit chain_id for the main chain. When include_mempool is true, unconfirmed activity is read from the selected chain's isolated mempool.\n"
        "This call may take several minutes. If you encounter timeouts, try specifying no RPC timeout (kronein-cli -rpcclienttimeout=0)",
        {
            RPCArg{"blockhashes", RPCArg::Type::ARR, RPCArg::Optional::NO, "The list of blockhashes to examine for activity. Order doesn't matter. Must be along main chain or an error is thrown.\n", {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A valid blockhash"},
            }},
            RPCArg{"scanobjects", RPCArg::Type::ARR, RPCArg::Optional::NO, "The list of descriptors (scan objects) to examine for activity. Every scan object is either a string descriptor or an object:",
                {
                    {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                    output_descriptor_obj,
                },
                RPCArgOptions{.oneline_description="[scanobjects,...]"},
            },
            {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to include unconfirmed activity"},
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::ARR, "activity", "events", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "type", "always 'spend'"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the spent output"},
                        {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The blockhash this spend appears in (omitted if unconfirmed)"},
                        {RPCResult::Type::NUM, "height", /*optional=*/true, "Height of the spend (omitted if unconfirmed)"},
                        {RPCResult::Type::STR_HEX, "spend_txid", "The txid of the spending transaction"},
                        {RPCResult::Type::NUM, "spend_vin", "The input index of the spend"},
                        {RPCResult::Type::STR_HEX, "prevout_txid", "The txid of the prevout"},
                        {RPCResult::Type::NUM, "prevout_vout", "The vout of the prevout"},
                        {RPCResult::Type::OBJ, "prevout_spk", "", ScriptPubKeyDoc()},
                    }},
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "type", "always 'receive'"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the new output"},
                        {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block that this receive is in (omitted if unconfirmed)"},
                        {RPCResult::Type::NUM, "height", /*optional=*/true, "The height of the receive (omitted if unconfirmed)"},
                        {RPCResult::Type::STR_HEX, "txid", "The txid of the receiving transaction"},
                        {RPCResult::Type::NUM, "vout", "The vout of the receiving output"},
                        {RPCResult::Type::OBJ, "output_spk", "", ScriptPubKeyDoc()},
                    }},
                    // TODO is the skip_type_check avoidable with a heterogeneous ARR?
                }, /*skip_type_check=*/true},
                {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Selected child-chain identifier; omitted for the main chain"},
            },
        },
        RPCExamples{
            HelpExampleCli("getdescriptoractivity", "'[\"000000000000000000001347062c12fded7c528943c8ce133987e2e2f5a840ee\"]' '[\"addr(kne1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwzw77t)\"]'") +
            HelpExampleCli("getdescriptoractivity", "'[\"childblockhash\"]' '[\"raw(5120...)\"]' false \"chain_id\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);
    UniValue activity(UniValue::VARR);
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    struct CompareByHeightAscending {
        bool operator()(const CBlockIndex* a, const CBlockIndex* b) const {
            return a->nHeight < b->nHeight;
        }
    };

    std::vector<uint256> requested_hashes;
    for (const UniValue& blockhash : request.params[0].get_array().getValues()) {
        requested_hashes.push_back(ParseHashV(blockhash, "blockhash"));
    }

    std::optional<node::ChainManagerActiveBlocksView> child_blocks;
    std::set<const CBlockIndex*, CompareByHeightAscending> blockindexes_sorted;
    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        child_blocks = GetLoadedChildActiveBlockViews(
            request.context, *chain_id, requested_hashes);
    } else {
        // Validate all given blockhashes, and ensure blocks are along a single chain.
        LOCK(::cs_main);
        for (const uint256& bhash : requested_hashes) {
            CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(bhash);
            if (!pindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }
            if (!chainman.ActiveChain().Contains(pindex)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
            }
            blockindexes_sorted.insert(pindex);
        }
    }

    std::set<CScript> scripts_to_watch;

    // Determine scripts to watch.
    for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
        FlatSigningProvider provider;
        std::vector<CScript> scripts = EvalDescriptorStringOrObject(scanobject, provider);

        for (const CScript& script : scripts) {
            scripts_to_watch.insert(script);
        }
    }

    using BlockLocation = std::pair<uint256, int>;
    const auto AddSpend = [](
            const CScript& spk,
            const CAmount val,
            const CTransactionRef& tx,
            int vin,
            const CTxIn& txin,
            const std::optional<BlockLocation>& location
            ) {
        UniValue event(UniValue::VOBJ);
        UniValue spkUv(UniValue::VOBJ);
        ScriptToUniv(spk, /*out=*/spkUv, /*include_hex=*/true, /*include_address=*/true);

        event.pushKV("type", "spend");
        event.pushKV("amount", ValueFromAmount(val));
        if (location) {
            event.pushKV("blockhash", location->first.ToString());
            event.pushKV("height", location->second);
        }
        event.pushKV("spend_txid", tx->GetHash().ToString());
        event.pushKV("spend_vin", vin);
        event.pushKV("prevout_txid", txin.prevout.hash.ToString());
        event.pushKV("prevout_vout", txin.prevout.n);
        event.pushKV("prevout_spk", spkUv);

        return event;
    };

    const auto AddReceive = [](const CTxOut& txout, const std::optional<BlockLocation>& location, int vout, const CTransactionRef& tx) {
        UniValue event(UniValue::VOBJ);
        UniValue spkUv(UniValue::VOBJ);
        ScriptToUniv(txout.scriptPubKey, /*out=*/spkUv, /*include_hex=*/true, /*include_address=*/true);

        event.pushKV("type", "receive");
        event.pushKV("amount", ValueFromAmount(txout.nValue));
        if (location) {
            event.pushKV("blockhash", location->first.ToString());
            event.pushKV("height", location->second);
        }
        event.pushKV("txid", tx->GetHash().ToString());
        event.pushKV("vout", vout);
        event.pushKV("output_spk", spkUv);

        return event;
    };

    const auto ScanBlockActivity = [&](const CBlock& block,
                                       const CBlockUndo& block_undo,
                                       const BlockLocation& location) {
        for (size_t i = 0; i < block.vtx.size(); ++i) {
            const auto& tx = block.vtx.at(i);
            if (!tx->IsCoinBase()) {
                const auto& txundo = block_undo.vtxundo.at(i - 1);
                for (size_t vin_idx = 0; vin_idx < tx->vin.size(); ++vin_idx) {
                    const auto& coin = txundo.vprevout.at(vin_idx);
                    const auto& txin = tx->vin.at(vin_idx);
                    if (scripts_to_watch.contains(coin.out.scriptPubKey)) {
                        activity.push_back(AddSpend(
                            coin.out.scriptPubKey, coin.out.nValue, tx,
                            vin_idx, txin, location));
                    }
                }
            }
            for (size_t vout_idx = 0; vout_idx < tx->vout.size(); ++vout_idx) {
                const auto& vout = tx->vout.at(vout_idx);
                if (scripts_to_watch.contains(vout.scriptPubKey)) {
                    activity.push_back(
                        AddReceive(vout, location, vout_idx, tx));
                }
            }
        }
    };

    bool search_mempool = true;
    if (!request.params[2].isNull()) {
        search_mempool = request.params[2].get_bool();
    }

    if (child_blocks) {
        for (const auto& child_block : child_blocks->blocks) {
            CHECK_NONFATAL(child_block.block);
            CHECK_NONFATAL(child_block.undo);
            ScanBlockActivity(
                *child_block.block,
                child_block.undo->coins,
                {child_block.block_hash, child_block.height});
        }
        if (search_mempool) {
            const auto mempool{EnsureAnyChildChainman(request.context)
                                   .GetMempool(child_blocks->entry.chain_id)};
            if (!mempool.IsValid()) {
                throw JSONRPCError(
                    RPC_INTERNAL_ERROR,
                    "loaded child mempool became unavailable");
            }
            std::map<COutPoint, CTxOut> mempool_outputs;
            for (const auto& entry : mempool.runtime.entries) {
                for (size_t vout_idx = 0;
                     vout_idx < entry.transaction->vout.size(); ++vout_idx) {
                    mempool_outputs.emplace(
                        COutPoint{entry.transaction->GetHash(),
                                  static_cast<uint32_t>(vout_idx)},
                        entry.transaction->vout[vout_idx]);
                }
            }
            for (const auto& entry : mempool.runtime.entries) {
                const auto& tx{entry.transaction};
                for (size_t vin_idx = 0; vin_idx < tx->vin.size(); ++vin_idx) {
                    const auto& txin{tx->vin[vin_idx]};
                    std::optional<CTxOut> prevout;
                    if (const auto parent{mempool_outputs.find(txin.prevout)};
                        parent != mempool_outputs.end()) {
                        prevout = parent->second;
                    } else {
                        const auto coin{EnsureAnyChildChainman(request.context)
                                            .GetCoinView(
                                                child_blocks->entry.chain_id,
                                                txin.prevout)};
                        if (!coin.IsValid()) {
                            throw JSONRPCError(
                                RPC_INTERNAL_ERROR,
                                "loaded child UTXO view became unavailable");
                        }
                        if (coin.coin) prevout = coin.coin->out;
                    }
                    if (!prevout) {
                        throw JSONRPCError(
                            RPC_INTERNAL_ERROR,
                            "child mempool input is missing its previous output");
                    }
                    if (scripts_to_watch.contains(prevout->scriptPubKey)) {
                        activity.push_back(AddSpend(
                            prevout->scriptPubKey, prevout->nValue, tx,
                            vin_idx, txin, std::nullopt));
                    }
                }
                for (size_t vout_idx = 0; vout_idx < tx->vout.size();
                     ++vout_idx) {
                    const auto& txout{tx->vout[vout_idx]};
                    if (scripts_to_watch.contains(txout.scriptPubKey)) {
                        activity.push_back(AddReceive(
                            txout, std::nullopt, vout_idx, tx));
                    }
                }
            }
        }
        ret.pushKV("activity", activity);
        ret.pushKV("chain_id", child_blocks->entry.chain_id.GetHex());
        return ret;
    }

    BlockManager* blockman;
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    {
        LOCK(::cs_main);
        blockman = CHECK_NONFATAL(&active_chainstate.m_blockman);
    }

    for (const CBlockIndex* blockindex : blockindexes_sorted) {
        const CBlock block{GetBlockChecked(chainman.m_blockman, *blockindex)};
        const CBlockUndo block_undo{GetUndoChecked(*blockman, *blockindex)};
        ScanBlockActivity(
            block, block_undo,
            {blockindex->GetBlockHash(), blockindex->nHeight});
    }

    if (search_mempool) {
        const CTxMemPool& mempool = EnsureMemPool(node);
        LOCK(::cs_main);
        LOCK(mempool.cs);
        const CCoinsViewCache& coins_view = &active_chainstate.CoinsTip();

        for (const CTxMemPoolEntry& e : mempool.entryAll()) {
            const auto& tx = e.GetSharedTx();

            for (size_t vin_idx = 0; vin_idx < tx->vin.size(); ++vin_idx) {
                CScript scriptPubKey;
                CAmount value;
                const auto& txin = tx->vin.at(vin_idx);
                std::optional<Coin> coin = coins_view.GetCoin(txin.prevout);

                // Check if the previous output is in the chain
                if (!coin) {
                    // If not found in the chain, check the mempool. Likely, this is a
                    // child transaction of another transaction in the mempool.
                    CTransactionRef prev_tx = CHECK_NONFATAL(mempool.get(txin.prevout.hash));

                    if (txin.prevout.n >= prev_tx->vout.size()) {
                        throw std::runtime_error("Invalid output index");
                    }
                    const CTxOut& out = prev_tx->vout[txin.prevout.n];
                    scriptPubKey = out.scriptPubKey;
                    value = out.nValue;
                } else {
                    // Coin found in the chain
                    const CTxOut& out = coin->out;
                    scriptPubKey = out.scriptPubKey;
                    value = out.nValue;
                }

                if (scripts_to_watch.contains(scriptPubKey)) {
                    UniValue event(UniValue::VOBJ);
                    activity.push_back(AddSpend(
                                scriptPubKey, value, tx, vin_idx, txin, std::nullopt));
                }
            }

            for (size_t vout_idx = 0; vout_idx < tx->vout.size(); ++vout_idx) {
                const auto& vout = tx->vout.at(vout_idx);
                if (scripts_to_watch.contains(vout.scriptPubKey)) {
                    activity.push_back(AddReceive(vout, std::nullopt, vout_idx, tx));
                }
            }
        }
    }

    ret.pushKV("activity", activity);
    return ret;
},
    };
}

static RPCHelpMan getblockfilter()
{
    return RPCHelpMan{
        "getblockfilter",
        "Retrieve a BIP 157 content filter for a particular block.\n"
        "Omit chain_id for the main chain. Child basic filters are persisted by the child runtime and do not require the main-chain blockfilter index.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the block"},
                    {"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
                    {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "filter", "the hex-encoded filter data"},
                        {RPCResult::Type::STR_HEX, "header", "the hex-encoded filter header"},
                    }},
                RPCExamples{
                    HelpExampleCli("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" \"basic\"") +
                    HelpExampleRpc("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\", \"basic\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 block_hash = ParseHashV(request.params[0], "blockhash");
    auto filtertype_name{self.Arg<std::string_view>("filtertype")};

    BlockFilterType filtertype;
    if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
    }

    if (const auto chain_id{self.MaybeArg<std::string_view>("chain_id")}) {
        if (filtertype != BlockFilterType::BASIC) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               "Unknown child filtertype");
        }
        const auto view{GetLoadedChildBlockView(
            request.context, *chain_id, block_hash)};
        if (view.block.virtual_genesis) {
            throw JSONRPCError(
                RPC_INVALID_ADDRESS_OR_KEY,
                "The virtual child genesis has no BIP 157 block filter");
        }
        if (!view.block.basic_filter) {
            throw JSONRPCError(
                RPC_INTERNAL_ERROR,
                "Child block filter is unavailable");
        }
        UniValue ret{UniValue::VOBJ};
        ret.pushKV(
            "filter", HexStr(view.block.basic_filter->encoded_filter));
        ret.pushKV(
            "header", view.block.basic_filter->filter_header.GetHex());
        return ret;
    }

    BlockFilterIndex* index = GetBlockFilterIndex(filtertype);
    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, tfm::format("Index is not enabled for filtertype %s", filtertype_name));
    }

    const CBlockIndex* block_index;
    bool block_was_connected;
    {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        LOCK(cs_main);
        block_index = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!block_index) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        block_was_connected = block_index->IsValid(BLOCK_VALID_SCRIPTS);
    }

    bool index_ready = index->BlockUntilSyncedToCurrentChain();

    BlockFilter filter;
    uint256 filter_header;
    if (!index->LookupFilter(block_index, filter) ||
        !index->LookupFilterHeader(block_index, filter_header)) {
        int err_code;
        std::string errmsg = "Filter not found.";

        if (!block_was_connected) {
            err_code = RPC_INVALID_ADDRESS_OR_KEY;
            errmsg += " Block was not connected to active chain.";
        } else if (!index_ready) {
            err_code = RPC_MISC_ERROR;
            errmsg += " Block filters are still in the process of being indexed.";
        } else {
            err_code = RPC_INTERNAL_ERROR;
            errmsg += " This error is unexpected and indicates index corruption.";
        }

        throw JSONRPCError(err_code, errmsg);
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("filter", HexStr(filter.GetEncodedFilter()));
    ret.pushKV("header", filter_header.GetHex());
    return ret;
},
    };
}

/**
 * RAII class that disables the network in its constructor and enables it in its
 * destructor.
 */
class NetworkDisable
{
    CConnman& m_connman;
public:
    NetworkDisable(CConnman& connman) : m_connman(connman) {
        m_connman.SetNetworkActive(false);
        if (m_connman.GetNetworkActive()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Network activity could not be suspended.");
        }
    };
    ~NetworkDisable() {
        m_connman.SetNetworkActive(true);
    };
};

/**
 * RAII class that temporarily rolls back the local chain in it's constructor
 * and rolls it forward again in it's destructor.
 */
class TemporaryRollback
{
    ChainstateManager& m_chainman;
    const CBlockIndex& m_invalidate_index;
public:
    TemporaryRollback(ChainstateManager& chainman, const CBlockIndex& index) : m_chainman(chainman), m_invalidate_index(index) {
        InvalidateBlock(m_chainman, m_invalidate_index.GetBlockHash());
    };
    ~TemporaryRollback() {
        ReconsiderBlock(m_chainman, m_invalidate_index.GetBlockHash());
    };
};

/**
 * Serialize the UTXO set to a file for loading elsewhere.
 *
 * @see SnapshotMetadata
 */
static RPCHelpMan dumptxoutset()
{
    return RPCHelpMan{
        "dumptxoutset",
        "Write the serialized UTXO set to a file. This can be used in loadtxoutset afterwards if this snapshot height is supported in the chainparams as well.\n\n"
        "Unless the \"latest\" type is requested, the node will roll back to the requested height and network activity will be suspended during this process. "
        "Because of this it is discouraged to interact with the node in any other way during the execution of this call to avoid inconsistent results and race conditions, particularly RPCs that interact with blockstorage.\n\n"
        "This call may take several minutes. Make sure to use no RPC timeout (kronein-cli -rpcclienttimeout=0)",
        {
            {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "Path to the output file. If relative, will be prefixed by datadir."},
            {"type", RPCArg::Type::STR, RPCArg::Default(""), "The type of snapshot to create. Can be \"latest\" to create a snapshot of the current UTXO set or \"rollback\" to temporarily roll back the state of the node to a historical block before creating the snapshot of a historical UTXO set. This parameter can be omitted if a separate \"rollback\" named parameter is specified indicating the height or hash of a specific historical block. If \"rollback\" is specified and separate \"rollback\" named parameter is not specified, this will roll back to the latest valid snapshot block that can currently be loaded with loadtxoutset."},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"rollback", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                        "Height or hash of the block to roll back to before creating the snapshot. Note: The further this number is from the tip, the longer this process will take. Consider setting a higher -rpcclienttimeout value in this case.",
                    RPCArgOptions{.skip_type_check = true, .type_str = {"", "string or numeric"}}},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_written", "the number of coins written in the snapshot"},
                    {RPCResult::Type::STR_HEX, "base_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was written to"},
                    {RPCResult::Type::STR_HEX, "txoutset_hash", "the hash of the UTXO set contents"},
                    {RPCResult::Type::NUM, "nchaintx", "the number of transactions in the chain up to and including the base block"},
                    {RPCResult::Type::STR_HEX, "registry_root", /*optional=*/true, "the authenticated child chain registry root"},
                    {RPCResult::Type::NUM, "registry_records", /*optional=*/true, "the number of child chain registry records written"},
                }
        },
        RPCExamples{
            HelpExampleCli("-rpcclienttimeout=0 dumptxoutset", "utxo.dat latest") +
            HelpExampleCli("-rpcclienttimeout=0 dumptxoutset", "utxo.dat rollback") +
            HelpExampleCli("-rpcclienttimeout=0 -named dumptxoutset", R"(utxo.dat rollback=853456)")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CBlockIndex* tip{WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip())};
    const CBlockIndex* target_index{nullptr};
    const auto snapshot_type{self.Arg<std::string_view>("type")};
    const UniValue options{request.params[2].isNull() ? UniValue::VOBJ : request.params[2]};
    if (options.exists("rollback")) {
        if (!snapshot_type.empty() && snapshot_type != "rollback") {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid snapshot type \"%s\" specified with rollback option", snapshot_type));
        }
        target_index = ParseHashOrHeight(options["rollback"], *node.chainman);
    } else if (snapshot_type == "rollback") {
        auto snapshot_heights = node.chainman->GetParams().GetAvailableSnapshotHeights();
        CHECK_NONFATAL(snapshot_heights.size() > 0);
        auto max_height = std::max_element(snapshot_heights.begin(), snapshot_heights.end());
        target_index = ParseHashOrHeight(*max_height, *node.chainman);
    } else if (snapshot_type == "latest") {
        target_index = tip;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid snapshot type \"%s\" specified. Please specify \"rollback\" or \"latest\"", snapshot_type));
    }

    const ArgsManager& args{EnsureAnyArgsman(request.context)};
    const fs::path path = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(self.Arg<std::string_view>("path")));
    // Write to a temporary path and then move into `path` on completion
    // to avoid confusion due to an interruption.
    const fs::path temppath = path + ".incomplete";

    if (fs::exists(path)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            path.utf8string() + " already exists. If you are sure this is what you want, "
            "move it out of the way first");
    }

    FILE* file{fsbridge::fopen(temppath, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + temppath.utf8string() + " for writing.");
    }

    CConnman& connman = EnsureConnman(node);
    const CBlockIndex* invalidate_index{nullptr};
    std::optional<NetworkDisable> disable_network;
    std::optional<TemporaryRollback> temporary_rollback;

    // If the user wants to dump the txoutset of the current tip, we don't have
    // to roll back at all
    if (target_index != tip) {
        // If the node is running in pruned mode we ensure all necessary block
        // data is available before starting to roll back.
        if (node.chainman->m_blockman.IsPruneMode()) {
            LOCK(node.chainman->GetMutex());
            const CBlockIndex* current_tip{node.chainman->ActiveChain().Tip()};
            const CBlockIndex& first_block{node.chainman->m_blockman.GetFirstBlock(*current_tip, /*status_mask=*/BLOCK_HAVE_MASK)};
            if (first_block.nHeight > target_index->nHeight) {
                throw JSONRPCError(RPC_MISC_ERROR, "Could not roll back to requested height since necessary block data is already pruned.");
            }
        }

        // Suspend network activity for the duration of the process when we are
        // rolling back the chain to get a utxo set from a past height. We do
        // this so we don't punish peers that send us that send us data that
        // seems wrong in this temporary state. For example a normal new block
        // would be classified as a block connecting an invalid block.
        // Skip if the network is already disabled because this
        // automatically re-enables the network activity at the end of the
        // process which may not be what the user wants.
        if (connman.GetNetworkActive()) {
            disable_network.emplace(connman);
        }

        invalidate_index = WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Next(target_index));
        temporary_rollback.emplace(*node.chainman, *invalidate_index);
    }

    Chainstate* chainstate;
    std::unique_ptr<CCoinsViewCursor> cursor;
    CCoinsStats stats;
    std::optional<node::RegistrySnapshot> registry_snapshot;
    {
        // Lock the chainstate before calling PrepareUtxoSnapshot, to be able
        // to get a UTXO database cursor while the chain is pointing at the
        // target block. After that, release the lock while calling
        // WriteUTXOSnapshot. The cursor will remain valid and be used by
        // WriteUTXOSnapshot to write a consistent snapshot even if the
        // chainstate changes.
        LOCK(node.chainman->GetMutex());
        chainstate = &node.chainman->ActiveChainstate();
        // In case there is any issue with a block being read from disk we need
        // to stop here, otherwise the dump could still be created for the wrong
        // height.
        // The new tip could also not be the target block if we have a stale
        // sister block of invalidate_index. This block (or a descendant) would
        // be activated as the new tip and we would not get to new_tip_index.
        if (target_index != chainstate->m_chain.Tip()) {
            LogWarning("dumptxoutset failed to roll back to requested height, reverting to tip.\n");
            throw JSONRPCError(RPC_MISC_ERROR, "Could not roll back to requested height.");
        } else {
            auto prepared{PrepareUTXOSnapshot(*chainstate, node.rpc_interruption_point)};
            cursor = std::move(prepared.cursor);
            stats = std::move(prepared.stats);
            tip = prepared.tip;
            registry_snapshot = std::move(prepared.registry);
        }
    }

    UniValue result = WriteUTXOSnapshot(*chainstate,
                                        cursor.get(),
                                        &stats,
                                        tip,
                                        registry_snapshot,
                                        std::move(afile),
                                        path,
                                        temppath,
                                        node.rpc_interruption_point);
    fs::rename(temppath, path);

    result.pushKV("path", path.utf8string());
    return result;
},
    };
}

PreparedUTXOSnapshot
PrepareUTXOSnapshot(
    Chainstate& chainstate,
    const std::function<void()>& interruption_point)
{
    std::unique_ptr<CCoinsViewCursor> pcursor;
    std::optional<CCoinsStats> maybe_stats;
    const CBlockIndex* tip;
    std::optional<node::RegistrySnapshot> registry_snapshot;

    {
        // We need to lock cs_main to ensure that the coinsdb isn't written to
        // between (i) flushing coins cache to disk (coinsdb), (ii) getting stats
        // based upon the coinsdb, and (iii) constructing a cursor to the
        // coinsdb for use in WriteUTXOSnapshot.
        //
        // Cursors returned by leveldb iterate over snapshots, so the contents
        // of the pcursor will not be affected by simultaneous writes during
        // use below this block.
        //
        // See discussion here:
        //   https://github.com/bitcoin/bitcoin/pull/15606#discussion_r274479369
        //
        AssertLockHeld(::cs_main);

        chainstate.ForceFlushStateToDisk(/*wipe_cache=*/false);

        maybe_stats = GetUTXOStats(&chainstate.CoinsDB(), chainstate.m_blockman, CoinStatsHashType::MUHASH, interruption_point);
        if (!maybe_stats) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
        }

        pcursor = chainstate.CoinsDB().Cursor();
        tip = CHECK_NONFATAL(chainstate.m_blockman.LookupBlockIndex(maybe_stats->hashBlock));

        if (chainstate.m_chainman.GetConsensus().chain_registry.IsActive(tip->nHeight)) {
            const auto& registry_state{chainstate.ChainRegistryState()};
            if (!registry_state.IsInitialized() || registry_state.State().best_block != tip->GetBlockHash()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Child chain registry state is not aligned with the UTXO snapshot base");
            }

            CBlock block;
            if (!chainstate.m_blockman.ReadBlock(block, *tip) || block.vtx.empty()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Unable to read the snapshot base block for the child chain registry proof");
            }

            node::RegistrySnapshot snapshot;
            snapshot.base_blockhash = tip->GetBlockHash();
            snapshot.registry_root = registry_state.Registry().ComputeRoot();
            snapshot.records.reserve(registry_state.Registry().Size());
            for (const auto& entry : registry_state.Registry().Records()) {
                snapshot.records.push_back(entry.second);
            }
            snapshot.dealers.reserve(registry_state.Registry().DealerSize());
            for (const auto& entry : registry_state.Registry().Dealers()) {
                snapshot.dealers.push_back(entry.second);
            }
            snapshot.authority_sequence = registry_state.Registry().AuthoritySequence();
            snapshot.authority_transition = registry_state.Registry().AuthorityTransition();
            snapshot.coinbase = CMutableTransaction{*block.vtx.front()};
            snapshot.coinbase_merkle_branch = TransactionMerklePath(block, /*position=*/0);
            registry_snapshot = std::move(snapshot);
        }
    }

    return {std::move(pcursor), *CHECK_NONFATAL(maybe_stats), tip, std::move(registry_snapshot)};
}

UniValue WriteUTXOSnapshot(
    Chainstate& chainstate,
    CCoinsViewCursor* pcursor,
    CCoinsStats* maybe_stats,
    const CBlockIndex* tip,
    const std::optional<node::RegistrySnapshot>& registry_snapshot,
    AutoFile&& afile,
    const fs::path& path,
    const fs::path& temppath,
    const std::function<void()>& interruption_point)
{
    LOG_TIME_SECONDS(strprintf("writing UTXO snapshot at height %s (%s) to file %s (via %s)",
        tip->nHeight, tip->GetBlockHash().ToString(),
        fs::PathToString(path), fs::PathToString(temppath)));

    SnapshotMetadata metadata{chainstate.m_chainman.GetParams().MessageStart(), tip->GetBlockHash(), maybe_stats->coins_count};

    afile << metadata;

    COutPoint key;
    Txid last_hash;
    Coin coin;
    unsigned int iter{0};
    size_t written_coins_count{0};
    std::vector<std::pair<uint32_t, Coin>> coins;

    // To reduce space the serialization format of the snapshot avoids
    // duplication of tx hashes. The code takes advantage of the guarantee by
    // leveldb that keys are lexicographically sorted.
    // In the coins vector we collect all coins that belong to a certain tx hash
    // (key.hash) and when we have them all (key.hash != last_hash) we write
    // them to file using the below lambda function.
    // See also https://github.com/bitcoin/bitcoin/issues/25675
    auto write_coins_to_file = [&](AutoFile& afile, const Txid& last_hash, const std::vector<std::pair<uint32_t, Coin>>& coins, size_t& written_coins_count) {
        afile << last_hash;
        WriteCompactSize(afile, coins.size());
        for (const auto& [n, coin] : coins) {
            WriteCompactSize(afile, n);
            afile << coin;
            ++written_coins_count;
        }
    };

    pcursor->GetKey(key);
    last_hash = key.hash;
    while (pcursor->Valid()) {
        if (iter % 5000 == 0) interruption_point();
        ++iter;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (key.hash != last_hash) {
                write_coins_to_file(afile, last_hash, coins, written_coins_count);
                last_hash = key.hash;
                coins.clear();
            }
            coins.emplace_back(key.n, coin);
        }
        pcursor->Next();
    }

    if (!coins.empty()) {
        write_coins_to_file(afile, last_hash, coins, written_coins_count);
    }

    CHECK_NONFATAL(written_coins_count == maybe_stats->coins_count);

    if (registry_snapshot) {
        afile << *registry_snapshot;
    }

    if (afile.fclose() != 0) {
        throw std::ios_base::failure(
            strprintf("Error closing %s: %s", fs::PathToString(temppath), SysErrorString(errno)));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_written", written_coins_count);
    result.pushKV("base_hash", tip->GetBlockHash().ToString());
    result.pushKV("base_height", tip->nHeight);
    result.pushKV("path", path.utf8string());
    result.pushKV("txoutset_hash", maybe_stats->muhash.ToString());
    result.pushKV("nchaintx", tip->m_chain_tx_count);
    if (registry_snapshot) {
        result.pushKV("registry_root", registry_snapshot->registry_root.ToString());
        result.pushKV("registry_records", registry_snapshot->records.size());
    }
    return result;
}

UniValue CreateUTXOSnapshot(
    node::NodeContext& node,
    Chainstate& chainstate,
    AutoFile&& afile,
    const fs::path& path,
    const fs::path& tmppath)
{
    auto prepared{WITH_LOCK(::cs_main, return PrepareUTXOSnapshot(chainstate, node.rpc_interruption_point))};
    return WriteUTXOSnapshot(chainstate,
                             prepared.cursor.get(),
                             &prepared.stats,
                             prepared.tip,
                             prepared.registry,
                             std::move(afile),
                             path,
                             tmppath,
                             node.rpc_interruption_point);
}

static RPCHelpMan loadtxoutset()
{
    return RPCHelpMan{
        "loadtxoutset",
        "Load the serialized UTXO set from a file.\n"
        "Once this snapshot is loaded, its contents will be "
        "deserialized into a second chainstate data structure, which is then used to sync to "
        "the network's tip. "
        "Meanwhile, the original chainstate will complete the initial block download process in "
        "the background, eventually validating up to the block that the snapshot is based upon.\n\n"

        "The result is a usable kroneind instance that is current with the network tip in a "
        "matter of minutes rather than hours. UTXO snapshot are typically obtained from "
        "third-party sources (HTTP, torrent, etc.) which is reasonable since their "
        "UTXO contents are checked against a compiled hash. After child-chain registry activation, "
        "the snapshot also carries registry records authenticated by the base block header.\n\n"

        "You can find more information on this process in the `assumeutxo` design "
        "document (<https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md>).",
        {
            {"path",
                RPCArg::Type::STR,
                RPCArg::Optional::NO,
                "path to the snapshot file. If relative, will be prefixed by datadir."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_loaded", "the number of coins loaded from the snapshot"},
                    {RPCResult::Type::STR_HEX, "tip_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was loaded from"},
                }
        },
        RPCExamples{
            HelpExampleCli("-rpcclienttimeout=0 loadtxoutset", "utxo.dat")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const fs::path path{AbsPathForConfigVal(EnsureArgsman(node), fs::u8path(self.Arg<std::string_view>("path")))};

    FILE* file{fsbridge::fopen(path, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + path.utf8string() + " for reading.");
    }

    SnapshotMetadata metadata{chainman.GetParams().MessageStart()};
    try {
        afile >> metadata;
    } catch (const std::ios_base::failure& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Unable to parse metadata: %s", e.what()));
    }

    auto activation_result{chainman.ActivateSnapshot(afile, metadata, false)};
    if (!activation_result) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to load UTXO snapshot: %s. (%s)", util::ErrorString(activation_result).original, path.utf8string()));
    }

    // Because we can't provide historical blocks during tip or background sync.
    // Update local services to reflect we are a limited peer until we are fully sync.
    node.connman->RemoveLocalServices(NODE_NETWORK);
    // Setting the limited state is usually redundant because the node can always
    // provide the last 288 blocks, but it doesn't hurt to set it.
    node.connman->AddLocalServices(NODE_NETWORK_LIMITED);

    CBlockIndex& snapshot_index{*CHECK_NONFATAL(*activation_result)};

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_loaded", metadata.m_coins_count);
    result.pushKV("tip_hash", snapshot_index.GetBlockHash().ToString());
    result.pushKV("base_height", snapshot_index.nHeight);
    result.pushKV("path", fs::PathToString(path));
    return result;
},
    };
}

const std::vector<RPCResult> RPCHelpForChainstate{
    {RPCResult::Type::NUM, "blocks", "number of blocks in this chainstate"},
    {RPCResult::Type::STR_HEX, "bestblockhash", "blockhash of the tip"},
    {RPCResult::Type::STR_HEX, "bits", "nBits: compact representation of the block difficulty target"},
    {RPCResult::Type::STR_HEX, "target", "The difficulty target"},
    {RPCResult::Type::NUM, "difficulty", "difficulty of the tip"},
    {RPCResult::Type::NUM, "verificationprogress", "progress towards the network tip"},
    {RPCResult::Type::STR_HEX, "snapshot_blockhash", /*optional=*/true, "the base block of the snapshot this chainstate is based on, if any"},
    {RPCResult::Type::NUM, "coins_db_cache_bytes", "size of the coinsdb cache"},
    {RPCResult::Type::NUM, "coins_tip_cache_bytes", "size of the coinstip cache"},
    {RPCResult::Type::BOOL, "validated", "whether the chainstate is fully validated. True if all blocks in the chainstate were validated, false if the chain is based on a snapshot and the snapshot has not yet been validated."},
};

static RPCHelpMan getchainstates()
{
return RPCHelpMan{
        "getchainstates",
        "Return information about chainstates.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "headers", "the number of headers seen so far"},
                {RPCResult::Type::ARR, "chainstates", "list of the chainstates ordered by work, with the most-work (active) chainstate last", {{RPCResult::Type::OBJ, "", "", RPCHelpForChainstate},}},
            }
        },
        RPCExamples{
            HelpExampleCli("getchainstates", "")
    + HelpExampleRpc("getchainstates", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);
    UniValue obj(UniValue::VOBJ);

    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    auto make_chain_data = [&](const Chainstate& cs) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        AssertLockHeld(::cs_main);
        UniValue data(UniValue::VOBJ);
        if (!cs.m_chain.Tip()) {
            return data;
        }
        const CChain& chain = cs.m_chain;
        const CBlockIndex* tip = chain.Tip();

        data.pushKV("blocks", chain.Height());
        data.pushKV("bestblockhash",         tip->GetBlockHash().GetHex());
        data.pushKV("bits", strprintf("%08x", tip->nBits));
        data.pushKV("target", GetTarget(*tip, chainman.GetConsensus().powLimit).GetHex());
        data.pushKV("difficulty", GetDifficulty(*tip));
        data.pushKV("verificationprogress", chainman.GuessVerificationProgress(tip));
        data.pushKV("coins_db_cache_bytes",  cs.m_coinsdb_cache_size_bytes);
        data.pushKV("coins_tip_cache_bytes", cs.m_coinstip_cache_size_bytes);
        if (cs.m_from_snapshot_blockhash) {
            data.pushKV("snapshot_blockhash", cs.m_from_snapshot_blockhash->ToString());
        }
        data.pushKV("validated", cs.m_assumeutxo == Assumeutxo::VALIDATED);
        return data;
    };

    obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);
    UniValue obj_chainstates{UniValue::VARR};
    if (const Chainstate * cs{chainman.HistoricalChainstate()}) {
        obj_chainstates.push_back(make_chain_data(*cs));
    }
    obj_chainstates.push_back(make_chain_data(chainman.CurrentChainstate()));
    obj.pushKV("chainstates", std::move(obj_chainstates));
    return obj;
}
    };
}

static UniValue ChainRegistryRecordToUniv(const chainregistry::ChainRecord& record)
{
    UniValue control_outpoint{UniValue::VOBJ};
    control_outpoint.pushKV("txid", record.control_outpoint.hash.GetHex());
    control_outpoint.pushKV("vout", record.control_outpoint.n);

    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", record.chain_id.GetHex());
    result.pushKV("manifest_hash", record.manifest_hash.GetHex());
    result.pushKV("template_id", record.template_id);
    result.pushKV("template_version", record.template_version);
    result.pushKV("control_outpoint", std::move(control_outpoint));
    result.pushKV("metadata_hash", record.metadata_hash.GetHex());
    result.pushKV("status", record.status == chainregistry::ChainStatus::ACTIVE ? "active" : "retired");
    result.pushKV("registered_height", record.registered_height);
    result.pushKV("updated_height", record.updated_height);
    result.pushKV("retired_height", record.retired_height);
    return result;
}

static UniValue ChainRegistryInclusionProofToUniv(const chainregistry::RegistryInclusionProof& proof)
{
    UniValue siblings{UniValue::VARR};
    for (const auto& sibling : proof.siblings) {
        siblings.push_back(sibling.GetHex());
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("leaf_count", proof.leaf_count);
    result.pushKV("leaf_index", proof.leaf_index);
    result.pushKV("siblings", std::move(siblings));
    result.pushKV("dealer_root", proof.dealer_root.GetHex());
    result.pushKV("authority_sequence", proof.authority_sequence);
    result.pushKV("authority_state_hash", proof.authority_state_hash.GetHex());
    return result;
}

static UniValue MerkleBranchToUniv(const std::vector<uint256>& branch)
{
    UniValue result{UniValue::VARR};
    for (const auto& hash : branch) result.push_back(hash.GetHex());
    return result;
}

static UniValue DepositEntryToUniv(const node::DepositIndexEntry& entry,
                                   int confirmations,
                                   bool proof_available)
{
    UniValue outpoint{UniValue::VOBJ};
    outpoint.pushKV("txid", entry.outpoint.hash.GetHex());
    outpoint.pushKV("vout", entry.outpoint.n);

    UniValue destination{UniValue::VOBJ};
    destination.pushKV("chain_id", entry.fund.chain_id.GetHex());
    destination.pushKV("recipient_type", entry.fund.recipient_type);
    destination.pushKV("recipient", HexStr(entry.fund.recipient));

    UniValue result{UniValue::VOBJ};
    result.pushKV("deposit_id", entry.deposit_id.GetHex());
    result.pushKV("outpoint", std::move(outpoint));
    result.pushKV("amount", ValueFromAmount(entry.amount));
    result.pushKV("destination", std::move(destination));
    result.pushKV("blockhash", entry.block_hash.GetHex());
    result.pushKV("blockheight", entry.block_height);
    result.pushKV("transaction_index", entry.transaction_index);
    result.pushKV("confirmations", confirmations);
    result.pushKV("proof_available", proof_available);
    result.pushKV("registry_root", entry.registry_root.GetHex());
    result.pushKV("chain_record", ChainRegistryRecordToUniv(entry.chain_record));
    result.pushKV("registry_proof", ChainRegistryInclusionProofToUniv(entry.registry_proof));
    return result;
}

static COutPoint ParseDepositOutPoint(const UniValue& txid_arg, const UniValue& vout_arg)
{
    const Txid txid{Txid::FromUint256(ParseHashV(txid_arg, "txid"))};
    const int64_t parsed_vout{vout_arg.getInt<int64_t>()};
    if (txid.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "txid must not be null");
    }
    if (parsed_vout < 0 ||
        static_cast<uint64_t>(parsed_vout) >= COutPoint::NULL_INDEX) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be less than 4294967295");
    }
    return COutPoint{txid, static_cast<uint32_t>(parsed_vout)};
}

static std::string SerializeDepositProofHex(const chainregistry::DepositProof& proof)
{
    DataStream stream;
    stream << proof;
    return HexStr(stream);
}

static std::string SerializeBmmAnchorProofHex(const chainregistry::BmmAnchorProof& proof)
{
    DataStream stream;
    stream << proof;
    return HexStr(stream);
}

static std::string SerializeHeaderHex(const CBlockHeader& header)
{
    DataStream stream;
    stream << header;
    return HexStr(stream);
}

static std::string SerializeBaseTransactionHex(const CMutableTransaction& transaction)
{
    DataStream stream;
    stream << TX_BASE(transaction);
    return HexStr(stream);
}

static UniValue ChainRegistryProofEntryToUniv(const chainregistry::RegistryProofEntry& entry)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("record", ChainRegistryRecordToUniv(entry.record));
    result.pushKV("proof", ChainRegistryInclusionProofToUniv(entry.proof));
    return result;
}

static UniValue ChainRegistryNonInclusionProofToUniv(const chainregistry::RegistryNonInclusionProof& proof)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("leaf_count", proof.leaf_count);
    result.pushKV("dealer_root", proof.dealer_root.GetHex());
    result.pushKV("authority_sequence", proof.authority_sequence);
    result.pushKV("authority_state_hash", proof.authority_state_hash.GetHex());
    if (proof.has_left) result.pushKV("left", ChainRegistryProofEntryToUniv(proof.left));
    if (proof.has_right) result.pushKV("right", ChainRegistryProofEntryToUniv(proof.right));
    return result;
}

static const std::vector<RPCResult> CHAIN_REGISTRY_RECORD_RESULT{
    {RPCResult::Type::STR_HEX, "chain_id", "Stable child-chain identifier"},
    {RPCResult::Type::STR_HEX, "manifest_hash", "Hash of the immutable chain manifest"},
    {RPCResult::Type::NUM, "template_id", "Consensus template identifier"},
    {RPCResult::Type::NUM, "template_version", "Consensus template version"},
    {RPCResult::Type::OBJ, "control_outpoint", "Outpoint authorizing the next update or retirement", {
        {RPCResult::Type::STR_HEX, "txid", "Control transaction id"},
        {RPCResult::Type::NUM, "vout", "Control output index"},
    }},
    {RPCResult::Type::STR_HEX, "metadata_hash", "Commitment to the current external metadata"},
    {RPCResult::Type::STR, "status", "Registry status: active or retired"},
    {RPCResult::Type::NUM, "registered_height", "Main-chain registration height"},
    {RPCResult::Type::NUM, "updated_height", "Most recent metadata/control update height"},
    {RPCResult::Type::NUM, "retired_height", "Retirement height, or 0 while active"},
};

static const std::vector<RPCResult> CHAIN_REGISTRY_INCLUSION_PROOF_RESULT{
    {RPCResult::Type::NUM, "leaf_count", "Number of leaves committed by the registry root"},
    {RPCResult::Type::NUM, "leaf_index", "Zero-based canonical leaf index"},
    {RPCResult::Type::ARR, "siblings", "Sibling hashes from leaf to root", {
        {RPCResult::Type::STR_HEX, "", "Sibling hash"},
    }},
    {RPCResult::Type::STR_HEX, "dealer_root", "Root committing to the authorized dealer set"},
    {RPCResult::Type::NUM, "authority_sequence", "Dealer-authority sequence committed by the registry root"},
    {RPCResult::Type::STR_HEX, "authority_state_hash", "Committed delayed authority handover state"},
};

static RPCHelpMan getchainregistryinfo()
{
    return RPCHelpMan{
        "getchainregistryinfo",
        "Return consensus parameters and the verified child-chain registry state at the active tip.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "enabled", "Whether registry consensus is configured on this network"},
            {RPCResult::Type::BOOL, "active", "Whether registry consensus is active at the current tip"},
            {RPCResult::Type::BOOL, "active_for_next_block", "Whether registry consensus applies to the next block"},
            {RPCResult::Type::NUM, "activation_height", "Activation height, or -1 when disabled"},
            {RPCResult::Type::ARR, "dealer_authority_keys", "Ordered BIP340 x-only authority keys; array offsets are signer indices", {
                {RPCResult::Type::STR_HEX, "", "Authority public key"},
            }},
            {RPCResult::Type::NUM, "dealer_authority_threshold", "Required number of distinct authority signatures"},
            {RPCResult::Type::STR_HEX, "dealer_authority_policy_hash", /*optional=*/true, "Authority policy effective at the current tip"},
            {RPCResult::Type::ARR, "dealer_authority_next_block_keys", "Keys effective for the next block (may change at the activation boundary)", {
                {RPCResult::Type::STR_HEX, "", "X-only key"},
            }},
            {RPCResult::Type::STR_HEX, "dealer_authority_next_block_policy_hash", /*optional=*/true, "Authority policy effective for the next block"},
            {RPCResult::Type::BOOL, "dealer_authority_rotation_pending", "Whether a confirmed handover has not yet activated"},
            {RPCResult::Type::NUM, "dealer_authority_activation_height", "Last handover activation height, or zero if none"},
            {RPCResult::Type::NUM, "dealer_authority_rotation_delay", "Fixed delay from inclusion to activation"},
            {RPCResult::Type::STR_HEX, "authority_state_hash", "Committed authority handover state"},
            {RPCResult::Type::ARR, "dealer_authority_pending_keys", "Replacement keys, empty when no handover is pending", {
                {RPCResult::Type::STR_HEX, "", "X-only key"},
            }},
            {RPCResult::Type::NUM, "dealer_initial_licenses", "Required initial allocation per dealer"},
            {RPCResult::Type::NUM, "dealer_max_added_licenses", "Maximum allocation per dealer update"},
            {RPCResult::Type::NUM, "maximum_operations", "Maximum registry transitions per block"},
            {RPCResult::Type::BOOL, "bmm_enabled", "Whether child-chain BMM anchor consensus is configured"},
            {RPCResult::Type::BOOL, "bmm_active", "Whether child-chain BMM anchors are active at the current tip"},
            {RPCResult::Type::BOOL, "bmm_active_for_next_block", "Whether child-chain BMM anchor consensus applies to the next block"},
            {RPCResult::Type::NUM, "bmm_activation_height", "BMM activation height, or -1 when disabled"},
            {RPCResult::Type::NUM, "maximum_bmm_anchors", "Maximum KBMM anchors per block"},
            {RPCResult::Type::BOOL, "deposits_enabled", "Whether one-way deposit consensus is configured"},
            {RPCResult::Type::BOOL, "deposits_active", "Whether one-way deposits are active at the current tip"},
            {RPCResult::Type::BOOL, "deposits_active_for_next_block", "Whether one-way deposit consensus applies to the next block"},
            {RPCResult::Type::NUM, "deposit_activation_height", "Deposit activation height, or -1 when disabled"},
            {RPCResult::Type::STR_AMOUNT, "minimum_deposit_amount", "Minimum FUND_CHAIN burn in KNE"},
            {RPCResult::Type::NUM, "maximum_deposits", "Maximum FUND_CHAIN outputs per block"},
            {RPCResult::Type::STR_HEX, "bestblockhash", "Block hash paired with this registry state"},
            {RPCResult::Type::NUM, "height", "Block height paired with this registry state"},
            {RPCResult::Type::STR_HEX, "root", "Count-committed deterministic registry root"},
            {RPCResult::Type::NUM, "size", "Number of registered child-chain records"},
            {RPCResult::Type::NUM, "dealer_count", "Number of authorized dealer records, including revoked dealers"},
            {RPCResult::Type::NUM, "authority_sequence", "Last consumed dealer-authority sequence"},
            {RPCResult::Type::NUM, "deposit_history_start_height", "First height covered completely by the persistent deposit index"},
            {RPCResult::Type::BOOL, "deposit_history_complete", "Whether the deposit index covers the chain from genesis"},
            {RPCResult::Type::NUM, "deposit_count", "Number of indexed deposits in the covered active-chain history"},
            {RPCResult::Type::NUM, "bmm_anchor_history_start_height", "First height covered completely by the persistent BMM anchor index"},
            {RPCResult::Type::BOOL, "bmm_anchor_history_complete", "Whether the BMM anchor index covers the chain from genesis"},
            {RPCResult::Type::NUM, "bmm_anchor_count", "Number of indexed BMM anchors in the covered active-chain history"},
        }},
        RPCExamples{
            HelpExampleCli("getchainregistryinfo", "")
            + HelpExampleRpc("getchainregistryinfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman{EnsureAnyChainman(request.context)};
    LOCK(cs_main);

    const auto& params{chainman.GetConsensus().chain_registry};
    const Chainstate& chainstate{chainman.ActiveChainstate()};
    const auto& state{chainstate.ChainRegistryState().State()};
    const int height{chainstate.m_chain.Height()};

    UniValue result{UniValue::VOBJ};
    result.pushKV("enabled", params.Enabled());
    result.pushKV("active", params.IsActive(height));
    result.pushKV("active_for_next_block", params.IsActive(height + 1));
    result.pushKV("activation_height", params.activation_height);
    const auto& transition{state.authority_transition};
    const auto& authority{transition.Effective(std::max(height, 0), params.dealer_authority)};
    const auto& next_authority{transition.Effective(std::max(height + 1, 0), params.dealer_authority)};
    UniValue authority_keys{UniValue::VARR};
    for (const auto& key : authority.keys) authority_keys.push_back(HexStr(key));
    result.pushKV("dealer_authority_keys", std::move(authority_keys));
    result.pushKV("dealer_authority_threshold", authority.threshold);
    if (authority.IsValid()) result.pushKV("dealer_authority_policy_hash", authority.GetHash().GetHex());
    UniValue next_keys{UniValue::VARR};
    for (const auto& key : next_authority.keys) next_keys.push_back(HexStr(key));
    result.pushKV("dealer_authority_next_block_keys", std::move(next_keys));
    if (next_authority.IsValid()) result.pushKV("dealer_authority_next_block_policy_hash", next_authority.GetHash().GetHex());
    const bool pending{transition.Pending(std::max(height, 0))};
    result.pushKV("dealer_authority_rotation_pending", pending);
    result.pushKV("dealer_authority_activation_height", transition.activation_height);
    result.pushKV("dealer_authority_rotation_delay", chainregistry::DEALER_AUTHORITY_ROTATION_DELAY);
    result.pushKV("authority_state_hash", transition.GetHash().GetHex());
    UniValue pending_keys{UniValue::VARR};
    if (pending) for (const auto& key : transition.next.keys) pending_keys.push_back(HexStr(key));
    result.pushKV("dealer_authority_pending_keys", std::move(pending_keys));
    result.pushKV("dealer_initial_licenses", chainregistry::DEALER_INITIAL_LICENSES);
    result.pushKV("dealer_max_added_licenses", chainregistry::DEALER_MAX_ADDED_LICENSES);
    result.pushKV("maximum_operations", params.maximum_operations);
    result.pushKV("bmm_enabled", params.BmmEnabled());
    result.pushKV("bmm_active", params.BmmActive(height));
    result.pushKV("bmm_active_for_next_block", params.BmmActive(height + 1));
    result.pushKV("bmm_activation_height", params.bmm_activation_height);
    result.pushKV("maximum_bmm_anchors", params.maximum_bmm_anchors);
    result.pushKV("deposits_enabled", params.DepositsEnabled());
    result.pushKV("deposits_active", params.DepositsActive(height));
    result.pushKV("deposits_active_for_next_block", params.DepositsActive(height + 1));
    result.pushKV("deposit_activation_height", params.deposit_activation_height);
    result.pushKV("minimum_deposit_amount", ValueFromAmount(params.minimum_deposit_amount));
    result.pushKV("maximum_deposits", params.maximum_deposits);
    result.pushKV("bestblockhash", state.best_block.GetHex());
    result.pushKV("height", state.height);
    result.pushKV("root", state.registry_root.GetHex());
    result.pushKV("size", state.record_count);
    result.pushKV("dealer_count", state.dealer_count);
    result.pushKV("authority_sequence", state.authority_sequence);
    result.pushKV("deposit_history_start_height", state.deposit_history_start_height);
    result.pushKV("deposit_history_complete", state.deposit_history_start_height == 0);
    result.pushKV("deposit_count", state.deposit_count);
    result.pushKV("bmm_anchor_history_start_height", state.anchor_history_start_height);
    result.pushKV("bmm_anchor_history_complete", state.anchor_history_start_height == 0);
    result.pushKV("bmm_anchor_count", state.anchor_count);
    return result;
}
    };
}

static const std::vector<RPCResult> DEPOSIT_INDEX_ENTRY_RESULT{
    {RPCResult::Type::STR_HEX, "deposit_id", "Network-bound identifier derived from main genesis hash and funding outpoint"},
    {RPCResult::Type::OBJ, "outpoint", "Irreversibly burned main-chain output", {
        {RPCResult::Type::STR_HEX, "txid", "Funding transaction id"},
        {RPCResult::Type::NUM, "vout", "Funding output index"},
    }},
    {RPCResult::Type::STR_AMOUNT, "amount", "Amount burned on the main chain in KNE"},
    {RPCResult::Type::OBJ, "destination", "Canonical child destination", {
        {RPCResult::Type::STR_HEX, "chain_id", "Destination child-chain identifier"},
        {RPCResult::Type::NUM, "recipient_type", "Child-template recipient namespace"},
        {RPCResult::Type::STR_HEX, "recipient", "Canonical recipient bytes"},
    }},
    {RPCResult::Type::STR_HEX, "blockhash", "Containing main-chain block hash"},
    {RPCResult::Type::NUM, "blockheight", "Containing main-chain block height"},
    {RPCResult::Type::NUM, "transaction_index", "Funding transaction position in the block"},
    {RPCResult::Type::NUM, "confirmations", "Current active-chain confirmations"},
    {RPCResult::Type::BOOL, "proof_available", "Whether the block data required to export a KDPR proof is currently available"},
    {RPCResult::Type::STR_HEX, "registry_root", "Historical registry root committed by the containing block"},
    {RPCResult::Type::OBJ, "chain_record", "Historical active child-chain record", CHAIN_REGISTRY_RECORD_RESULT},
    {RPCResult::Type::OBJ, "registry_proof", "Historical record inclusion proof", CHAIN_REGISTRY_INCLUSION_PROOF_RESULT},
};

static RPCHelpMan getdepositstatus()
{
    return RPCHelpMan{
        "getdepositstatus",
        "Look up a consensus-validated one-way child deposit by its main-chain outpoint. This uses the persistent compact index and remains available when the containing block has been pruned.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Funding transaction id"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Funding output index"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "deposit_id", "Derived network-bound deposit identifier"},
            {RPCResult::Type::BOOL, "found", "Whether the deposit exists in the indexed active-chain history"},
            {RPCResult::Type::NUM, "history_start_height", "First height completely covered by this index"},
            {RPCResult::Type::BOOL, "history_complete", "Whether indexed history starts at genesis"},
            {RPCResult::Type::OBJ, "deposit", /*optional=*/true, "Validated deposit", DEPOSIT_INDEX_ENTRY_RESULT},
        }},
        RPCExamples{
            HelpExampleCli("getdepositstatus", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" 0")
            + HelpExampleRpc("getdepositstatus", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const COutPoint outpoint{ParseDepositOutPoint(
        self.Arg<UniValue>("txid"), self.Arg<UniValue>("vout"))};
    ChainstateManager& chainman{EnsureAnyChainman(request.context)};
    LOCK(cs_main);
    const Chainstate& chainstate{chainman.ActiveChainstate()};
    const auto& registry_state{chainstate.ChainRegistryState()};
    const auto& state{registry_state.State()};
    const chainregistry::DepositId deposit_id{chainregistry::DeriveDepositId(
        chainman.GetConsensus().hashGenesisBlock, outpoint)};
    const auto entry{registry_state.FindDeposit(deposit_id)};

    UniValue result{UniValue::VOBJ};
    result.pushKV("deposit_id", deposit_id.GetHex());
    result.pushKV("found", entry.has_value());
    result.pushKV("history_start_height", state.deposit_history_start_height);
    result.pushKV("history_complete", state.deposit_history_start_height == 0);
    if (!entry) return result;

    const CBlockIndex* block_index{chainman.m_blockman.LookupBlockIndex(entry->block_hash)};
    if (!block_index || block_index->nHeight != static_cast<int>(entry->block_height) ||
        !chainstate.m_chain.Contains(block_index)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "deposit index references a block outside the active chain");
    }
    const int confirmations{chainstate.m_chain.Height() - block_index->nHeight + 1};
    const bool proof_available{(block_index->nStatus & BLOCK_HAVE_DATA) != 0};
    result.pushKV("deposit", DepositEntryToUniv(*entry, confirmations, proof_available));
    return result;
}
    };
}

static RPCHelpMan getdepositproof()
{
    return RPCHelpMan{
        "getdepositproof",
        "Build and independently validate a canonical KDPR v2 proof for a consensus-validated one-way child deposit. The child must separately authenticate the returned block header in the main-chain header chain and apply its confirmation policy.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Funding transaction id"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Funding output index"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "proof", "Canonical serialized KDPR v2 package"},
            {RPCResult::Type::NUM, "proof_version", "KDPR format version"},
            {RPCResult::Type::STR_HEX, "main_genesis_hash", "Main-network identity bound into the proof"},
            {RPCResult::Type::OBJ, "deposit", "Indexed deposit metadata", DEPOSIT_INDEX_ENTRY_RESULT},
            {RPCResult::Type::STR_HEX, "block_header", "Serialized containing main-chain block header"},
            {RPCResult::Type::STR_HEX, "funding_transaction", "Serialized stripped funding transaction"},
            {RPCResult::Type::ARR, "transaction_merkle_branch", "Funding transaction branch from leaf to root", {
                {RPCResult::Type::STR_HEX, "", "Sibling hash"},
            }},
            {RPCResult::Type::STR_HEX, "coinbase_transaction", "Serialized stripped coinbase transaction carrying the registry commitment"},
            {RPCResult::Type::ARR, "coinbase_merkle_branch", "Coinbase branch from leaf to root", {
                {RPCResult::Type::STR_HEX, "", "Sibling hash"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getdepositproof", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" 0")
            + HelpExampleRpc("getdepositproof", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const COutPoint outpoint{ParseDepositOutPoint(
        self.Arg<UniValue>("txid"), self.Arg<UniValue>("vout"))};
    ChainstateManager& chainman{EnsureAnyChainman(request.context)};
    const CBlockIndex* block_index{nullptr};
    node::DepositIndexEntry entry;
    int confirmations{0};
    const uint256 main_genesis_hash{chainman.GetConsensus().hashGenesisBlock};
    const chainregistry::DepositId deposit_id{chainregistry::DeriveDepositId(
        main_genesis_hash, outpoint)};
    {
        LOCK(cs_main);
        const Chainstate& chainstate{chainman.ActiveChainstate()};
        const auto indexed{chainstate.ChainRegistryState().FindDeposit(deposit_id)};
        if (!indexed) {
            const auto start{chainstate.ChainRegistryState().State().deposit_history_start_height};
            throw JSONRPCError(
                RPC_INVALID_ADDRESS_OR_KEY,
                strprintf("deposit not found in active-chain index (history is complete from height %u)", start));
        }
        entry = *indexed;
        block_index = chainman.m_blockman.LookupBlockIndex(entry.block_hash);
        if (!block_index || block_index->nHeight != static_cast<int>(entry.block_height) ||
            !chainstate.m_chain.Contains(block_index)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "deposit index references a block outside the active chain");
        }
        confirmations = chainstate.m_chain.Height() - block_index->nHeight + 1;
    }

    const CBlock block{GetBlockChecked(chainman.m_blockman, *block_index)};
    const auto built{node::BuildDepositProof(
        block, entry, main_genesis_hash)};
    if (!built.IsValid()) {
        throw JSONRPCError(
            RPC_INTERNAL_ERROR,
            strprintf("failed to build deposit proof (build error %u, validation error %u)",
                      static_cast<unsigned>(built.error),
                      static_cast<unsigned>(built.validation.error)));
    }
    const auto& proof{built.proof};

    UniValue result{UniValue::VOBJ};
    result.pushKV("proof", SerializeDepositProofHex(proof));
    result.pushKV("proof_version", proof.version);
    result.pushKV("main_genesis_hash", main_genesis_hash.GetHex());
    result.pushKV("deposit", DepositEntryToUniv(entry, confirmations, /*proof_available=*/true));
    result.pushKV("block_header", SerializeHeaderHex(proof.block_header));
    result.pushKV("funding_transaction", SerializeBaseTransactionHex(proof.funding_transaction));
    result.pushKV("transaction_merkle_branch", MerkleBranchToUniv(proof.transaction_merkle_branch));
    result.pushKV("coinbase_transaction", SerializeBaseTransactionHex(proof.coinbase_transaction));
    result.pushKV("coinbase_merkle_branch", MerkleBranchToUniv(proof.coinbase_merkle_branch));
    return result;
}
    };
}

static RPCHelpMan getbmmanchorproof()
{
    return RPCHelpMan{
        "getbmmanchorproof",
        "Build and independently validate a canonical KBPR v2 proof for one consensus-validated BMM anchor in an active main-chain block. The loaded child runtime can consume this proof through submitchildanchor or submitchildblock.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Exact non-null child-chain identifier"},
            {"main_block_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Active main-chain block containing the KBMM anchor"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "proof", "Canonical serialized KBPR v2 package"},
            {RPCResult::Type::NUM, "proof_version", "KBPR format version"},
            {RPCResult::Type::STR_HEX, "main_genesis_hash", "Main-network identity bound into the proof"},
            {RPCResult::Type::STR_HEX, "main_block_hash", "Containing active main-chain block"},
            {RPCResult::Type::NUM, "main_block_height", "Containing main-chain block height"},
            {RPCResult::Type::NUM, "confirmations", "Current active-main-chain confirmations"},
            {RPCResult::Type::STR_HEX, "chain_id", "Anchored child-chain identifier"},
            {RPCResult::Type::STR_HEX, "child_block_hash", "Child block committed by the anchor"},
            {RPCResult::Type::STR_HEX, "transaction_id", "Main-chain KBMM transaction id"},
            {RPCResult::Type::NUM, "transaction_index", "KBMM transaction position in the block"},
            {RPCResult::Type::NUM, "output_index", "Canonical KBMM output position in the transaction"},
            {RPCResult::Type::STR_HEX, "registry_root", "Historical registry root committed by the containing block"},
            {RPCResult::Type::OBJ, "chain_record", "Historical active child-chain record", CHAIN_REGISTRY_RECORD_RESULT},
            {RPCResult::Type::OBJ, "registry_proof", "Historical record inclusion proof", CHAIN_REGISTRY_INCLUSION_PROOF_RESULT},
            {RPCResult::Type::STR_HEX, "block_header", "Serialized containing main-chain block header"},
            {RPCResult::Type::STR_HEX, "anchor_transaction", "Serialized stripped KBMM transaction"},
            {RPCResult::Type::ARR, "transaction_merkle_branch", "KBMM transaction branch from leaf to root", {
                {RPCResult::Type::STR_HEX, "", "Sibling hash"},
            }},
            {RPCResult::Type::STR_HEX, "coinbase_transaction", "Serialized stripped coinbase transaction carrying the registry commitment"},
            {RPCResult::Type::ARR, "coinbase_merkle_branch", "Coinbase branch from leaf to root", {
                {RPCResult::Type::STR_HEX, "", "Sibling hash"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getbmmanchorproof", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"")
            + HelpExampleRpc("getbmmanchorproof", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const chainregistry::ChainId chain_id{
        ParseChainId(self.Arg<std::string_view>("chain_id"))};
    const uint256 main_block_hash{
        ParseHashV(self.Arg<UniValue>("main_block_hash"), "main_block_hash")};
    if (main_block_hash.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "main_block_hash must not be null");
    }

    ChainstateManager& chainman{EnsureAnyChainman(request.context)};
    const CBlockIndex* block_index{nullptr};
    node::BmmAnchorIndexEntry entry;
    int confirmations{0};
    uint32_t history_start_height{0};
    const uint256 main_genesis_hash{chainman.GetConsensus().hashGenesisBlock};
    {
        LOCK(cs_main);
        const Chainstate& chainstate{chainman.ActiveChainstate()};
        const auto& registry_state{chainstate.ChainRegistryState()};
        history_start_height = registry_state.State().anchor_history_start_height;
        const auto indexed{registry_state.FindAnchor(node::BmmAnchorId{
            .chain_id = chain_id,
            .main_block_hash = main_block_hash,
        })};
        if (!indexed) {
            throw JSONRPCError(
                RPC_INVALID_ADDRESS_OR_KEY,
                strprintf("BMM anchor not found in active-chain index (history starts at height %u)",
                          history_start_height));
        }
        entry = *indexed;
        block_index = chainman.m_blockman.LookupBlockIndex(main_block_hash);
        if (!block_index ||
            block_index->nHeight != static_cast<int>(entry.block_height) ||
            !chainstate.m_chain.Contains(block_index)) {
            throw JSONRPCError(
                RPC_INTERNAL_ERROR,
                "BMM anchor index references a block outside the active chain");
        }
        confirmations = chainstate.m_chain.Height() - block_index->nHeight + 1;
    }

    const CBlock block{GetBlockChecked(chainman.m_blockman, *block_index)};
    const auto built{
        node::BuildBmmAnchorProof(block, entry, main_genesis_hash)};
    if (!built.IsValid()) {
        throw JSONRPCError(
            RPC_INTERNAL_ERROR,
            strprintf("failed to build BMM anchor proof (build error %u, validation error %u)",
                      static_cast<unsigned>(built.error),
                      static_cast<unsigned>(built.validation.error)));
    }
    const auto& proof{built.proof};

    UniValue result{UniValue::VOBJ};
    result.pushKV("proof", SerializeBmmAnchorProofHex(proof));
    result.pushKV("proof_version", proof.version);
    result.pushKV("main_genesis_hash", main_genesis_hash.GetHex());
    result.pushKV("main_block_hash", main_block_hash.GetHex());
    result.pushKV("main_block_height", entry.block_height);
    result.pushKV("confirmations", confirmations);
    result.pushKV("chain_id", entry.anchor.chain_id.GetHex());
    result.pushKV("child_block_hash", entry.anchor.child_block_hash.GetHex());
    result.pushKV("transaction_id", entry.transaction_id.GetHex());
    result.pushKV("transaction_index", entry.transaction_index);
    result.pushKV("output_index", entry.output_index);
    result.pushKV("registry_root", entry.registry_root.GetHex());
    result.pushKV("chain_record", ChainRegistryRecordToUniv(entry.chain_record));
    result.pushKV("registry_proof", ChainRegistryInclusionProofToUniv(entry.registry_proof));
    result.pushKV("block_header", SerializeHeaderHex(proof.block_header));
    result.pushKV("anchor_transaction", SerializeBaseTransactionHex(proof.anchor_transaction));
    result.pushKV("transaction_merkle_branch", MerkleBranchToUniv(proof.transaction_merkle_branch));
    result.pushKV("coinbase_transaction", SerializeBaseTransactionHex(proof.coinbase_transaction));
    result.pushKV("coinbase_merkle_branch", MerkleBranchToUniv(proof.coinbase_merkle_branch));
    return result;
}
    };
}

static RPCHelpMan listchildchains()
{
    return RPCHelpMan{
        "listchildchains",
        "List verified child-chain records in canonical chain_id order.\n",
        {
            {"start_after", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Return records strictly after this chain_id"},
            {"limit", RPCArg::Type::NUM, RPCArg::Default{100}, "Maximum records to return (1-1000)"},
            {"include_retired", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include retired child chains"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "bestblockhash", "Block hash paired with this registry view"},
            {RPCResult::Type::NUM, "height", "Block height paired with this registry view"},
            {RPCResult::Type::STR_HEX, "root", "Registry root for this view"},
            {RPCResult::Type::NUM, "size", "Total records, including retired records"},
            {RPCResult::Type::NUM, "returned", "Number of records returned"},
            {RPCResult::Type::BOOL, "has_more", "Whether another matching page exists"},
            {RPCResult::Type::STR_HEX, "next_start_after", /*optional=*/true, "Pass this value as start_after for the next page"},
            {RPCResult::Type::ARR, "chains", "Child-chain records", {
                {RPCResult::Type::OBJ, "", "", CHAIN_REGISTRY_RECORD_RESULT},
            }},
        }},
        RPCExamples{
            HelpExampleCli("listchildchains", "")
            + HelpExampleCli("listchildchains", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" 25 true")
            + HelpExampleRpc("listchildchains", "null, 100, false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto start_after_arg{self.MaybeArg<std::string_view>("start_after")};
    const int limit{self.Arg<int>("limit")};
    const bool include_retired{self.Arg<bool>("include_retired")};
    if (limit < 1 || limit > 1000) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "limit must be between 1 and 1000");
    }

    std::optional<chainregistry::ChainId> start_after;
    if (start_after_arg) start_after = ParseChainId(*start_after_arg);

    ChainstateManager& chainman{EnsureAnyChainman(request.context)};
    LOCK(cs_main);
    const Chainstate& chainstate{chainman.ActiveChainstate()};
    const auto& registry_state{chainstate.ChainRegistryState()};
    const auto& records{registry_state.Registry().Records()};
    const auto& state{registry_state.State()};

    auto it{start_after ? records.upper_bound(*start_after) : records.begin()};
    UniValue chains{UniValue::VARR};
    const chainregistry::ChainRecord* last_record{nullptr};
    int returned{0};
    bool has_more{false};
    for (; it != records.end(); ++it) {
        if (!include_retired && it->second.status == chainregistry::ChainStatus::RETIRED) continue;
        if (returned == limit) {
            has_more = true;
            break;
        }
        chains.push_back(ChainRegistryRecordToUniv(it->second));
        last_record = &it->second;
        ++returned;
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("bestblockhash", state.best_block.GetHex());
    result.pushKV("height", state.height);
    result.pushKV("root", state.registry_root.GetHex());
    result.pushKV("size", state.record_count);
    result.pushKV("returned", returned);
    result.pushKV("has_more", has_more);
    if (has_more) result.pushKV("next_start_after", last_record->chain_id.GetHex());
    result.pushKV("chains", std::move(chains));
    return result;
}
    };
}

static RPCHelpMan getchildchain()
{
    return RPCHelpMan{
        "getchildchain",
        "Return a verified child-chain record and, optionally, a Merkle inclusion or non-inclusion proof.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The exact 32-byte child-chain identifier"},
            {"include_proof", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include a proof against the returned registry root"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "bestblockhash", "Block hash paired with this registry view"},
            {RPCResult::Type::NUM, "height", "Block height paired with this registry view"},
            {RPCResult::Type::STR_HEX, "root", "Registry root against which proofs verify"},
            {RPCResult::Type::BOOL, "found", "Whether the requested chain exists"},
            {RPCResult::Type::OBJ, "chain", /*optional=*/true, "Registered child-chain record", CHAIN_REGISTRY_RECORD_RESULT},
            {RPCResult::Type::OBJ, "inclusion_proof", /*optional=*/true, "Merkle inclusion proof", CHAIN_REGISTRY_INCLUSION_PROOF_RESULT},
            {RPCResult::Type::OBJ, "non_inclusion_proof", /*optional=*/true, "Boundary proof showing the chain_id is absent", {
                {RPCResult::Type::NUM, "leaf_count", "Number of leaves committed by the registry root"},
                {RPCResult::Type::STR_HEX, "dealer_root", "Root committing to the authorized dealer set"},
                {RPCResult::Type::NUM, "authority_sequence", "Dealer-authority sequence committed by the registry root"},
    {RPCResult::Type::STR_HEX, "authority_state_hash", "Committed delayed authority handover state"},
                {RPCResult::Type::OBJ, "left", /*optional=*/true, "Immediate lower neighboring record and proof", {
                    {RPCResult::Type::OBJ, "record", "Neighbor record", CHAIN_REGISTRY_RECORD_RESULT},
                    {RPCResult::Type::OBJ, "proof", "Neighbor inclusion proof", CHAIN_REGISTRY_INCLUSION_PROOF_RESULT},
                }},
                {RPCResult::Type::OBJ, "right", /*optional=*/true, "Immediate higher neighboring record and proof", {
                    {RPCResult::Type::OBJ, "record", "Neighbor record", CHAIN_REGISTRY_RECORD_RESULT},
                    {RPCResult::Type::OBJ, "proof", "Neighbor inclusion proof", CHAIN_REGISTRY_INCLUSION_PROOF_RESULT},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getchildchain", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" true")
            + HelpExampleRpc("getchildchain", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<std::string_view>("chain_id"))};
    const bool include_proof{self.Arg<bool>("include_proof")};

    ChainstateManager& chainman{EnsureAnyChainman(request.context)};
    LOCK(cs_main);
    const Chainstate& chainstate{chainman.ActiveChainstate()};
    const auto& registry_state{chainstate.ChainRegistryState()};
    const auto& registry{registry_state.Registry()};
    const auto& state{registry_state.State()};
    const auto* record{registry.Find(chain_id)};

    UniValue result{UniValue::VOBJ};
    result.pushKV("bestblockhash", state.best_block.GetHex());
    result.pushKV("height", state.height);
    result.pushKV("root", state.registry_root.GetHex());
    result.pushKV("found", record != nullptr);
    if (record) {
        result.pushKV("chain", ChainRegistryRecordToUniv(*record));
        if (include_proof) {
            const auto proof{registry.GetInclusionProof(chain_id)};
            CHECK_NONFATAL(proof.has_value());
            result.pushKV("inclusion_proof", ChainRegistryInclusionProofToUniv(*proof));
        }
    } else if (include_proof) {
        const auto proof{registry.GetNonInclusionProof(chain_id)};
        CHECK_NONFATAL(proof.has_value());
        result.pushKV("non_inclusion_proof", ChainRegistryNonInclusionProofToUniv(*proof));
    }
    return result;
}
    };
}


void RegisterBlockchainRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &getblockchaininfo},
        {"blockchain", &getchaintxstats},
        {"blockchain", &getblockstats},
        {"blockchain", &getbestblockhash},
        {"blockchain", &getblockcount},
        {"blockchain", &getblock},
        {"blockchain", &getblockfrompeer},
        {"blockchain", &getblockhash},
        {"blockchain", &getblockheader},
        {"blockchain", &getchaintips},
        {"blockchain", &getdifficulty},
        {"blockchain", &gettxout},
        {"blockchain", &gettxoutsetinfo},
        {"blockchain", &pruneblockchain},
        {"blockchain", &verifychain},
        {"blockchain", &preciousblock},
        {"blockchain", &scantxoutset},
        {"blockchain", &scanblocks},
        {"blockchain", &getdescriptoractivity},
        {"blockchain", &getblockfilter},
        {"blockchain", &dumptxoutset},
        {"blockchain", &loadtxoutset},
        {"blockchain", &getchainstates},
        {"blockchain", &getchainregistryinfo},
        {"blockchain", &getdepositstatus},
        {"blockchain", &getdepositproof},
        {"blockchain", &getbmmanchorproof},
        {"blockchain", &listchildchains},
        {"blockchain", &getchildchain},
        {"hidden", &invalidateblock},
        {"hidden", &reconsiderblock},
        {"blockchain", &waitfornewblock},
        {"blockchain", &waitforblock},
        {"blockchain", &waitforblockheight},
        {"hidden", &syncwithvalidationinterfacequeue},
    };
    for (const auto& c : commands) {
        t.appendCommand(&c);
    }
}
