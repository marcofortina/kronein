// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHAIN_MANAGER_H
#define KRONEIN_NODE_CHAIN_MANAGER_H

#include <chainregistry/child_template.h>
#include <consensus/chainregistry.h>
#include <consensus/params.h>
#include <node/child_chain_catalog_db.h>
#include <node/child_chain.h>
#include <primitives/block.h>
#include <script/script.h>
#include <sync.h>
#include <util/fs.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <utility>
#include <vector>

namespace node {

static constexpr size_t DEFAULT_CHILD_CHAIN_DB_CACHE{8 << 20};
inline constexpr size_t MAX_LOADED_CHILD_CHAINS{8};

enum class ChainManagerError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    INVALID_DEFINITION,
    WRONG_MAIN_GENESIS,
    DEFINITION_CONFLICT,
    UNKNOWN_CHAIN,
    CHAIN_LOADED,
    CHAIN_NOT_LOADED,
    TOO_MANY_LOADED_CHAINS,
    INITIALIZATION_FAILED,
    RUNTIME_REJECTED,
    CATALOG_UNAVAILABLE,
    DATABASE_WRITE_FAILED,
};

enum class ChainManagerUnloadReason : uint8_t {
    REGISTRY_MISSING,
    REGISTRY_RETIRED,
    REGISTRY_DEFINITION_MISMATCH,
    MAIN_HEADER_REJECTED,
};

struct ChainManagerRuntimeEvent {
    chainregistry::ChainId chain_id;
    ChainManagerUnloadReason reason;
    ReferenceChildRuntimeError runtime_error{
        ReferenceChildRuntimeError::NONE};
};

struct ChainManagerMainUpdate {
    std::vector<chainregistry::ChainId> advanced;
    std::vector<ChainManagerRuntimeEvent> unloaded;
};

struct ChainManagerResult {
    ChainManagerError error{ChainManagerError::NONE};
    ReferenceChildRuntimeResult runtime;
    bool already_registered{false};
    bool already_loaded{false};

    bool IsValid() const { return error == ChainManagerError::NONE; }
};

struct ChainManagerEntry {
    chainregistry::ChainId chain_id;
    chainregistry::ManifestHash manifest_hash;
    uint32_t template_id{0};
    uint32_t template_version{0};
    uint256 genesis_hash;
    fs::path data_path;
    bool loaded{false};
    bool failed{false};
    bool safe_halt{false};
    uint32_t height{0};
    uint256 tip{};
    uint32_t main_height{0};
    uint256 main_tip{};
    uint64_t anchor_count{0};
    uint64_t pending_anchor_count{0};
    uint64_t pending_anchor_bytes{0};
    uint64_t pending_block_count{0};
    uint64_t side_candidate_count{0};
    uint64_t side_candidate_bytes{0};
    uint64_t candidate_anchor_count{0};
    uint64_t candidate_anchor_bytes{0};
};

enum class ChainManagerViewError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    UNKNOWN_CHAIN,
    CHAIN_NOT_LOADED,
    HEIGHT_OUT_OF_RANGE,
};

struct ChainManagerView {
    ChainManagerViewError error{ChainManagerViewError::NONE};
    ChainManagerEntry entry;
    std::optional<uint256> block_hash;

    bool IsValid() const { return error == ChainManagerViewError::NONE; }
};

struct ChainManagerWaitResult {
    ChainManagerView view;
    bool interrupted{false};

    bool IsValid() const { return view.IsValid(); }
};

enum class ChainManagerBlockViewError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    UNKNOWN_CHAIN,
    CHAIN_NOT_LOADED,
    BLOCK_NOT_FOUND,
};

struct ChainManagerBlockView {
    ChainManagerBlockViewError error{ChainManagerBlockViewError::NONE};
    ChainManagerEntry entry;
    ReferenceChildBlockView block;

    bool IsValid() const { return error == ChainManagerBlockViewError::NONE; }
};

enum class ChainManagerCoinViewError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    UNKNOWN_CHAIN,
    CHAIN_NOT_LOADED,
};

struct ChainManagerCoinView {
    ChainManagerCoinViewError error{ChainManagerCoinViewError::NONE};
    ChainManagerEntry entry;
    std::optional<Coin> coin;

    bool IsValid() const { return error == ChainManagerCoinViewError::NONE; }
};

enum class ChainManagerTipsViewError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    UNKNOWN_CHAIN,
    CHAIN_NOT_LOADED,
    DATA_UNAVAILABLE,
};

struct ChainManagerTipsView {
    ChainManagerTipsViewError error{ChainManagerTipsViewError::NONE};
    ChainManagerEntry entry;
    std::vector<ReferenceChildChainTipView> tips;

    bool IsValid() const { return error == ChainManagerTipsViewError::NONE; }
};

enum class ChainManagerPendingBlocksViewError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    UNKNOWN_CHAIN,
    CHAIN_NOT_LOADED,
    DATA_UNAVAILABLE,
};

struct ChainManagerPendingBlocksView {
    ChainManagerPendingBlocksViewError error{
        ChainManagerPendingBlocksViewError::NONE};
    std::vector<ChildPendingBlockView> blocks;

    bool IsValid() const
    {
        return error == ChainManagerPendingBlocksViewError::NONE;
    }
};

enum class ChainManagerUTXOStatsViewError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    UNKNOWN_CHAIN,
    CHAIN_NOT_LOADED,
    DATA_UNAVAILABLE,
};

enum class ChainManagerVerifyError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    UNKNOWN_CHAIN,
    CHAIN_NOT_LOADED,
};

struct ChainManagerVerifyResult {
    ChainManagerVerifyError error{ChainManagerVerifyError::NONE};
    bool verified{false};

    bool IsValid() const { return error == ChainManagerVerifyError::NONE; }
};

struct ChainManagerUTXOStatsView {
    ChainManagerUTXOStatsViewError error{
        ChainManagerUTXOStatsViewError::NONE};
    ChainManagerEntry entry;
    kernel::CCoinsStats stats;

    bool IsValid() const
    {
        return error == ChainManagerUTXOStatsViewError::NONE;
    }
};

struct ChainManagerUTXOScanView {
    ChainManagerUTXOStatsViewError error{
        ChainManagerUTXOStatsViewError::NONE};
    ChainManagerEntry entry;
    bool completed{false};
    int64_t scanned{0};
    std::map<COutPoint, Coin> matches;
    std::map<int, uint256> block_hashes;

    bool IsValid() const
    {
        return error == ChainManagerUTXOStatsViewError::NONE;
    }
};

/**
 * Opt-in owner for isolated child runtimes.
 *
 * Registration updates only the local catalog. A registered child is never
 * opened or synchronized until LoadChain is called explicitly. Every child
 * gets a fixed directory named by its complete, non-null chain ID.
 */
class ChainManager
{
private:
    Consensus::Params m_main_params;
    CBlockHeader m_main_genesis;
    fs::path m_chains_directory;
    size_t m_cache_bytes;
    std::unique_ptr<ChildChainCatalogDB> m_catalog_db;
    ChildChainCatalogLoadError m_catalog_error{
        ChildChainCatalogLoadError::NONE};
    mutable Mutex m_mutex;
    std::map<chainregistry::ChainId,
             chainregistry::ReferenceChildDefinition> m_definitions
        GUARDED_BY(m_mutex);
    std::map<chainregistry::ChainId,
             std::unique_ptr<ReferenceChildRuntime>> m_loaded
        GUARDED_BY(m_mutex);
    std::condition_variable m_tip_changed_cv GUARDED_BY(m_mutex);
    bool m_interrupt_waits GUARDED_BY(m_mutex){false};
    ChainManagerView GetChainViewLocked(
        const chainregistry::ChainId& chain_id,
        std::optional<int> height = std::nullopt) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    ChainManagerBlockView GetBlockViewLocked(
        const chainregistry::ChainId& chain_id,
        const uint256& block_hash) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    ChainManager(Consensus::Params main_params,
                 CBlockHeader main_genesis,
                 fs::path chains_directory,
                 size_t cache_bytes);
    ~ChainManager();

    bool IsCatalogReady() const
    {
        return m_catalog_error == ChildChainCatalogLoadError::NONE;
    }
    ChildChainCatalogLoadError CatalogError() const { return m_catalog_error; }

    ChainManagerResult RegisterChain(
        const chainregistry::ReferenceChildDefinition& definition);
    ChainManagerResult ForgetChain(const chainregistry::ChainId& chain_id);
    ChainManagerResult LoadChain(const chainregistry::ChainId& chain_id,
                                 int64_t current_time,
                                 bool wipe_data = false,
                                 bool sync = false,
                                 std::span<const CBlockHeader> main_headers = {});
    ChainManagerResult UnloadChain(const chainregistry::ChainId& chain_id);
    ChainManagerResult StageBmmAnchor(
        const chainregistry::ChainId& chain_id,
        const chainregistry::BmmAnchorProof& anchor_proof,
        int64_t current_time,
        bool sync = false);
    ChainManagerResult SubmitBlock(
        const chainregistry::ChainId& chain_id,
        const CBlock& block,
        const chainregistry::BmmAnchorProof& anchor_proof,
        int64_t current_time,
        bool sync = false);
    ChainManagerResult SubmitBlockData(
        const chainregistry::ChainId& chain_id,
        const CBlock& block,
        int64_t current_time,
        bool sync = false);
    /** Feed a header already connected by the local main chainstate. */
    ChainManagerMainUpdate AddMainHeader(
        const CBlockHeader& header,
        int64_t current_time,
        bool sync = false);
    ChainManagerMainUpdate SynchronizeMainChain(
        std::span<const CBlockHeader> active_headers,
        const uint256& active_tip,
        int64_t current_time,
        bool sync = false);
    ChainManagerMainUpdate ReconcileRegistry(
        const std::map<chainregistry::ChainId,
                       chainregistry::ChainRecord>& records);

    ReferenceChildRuntime* Get(const chainregistry::ChainId& chain_id);
    const ReferenceChildRuntime* Get(
        const chainregistry::ChainId& chain_id) const;
    bool IsRegistered(const chainregistry::ChainId& chain_id) const;
    bool IsLoaded(const chainregistry::ChainId& chain_id) const;
    std::optional<chainregistry::ReferenceChildDefinition> Definition(
        const chainregistry::ChainId& chain_id) const;
    fs::path DataPath(const chainregistry::ChainId& chain_id) const;
    ChainManagerView GetChainView(
        const chainregistry::ChainId& chain_id,
        std::optional<int> height = std::nullopt) const;
    ChainManagerWaitResult WaitForTipChanged(
        const chainregistry::ChainId& chain_id,
        std::optional<uint256> current_tip,
        std::optional<std::chrono::milliseconds> timeout = std::nullopt);
    void InterruptWaits();
    ChainManagerBlockView GetBlockView(
        const chainregistry::ChainId& chain_id,
        const uint256& block_hash) const;
    ChainManagerBlockView GetTipBlockView(
        const chainregistry::ChainId& chain_id) const;
    ChainManagerCoinView GetCoinView(
        const chainregistry::ChainId& chain_id,
        const COutPoint& outpoint) const;
    ChainManagerTipsView GetChainTipsView(
        const chainregistry::ChainId& chain_id) const;
    ChainManagerPendingBlocksView GetPendingBlocksView(
        const chainregistry::ChainId& chain_id) const;
    ChainManagerUTXOStatsView GetUTXOStatsView(
        const chainregistry::ChainId& chain_id,
        kernel::CoinStatsHashType hash_type,
        const std::function<void()>& interruption_point = {}) const;
    ChainManagerUTXOScanView ScanUTXOSet(
        const chainregistry::ChainId& chain_id,
        const std::set<CScript>& needles,
        std::atomic<int>& progress,
        const std::atomic<bool>& should_abort,
        const std::function<void()>& interruption_point = {}) const;
    ChainManagerVerifyResult VerifyChain(
        const chainregistry::ChainId& chain_id,
        int64_t current_time) const;
    std::vector<ChainManagerEntry> List() const;
    size_t RegisteredCount() const;
    size_t LoadedCount() const;
};

} // namespace node

#endif // KRONEIN_NODE_CHAIN_MANAGER_H
