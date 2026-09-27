// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_NODE_CHAIN_MANAGER_H
#define KRONEIN_NODE_CHAIN_MANAGER_H

#include <chainregistry/child_template.h>
#include <consensus/params.h>
#include <node/child_chain_catalog_db.h>
#include <node/child_chain.h>
#include <primitives/block.h>
#include <util/fs.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace node {

static constexpr size_t DEFAULT_CHILD_CHAIN_DB_CACHE{8 << 20};

enum class ChainManagerError : uint8_t {
    NONE,
    NULL_CHAIN_ID,
    INVALID_DEFINITION,
    WRONG_MAIN_GENESIS,
    DEFINITION_CONFLICT,
    UNKNOWN_CHAIN,
    CHAIN_LOADED,
    CHAIN_NOT_LOADED,
    INITIALIZATION_FAILED,
    CATALOG_UNAVAILABLE,
    DATABASE_WRITE_FAILED,
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
    uint256 genesis_hash;
    fs::path data_path;
    bool loaded{false};
    bool failed{false};
    bool safe_halt{false};
    uint32_t height{0};
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
    std::map<chainregistry::ChainId,
             chainregistry::ReferenceChildDefinition> m_definitions;
    std::map<chainregistry::ChainId,
             std::unique_ptr<ReferenceChildRuntime>> m_loaded;

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
                                 bool sync = false);
    ChainManagerResult UnloadChain(const chainregistry::ChainId& chain_id);

    ReferenceChildRuntime* Get(const chainregistry::ChainId& chain_id);
    const ReferenceChildRuntime* Get(
        const chainregistry::ChainId& chain_id) const;
    bool IsRegistered(const chainregistry::ChainId& chain_id) const;
    bool IsLoaded(const chainregistry::ChainId& chain_id) const;
    fs::path DataPath(const chainregistry::ChainId& chain_id) const;
    std::vector<ChainManagerEntry> List() const;
    size_t RegisteredCount() const { return m_definitions.size(); }
    size_t LoadedCount() const { return m_loaded.size(); }
};

} // namespace node

#endif // KRONEIN_NODE_CHAIN_MANAGER_H
