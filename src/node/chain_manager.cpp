// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chain_manager.h>

#include <dbwrapper.h>

#include <utility>

namespace node {
namespace {

ChainManagerResult ManagerError(ChainManagerError error)
{
    ChainManagerResult result;
    result.error = error;
    return result;
}

} // namespace

ChainManager::ChainManager(Consensus::Params main_params,
                           CBlockHeader main_genesis,
                           fs::path chains_directory,
                           size_t cache_bytes)
    : m_main_params{std::move(main_params)},
      m_main_genesis{std::move(main_genesis)},
      m_chains_directory{std::move(chains_directory)},
      m_cache_bytes{cache_bytes}
{
}

ChainManager::~ChainManager() = default;

ChainManagerResult ChainManager::RegisterChain(
    const chainregistry::ReferenceChildDefinition& definition)
{
    if (definition.chain_id.IsNull()) {
        return ManagerError(ChainManagerError::NULL_CHAIN_ID);
    }
    const auto validated{chainregistry::ValidateReferenceChildManifest(
        definition.genesis.main_genesis_hash,
        definition.genesis.registration_anchor,
        definition.manifest)};
    if (!validated.IsValid() || !validated.definition ||
        *validated.definition != definition) {
        return ManagerError(ChainManagerError::INVALID_DEFINITION);
    }
    if (definition.genesis.main_genesis_hash !=
            m_main_params.hashGenesisBlock ||
        m_main_genesis.GetHash() != m_main_params.hashGenesisBlock) {
        return ManagerError(ChainManagerError::WRONG_MAIN_GENESIS);
    }

    auto [entry, inserted]{m_definitions.emplace(
        definition.chain_id, definition)};
    ChainManagerResult result;
    if (!inserted) {
        if (entry->second != definition) {
            return ManagerError(ChainManagerError::DEFINITION_CONFLICT);
        }
        result.already_registered = true;
    }
    return result;
}

ChainManagerResult ChainManager::ForgetChain(
    const chainregistry::ChainId& chain_id)
{
    if (chain_id.IsNull()) {
        return ManagerError(ChainManagerError::NULL_CHAIN_ID);
    }
    if (!m_definitions.contains(chain_id)) {
        return ManagerError(ChainManagerError::UNKNOWN_CHAIN);
    }
    if (m_loaded.contains(chain_id)) {
        return ManagerError(ChainManagerError::CHAIN_LOADED);
    }
    m_definitions.erase(chain_id);
    return {};
}

ChainManagerResult ChainManager::LoadChain(
    const chainregistry::ChainId& chain_id,
    int64_t current_time,
    bool wipe_data,
    bool sync)
{
    if (chain_id.IsNull()) {
        return ManagerError(ChainManagerError::NULL_CHAIN_ID);
    }
    const auto definition{m_definitions.find(chain_id)};
    if (definition == m_definitions.end()) {
        return ManagerError(ChainManagerError::UNKNOWN_CHAIN);
    }
    if (m_loaded.contains(chain_id)) {
        ChainManagerResult result;
        result.already_loaded = true;
        return result;
    }

    auto runtime{std::make_unique<ReferenceChildRuntime>(
        m_main_params, definition->second)};
    ChainManagerResult result;
    result.runtime = runtime->Initialize(
        DBParams{
            .path = DataPath(chain_id),
            .cache_bytes = m_cache_bytes,
            .memory_only = false,
            .wipe_data = wipe_data,
            .obfuscate = true,
        },
        m_main_genesis,
        current_time,
        sync);
    if (!result.runtime.IsValid()) {
        result.error = ChainManagerError::INITIALIZATION_FAILED;
        return result;
    }
    m_loaded.emplace(chain_id, std::move(runtime));
    return result;
}

ChainManagerResult ChainManager::UnloadChain(
    const chainregistry::ChainId& chain_id)
{
    if (chain_id.IsNull()) {
        return ManagerError(ChainManagerError::NULL_CHAIN_ID);
    }
    if (!m_definitions.contains(chain_id)) {
        return ManagerError(ChainManagerError::UNKNOWN_CHAIN);
    }
    if (m_loaded.erase(chain_id) == 0) {
        return ManagerError(ChainManagerError::CHAIN_NOT_LOADED);
    }
    return {};
}

ReferenceChildRuntime* ChainManager::Get(
    const chainregistry::ChainId& chain_id)
{
    const auto entry{m_loaded.find(chain_id)};
    return entry == m_loaded.end() ? nullptr : entry->second.get();
}

const ReferenceChildRuntime* ChainManager::Get(
    const chainregistry::ChainId& chain_id) const
{
    const auto entry{m_loaded.find(chain_id)};
    return entry == m_loaded.end() ? nullptr : entry->second.get();
}

bool ChainManager::IsRegistered(
    const chainregistry::ChainId& chain_id) const
{
    return !chain_id.IsNull() && m_definitions.contains(chain_id);
}

bool ChainManager::IsLoaded(const chainregistry::ChainId& chain_id) const
{
    return !chain_id.IsNull() && m_loaded.contains(chain_id);
}

fs::path ChainManager::DataPath(
    const chainregistry::ChainId& chain_id) const
{
    if (chain_id.IsNull()) return {};
    return m_chains_directory / fs::PathFromString(chain_id.GetHex());
}

std::vector<ChainManagerEntry> ChainManager::List() const
{
    std::vector<ChainManagerEntry> result;
    result.reserve(m_definitions.size());
    for (const auto& [chain_id, definition] : m_definitions) {
        ChainManagerEntry entry{
            .chain_id = chain_id,
            .genesis_hash = definition.genesis_hash,
            .data_path = DataPath(chain_id),
        };
        if (const auto loaded{m_loaded.find(chain_id)};
            loaded != m_loaded.end()) {
            entry.loaded = true;
            entry.failed = loaded->second->IsFailed();
            entry.safe_halt = loaded->second->Imports().IsSafeHalted();
            entry.height = loaded->second->State().child_height;
        }
        result.push_back(std::move(entry));
    }
    return result;
}

} // namespace node
