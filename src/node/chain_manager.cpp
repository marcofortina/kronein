// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chain_manager.h>

#include <dbwrapper.h>

#include <utility>

namespace node {
namespace {

constexpr size_t CHILD_CHAIN_CATALOG_DB_CACHE{1 << 20};

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
    m_catalog_db = std::make_unique<ChildChainCatalogDB>(
        DBParams{
            .path = m_chains_directory / "catalog",
            .cache_bytes = CHILD_CHAIN_CATALOG_DB_CACHE,
            .memory_only = false,
            .wipe_data = false,
            .obfuscate = true,
        },
        m_main_params.hashGenesisBlock);
    auto loaded{m_catalog_db->Load()};
    m_catalog_error = loaded.error;
    if (!loaded.IsValid()) return;
    if (!loaded.initialized && !m_catalog_db->WriteInitialState(/*sync=*/true)) {
        m_catalog_error = ChildChainCatalogLoadError::DATABASE_WRITE_FAILED;
        return;
    }
    for (auto& definition : loaded.definitions) {
        const auto chain_id{definition.chain_id};
        auto [_, inserted]{m_definitions.emplace(
            chain_id, std::move(definition))};
        if (!inserted) {
            m_definitions.clear();
            m_catalog_error = ChildChainCatalogLoadError::DUPLICATE_RECORD;
            return;
        }
    }
}

ChainManager::~ChainManager() = default;

ChainManagerResult ChainManager::RegisterChain(
    const chainregistry::ReferenceChildDefinition& definition)
{
    LOCK(m_mutex);
    if (!IsCatalogReady()) {
        return ManagerError(ChainManagerError::CATALOG_UNAVAILABLE);
    }
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

    ChainManagerResult result;
    if (const auto entry{m_definitions.find(definition.chain_id)};
        entry != m_definitions.end()) {
        if (entry->second != definition) {
            return ManagerError(ChainManagerError::DEFINITION_CONFLICT);
        }
        result.already_registered = true;
        return result;
    }
    if (!m_catalog_db->WriteDefinition(
            definition, m_definitions.size(), /*sync=*/true)) {
        return ManagerError(ChainManagerError::DATABASE_WRITE_FAILED);
    }
    m_definitions.emplace(definition.chain_id, definition);
    return result;
}

ChainManagerResult ChainManager::ForgetChain(
    const chainregistry::ChainId& chain_id)
{
    LOCK(m_mutex);
    if (!IsCatalogReady()) {
        return ManagerError(ChainManagerError::CATALOG_UNAVAILABLE);
    }
    if (chain_id.IsNull()) {
        return ManagerError(ChainManagerError::NULL_CHAIN_ID);
    }
    if (!m_definitions.contains(chain_id)) {
        return ManagerError(ChainManagerError::UNKNOWN_CHAIN);
    }
    if (m_loaded.contains(chain_id)) {
        return ManagerError(ChainManagerError::CHAIN_LOADED);
    }
    if (!m_catalog_db->EraseDefinition(
            chain_id, m_definitions.size(), /*sync=*/true)) {
        return ManagerError(ChainManagerError::DATABASE_WRITE_FAILED);
    }
    m_definitions.erase(chain_id);
    return {};
}

ChainManagerResult ChainManager::LoadChain(
    const chainregistry::ChainId& chain_id,
    int64_t current_time,
    bool wipe_data,
    bool sync,
    std::span<const CBlockHeader> main_headers)
{
    LOCK(m_mutex);
    if (!IsCatalogReady()) {
        return ManagerError(ChainManagerError::CATALOG_UNAVAILABLE);
    }
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
        sync,
        std::optional<std::span<const CBlockHeader>>{main_headers});
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
    LOCK(m_mutex);
    if (!IsCatalogReady()) {
        return ManagerError(ChainManagerError::CATALOG_UNAVAILABLE);
    }
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

ChainManagerResult ChainManager::StageBmmAnchor(
    const chainregistry::ChainId& chain_id,
    const chainregistry::BmmAnchorProof& anchor_proof,
    int64_t current_time,
    bool sync)
{
    LOCK(m_mutex);
    if (!IsCatalogReady()) {
        return ManagerError(ChainManagerError::CATALOG_UNAVAILABLE);
    }
    ChainManagerResult result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerError::UNKNOWN_CHAIN;
        return result;
    }
    const auto runtime{m_loaded.find(chain_id)};
    if (runtime == m_loaded.end()) {
        result.error = ChainManagerError::CHAIN_NOT_LOADED;
        return result;
    }
    result.runtime = runtime->second->StageBmmAnchor(
        anchor_proof, current_time, sync);
    if (!result.runtime.IsValid()) {
        result.error = ChainManagerError::RUNTIME_REJECTED;
    }
    return result;
}

ChainManagerResult ChainManager::SubmitBlock(
    const chainregistry::ChainId& chain_id,
    const CBlock& block,
    const chainregistry::BmmAnchorProof& anchor_proof,
    int64_t current_time,
    bool sync)
{
    LOCK(m_mutex);
    if (!IsCatalogReady()) {
        return ManagerError(ChainManagerError::CATALOG_UNAVAILABLE);
    }
    ChainManagerResult result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerError::UNKNOWN_CHAIN;
        return result;
    }
    const auto runtime{m_loaded.find(chain_id)};
    if (runtime == m_loaded.end()) {
        result.error = ChainManagerError::CHAIN_NOT_LOADED;
        return result;
    }
    result.runtime = runtime->second->ConnectBlock(
        block, anchor_proof, current_time, sync);
    if (!result.runtime.IsValid()) {
        result.error = ChainManagerError::RUNTIME_REJECTED;
    }
    return result;
}

ChainManagerMainUpdate ChainManager::AddMainHeader(
    const CBlockHeader& header,
    int64_t current_time,
    bool sync)
{
    LOCK(m_mutex);
    ChainManagerMainUpdate update;
    for (auto entry{m_loaded.begin()}; entry != m_loaded.end();) {
        const auto advanced{
            entry->second->AddValidatedMainHeader(
                header, current_time, sync)};
        if (!advanced.IsValid()) {
            update.unloaded.push_back({
                .chain_id = entry->first,
                .reason = ChainManagerUnloadReason::MAIN_HEADER_REJECTED,
                .runtime_error = advanced.error,
            });
            entry = m_loaded.erase(entry);
            continue;
        }
        if (!advanced.main_header.already_known) {
            update.advanced.push_back(entry->first);
        }
        ++entry;
    }
    return update;
}

ChainManagerMainUpdate ChainManager::SynchronizeMainChain(
    std::span<const CBlockHeader> active_headers,
    const uint256& active_tip,
    int64_t current_time,
    bool sync)
{
    LOCK(m_mutex);
    ChainManagerMainUpdate update;
    for (auto entry{m_loaded.begin()}; entry != m_loaded.end();) {
        auto& runtime{*entry->second};
        if (runtime.MainHeaders()->Tip()->GetBlockHash() == active_tip) {
            ++entry;
            continue;
        }
        ReferenceChildRuntimeResult result;
        for (const CBlockHeader& header : active_headers) {
            result = runtime.AddValidatedMainHeader(
                header, current_time, sync);
            if (!result.IsValid()) break;
        }
        if (result.IsValid()) {
            result = runtime.SelectValidatedMainTip(
                active_tip, current_time, sync);
        }
        if (!result.IsValid()) {
            update.unloaded.push_back({
                .chain_id = entry->first,
                .reason = ChainManagerUnloadReason::MAIN_HEADER_REJECTED,
                .runtime_error = result.error,
            });
            entry = m_loaded.erase(entry);
            continue;
        }
        update.advanced.push_back(entry->first);
        ++entry;
    }
    return update;
}

ChainManagerMainUpdate ChainManager::ReconcileRegistry(
    const std::map<chainregistry::ChainId,
                   chainregistry::ChainRecord>& records)
{
    LOCK(m_mutex);
    ChainManagerMainUpdate update;
    for (auto entry{m_loaded.begin()}; entry != m_loaded.end();) {
        const auto record{records.find(entry->first)};
        std::optional<ChainManagerUnloadReason> reason;
        if (record == records.end()) {
            reason = ChainManagerUnloadReason::REGISTRY_MISSING;
        } else if (record->second.status != chainregistry::ChainStatus::ACTIVE) {
            reason = ChainManagerUnloadReason::REGISTRY_RETIRED;
        } else {
            const auto& definition{entry->second->Definition()};
            if (record->second.manifest_hash != definition.manifest_hash ||
                record->second.template_id != definition.manifest.spec.template_id ||
                record->second.template_version != definition.manifest.spec.template_version) {
                reason = ChainManagerUnloadReason::REGISTRY_DEFINITION_MISMATCH;
            }
        }
        if (reason) {
            update.unloaded.push_back({
                .chain_id = entry->first,
                .reason = *reason,
            });
            entry = m_loaded.erase(entry);
            continue;
        }
        ++entry;
    }
    return update;
}

ReferenceChildRuntime* ChainManager::Get(
    const chainregistry::ChainId& chain_id)
{
    LOCK(m_mutex);
    const auto entry{m_loaded.find(chain_id)};
    return entry == m_loaded.end() ? nullptr : entry->second.get();
}

const ReferenceChildRuntime* ChainManager::Get(
    const chainregistry::ChainId& chain_id) const
{
    LOCK(m_mutex);
    const auto entry{m_loaded.find(chain_id)};
    return entry == m_loaded.end() ? nullptr : entry->second.get();
}

bool ChainManager::IsRegistered(
    const chainregistry::ChainId& chain_id) const
{
    LOCK(m_mutex);
    return !chain_id.IsNull() && m_definitions.contains(chain_id);
}

bool ChainManager::IsLoaded(const chainregistry::ChainId& chain_id) const
{
    LOCK(m_mutex);
    return !chain_id.IsNull() && m_loaded.contains(chain_id);
}

std::optional<chainregistry::ReferenceChildDefinition>
ChainManager::Definition(const chainregistry::ChainId& chain_id) const
{
    LOCK(m_mutex);
    if (chain_id.IsNull()) return std::nullopt;
    const auto entry{m_definitions.find(chain_id)};
    if (entry == m_definitions.end()) return std::nullopt;
    return entry->second;
}

fs::path ChainManager::DataPath(
    const chainregistry::ChainId& chain_id) const
{
    if (chain_id.IsNull()) return {};
    return m_chains_directory / fs::PathFromString(chain_id.GetHex());
}

ChainManagerView ChainManager::GetChainView(
    const chainregistry::ChainId& chain_id,
    std::optional<int> height) const
{
    LOCK(m_mutex);
    ChainManagerView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerViewError::NULL_CHAIN_ID;
        return result;
    }
    const auto definition{m_definitions.find(chain_id)};
    if (definition == m_definitions.end()) {
        result.error = ChainManagerViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerViewError::CHAIN_NOT_LOADED;
        return result;
    }
    const auto& runtime{*loaded->second};
    const auto* child_tip{runtime.Tip()};
    const auto* main_tip{runtime.MainHeaders()->Tip()};
    Assume(child_tip);
    Assume(main_tip);
    result.entry = {
        .chain_id = chain_id,
        .manifest_hash = definition->second.manifest_hash,
        .template_id = definition->second.manifest.spec.template_id,
        .template_version = definition->second.manifest.spec.template_version,
        .genesis_hash = definition->second.genesis_hash,
        .data_path = DataPath(chain_id),
        .loaded = true,
        .failed = runtime.IsFailed(),
        .safe_halt = runtime.Imports().IsSafeHalted(),
        .height = runtime.State().child_height,
        .tip = child_tip->GetBlockHash(),
        .main_height = static_cast<uint32_t>(main_tip->nHeight),
        .main_tip = main_tip->GetBlockHash(),
    };
    if (height) {
        result.block_hash = runtime.GetBlockHash(*height);
        if (!result.block_hash) {
            result.error = ChainManagerViewError::HEIGHT_OUT_OF_RANGE;
        }
    }
    return result;
}

ChainManagerBlockView ChainManager::GetBlockView(
    const chainregistry::ChainId& chain_id,
    const uint256& block_hash) const
{
    LOCK(m_mutex);
    return GetBlockViewLocked(chain_id, block_hash);
}

ChainManagerBlockView ChainManager::GetTipBlockView(
    const chainregistry::ChainId& chain_id) const
{
    LOCK(m_mutex);
    if (chain_id.IsNull()) {
        ChainManagerBlockView result;
        result.error = ChainManagerBlockViewError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        ChainManagerBlockView result;
        result.error = ChainManagerBlockViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        ChainManagerBlockView result;
        result.error = ChainManagerBlockViewError::CHAIN_NOT_LOADED;
        return result;
    }
    const CBlockIndex* tip{loaded->second->Tip()};
    Assume(tip);
    return GetBlockViewLocked(chain_id, tip->GetBlockHash());
}

ChainManagerBlockView ChainManager::GetBlockViewLocked(
    const chainregistry::ChainId& chain_id,
    const uint256& block_hash) const
{
    AssertLockHeld(m_mutex);
    ChainManagerBlockView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerBlockViewError::NULL_CHAIN_ID;
        return result;
    }
    const auto definition{m_definitions.find(chain_id)};
    if (definition == m_definitions.end()) {
        result.error = ChainManagerBlockViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerBlockViewError::CHAIN_NOT_LOADED;
        return result;
    }
    const auto& runtime{*loaded->second};
    const auto block{runtime.GetBlockView(block_hash)};
    if (!block) {
        result.error = ChainManagerBlockViewError::BLOCK_NOT_FOUND;
        return result;
    }
    const auto* child_tip{runtime.Tip()};
    const auto* main_tip{runtime.MainHeaders()->Tip()};
    Assume(child_tip);
    Assume(main_tip);
    result.entry = {
        .chain_id = chain_id,
        .manifest_hash = definition->second.manifest_hash,
        .template_id = definition->second.manifest.spec.template_id,
        .template_version = definition->second.manifest.spec.template_version,
        .genesis_hash = definition->second.genesis_hash,
        .data_path = DataPath(chain_id),
        .loaded = true,
        .failed = runtime.IsFailed(),
        .safe_halt = runtime.Imports().IsSafeHalted(),
        .height = runtime.State().child_height,
        .tip = child_tip->GetBlockHash(),
        .main_height = static_cast<uint32_t>(main_tip->nHeight),
        .main_tip = main_tip->GetBlockHash(),
    };
    result.block = *block;
    return result;
}

ChainManagerCoinView ChainManager::GetCoinView(
    const chainregistry::ChainId& chain_id,
    const COutPoint& outpoint) const
{
    LOCK(m_mutex);
    ChainManagerCoinView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerCoinViewError::NULL_CHAIN_ID;
        return result;
    }
    const auto definition{m_definitions.find(chain_id)};
    if (definition == m_definitions.end()) {
        result.error = ChainManagerCoinViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerCoinViewError::CHAIN_NOT_LOADED;
        return result;
    }
    const auto& runtime{*loaded->second};
    const auto* child_tip{runtime.Tip()};
    const auto* main_tip{runtime.MainHeaders()->Tip()};
    Assume(child_tip);
    Assume(main_tip);
    result.entry = {
        .chain_id = chain_id,
        .manifest_hash = definition->second.manifest_hash,
        .template_id = definition->second.manifest.spec.template_id,
        .template_version = definition->second.manifest.spec.template_version,
        .genesis_hash = definition->second.genesis_hash,
        .data_path = DataPath(chain_id),
        .loaded = true,
        .failed = runtime.IsFailed(),
        .safe_halt = runtime.Imports().IsSafeHalted(),
        .height = runtime.State().child_height,
        .tip = child_tip->GetBlockHash(),
        .main_height = static_cast<uint32_t>(main_tip->nHeight),
        .main_tip = main_tip->GetBlockHash(),
    };
    result.coin = runtime.GetCoin(outpoint);
    return result;
}

std::vector<ChainManagerEntry> ChainManager::List() const
{
    LOCK(m_mutex);
    std::vector<ChainManagerEntry> result;
    result.reserve(m_definitions.size());
    for (const auto& [chain_id, definition] : m_definitions) {
        ChainManagerEntry entry{
            .chain_id = chain_id,
            .manifest_hash = definition.manifest_hash,
            .template_id = definition.manifest.spec.template_id,
            .template_version = definition.manifest.spec.template_version,
            .genesis_hash = definition.genesis_hash,
            .data_path = DataPath(chain_id),
        };
        if (const auto loaded{m_loaded.find(chain_id)};
            loaded != m_loaded.end()) {
            entry.loaded = true;
            entry.failed = loaded->second->IsFailed();
            entry.safe_halt = loaded->second->Imports().IsSafeHalted();
            entry.height = loaded->second->State().child_height;
            entry.tip = loaded->second->Tip()->GetBlockHash();
            const auto* main_tip{loaded->second->MainHeaders()->Tip()};
            Assume(main_tip);
            entry.main_height = static_cast<uint32_t>(main_tip->nHeight);
            entry.main_tip = main_tip->GetBlockHash();
        }
        result.push_back(std::move(entry));
    }
    return result;
}

size_t ChainManager::RegisteredCount() const
{
    LOCK(m_mutex);
    return m_definitions.size();
}

size_t ChainManager::LoadedCount() const
{
    LOCK(m_mutex);
    return m_loaded.size();
}

} // namespace node
