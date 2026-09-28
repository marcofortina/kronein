// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chain_manager.h>

#include <dbwrapper.h>

#include <algorithm>
#include <limits>
#include <set>
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

ChainManagerImportBuildResult BuildAuthenticatedImport(
    const ReferenceChildRuntime& runtime,
    const chainregistry::DepositProof& proof)
{
    ChainManagerImportBuildResult result;
    if (runtime.Imports().IsSafeHalted()) {
        result.error = ChainManagerImportBuildError::SAFE_HALT;
        return result;
    }

    const auto& definition{runtime.Definition()};
    result.minimum_confirmations = definition.parameters.deposit_maturity;
    const auto* main_headers{runtime.MainHeaders()};
    Assume(main_headers);
    result.authenticated = main_headers->AuthenticateDeposit(
        proof, definition.chain_id, definition.parameters.deposit_maturity);
    if (!result.authenticated.IsValid()) {
        result.error = ChainManagerImportBuildError::PROOF_REJECTED;
        return result;
    }
    if (runtime.Imports().Find(
            result.authenticated.proof.deposit_id)) {
        result.error = ChainManagerImportBuildError::ALREADY_IMPORTED;
        return result;
    }
    result.import = chainregistry::BuildReferenceChildImportTransaction(
        proof, definition);
    if (!result.import.IsValid() || !result.import.deposit_id ||
        *result.import.deposit_id != result.authenticated.proof.deposit_id) {
        result.error = ChainManagerImportBuildError::BUILD_FAILED;
    }
    return result;
}

std::pair<uint64_t, uint64_t> LocalProposalUsage(
    const ReferenceChildRuntime& runtime)
{
    const auto proposals{runtime.GetLocalProposals()};
    if (!proposals) return {};
    uint64_t bytes{0};
    for (const auto& proposal : *proposals) {
        bytes += proposal.serialized_size;
    }
    return {proposals->size(), bytes};
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
    if (m_loaded.size() >= MAX_LOADED_CHILD_CHAINS) {
        return ManagerError(ChainManagerError::TOO_MANY_LOADED_CHAINS);
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
    m_tip_changed_cv.notify_all();
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
    m_tip_changed_cv.notify_all();
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
    const uint256 old_tip{runtime->second->Tip()->GetBlockHash()};
    result.runtime = runtime->second->StageBmmAnchor(
        anchor_proof, current_time, sync);
    if (!result.runtime.IsValid()) {
        result.error = ChainManagerError::RUNTIME_REJECTED;
    } else if (runtime->second->Tip()->GetBlockHash() != old_tip) {
        m_tip_changed_cv.notify_all();
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
    const uint256 old_tip{runtime->second->Tip()->GetBlockHash()};
    result.runtime = runtime->second->ConnectBlock(
        block, anchor_proof, current_time, sync);
    if (!result.runtime.IsValid()) {
        result.error = ChainManagerError::RUNTIME_REJECTED;
    } else if (runtime->second->Tip()->GetBlockHash() != old_tip) {
        m_tip_changed_cv.notify_all();
    }
    return result;
}

ChainManagerResult ChainManager::SubmitBlockData(
    const chainregistry::ChainId& chain_id,
    const CBlock& block,
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
    const uint256 old_tip{runtime->second->Tip()->GetBlockHash()};
    result.runtime = runtime->second->ConnectStagedBlock(
        block, current_time, sync);
    if (!result.runtime.IsValid()) {
        result.error = ChainManagerError::RUNTIME_REJECTED;
    } else if (runtime->second->Tip()->GetBlockHash() != old_tip) {
        m_tip_changed_cv.notify_all();
    }
    return result;
}

ChainManagerResult ChainManager::StoreProposal(
    const chainregistry::ChainId& chain_id,
    const CBlock& block,
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
    result.runtime = runtime->second->StoreLocalProposal(
        block, current_time, sync);
    if (!result.runtime.IsValid()) {
        result.error = ChainManagerError::RUNTIME_REJECTED;
    }
    return result;
}

ChainManagerResult ChainManager::SubmitProposal(
    const chainregistry::ChainId& chain_id,
    const uint256& block_hash,
    const std::optional<chainregistry::BmmAnchorProof>& anchor_proof,
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
    const uint256 old_tip{runtime->second->Tip()->GetBlockHash()};
    result.runtime = runtime->second->SubmitLocalProposal(
        block_hash, anchor_proof, current_time, sync);
    if (!result.runtime.IsValid()) {
        result.error = ChainManagerError::RUNTIME_REJECTED;
    } else if (runtime->second->Tip()->GetBlockHash() != old_tip) {
        m_tip_changed_cv.notify_all();
    }
    return result;
}

ChainManagerResult ChainManager::RemoveProposal(
    const chainregistry::ChainId& chain_id,
    const uint256& block_hash,
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
    result.runtime = runtime->second->RemoveLocalProposal(block_hash, sync);
    if (!result.runtime.IsValid()) {
        result.error = ChainManagerError::RUNTIME_REJECTED;
    }
    return result;
}

ChainManagerImportBuildResult ChainManager::BuildImportTransaction(
    const chainregistry::ChainId& chain_id,
    const chainregistry::DepositProof& proof) const
{
    LOCK(m_mutex);
    ChainManagerImportBuildResult result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerImportBuildError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerImportBuildError::UNKNOWN_CHAIN;
        return result;
    }
    const auto runtime{m_loaded.find(chain_id)};
    if (runtime == m_loaded.end()) {
        result.error = ChainManagerImportBuildError::CHAIN_NOT_LOADED;
        return result;
    }
    return BuildAuthenticatedImport(*runtime->second, proof);
}

ChainManagerImportBlockBuildResult ChainManager::BuildImportBlock(
    const chainregistry::ChainId& chain_id,
    std::span<const chainregistry::DepositProof> proofs,
    int64_t current_time,
    bool sync,
    bool require_empty_proposal_queue)
{
    LOCK(m_mutex);
    ChainManagerImportBlockBuildResult result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerImportBlockBuildError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerImportBlockBuildError::UNKNOWN_CHAIN;
        return result;
    }
    const auto runtime{m_loaded.find(chain_id)};
    if (runtime == m_loaded.end()) {
        result.error = ChainManagerImportBlockBuildError::CHAIN_NOT_LOADED;
        return result;
    }
    if (proofs.empty()) {
        result.error = ChainManagerImportBlockBuildError::EMPTY_PROOFS;
        return result;
    }
    if (proofs.size() > MAX_CHILD_IMPORTS_PER_BLOCK) {
        result.error = ChainManagerImportBlockBuildError::TOO_MANY_PROOFS;
        return result;
    }
    const auto pruned{runtime->second->PruneInvalidLocalProposals(
        current_time, sync)};
    if (!pruned.IsValid()) {
        result.error =
            ChainManagerImportBlockBuildError::PROPOSAL_QUEUE_UNAVAILABLE;
        return result;
    }
    result.pruned_local_proposals = pruned.pruned_local_proposals;
    if (require_empty_proposal_queue) {
        const auto proposals{runtime->second->GetLocalProposals()};
        if (!proposals || !proposals->empty()) {
            result.error = ChainManagerImportBlockBuildError::PROPOSAL_PENDING;
            return result;
        }
    }

    const CBlockIndex* parent{runtime->second->Tip()};
    Assume(parent);
    const int64_t block_time{std::max({
        current_time,
        parent->GetBlockTime(),
        parent->GetMedianTimePast() + 1})};
    if (current_time < 0 || block_time < 0 ||
        block_time > std::numeric_limits<uint32_t>::max()) {
        result.error = ChainManagerImportBlockBuildError::TIME_OUT_OF_RANGE;
        return result;
    }
    result.block_time = static_cast<uint32_t>(block_time);

    std::set<chainregistry::DepositId> deposit_ids;
    std::vector<CTransactionRef> transactions;
    result.imports.reserve(proofs.size());
    transactions.reserve(proofs.size());
    for (size_t index{0}; index < proofs.size(); ++index) {
        auto imported{BuildAuthenticatedImport(
            *runtime->second, proofs[index])};
        if (!imported.IsValid()) {
            result.error =
                ChainManagerImportBlockBuildError::IMPORT_REJECTED;
            result.failed_proof = index;
            result.imports.push_back(std::move(imported));
            return result;
        }
        Assume(imported.import.deposit_id);
        Assume(imported.import.transaction);
        if (!deposit_ids.insert(*imported.import.deposit_id).second) {
            result.error =
                ChainManagerImportBlockBuildError::DUPLICATE_DEPOSIT;
            result.failed_proof = index;
            result.imports.push_back(std::move(imported));
            return result;
        }
        transactions.push_back(MakeTransactionRef(
            CMutableTransaction{*imported.import.transaction}));
        result.imports.push_back(std::move(imported));
    }

    result.build = chainregistry::BuildReferenceChildBlock(
        *parent,
        result.block_time,
        runtime->second->Definition(),
        std::move(transactions));
    if (!result.build.IsValid()) {
        result.error = ChainManagerImportBlockBuildError::BUILD_FAILED;
        return result;
    }
    result.block_height = static_cast<uint32_t>(parent->nHeight + 1);
    result.validation = runtime->second->ValidateTipBlock(
        *result.build.block, current_time);
    if (!result.validation.IsValid()) {
        result.error =
            ChainManagerImportBlockBuildError::CONTEXT_REJECTED;
        return result;
    }
    const auto stored{runtime->second->StoreLocalProposal(
        *result.build.block, current_time, sync)};
    if (!stored.IsValid()) {
        result.error =
            ChainManagerImportBlockBuildError::PROPOSAL_PERSIST_FAILED;
    } else {
        result.pruned_local_proposals.insert(
            result.pruned_local_proposals.end(),
            stored.pruned_local_proposals.begin(),
            stored.pruned_local_proposals.end());
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
    bool tip_changed{false};
    for (auto entry{m_loaded.begin()}; entry != m_loaded.end();) {
        const uint256 old_tip{entry->second->Tip()->GetBlockHash()};
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
            tip_changed = true;
            continue;
        }
        if (!advanced.main_header.already_known) {
            update.advanced.push_back(entry->first);
        }
        tip_changed |= entry->second->Tip()->GetBlockHash() != old_tip;
        ++entry;
    }
    if (tip_changed) m_tip_changed_cv.notify_all();
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
    bool tip_changed{false};
    for (auto entry{m_loaded.begin()}; entry != m_loaded.end();) {
        auto& runtime{*entry->second};
        if (runtime.MainHeaders()->Tip()->GetBlockHash() == active_tip) {
            ++entry;
            continue;
        }
        const uint256 old_tip{runtime.Tip()->GetBlockHash()};
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
            tip_changed = true;
            continue;
        }
        update.advanced.push_back(entry->first);
        tip_changed |= runtime.Tip()->GetBlockHash() != old_tip;
        ++entry;
    }
    if (tip_changed) m_tip_changed_cv.notify_all();
    return update;
}

ChainManagerMainUpdate ChainManager::ReconcileRegistry(
    const std::map<chainregistry::ChainId,
                   chainregistry::ChainRecord>& records)
{
    LOCK(m_mutex);
    ChainManagerMainUpdate update;
    bool unloaded{false};
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
            unloaded = true;
            continue;
        }
        ++entry;
    }
    if (unloaded) m_tip_changed_cv.notify_all();
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
    return GetChainViewLocked(chain_id, height);
}

ChainManagerView ChainManager::GetChainViewLocked(
    const chainregistry::ChainId& chain_id,
    std::optional<int> height) const
{
    AssertLockHeld(m_mutex);
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
    const auto pending_blocks{runtime.GetPendingBlocks()};
    const auto [local_proposal_count, local_proposal_bytes]{
        LocalProposalUsage(runtime)};
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
        .anchor_count = runtime.State().anchor_count,
        .pending_anchor_count = runtime.State().pending_anchor_count,
        .pending_anchor_bytes = runtime.State().pending_anchor_bytes,
        .pending_block_count = pending_blocks ? pending_blocks->size() : 0,
        .local_proposal_count = local_proposal_count,
        .local_proposal_bytes = local_proposal_bytes,
        .side_candidate_count = runtime.State().side_candidate_count,
        .side_candidate_bytes = runtime.State().side_candidate_bytes,
        .candidate_anchor_count = runtime.State().candidate_anchor_count,
        .candidate_anchor_bytes = runtime.State().candidate_anchor_bytes,
    };
    if (height) {
        result.block_hash = runtime.GetBlockHash(*height);
        if (!result.block_hash) {
            result.error = ChainManagerViewError::HEIGHT_OUT_OF_RANGE;
        }
    }
    return result;
}

ChainManagerWaitResult ChainManager::WaitForTipChanged(
    const chainregistry::ChainId& chain_id,
    std::optional<uint256> current_tip,
    std::optional<std::chrono::milliseconds> timeout)
{
    WAIT_LOCK(m_mutex, lock);
    ChainManagerView current{GetChainViewLocked(chain_id)};
    if (!current.IsValid()) return {.view = std::move(current)};
    const uint256 watched_tip{current_tip.value_or(current.entry.tip)};
    const auto changed{[&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        AssertLockHeld(m_mutex);
        current = GetChainViewLocked(chain_id);
        return m_interrupt_waits || !current.IsValid() ||
            current.entry.tip != watched_tip;
    }};
    if (timeout) {
        m_tip_changed_cv.wait_for(lock, *timeout, changed);
    } else {
        m_tip_changed_cv.wait(lock, changed);
    }
    return {
        .view = GetChainViewLocked(chain_id),
        .interrupted = m_interrupt_waits,
    };
}

void ChainManager::InterruptWaits()
{
    LOCK(m_mutex);
    m_interrupt_waits = true;
    m_tip_changed_cv.notify_all();
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

ChainManagerActiveBlocksView ChainManager::GetActiveBlockViews(
    const chainregistry::ChainId& chain_id,
    std::span<const uint256> block_hashes) const
{
    LOCK(m_mutex);
    ChainManagerActiveBlocksView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerActiveBlocksViewError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerActiveBlocksViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerActiveBlocksViewError::CHAIN_NOT_LOADED;
        return result;
    }

    const ChainManagerView chain_view{GetChainViewLocked(chain_id)};
    Assume(chain_view.IsValid());
    result.entry = chain_view.entry;

    std::set<uint256> seen;
    for (const uint256& block_hash : block_hashes) {
        if (!seen.insert(block_hash).second) continue;
        const auto block{loaded->second->GetBlockView(block_hash)};
        if (!block) {
            result.error = ChainManagerActiveBlocksViewError::BLOCK_NOT_FOUND;
            return result;
        }
        if (block->virtual_genesis) {
            result.error = ChainManagerActiveBlocksViewError::VIRTUAL_GENESIS;
            return result;
        }
        if (!block->active) {
            result.error = ChainManagerActiveBlocksViewError::BLOCK_NOT_ACTIVE;
            return result;
        }
        if (!block->block || !block->undo) {
            result.error = ChainManagerActiveBlocksViewError::DATA_UNAVAILABLE;
            return result;
        }
        result.blocks.push_back(*block);
    }
    std::ranges::sort(result.blocks, {}, &ReferenceChildBlockView::height);
    return result;
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
    const auto pending_blocks{runtime.GetPendingBlocks()};
    const auto [local_proposal_count, local_proposal_bytes]{
        LocalProposalUsage(runtime)};
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
        .anchor_count = runtime.State().anchor_count,
        .pending_anchor_count = runtime.State().pending_anchor_count,
        .pending_anchor_bytes = runtime.State().pending_anchor_bytes,
        .pending_block_count = pending_blocks ? pending_blocks->size() : 0,
        .local_proposal_count = local_proposal_count,
        .local_proposal_bytes = local_proposal_bytes,
        .side_candidate_count = runtime.State().side_candidate_count,
        .side_candidate_bytes = runtime.State().side_candidate_bytes,
        .candidate_anchor_count = runtime.State().candidate_anchor_count,
        .candidate_anchor_bytes = runtime.State().candidate_anchor_bytes,
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
    const auto pending_blocks{runtime.GetPendingBlocks()};
    const auto [local_proposal_count, local_proposal_bytes]{
        LocalProposalUsage(runtime)};
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
        .anchor_count = runtime.State().anchor_count,
        .pending_anchor_count = runtime.State().pending_anchor_count,
        .pending_anchor_bytes = runtime.State().pending_anchor_bytes,
        .pending_block_count = pending_blocks ? pending_blocks->size() : 0,
        .local_proposal_count = local_proposal_count,
        .local_proposal_bytes = local_proposal_bytes,
        .side_candidate_count = runtime.State().side_candidate_count,
        .side_candidate_bytes = runtime.State().side_candidate_bytes,
        .candidate_anchor_count = runtime.State().candidate_anchor_count,
        .candidate_anchor_bytes = runtime.State().candidate_anchor_bytes,
    };
    result.coin = runtime.GetCoin(outpoint);
    return result;
}

ChainManagerTipsView ChainManager::GetChainTipsView(
    const chainregistry::ChainId& chain_id) const
{
    LOCK(m_mutex);
    ChainManagerTipsView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerTipsViewError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerTipsViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerTipsViewError::CHAIN_NOT_LOADED;
        return result;
    }
    const CBlockIndex* tip{loaded->second->Tip()};
    Assume(tip);
    const auto tip_view{GetBlockViewLocked(chain_id, tip->GetBlockHash())};
    Assume(tip_view.IsValid());
    result.entry = tip_view.entry;
    const auto tips{loaded->second->GetChainTips()};
    if (!tips) {
        result.error = ChainManagerTipsViewError::DATA_UNAVAILABLE;
        return result;
    }
    result.tips = *tips;
    return result;
}

ChainManagerPendingBlocksView ChainManager::GetPendingBlocksView(
    const chainregistry::ChainId& chain_id) const
{
    LOCK(m_mutex);
    ChainManagerPendingBlocksView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerPendingBlocksViewError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerPendingBlocksViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerPendingBlocksViewError::CHAIN_NOT_LOADED;
        return result;
    }
    const auto blocks{loaded->second->GetPendingBlocks()};
    if (!blocks) {
        result.error = ChainManagerPendingBlocksViewError::DATA_UNAVAILABLE;
        return result;
    }
    result.blocks = std::move(*blocks);
    return result;
}

ChainManagerProposalsView ChainManager::GetProposalsView(
    const chainregistry::ChainId& chain_id,
    std::optional<uint256> block_hash) const
{
    LOCK(m_mutex);
    ChainManagerProposalsView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerProposalsViewError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerProposalsViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerProposalsViewError::CHAIN_NOT_LOADED;
        return result;
    }
    if (block_hash) {
        const auto proposal{loaded->second->GetLocalProposal(*block_hash)};
        if (!proposal) {
            result.error =
                ChainManagerProposalsViewError::PROPOSAL_NOT_FOUND;
            return result;
        }
        result.proposals.push_back(*proposal);
        return result;
    }
    const auto proposals{loaded->second->GetLocalProposals()};
    if (!proposals) {
        result.error = ChainManagerProposalsViewError::DATA_UNAVAILABLE;
        return result;
    }
    result.proposals = *proposals;
    return result;
}

ChainManagerBmmStatusView ChainManager::GetBmmStatusView(
    const chainregistry::ChainId& chain_id) const
{
    LOCK(m_mutex);
    ChainManagerBmmStatusView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerBmmStatusViewError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerBmmStatusViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerBmmStatusViewError::CHAIN_NOT_LOADED;
        return result;
    }

    const ChainManagerView chain_view{GetChainViewLocked(chain_id)};
    Assume(chain_view.IsValid());
    result.entry = chain_view.entry;
    const auto pending_blocks{loaded->second->GetPendingBlocks()};
    const auto proposals{loaded->second->GetLocalProposals()};
    if (!pending_blocks || !proposals) {
        result.error = ChainManagerBmmStatusViewError::DATA_UNAVAILABLE;
        return result;
    }
    result.pending_blocks = *pending_blocks;
    result.proposals = *proposals;

    if (result.entry.height != 0) {
        result.tip_anchor = loaded->second->GetBmmAnchor(result.entry.tip);
        if (!result.tip_anchor ||
            result.tip_anchor->child_block_hash != result.entry.tip ||
            result.tip_anchor->proof.block_height > result.entry.main_height ||
            result.tip_anchor->proof.block_header.GetHash().IsNull()) {
            result.error = ChainManagerBmmStatusViewError::DATA_UNAVAILABLE;
        }
    }
    return result;
}

ChainManagerUTXOStatsView ChainManager::GetUTXOStatsView(
    const chainregistry::ChainId& chain_id,
    kernel::CoinStatsHashType hash_type,
    const std::function<void()>& interruption_point) const
{
    LOCK(m_mutex);
    ChainManagerUTXOStatsView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerUTXOStatsViewError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerUTXOStatsViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerUTXOStatsViewError::CHAIN_NOT_LOADED;
        return result;
    }
    const CBlockIndex* tip{loaded->second->Tip()};
    Assume(tip);
    const auto tip_view{GetBlockViewLocked(chain_id, tip->GetBlockHash())};
    Assume(tip_view.IsValid());
    result.entry = tip_view.entry;
    const auto stats{
        loaded->second->GetUTXOStats(hash_type, interruption_point)};
    if (!stats) {
        result.error = ChainManagerUTXOStatsViewError::DATA_UNAVAILABLE;
        return result;
    }
    result.stats = *stats;
    return result;
}

ChainManagerUTXOScanView ChainManager::ScanUTXOSet(
    const chainregistry::ChainId& chain_id,
    const std::set<CScript>& needles,
    std::atomic<int>& progress,
    const std::atomic<bool>& should_abort,
    const std::function<void()>& interruption_point) const
{
    LOCK(m_mutex);
    ChainManagerUTXOScanView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerUTXOStatsViewError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerUTXOStatsViewError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerUTXOStatsViewError::CHAIN_NOT_LOADED;
        return result;
    }

    const CBlockIndex* tip{loaded->second->Tip()};
    Assume(tip);
    const auto tip_view{GetBlockViewLocked(chain_id, tip->GetBlockHash())};
    Assume(tip_view.IsValid());
    result.entry = tip_view.entry;
    auto cursor{loaded->second->GetUTXOCursor()};
    if (!cursor || cursor->GetBestBlock() != result.entry.tip) {
        result.error = ChainManagerUTXOStatsViewError::DATA_UNAVAILABLE;
        return result;
    }

    progress = 0;
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (!cursor->GetKey(outpoint) || !cursor->GetValue(coin) ||
            result.scanned == std::numeric_limits<int64_t>::max()) {
            result.error = ChainManagerUTXOStatsViewError::DATA_UNAVAILABLE;
            return result;
        }
        ++result.scanned;
        if (result.scanned % 8192 == 0) {
            if (interruption_point) interruption_point();
            if (should_abort) break;
        }
        if (result.scanned % 256 == 0) {
            const uint32_t high{
                std::to_integer<uint32_t>(outpoint.hash.begin()[0]) * 0x100U +
                std::to_integer<uint32_t>(outpoint.hash.begin()[1])};
            progress = static_cast<int>(high * 100.0 / 65536.0 + 0.5);
        }
        if (needles.contains(coin.out.scriptPubKey)) {
            result.matches.emplace(outpoint, coin);
        }
        cursor->Next();
    }
    result.completed = !cursor->Valid();
    if (result.completed) progress = 100;

    for (const auto& [_, coin] : result.matches) {
        if (coin.nHeight > result.entry.height) {
            result.error = ChainManagerUTXOStatsViewError::DATA_UNAVAILABLE;
            return result;
        }
        if (result.block_hashes.contains(coin.nHeight)) continue;
        const auto block_hash{loaded->second->GetBlockHash(coin.nHeight)};
        if (!block_hash) {
            result.error = ChainManagerUTXOStatsViewError::DATA_UNAVAILABLE;
            return result;
        }
        result.block_hashes.emplace(coin.nHeight, *block_hash);
    }
    return result;
}

ChainManagerBlockFilterScanView ChainManager::ScanBlockFilters(
    const chainregistry::ChainId& chain_id,
    int start_height,
    std::optional<int> stop_height,
    const GCSFilter::ElementSet& needles,
    bool filter_false_positives,
    std::atomic<int>& progress,
    std::atomic<int>& progress_height,
    const std::atomic<bool>& should_abort,
    const std::function<void()>& interruption_point) const
{
    LOCK(m_mutex);
    ChainManagerBlockFilterScanView result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerBlockFilterScanError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerBlockFilterScanError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerBlockFilterScanError::CHAIN_NOT_LOADED;
        return result;
    }

    const CBlockIndex* tip{loaded->second->Tip()};
    Assume(tip);
    const int last_height{stop_height.value_or(tip->nHeight)};
    if (start_height < 0 || start_height > tip->nHeight ||
        last_height < start_height || last_height > tip->nHeight) {
        result.error = ChainManagerBlockFilterScanError::HEIGHT_OUT_OF_RANGE;
        return result;
    }
    const auto chain_view{GetChainViewLocked(chain_id)};
    Assume(chain_view.IsValid());
    result.entry = chain_view.entry;
    const auto scan{loaded->second->ScanBlockFilters(
        start_height,
        last_height,
        needles,
        filter_false_positives,
        progress,
        progress_height,
        should_abort,
        interruption_point)};
    if (!scan) {
        result.error = ChainManagerBlockFilterScanError::DATA_UNAVAILABLE;
        return result;
    }
    result.scan = *scan;
    return result;
}

ChainManagerVerifyResult ChainManager::VerifyChain(
    const chainregistry::ChainId& chain_id,
    int64_t current_time) const
{
    LOCK(m_mutex);
    ChainManagerVerifyResult result;
    if (chain_id.IsNull()) {
        result.error = ChainManagerVerifyError::NULL_CHAIN_ID;
        return result;
    }
    if (!m_definitions.contains(chain_id)) {
        result.error = ChainManagerVerifyError::UNKNOWN_CHAIN;
        return result;
    }
    const auto loaded{m_loaded.find(chain_id)};
    if (loaded == m_loaded.end()) {
        result.error = ChainManagerVerifyError::CHAIN_NOT_LOADED;
        return result;
    }
    result.verified = loaded->second->VerifyDatabase(current_time);
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
            entry.anchor_count = loaded->second->State().anchor_count;
            entry.pending_anchor_count = loaded->second->State().pending_anchor_count;
            entry.pending_anchor_bytes = loaded->second->State().pending_anchor_bytes;
            if (const auto pending_blocks{
                    loaded->second->GetPendingBlocks()}) {
                entry.pending_block_count = pending_blocks->size();
            }
            const auto [local_proposal_count, local_proposal_bytes]{
                LocalProposalUsage(*loaded->second)};
            entry.local_proposal_count = local_proposal_count;
            entry.local_proposal_bytes = local_proposal_bytes;
            entry.side_candidate_count = loaded->second->State().side_candidate_count;
            entry.side_candidate_bytes = loaded->second->State().side_candidate_bytes;
            entry.candidate_anchor_count = loaded->second->State().candidate_anchor_count;
            entry.candidate_anchor_bytes = loaded->second->State().candidate_anchor_bytes;
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
