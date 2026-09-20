// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/deposit_import.h>

#include <set>
#include <utility>

namespace chainregistry {
namespace {

DepositImportResult ImportError(DepositImportError error,
                                std::optional<size_t> failed_proof = std::nullopt,
                                AuthenticatedDepositError authentication_error =
                                    AuthenticatedDepositError::NONE)
{
    DepositImportResult result;
    result.error = error;
    result.authentication_error = authentication_error;
    result.failed_proof = failed_proof;
    return result;
}

DepositImportLoadResult LoadError(DepositImportLoadError error,
                                  std::optional<size_t> failed_record = std::nullopt)
{
    DepositImportLoadResult result;
    result.error = error;
    result.failed_record = failed_record;
    return result;
}

} // namespace

DepositImportState::DepositImportState(ChainId child_chain,
                                       uint32_t minimum_confirmations)
    : m_child_chain{std::move(child_chain)},
      m_minimum_confirmations{minimum_confirmations}
{
}

const ImportedDeposit* DepositImportState::Find(const DepositId& deposit_id) const
{
    const auto it{m_imports.find(deposit_id)};
    return it == m_imports.end() ? nullptr : &it->second;
}

DepositImportLoadResult DepositImportState::LoadRecords(
    std::span<const ImportedDeposit> records,
    std::optional<DepositSafeHalt> safe_halt,
    const uint256& main_genesis_hash)
{
    if (!m_imports.empty() || m_safe_halt) {
        return LoadError(DepositImportLoadError::STATE_NOT_EMPTY);
    }
    if (m_child_chain.IsNull() || main_genesis_hash.IsNull()) {
        return LoadError(DepositImportLoadError::INVALID_CHILD_CHAIN);
    }
    if (m_minimum_confirmations == 0) {
        return LoadError(DepositImportLoadError::INVALID_CONFIRMATION_POLICY);
    }

    std::map<DepositId, ImportedDeposit> loaded;
    for (size_t index{0}; index < records.size(); ++index) {
        const ImportedDeposit& record{records[index]};
        if (record.version != IMPORTED_DEPOSIT_VERSION) {
            return LoadError(DepositImportLoadError::UNSUPPORTED_RECORD_VERSION, index);
        }
        if (record.deposit_id.IsNull()) {
            return LoadError(DepositImportLoadError::NULL_DEPOSIT_ID, index);
        }
        if (record.main_outpoint.IsNull() ||
            record.deposit_id != DeriveDepositId(main_genesis_hash, record.main_outpoint)) {
            return LoadError(DepositImportLoadError::DEPOSIT_ID_MISMATCH, index);
        }
        if (record.amount <= 0 || !MoneyRange(record.amount)) {
            return LoadError(DepositImportLoadError::INVALID_AMOUNT, index);
        }
        if (ValidateFund(record.fund) != FundValidationError::NONE) {
            return LoadError(DepositImportLoadError::INVALID_FUND, index);
        }
        if (record.fund.chain_id != m_child_chain) {
            return LoadError(DepositImportLoadError::WRONG_CHILD_CHAIN, index);
        }
        if (record.main_block_hash.IsNull() || record.main_block_height == 0) {
            return LoadError(DepositImportLoadError::INVALID_MAIN_REFERENCE, index);
        }
        if (record.child_block_hash.IsNull() || record.child_block_height == 0) {
            return LoadError(DepositImportLoadError::INVALID_CHILD_REFERENCE, index);
        }
        if (!loaded.emplace(record.deposit_id, record).second) {
            return LoadError(DepositImportLoadError::DUPLICATE_DEPOSIT_ID, index);
        }
    }

    if (safe_halt) {
        if (safe_halt->reason !=
                DepositSafeHaltReason::IMPORTED_DEPOSIT_LEFT_MAIN_CHAIN ||
            safe_halt->observed_main_tip.IsNull() ||
            safe_halt->affected_imports.empty()) {
            return LoadError(DepositImportLoadError::INVALID_SAFE_HALT);
        }
        std::set<DepositId> affected;
        for (const auto& deposit_id : safe_halt->affected_imports) {
            if (deposit_id.IsNull() || !affected.insert(deposit_id).second) {
                return LoadError(DepositImportLoadError::INVALID_SAFE_HALT);
            }
        }
    }

    m_imports = std::move(loaded);
    m_safe_halt = std::move(safe_halt);
    return {};
}

DepositImportResult DepositImportState::ImportProofs(
    std::span<const DepositProof> proofs,
    const MainHeaderChain& main_headers,
    const uint256& child_block_hash,
    uint32_t child_block_height)
{
    if (m_child_chain.IsNull()) {
        return ImportError(DepositImportError::INVALID_CHILD_CHAIN);
    }
    if (m_minimum_confirmations == 0) {
        return ImportError(DepositImportError::INVALID_CONFIRMATION_POLICY);
    }
    if (child_block_hash.IsNull()) {
        return ImportError(DepositImportError::INVALID_CHILD_BLOCK);
    }
    if (m_safe_halt) return ImportError(DepositImportError::SAFE_HALT);

    std::set<DepositId> batch_ids;
    std::vector<ImportedDeposit> pending;
    pending.reserve(proofs.size());
    for (size_t index{0}; index < proofs.size(); ++index) {
        const DepositProof& proof{proofs[index]};
        const auto authenticated{main_headers.AuthenticateDeposit(
            proof, m_child_chain, m_minimum_confirmations)};
        if (!authenticated.IsValid()) {
            return ImportError(
                DepositImportError::PROOF_REJECTED, index, authenticated.error);
        }

        const DepositId& deposit_id{authenticated.proof.deposit_id};
        if (m_imports.contains(deposit_id)) {
            return ImportError(DepositImportError::ALREADY_IMPORTED, index);
        }
        if (!batch_ids.insert(deposit_id).second) {
            return ImportError(DepositImportError::DUPLICATE_IN_BATCH, index);
        }

        const FundOutput& fund{*authenticated.proof.fund};
        const CTransaction funding_transaction{proof.funding_transaction};
        pending.push_back({
            .deposit_id = deposit_id,
            .main_outpoint = COutPoint{funding_transaction.GetHash(), proof.funding_vout},
            .amount = fund.amount,
            .fund = fund.fund,
            .main_block_hash = proof.block_header.GetHash(),
            .main_block_height = proof.block_height,
            .child_block_hash = child_block_hash,
            .child_block_height = child_block_height,
        });
    }

    DepositImportResult result;
    result.imports = pending;
    result.undo.imports.reserve(pending.size());
    for (auto& imported : pending) {
        result.undo.imports.push_back(imported.deposit_id);
        m_imports.emplace(imported.deposit_id, std::move(imported));
    }
    return result;
}

DepositImportResult DepositImportState::ImportProof(
    const DepositProof& proof,
    const MainHeaderChain& main_headers,
    const uint256& child_block_hash,
    uint32_t child_block_height)
{
    return ImportProofs(
        std::span<const DepositProof>{&proof, 1},
        main_headers,
        child_block_hash,
        child_block_height);
}

bool DepositImportState::DisconnectImports(const uint256& child_block_hash,
                                           const DepositImportUndo& undo)
{
    std::set<DepositId> unique;
    for (const auto& deposit_id : undo.imports) {
        const auto it{m_imports.find(deposit_id)};
        if (!unique.insert(deposit_id).second || it == m_imports.end() ||
            it->second.child_block_hash != child_block_hash) {
            return false;
        }
    }
    for (const auto& deposit_id : undo.imports) m_imports.erase(deposit_id);
    return true;
}

DepositReconcileResult DepositImportState::Reconcile(
    const MainHeaderChain& main_headers)
{
    if (m_safe_halt) {
        return {
            .safe_halt = true,
            .newly_halted = false,
            .affected_imports = m_safe_halt->affected_imports,
        };
    }

    std::vector<DepositId> affected;
    for (const auto& [deposit_id, imported] : m_imports) {
        const MainHeaderStatus status{main_headers.GetStatus(imported.main_block_hash)};
        if (!status.known || !status.active ||
            status.height != static_cast<int>(imported.main_block_height)) {
            affected.push_back(deposit_id);
        }
    }
    if (affected.empty()) return {};

    const CBlockIndex* tip{main_headers.Tip()};
    m_safe_halt = DepositSafeHalt{
        .observed_main_tip = tip ? tip->GetBlockHash() : uint256{},
        .affected_imports = affected,
    };
    return {
        .safe_halt = true,
        .newly_halted = true,
        .affected_imports = std::move(affected),
    };
}

} // namespace chainregistry
