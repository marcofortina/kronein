// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_CHAINREGISTRY_DEPOSIT_IMPORT_H
#define KRONEIN_CHAINREGISTRY_DEPOSIT_IMPORT_H

#include <chainregistry/mainchain_lightclient.h>
#include <consensus/amount.h>
#include <consensus/deposit_proof.h>
#include <primitives/chainregistry.h>
#include <primitives/deposit.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace chainregistry {

inline constexpr uint8_t IMPORTED_DEPOSIT_VERSION{1};

/** Consensus record proving that one main-chain burn was consumed by a child. */
struct ImportedDeposit {
    uint8_t version{IMPORTED_DEPOSIT_VERSION};
    DepositId deposit_id;
    COutPoint main_outpoint;
    CAmount amount{0};
    FundChain fund;
    uint256 main_block_hash;
    uint32_t main_block_height{0};
    uint256 child_block_hash;
    uint32_t child_block_height{0};

    SERIALIZE_METHODS(ImportedDeposit, obj)
    {
        READWRITE(obj.version,
                  obj.deposit_id,
                  obj.main_outpoint,
                  obj.amount,
                  obj.fund,
                  obj.main_block_hash,
                  obj.main_block_height,
                  obj.child_block_hash,
                  obj.child_block_height);
    }

    friend bool operator==(const ImportedDeposit&, const ImportedDeposit&) = default;
};

struct DepositImportUndo {
    std::vector<DepositId> imports;

    SERIALIZE_METHODS(DepositImportUndo, obj) { READWRITE(obj.imports); }

    friend bool operator==(const DepositImportUndo&, const DepositImportUndo&) = default;
};

enum class DepositImportError : uint8_t {
    NONE,
    INVALID_CHILD_CHAIN,
    INVALID_CONFIRMATION_POLICY,
    INVALID_CHILD_BLOCK,
    SAFE_HALT,
    PROOF_REJECTED,
    ALREADY_IMPORTED,
    DUPLICATE_IN_BATCH,
};

struct DepositImportResult {
    DepositImportError error{DepositImportError::NONE};
    AuthenticatedDepositError authentication_error{AuthenticatedDepositError::NONE};
    std::optional<size_t> failed_proof;
    std::vector<ImportedDeposit> imports;
    DepositImportUndo undo;

    bool IsValid() const { return error == DepositImportError::NONE; }
};

enum class DepositSafeHaltReason : uint8_t {
    IMPORTED_DEPOSIT_LEFT_MAIN_CHAIN,
};

struct DepositSafeHalt {
    DepositSafeHaltReason reason{DepositSafeHaltReason::IMPORTED_DEPOSIT_LEFT_MAIN_CHAIN};
    uint256 observed_main_tip;
    std::vector<DepositId> affected_imports;

    SERIALIZE_METHODS(DepositSafeHalt, obj)
    {
        READWRITE(obj.reason, obj.observed_main_tip, obj.affected_imports);
    }

    friend bool operator==(const DepositSafeHalt&, const DepositSafeHalt&) = default;
};

struct DepositReconcileResult {
    bool safe_halt{false};
    bool newly_halted{false};
    std::vector<DepositId> affected_imports;
};

/**
 * Child consensus ledger for one-way main-chain imports.
 *
 * A batch is validated completely before any deposit ID is consumed. Child
 * block disconnects use the returned undo record. Once an imported deposit
 * leaves the active main chain, the ledger enters a fail-closed SAFE_HALT that
 * cannot be cleared implicitly by a later header or child reorganization.
 */
class DepositImportState
{
private:
    ChainId m_child_chain;
    uint32_t m_minimum_confirmations{0};
    std::map<DepositId, ImportedDeposit> m_imports;
    std::optional<DepositSafeHalt> m_safe_halt;

public:
    DepositImportState(ChainId child_chain, uint32_t minimum_confirmations);

    const ChainId& ChildChain() const { return m_child_chain; }
    uint32_t MinimumConfirmations() const { return m_minimum_confirmations; }
    size_t Size() const { return m_imports.size(); }
    bool IsSafeHalted() const { return m_safe_halt.has_value(); }
    const std::optional<DepositSafeHalt>& SafeHalt() const { return m_safe_halt; }
    const std::map<DepositId, ImportedDeposit>& Imports() const { return m_imports; }
    const ImportedDeposit* Find(const DepositId& deposit_id) const;

    DepositImportResult ImportProofs(std::span<const DepositProof> proofs,
                                     const MainHeaderChain& main_headers,
                                     const uint256& child_block_hash,
                                     uint32_t child_block_height);
    DepositImportResult ImportProof(const DepositProof& proof,
                                    const MainHeaderChain& main_headers,
                                    const uint256& child_block_hash,
                                    uint32_t child_block_height);
    bool DisconnectImports(const uint256& child_block_hash,
                           const DepositImportUndo& undo);
    DepositReconcileResult Reconcile(const MainHeaderChain& main_headers);
};

} // namespace chainregistry

#endif // KRONEIN_CHAINREGISTRY_DEPOSIT_IMPORT_H
