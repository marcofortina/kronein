// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/chainregistry.h>

#include <primitives/block.h>

#include <optional>
#include <utility>

namespace node {
namespace {

ChainRegistryStateResult StateError(ChainRegistryStateError error)
{
    ChainRegistryStateResult result;
    result.error = error;
    return result;
}

bool ExpectedTipIsValid(const uint256& tip, int height)
{
    return (tip.IsNull() && height == -1) || (!tip.IsNull() && height >= 0);
}

std::optional<chainregistry::DepositValidationParams> DepositParamsForHeight(
    const Consensus::Params::ChainRegistryParams& params,
    int height)
{
    if (!params.DepositsActive(height)) return std::nullopt;
    return chainregistry::DepositValidationParams{
        .minimum_amount = params.minimum_deposit_amount,
        .maximum_deposits = params.maximum_deposits,
    };
}

} // namespace

ChainRegistryState::ChainRegistryState(Consensus::Params::ChainRegistryParams params,
                                       const uint256& main_genesis_hash)
    : m_params{params}, m_main_genesis_hash{main_genesis_hash}
{
    if (!Enabled()) {
        m_state = MakeChainRegistryDBState({}, 0, m_registry);
        m_initialized = true;
    }
}

ChainRegistryStateResult ChainRegistryState::Initialize(const DBParams& db_params,
                                                        const uint256& expected_tip,
                                                        int expected_height)
{
    if (!ExpectedTipIsValid(expected_tip, expected_height)) {
        return StateError(ChainRegistryStateError::INVALID_EXPECTED_TIP);
    }

    if (!Enabled()) {
        m_state = MakeChainRegistryDBState(expected_tip,
                                           expected_height < 0 ? 0 : static_cast<uint32_t>(expected_height),
                                           m_registry);
        m_initialized = true;
        return {};
    }

    m_db = std::make_unique<ChainRegistryDB>(db_params);
    ChainRegistryDBState loaded_state;
    auto load_result{m_db->Load(m_registry, loaded_state)};
    if (!load_result.IsValid()) {
        ChainRegistryStateResult result;
        result.error = ChainRegistryStateError::DATABASE_LOAD_FAILED;
        result.load_result = std::move(load_result);
        return result;
    }

    if (!load_result.initialized) {
        if (m_params.IsActive(expected_height)) {
            return StateError(ChainRegistryStateError::ACTIVE_STATE_REQUIRES_REINDEX);
        }
        loaded_state = MakeChainRegistryDBState(
            expected_tip,
            expected_height < 0 ? 0 : static_cast<uint32_t>(expected_height),
            m_registry);
        if (!m_db->WriteInitialState(m_registry, loaded_state, /*sync=*/true)) {
            return StateError(ChainRegistryStateError::DATABASE_WRITE_FAILED);
        }
    } else if (loaded_state.best_block != expected_tip ||
               (expected_height >= 0 && loaded_state.height != static_cast<uint32_t>(expected_height))) {
        return StateError(ChainRegistryStateError::DATABASE_TIP_MISMATCH);
    }

    m_state = loaded_state;
    m_initialized = true;
    return {};
}

ChainRegistryStateResult ChainRegistryState::InitializeFromSnapshot(
    const DBParams& db_params,
    const uint256& expected_tip,
    int expected_height,
    chainregistry::ChainRegistry registry,
    const uint256& expected_root)
{
    if (!ExpectedTipIsValid(expected_tip, expected_height)) {
        return StateError(ChainRegistryStateError::INVALID_EXPECTED_TIP);
    }
    if (!Enabled() || !m_params.IsActive(expected_height)) {
        return StateError(ChainRegistryStateError::SNAPSHOT_HEIGHT_INACTIVE);
    }
    if (registry.ComputeRoot() != expected_root) {
        return StateError(ChainRegistryStateError::SNAPSHOT_ROOT_MISMATCH);
    }

    m_db = std::make_unique<ChainRegistryDB>(db_params);
    chainregistry::ChainRegistry existing_registry;
    ChainRegistryDBState existing_state;
    auto load_result{m_db->Load(existing_registry, existing_state)};
    if (!load_result.IsValid()) {
        ChainRegistryStateResult result;
        result.error = ChainRegistryStateError::DATABASE_LOAD_FAILED;
        result.load_result = std::move(load_result);
        return result;
    }
    if (load_result.initialized) {
        return StateError(ChainRegistryStateError::DATABASE_ALREADY_INITIALIZED);
    }

    const auto snapshot_state{MakeChainRegistryDBState(
        expected_tip, static_cast<uint32_t>(expected_height), registry)};
    if (!m_db->WriteInitialState(registry, snapshot_state, /*sync=*/true)) {
        return StateError(ChainRegistryStateError::DATABASE_WRITE_FAILED);
    }

    m_registry = std::move(registry);
    m_state = snapshot_state;
    m_initialized = true;
    return {};
}

ChainRegistryStateResult ChainRegistryState::ConnectBlock(const CBlock& block,
                                                          int height,
                                                          const uint256& block_hash,
                                                          bool sync)
{
    auto validation{ValidateBlock(block, height, block_hash)};
    if (!validation.IsValid() || !Enabled()) return validation;

    chainregistry::ChainRegistry candidate{m_registry};
    chainregistry::RegistryBlockUndo undo;
    chainregistry::RegistryBlockResult block_result;
    if (m_params.IsActive(height)) {
        block_result = candidate.ApplyBlock(block,
                                            static_cast<uint32_t>(height),
                                            m_main_genesis_hash,
                                            m_params.minimum_registration_burn,
                                            m_params.maximum_operations,
                                            chainregistry::CommitmentRequirement::REQUIRED,
                                            DepositParamsForHeight(m_params, height));
        if (!block_result.IsValid()) {
            ChainRegistryStateResult result;
            result.error = ChainRegistryStateError::INVALID_BLOCK;
            result.block_result = std::move(block_result);
            return result;
        }
        undo = *block_result.undo;
    }

    const auto next_state{MakeChainRegistryDBState(block_hash, static_cast<uint32_t>(height), candidate)};
    if (!m_db->WriteConnectedBlock(candidate, next_state, block_hash, undo, sync)) {
        return StateError(ChainRegistryStateError::DATABASE_WRITE_FAILED);
    }
    m_registry = std::move(candidate);
    m_state = next_state;

    ChainRegistryStateResult result;
    result.block_result = std::move(block_result);
    return result;
}

ChainRegistryStateResult ChainRegistryState::ValidateBlock(const CBlock& block,
                                                           int height,
                                                           const uint256& block_hash) const
{
    if (!m_initialized) return StateError(ChainRegistryStateError::NOT_INITIALIZED);
    if (!Enabled()) return {};
    if (height < 0 || block.GetHash() != block_hash) {
        return StateError(ChainRegistryStateError::NON_SEQUENTIAL_BLOCK);
    }

    const bool connects_genesis{m_state.best_block.IsNull() && height == 0 && block.hashPrevBlock.IsNull()};
    const bool connects_tip{!m_state.best_block.IsNull() &&
                            block.hashPrevBlock == m_state.best_block &&
                            static_cast<uint32_t>(height) == m_state.height + 1};
    if (!connects_genesis && !connects_tip) {
        return StateError(ChainRegistryStateError::NON_SEQUENTIAL_BLOCK);
    }

    if (!m_params.IsActive(height)) return {};

    chainregistry::ChainRegistry candidate{m_registry};
    auto block_result{candidate.ApplyBlock(block,
                                           static_cast<uint32_t>(height),
                                           m_main_genesis_hash,
                                           m_params.minimum_registration_burn,
                                           m_params.maximum_operations,
                                           chainregistry::CommitmentRequirement::REQUIRED,
                                           DepositParamsForHeight(m_params, height))};
    if (!block_result.IsValid()) {
        ChainRegistryStateResult result;
        result.error = ChainRegistryStateError::INVALID_BLOCK;
        result.block_result = std::move(block_result);
        return result;
    }
    ChainRegistryStateResult result;
    result.block_result = std::move(block_result);
    return result;
}

ChainRegistryStateResult ChainRegistryState::DisconnectBlock(const uint256& block_hash,
                                                             const uint256& parent_hash,
                                                             int parent_height,
                                                             bool sync)
{
    if (!m_initialized) return StateError(ChainRegistryStateError::NOT_INITIALIZED);
    if (!Enabled()) return {};
    if (m_state.best_block != block_hash || parent_height < -1 ||
        (parent_height < 0 && !parent_hash.IsNull()) ||
        (parent_height >= 0 && parent_hash.IsNull()) ||
        (parent_height < 0 && m_state.height != 0) ||
        (parent_height >= 0 && static_cast<uint32_t>(parent_height + 1) != m_state.height)) {
        return StateError(ChainRegistryStateError::NON_SEQUENTIAL_BLOCK);
    }

    chainregistry::RegistryBlockUndo undo;
    if (!m_db->ReadUndo(block_hash, undo)) {
        return StateError(ChainRegistryStateError::UNDO_MISSING);
    }

    chainregistry::ChainRegistry candidate{m_registry};
    if (!candidate.UndoBlock(undo)) {
        return StateError(ChainRegistryStateError::UNDO_FAILED);
    }
    const auto parent_state{MakeChainRegistryDBState(
        parent_hash,
        parent_height < 0 ? 0 : static_cast<uint32_t>(parent_height),
        candidate)};
    if (!m_db->WriteDisconnectedBlock(candidate, parent_state, block_hash, undo, sync)) {
        return StateError(ChainRegistryStateError::DATABASE_WRITE_FAILED);
    }
    m_registry = std::move(candidate);
    m_state = parent_state;
    return {};
}

ChainRegistryStateResult ChainRegistryState::PruneUndo(std::span<const uint256> block_hashes,
                                                       bool sync)
{
    if (!m_initialized) return StateError(ChainRegistryStateError::NOT_INITIALIZED);
    if (!Enabled() || block_hashes.empty()) return {};
    if (!m_db->EraseUndo(block_hashes, sync)) {
        return StateError(ChainRegistryStateError::DATABASE_WRITE_FAILED);
    }
    return {};
}

} // namespace node
