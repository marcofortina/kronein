// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/mainchain_lightclient.h>

#include <consensus/consensus.h>
#include <pow.h>
#include <util/check.h>

#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace chainregistry {
namespace {

MainHeaderResult HeaderError(MainHeaderError error, const uint256& hash = {})
{
    MainHeaderResult result;
    result.error = error;
    result.block_hash = hash;
    return result;
}

AuthenticatedDepositResult DepositError(
    AuthenticatedDepositError error,
    DepositProofValidationResult proof = {})
{
    AuthenticatedDepositResult result;
    result.error = error;
    result.proof = std::move(proof);
    return result;
}

MainHeaderLoadResult LoadError(MainHeaderLoadError error,
                               std::optional<size_t> failed_record = std::nullopt,
                               MainHeaderError header_error = MainHeaderError::NONE)
{
    MainHeaderLoadResult result;
    result.error = error;
    result.header_error = header_error;
    result.failed_record = failed_record;
    return result;
}

} // namespace

MainHeaderChain::MainHeaderChain(Consensus::Params params)
    : m_params{std::move(params)}
{
}

MainHeaderResult MainHeaderChain::Initialize(const CBlockHeader& genesis)
{
    m_headers.clear();
    m_tip = nullptr;

    const uint256 hash{genesis.GetHash()};
    if (hash != m_params.hashGenesisBlock || !genesis.hashPrevBlock.IsNull()) {
        return HeaderError(MainHeaderError::WRONG_GENESIS, hash);
    }
    if (!CheckProofOfWork(genesis, m_params)) {
        return HeaderError(MainHeaderError::INVALID_GENESIS_POW, hash);
    }

    auto [it, inserted]{m_headers.try_emplace(hash, genesis)};
    Assume(inserted);
    CBlockIndex& entry{it->second};
    entry.phashBlock = &it->first;
    entry.nHeight = 0;
    entry.nChainWork = GetBlockProof(entry);
    entry.nTimeMax = entry.nTime;
    m_tip = &entry;

    MainHeaderResult result;
    result.block_hash = hash;
    result.height = 0;
    result.became_best = true;
    result.fork_height = 0;
    return result;
}

MainHeaderResult MainHeaderChain::AddHeader(const CBlockHeader& header,
                                            int64_t current_time)
{
    const uint256 hash{header.GetHash()};
    if (!m_tip) return HeaderError(MainHeaderError::NOT_INITIALIZED, hash);
    if (const auto known{m_headers.find(hash)}; known != m_headers.end()) {
        MainHeaderResult result;
        result.block_hash = hash;
        result.height = known->second.nHeight;
        result.already_known = true;
        return result;
    }

    const auto parent_it{m_headers.find(header.hashPrevBlock)};
    if (parent_it == m_headers.end()) {
        return HeaderError(MainHeaderError::UNKNOWN_PARENT, hash);
    }
    CBlockIndex* const parent{&parent_it->second};
    const int height{parent->nHeight + 1};
    if (header.nVersion != CBlockHeader::CURRENT_VERSION) {
        return HeaderError(MainHeaderError::INVALID_VERSION, hash);
    }
    if (header.nBits != GetNextWorkRequired(parent, &header, m_params)) {
        return HeaderError(MainHeaderError::INVALID_DIFFICULTY, hash);
    }
    const auto randomx_seed{GetRandomXSeed(parent, height, m_params)};
    if (!randomx_seed) {
        return HeaderError(MainHeaderError::RANDOMX_SEED_UNAVAILABLE, hash);
    }
    if (!CheckProofOfWork(header, *randomx_seed, m_params)) {
        return HeaderError(MainHeaderError::INVALID_PROOF_OF_WORK, hash);
    }
    if (header.GetBlockTime() <= parent->GetMedianTimePast()) {
        return HeaderError(MainHeaderError::TIME_TOO_OLD, hash);
    }
    if (m_params.enforce_timestamp_monotonicity &&
        header.GetBlockTime() < parent->GetBlockTime()) {
        return HeaderError(MainHeaderError::TIME_MOVED_BACKWARDS, hash);
    }
    if (m_params.enforce_BIP94 &&
        height % m_params.DifficultyAdjustmentInterval() == 0 &&
        header.GetBlockTime() < parent->GetBlockTime() - MAX_TIMEWARP) {
        return HeaderError(MainHeaderError::TIMEWARP, hash);
    }
    if (header.GetBlockTime() > current_time + MAX_FUTURE_BLOCK_TIME) {
        return HeaderError(MainHeaderError::TIME_TOO_NEW, hash);
    }

    CBlockIndex* const old_tip{m_tip};
    auto [it, inserted]{m_headers.try_emplace(hash, header)};
    Assume(inserted);
    CBlockIndex& entry{it->second};
    entry.phashBlock = &it->first;
    entry.pprev = parent;
    entry.nHeight = height;
    entry.nChainWork = parent->nChainWork + GetBlockProof(entry);
    entry.nTimeMax = std::max(parent->nTimeMax, entry.nTime);
    entry.BuildSkip();

    MainHeaderResult result;
    result.block_hash = hash;
    result.height = height;
    if (entry.nChainWork > m_tip->nChainWork) {
        const CBlockIndex* fork{LastCommonAncestor(old_tip, &entry)};
        result.became_best = true;
        result.previous_best = old_tip->GetBlockHash();
        result.fork_height = fork->nHeight;
        result.disconnected_headers = static_cast<uint32_t>(
            old_tip->nHeight - fork->nHeight);
        m_tip = &entry;
    }
    return result;
}

std::vector<MainHeaderRecord> MainHeaderChain::ExportHeaders() const
{
    std::vector<MainHeaderRecord> records;
    records.reserve(m_headers.size());
    for (const auto& [hash, entry] : m_headers) {
        records.push_back({
            .height = static_cast<uint32_t>(entry.nHeight),
            .header = entry.GetBlockHeader(),
        });
    }
    std::sort(records.begin(), records.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.height != rhs.height) return lhs.height < rhs.height;
        return lhs.header.GetHash() < rhs.header.GetHash();
    });
    return records;
}

MainHeaderLoadResult MainHeaderChain::LoadHeaders(
    std::span<const MainHeaderRecord> records,
    const uint256& active_tip,
    int64_t current_time)
{
    if (records.empty()) return LoadError(MainHeaderLoadError::EMPTY);

    std::vector<MainHeaderRecord> ordered{records.begin(), records.end()};
    std::sort(ordered.begin(), ordered.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.height != rhs.height) return lhs.height < rhs.height;
        return lhs.header.GetHash() < rhs.header.GetHash();
    });
    std::set<uint256> hashes;
    for (size_t index{0}; index < ordered.size(); ++index) {
        if (ordered[index].version != MAIN_HEADER_RECORD_VERSION) {
            return LoadError(MainHeaderLoadError::UNSUPPORTED_RECORD_VERSION, index);
        }
        if (ordered[index].height > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
            return LoadError(MainHeaderLoadError::INVALID_HEIGHT, index);
        }
        if (!hashes.insert(ordered[index].header.GetHash()).second) {
            return LoadError(MainHeaderLoadError::DUPLICATE_HEADER, index);
        }
    }
    if (ordered.front().height != 0 ||
        ordered.front().header.GetHash() != m_params.hashGenesisBlock) {
        return LoadError(MainHeaderLoadError::MISSING_GENESIS, 0);
    }

    MainHeaderChain loaded{m_params};
    const auto initialized{loaded.Initialize(ordered.front().header)};
    if (!initialized.IsValid()) {
        return LoadError(
            MainHeaderLoadError::HEADER_REJECTED, 0, initialized.error);
    }
    for (size_t index{1}; index < ordered.size(); ++index) {
        if (ordered[index].height == 0) {
            return LoadError(MainHeaderLoadError::INVALID_HEIGHT, index);
        }
        const auto added{loaded.AddHeader(ordered[index].header, current_time)};
        if (!added.IsValid()) {
            return LoadError(
                MainHeaderLoadError::HEADER_REJECTED, index, added.error);
        }
        if (added.height != static_cast<int>(ordered[index].height)) {
            return LoadError(MainHeaderLoadError::INVALID_HEIGHT, index);
        }
    }

    const CBlockIndex* preferred{loaded.Find(active_tip)};
    if (!preferred || !loaded.m_tip ||
        preferred->nChainWork != loaded.m_tip->nChainWork) {
        return LoadError(MainHeaderLoadError::INVALID_ACTIVE_TIP);
    }

    m_headers = std::move(loaded.m_headers);
    m_tip = &m_headers.find(active_tip)->second;
    return {};
}

const CBlockIndex* MainHeaderChain::Find(const uint256& block_hash) const
{
    const auto it{m_headers.find(block_hash)};
    return it == m_headers.end() ? nullptr : &it->second;
}

bool MainHeaderChain::IsActive(const CBlockIndex& entry) const
{
    if (!m_tip || entry.nHeight > m_tip->nHeight) return false;
    return m_tip->GetAncestor(entry.nHeight) == &entry;
}

MainHeaderStatus MainHeaderChain::GetStatus(const uint256& block_hash) const
{
    MainHeaderStatus result;
    const CBlockIndex* entry{Find(block_hash)};
    if (!entry) return result;
    result.known = true;
    result.active = IsActive(*entry);
    result.height = entry->nHeight;
    result.confirmations = result.active ? m_tip->nHeight - entry->nHeight + 1 : 0;
    result.chain_work = entry->nChainWork;
    return result;
}

AuthenticatedDepositResult MainHeaderChain::AuthenticateDeposit(
    const DepositProof& proof,
    const ChainId& expected_child_chain,
    uint32_t minimum_confirmations) const
{
    if (minimum_confirmations == 0) {
        return DepositError(AuthenticatedDepositError::INVALID_CONFIRMATION_POLICY);
    }
    const auto structural{ValidateDepositProofStructure(
        proof, m_params.hashGenesisBlock, expected_child_chain)};
    if (!structural.IsValid()) {
        return DepositError(
            AuthenticatedDepositError::STRUCTURAL_PROOF_INVALID, structural);
    }
    const CBlockIndex* entry{Find(proof.block_header.GetHash())};
    if (!entry) {
        return DepositError(AuthenticatedDepositError::HEADER_UNKNOWN, structural);
    }
    if (entry->nHeight != static_cast<int>(proof.block_height)) {
        return DepositError(
            AuthenticatedDepositError::HEADER_HEIGHT_MISMATCH, structural);
    }
    if (!IsActive(*entry)) {
        return DepositError(AuthenticatedDepositError::HEADER_NOT_ACTIVE, structural);
    }
    if (m_tip->nChainWork < UintToArith256(m_params.nMinimumChainWork)) {
        return DepositError(
            AuthenticatedDepositError::INSUFFICIENT_CHAINWORK, structural);
    }
    const int confirmations{m_tip->nHeight - entry->nHeight + 1};
    if (confirmations < static_cast<int64_t>(minimum_confirmations)) {
        auto result{DepositError(AuthenticatedDepositError::IMMATURE, structural)};
        result.confirmations = confirmations;
        result.tip_chain_work = m_tip->nChainWork;
        return result;
    }

    AuthenticatedDepositResult result;
    result.proof = structural;
    result.confirmations = confirmations;
    result.tip_chain_work = m_tip->nChainWork;
    return result;
}

} // namespace chainregistry
