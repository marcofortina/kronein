// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_CHAINREGISTRY_MAINCHAIN_LIGHTCLIENT_H
#define KRONEIN_CHAINREGISTRY_MAINCHAIN_LIGHTCLIENT_H

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/bmm.h>
#include <consensus/deposit_proof.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <serialize.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace chainregistry {

inline constexpr uint8_t MAIN_HEADER_RECORD_VERSION{1};

struct MainHeaderRecord {
    uint8_t version{MAIN_HEADER_RECORD_VERSION};
    uint32_t height{0};
    CBlockHeader header;

    SERIALIZE_METHODS(MainHeaderRecord, obj)
    {
        READWRITE(obj.version, obj.height, obj.header);
    }

    friend bool operator==(const MainHeaderRecord&, const MainHeaderRecord&) = default;
};

enum class MainHeaderError : uint8_t {
    NONE,
    NOT_INITIALIZED,
    WRONG_GENESIS,
    INVALID_GENESIS_POW,
    UNKNOWN_PARENT,
    INVALID_VERSION,
    INVALID_DIFFICULTY,
    RANDOMX_SEED_UNAVAILABLE,
    INVALID_PROOF_OF_WORK,
    TIME_TOO_OLD,
    TIME_MOVED_BACKWARDS,
    TIMEWARP,
    TIME_TOO_NEW,
};

enum class MainHeaderLoadError : uint8_t {
    NONE,
    EMPTY,
    UNSUPPORTED_RECORD_VERSION,
    DUPLICATE_HEADER,
    MISSING_GENESIS,
    INVALID_HEIGHT,
    HEADER_REJECTED,
    INVALID_ACTIVE_TIP,
};

struct MainHeaderLoadResult {
    MainHeaderLoadError error{MainHeaderLoadError::NONE};
    MainHeaderError header_error{MainHeaderError::NONE};
    std::optional<size_t> failed_record;

    bool IsValid() const { return error == MainHeaderLoadError::NONE; }
};

struct MainHeaderResult {
    MainHeaderError error{MainHeaderError::NONE};
    uint256 block_hash;
    int height{-1};
    bool already_known{false};
    bool became_best{false};
    uint256 previous_best;
    int fork_height{-1};
    uint32_t disconnected_headers{0};

    bool IsValid() const { return error == MainHeaderError::NONE; }
};

struct MainHeaderStatus {
    bool known{false};
    bool active{false};
    int height{-1};
    int confirmations{0};
    arith_uint256 chain_work;
};

enum class AuthenticatedDepositError : uint8_t {
    NONE,
    INVALID_CONFIRMATION_POLICY,
    STRUCTURAL_PROOF_INVALID,
    HEADER_UNKNOWN,
    HEADER_HEIGHT_MISMATCH,
    HEADER_NOT_ACTIVE,
    INSUFFICIENT_CHAINWORK,
    IMMATURE,
};

struct AuthenticatedDepositResult {
    AuthenticatedDepositError error{AuthenticatedDepositError::NONE};
    DepositProofValidationResult proof;
    int confirmations{0};
    arith_uint256 tip_chain_work;

    bool IsValid() const { return error == AuthenticatedDepositError::NONE; }
};

enum class AuthenticatedBmmAnchorError : uint8_t {
    NONE,
    INVALID_CONFIRMATION_POLICY,
    STRUCTURAL_PROOF_INVALID,
    HEADER_UNKNOWN,
    HEADER_HEIGHT_MISMATCH,
    HEADER_NOT_ACTIVE,
    INSUFFICIENT_CHAINWORK,
    IMMATURE,
};

struct AuthenticatedBmmAnchorResult {
    AuthenticatedBmmAnchorError error{AuthenticatedBmmAnchorError::NONE};
    BmmProofValidationResult proof;
    int confirmations{0};
    arith_uint256 anchor_chain_work;
    arith_uint256 tip_chain_work;

    bool IsValid() const { return error == AuthenticatedBmmAnchorError::NONE; }
};

/**
 * Minimal main-chain header DAG for child-chain consensus.
 *
 * It validates the same RandomX, difficulty, timestamp and most-work rules as
 * the main node. Full block data, the UTXO set and main-chain RPC trust are not
 * part of this component. Headers are retained so RandomX epoch seeds and fork
 * proofs remain locally derivable.
 */
class MainHeaderChain
{
private:
    Consensus::Params m_params;
    std::map<uint256, CBlockIndex> m_headers;
    CBlockIndex* m_tip{nullptr};

    bool IsActive(const CBlockIndex& entry) const;

public:
    explicit MainHeaderChain(Consensus::Params params);

    MainHeaderResult Initialize(const CBlockHeader& genesis);
    MainHeaderResult AddHeader(const CBlockHeader& header, int64_t current_time);
    std::vector<MainHeaderRecord> ExportHeaders() const;
    MainHeaderLoadResult LoadHeaders(std::span<const MainHeaderRecord> records,
                                     const uint256& active_tip,
                                     int64_t current_time);

    bool IsInitialized() const { return m_tip != nullptr; }
    const Consensus::Params& Params() const { return m_params; }
    const CBlockIndex* Tip() const { return m_tip; }
    const CBlockIndex* Find(const uint256& block_hash) const;
    MainHeaderStatus GetStatus(const uint256& block_hash) const;

    AuthenticatedDepositResult AuthenticateDeposit(
        const DepositProof& proof,
        const ChainId& expected_child_chain,
        uint32_t minimum_confirmations) const;
    AuthenticatedBmmAnchorResult AuthenticateBmmAnchor(
        const BmmAnchorProof& proof,
        const ChainId& expected_child_chain,
        uint32_t minimum_confirmations) const;
};

} // namespace chainregistry

#endif // KRONEIN_CHAINREGISTRY_MAINCHAIN_LIGHTCLIENT_H
