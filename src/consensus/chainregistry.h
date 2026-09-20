// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_CONSENSUS_CHAINREGISTRY_H
#define KRONEIN_CONSENSUS_CHAINREGISTRY_H

#include <consensus/amount.h>
#include <primitives/chainregistry.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <vector>

class CBlock;

namespace chainregistry {

inline constexpr std::string_view REGISTRY_LEAF_HASH_TAG{"Kronein/RegistryLeaf/v1"};
inline constexpr std::string_view REGISTRY_NODE_HASH_TAG{"Kronein/RegistryNode/v1"};
inline constexpr std::string_view REGISTRY_ROOT_HASH_TAG{"Kronein/RegistryRoot/v1"};
inline constexpr uint8_t CHAIN_RECORD_VERSION{1};
inline constexpr std::array<unsigned char, 4> REGISTRY_COMMITMENT_MAGIC{'K', 'R', 'R', 'T'};
inline constexpr uint8_t REGISTRY_COMMITMENT_VERSION{1};

enum class ChainStatus : uint8_t {
    ACTIVE = 1,
    RETIRED = 2,
};

/** Consensus state committed for every registered child chain. */
struct ChainRecord {
    uint8_t record_version{CHAIN_RECORD_VERSION};
    ChainId chain_id;
    ManifestHash manifest_hash;
    uint32_t template_id{0};
    uint32_t template_version{0};
    COutPoint control_outpoint;
    MetadataHash metadata_hash;
    ChainStatus status{ChainStatus::ACTIVE};
    uint32_t registered_height{0};
    uint32_t updated_height{0};
    uint32_t retired_height{0};

    SERIALIZE_METHODS(ChainRecord, obj)
    {
        uint8_t status;
        SER_WRITE(obj, status = static_cast<uint8_t>(obj.status));
        READWRITE(obj.record_version,
                  obj.chain_id,
                  obj.manifest_hash,
                  obj.template_id,
                  obj.template_version,
                  obj.control_outpoint,
                  obj.metadata_hash,
                  status,
                  obj.registered_height,
                  obj.updated_height,
                  obj.retired_height);
        SER_READ(obj, obj.status = static_cast<ChainStatus>(status));
    }

    friend bool operator==(const ChainRecord&, const ChainRecord&) = default;
};

/** One reversible registry mutation. */
struct RegistryUndo {
    ChainId chain_id;
    bool had_previous{false};
    ChainRecord previous;

    SERIALIZE_METHODS(RegistryUndo, obj)
    {
        READWRITE(obj.chain_id, obj.had_previous);
        if (obj.had_previous) READWRITE(obj.previous);
    }

    friend bool operator==(const RegistryUndo&, const RegistryUndo&) = default;
};

enum class RegistryError : uint8_t {
    NONE,
    INVALID_TRANSACTION_OPERATION,
    CONTROL_SPEND_WITHOUT_OPERATION,
    WRONG_CONTROL_OUTPOINT,
    MULTIPLE_CONTROL_OUTPOINTS,
    DUPLICATE_CHAIN_ID,
    UNKNOWN_CHAIN,
    RETIRED_CHAIN,
};

struct RegistryTransitionResult {
    RegistryError error{RegistryError::NONE};
    TxOperationError tx_error{TxOperationError::NONE};
    OperationParseError parse_error{OperationParseError::NONE};
    std::optional<ChainId> chain_id;
    std::optional<RegistryUndo> undo;

    bool IsValid() const { return error == RegistryError::NONE; }
    bool HasOperation() const { return chain_id.has_value(); }
};

uint256 ComputeRegistryLeafHash(const ChainRecord& record);
uint256 ComputeRegistryNodeHash(const uint256& left, const uint256& right);
/** Compute the count-committed root from leaves already ordered by ChainId. */
uint256 ComputeRegistryRootFromLeaves(std::vector<uint256> ordered_leaves);

struct RegistryInclusionProof {
    uint64_t leaf_count{0};
    uint64_t leaf_index{0};
    std::vector<uint256> siblings;

    SERIALIZE_METHODS(RegistryInclusionProof, obj)
    {
        READWRITE(obj.leaf_count, obj.leaf_index, obj.siblings);
    }

    friend bool operator==(const RegistryInclusionProof&, const RegistryInclusionProof&) = default;
};

struct RegistryProofEntry {
    ChainRecord record;
    RegistryInclusionProof proof;

    SERIALIZE_METHODS(RegistryProofEntry, obj) { READWRITE(obj.record, obj.proof); }

    friend bool operator==(const RegistryProofEntry&, const RegistryProofEntry&) = default;
};

struct RegistryNonInclusionProof {
    uint64_t leaf_count{0};
    bool has_left{false};
    RegistryProofEntry left;
    bool has_right{false};
    RegistryProofEntry right;

    SERIALIZE_METHODS(RegistryNonInclusionProof, obj)
    {
        READWRITE(obj.leaf_count, obj.has_left);
        if (obj.has_left) READWRITE(obj.left);
        READWRITE(obj.has_right);
        if (obj.has_right) READWRITE(obj.right);
    }

    friend bool operator==(const RegistryNonInclusionProof&, const RegistryNonInclusionProof&) = default;
};

bool VerifyRegistryInclusion(const ChainRecord& record,
                             const RegistryInclusionProof& proof,
                             const uint256& expected_root);
bool VerifyRegistryNonInclusion(const ChainId& chain_id,
                                const RegistryNonInclusionProof& proof,
                                const uint256& expected_root);

enum class CommitmentParseError : uint8_t {
    NONE,
    NOT_COMMITMENT,
    MALFORMED_SCRIPT,
    NON_CANONICAL_SCRIPT,
    INVALID_LENGTH,
    UNSUPPORTED_VERSION,
};

struct CommitmentParseResult {
    CommitmentParseError error{CommitmentParseError::NOT_COMMITMENT};
    std::optional<uint256> root;

    explicit operator bool() const { return error == CommitmentParseError::NONE && root.has_value(); }
};

enum class CommitmentTxError : uint8_t {
    NONE,
    INVALID_COMMITMENT,
    MULTIPLE_COMMITMENTS,
    NONZERO_VALUE,
};

struct CommitmentTxResult {
    CommitmentTxError error{CommitmentTxError::NONE};
    CommitmentParseError parse_error{CommitmentParseError::NONE};
    std::optional<uint32_t> output_index;
    std::optional<uint256> root;

    bool IsValid() const { return error == CommitmentTxError::NONE; }
};

enum class CommitmentRequirement : uint8_t {
    OPTIONAL,
    REQUIRED,
};

struct RegistryBlockUndo {
    std::vector<RegistryUndo> operations;

    SERIALIZE_METHODS(RegistryBlockUndo, obj) { READWRITE(obj.operations); }

    friend bool operator==(const RegistryBlockUndo&, const RegistryBlockUndo&) = default;
};

enum class RegistryBlockError : uint8_t {
    NONE,
    EMPTY_BLOCK,
    INVALID_COINBASE,
    COINBASE_OPERATION,
    INVALID_COINBASE_COMMITMENT,
    NON_COINBASE_COMMITMENT,
    TRANSACTION_TRANSITION,
    TOO_MANY_OPERATIONS,
    MISSING_COMMITMENT,
    COMMITMENT_MISMATCH,
    ROLLBACK_FAILED,
};

struct RegistryBlockResult {
    RegistryBlockError error{RegistryBlockError::NONE};
    std::optional<size_t> tx_index;
    RegistryTransitionResult transition;
    CommitmentTxError commitment_error{CommitmentTxError::NONE};
    CommitmentParseError commitment_parse_error{CommitmentParseError::NONE};
    uint256 computed_root;
    std::optional<RegistryBlockUndo> undo;

    bool IsValid() const { return error == RegistryBlockError::NONE; }
};

CScript BuildRegistryCommitment(const uint256& registry_root);
CommitmentParseResult ParseRegistryCommitment(const CScript& script);
/** Find at most one zero-valued commitment output in a transaction. */
CommitmentTxResult ExtractRegistryCommitment(const CTransaction& tx);

/** In-memory deterministic registry state. Persistence is added by M2. */
class ChainRegistry
{
private:
    std::map<ChainId, ChainRecord> m_records;
    std::map<COutPoint, ChainId> m_control_index;

public:
    const ChainRecord* Find(const ChainId& chain_id) const;
    size_t Size() const { return m_records.size(); }
    const std::map<ChainId, ChainRecord>& Records() const { return m_records; }

    /** Root commits to ordered records and their count. */
    uint256 ComputeRoot() const;
    std::optional<RegistryInclusionProof> GetInclusionProof(const ChainId& chain_id) const;
    /** Returns nullopt when the queried ChainId is present. */
    std::optional<RegistryNonInclusionProof> GetNonInclusionProof(const ChainId& chain_id) const;

    RegistryTransitionResult ApplyTransaction(const CTransaction& tx,
                                              uint32_t height,
                                              const uint256& main_genesis_hash,
                                              CAmount minimum_registration_burn);
    bool Undo(const RegistryUndo& undo);

    RegistryBlockResult ApplyBlock(const CBlock& block,
                                   uint32_t height,
                                   const uint256& main_genesis_hash,
                                   CAmount minimum_registration_burn,
                                   size_t maximum_operations,
                                   CommitmentRequirement commitment_requirement);
    bool UndoBlock(const RegistryBlockUndo& undo);
};

} // namespace chainregistry

#endif // KRONEIN_CONSENSUS_CHAINREGISTRY_H
