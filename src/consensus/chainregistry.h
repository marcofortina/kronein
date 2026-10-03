// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CONSENSUS_CHAINREGISTRY_H
#define BITCOIN_CONSENSUS_CHAINREGISTRY_H

#include <consensus/amount.h>
#include <consensus/deposit.h>
#include <primitives/chainregistry.h>
#include <primitives/transaction.h>
#include <pubkey.h>
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
inline constexpr std::string_view DEALER_LEAF_HASH_TAG{"Kronein/DealerLeaf/v1"};
inline constexpr std::string_view DEALER_NODE_HASH_TAG{"Kronein/DealerNode/v1"};
inline constexpr std::string_view DEALER_ROOT_HASH_TAG{"Kronein/DealerRoot/v1"};
inline constexpr std::string_view REGISTRY_STATE_HASH_TAG{"Kronein/RegistryState/v3"};
inline constexpr uint8_t CHAIN_RECORD_VERSION{1};
inline constexpr uint8_t DEALER_RECORD_VERSION{1};
inline constexpr std::array<unsigned char, 4> REGISTRY_COMMITMENT_MAGIC{'K', 'R', 'R', 'T'};
inline constexpr uint8_t REGISTRY_COMMITMENT_VERSION{3};

enum class ChainStatus : uint8_t {
    ACTIVE = 1,
    RETIRED = 2,
};

enum class RecordValidationError : uint8_t {
    NONE,
    UNSUPPORTED_VERSION,
    NULL_CHAIN_ID,
    NULL_MANIFEST_HASH,
    INVALID_TEMPLATE_ID,
    INVALID_TEMPLATE_VERSION,
    NULL_CONTROL_OUTPOINT,
    NULL_METADATA_HASH,
    UNKNOWN_STATUS,
    INVALID_HEIGHTS,
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

RecordValidationError ValidateChainRecord(const ChainRecord& record);

enum class DealerStatus : uint8_t {
    ACTIVE = 1,
    REVOKED = 2,
};

struct DealerRecord {
    uint8_t record_version{DEALER_RECORD_VERSION};
    DealerId dealer_id;
    COutPoint control_outpoint;
    CScript payout_script;
    uint32_t remaining_licenses{0};
    DealerStatus status{DealerStatus::ACTIVE};
    uint32_t authorized_height{0};
    uint32_t updated_height{0};

    SERIALIZE_METHODS(DealerRecord, obj)
    {
        uint8_t status;
        SER_WRITE(obj, status = static_cast<uint8_t>(obj.status));
        READWRITE(obj.record_version,
                  obj.dealer_id,
                  obj.control_outpoint,
                  obj.payout_script,
                  obj.remaining_licenses,
                  status,
                  obj.authorized_height,
                  obj.updated_height);
        SER_READ(obj, obj.status = static_cast<DealerStatus>(status));
    }

    friend bool operator==(const DealerRecord&, const DealerRecord&) = default;
};

enum class DealerRecordValidationError : uint8_t {
    NONE,
    UNSUPPORTED_VERSION,
    NULL_DEALER_ID,
    NULL_CONTROL_OUTPOINT,
    INVALID_PAYOUT_SCRIPT,
    UNKNOWN_STATUS,
    INVALID_HEIGHTS,
};

DealerRecordValidationError ValidateDealerRecord(const DealerRecord& record);

/** One reversible registry mutation. */
struct RegistryUndo {
    bool has_chain{false};
    ChainId chain_id;
    bool chain_had_previous{false};
    ChainRecord previous_chain;
    bool has_dealer{false};
    DealerId dealer_id;
    bool dealer_had_previous{false};
    DealerRecord previous_dealer;
    uint64_t previous_authority_sequence{0};
    std::optional<DealerAuthorityTransition> previous_authority_transition{};

    SERIALIZE_METHODS(RegistryUndo, obj)
    {
        READWRITE(obj.has_chain);
        if (obj.has_chain) {
            READWRITE(obj.chain_id, obj.chain_had_previous);
            if (obj.chain_had_previous) READWRITE(obj.previous_chain);
        }
        READWRITE(obj.has_dealer);
        if (obj.has_dealer) {
            READWRITE(obj.dealer_id, obj.dealer_had_previous);
            if (obj.dealer_had_previous) READWRITE(obj.previous_dealer);
        }
        READWRITE(obj.previous_authority_sequence);
        bool has_transition;
        SER_WRITE(obj, has_transition = obj.previous_authority_transition.has_value());
        READWRITE(has_transition);
        SER_READ(obj, obj.previous_authority_transition.reset());
        if (has_transition) {
            SER_READ(obj, obj.previous_authority_transition.emplace());
            READWRITE(*obj.previous_authority_transition);
        }
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
    UNAUTHORIZED_DEALER,
    REVOKED_DEALER,
    DEALER_LICENSES_EXHAUSTED,
    WRONG_DEALER_CONTROL_OUTPOINT,
    MULTIPLE_DEALER_CONTROL_OUTPOINTS,
    WRONG_DEALER_PAYMENT,
    INVALID_AUTHORITY_KEY,
    INVALID_AUTHORITY_SEQUENCE,
    INVALID_AUTHORITY_SIGNATURE,
    INVALID_AUTHORITY_ROTATION,
    AUTHORITY_ROTATION_PENDING,
    DUPLICATE_DEALER_ID,
    UNKNOWN_DEALER,
    LICENSE_COUNT_OVERFLOW,
};

enum class RegistryLoadError : uint8_t {
    NONE,
    INVALID_RECORD,
    DUPLICATE_CHAIN_ID,
    DUPLICATE_ACTIVE_CONTROL,
    INVALID_DEALER_RECORD,
    DUPLICATE_DEALER_ID,
    DUPLICATE_ACTIVE_DEALER_CONTROL,
    CONTROL_NAMESPACE_COLLISION,
    INVALID_AUTHORITY_TRANSITION,
};

struct RegistryLoadResult {
    RegistryLoadError error{RegistryLoadError::NONE};
    RecordValidationError record_error{RecordValidationError::NONE};
    DealerRecordValidationError dealer_record_error{DealerRecordValidationError::NONE};
    std::optional<ChainId> chain_id;
    std::optional<DealerId> dealer_id;

    bool IsValid() const { return error == RegistryLoadError::NONE; }
};

struct RegistryTransitionResult {
    RegistryError error{RegistryError::NONE};
    TxOperationError tx_error{TxOperationError::NONE};
    OperationParseError parse_error{OperationParseError::NONE};
    std::optional<ChainId> chain_id;
    std::optional<DealerId> dealer_id;
    bool applied{false};
    std::optional<RegistryUndo> undo;

    bool IsValid() const { return error == RegistryError::NONE; }
    bool HasOperation() const { return applied; }
};

uint256 ComputeRegistryLeafHash(const ChainRecord& record);
uint256 ComputeRegistryNodeHash(const uint256& left, const uint256& right);
/** Compute the count-committed root from leaves already ordered by ChainId. */
uint256 ComputeRegistryRootFromLeaves(std::vector<uint256> ordered_leaves);
uint256 ComputeDealerLeafHash(const DealerRecord& record);
uint256 ComputeDealerRoot(const std::map<DealerId, DealerRecord>& dealers);
uint256 ComputeRegistryStateRoot(const uint256& chain_root,
                                 const uint256& dealer_root,
                                 uint64_t authority_sequence,
                                 const uint256& authority_state_hash = DealerAuthorityTransition{}.GetHash());

struct RegistryInclusionProof {
    uint64_t leaf_count{0};
    uint64_t leaf_index{0};
    std::vector<uint256> siblings;
    uint256 dealer_root;
    uint64_t authority_sequence{0};
    uint256 authority_state_hash{DealerAuthorityTransition{}.GetHash()};

    SERIALIZE_METHODS(RegistryInclusionProof, obj)
    {
        READWRITE(obj.leaf_count,
                  obj.leaf_index,
                  obj.siblings,
                  obj.dealer_root,
                  obj.authority_sequence,
                  obj.authority_state_hash);
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
    uint256 dealer_root;
    uint64_t authority_sequence{0};
    uint256 authority_state_hash{DealerAuthorityTransition{}.GetHash()};
    bool has_left{false};
    RegistryProofEntry left;
    bool has_right{false};
    RegistryProofEntry right;

    SERIALIZE_METHODS(RegistryNonInclusionProof, obj)
    {
        READWRITE(obj.leaf_count, obj.dealer_root, obj.authority_sequence, obj.authority_state_hash, obj.has_left);
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
    NOT_REQUIRED,
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
    INVALID_DEPOSITS,
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
    BlockDepositsResult deposits;
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
    std::map<DealerId, DealerRecord> m_dealers;
    std::map<COutPoint, DealerId> m_dealer_control_index;
    uint64_t m_authority_sequence{0};
    DealerAuthorityTransition m_authority_transition{};

public:
    const ChainRecord* Find(const ChainId& chain_id) const;
    const DealerRecord* FindDealer(const DealerId& dealer_id) const;
    size_t Size() const { return m_records.size(); }
    size_t DealerSize() const { return m_dealers.size(); }
    uint64_t AuthoritySequence() const { return m_authority_sequence; }
    const DealerAuthorityTransition& AuthorityTransition() const { return m_authority_transition; }
    const DealerAuthority& Authority(uint32_t height, const DealerAuthority& initial) const
    {
        return m_authority_transition.Effective(height, initial);
    }
    const std::map<ChainId, ChainRecord>& Records() const { return m_records; }
    const std::map<DealerId, DealerRecord>& Dealers() const { return m_dealers; }
    /** Atomically replace state with validated records loaded from storage. */
    RegistryLoadResult LoadRecords(std::vector<ChainRecord> records);
    RegistryLoadResult LoadState(std::vector<ChainRecord> records,
                                 std::vector<DealerRecord> dealers,
                                 uint64_t authority_sequence,
                                 DealerAuthorityTransition authority_transition = {});

    /** Root commits to ordered records and their count. */
    uint256 ComputeRoot() const;
    std::optional<RegistryInclusionProof> GetInclusionProof(const ChainId& chain_id) const;
    /** Returns nullopt when the queried ChainId is present. */
    std::optional<RegistryNonInclusionProof> GetNonInclusionProof(const ChainId& chain_id) const;

    RegistryTransitionResult ApplyTransaction(const CTransaction& tx,
                                              uint32_t height,
                                              const uint256& main_genesis_hash,
                                              const DealerAuthority& dealer_authority);
    bool Undo(const RegistryUndo& undo);

    RegistryBlockResult ApplyBlock(const CBlock& block,
                                   uint32_t height,
                                   const uint256& main_genesis_hash,
                                   const DealerAuthority& dealer_authority,
                                   size_t maximum_operations,
                                   CommitmentRequirement commitment_requirement,
                                   std::optional<DepositValidationParams> deposit_params = std::nullopt);
    bool UndoBlock(const RegistryBlockUndo& undo);
};

} // namespace chainregistry

#endif // BITCOIN_CONSENSUS_CHAINREGISTRY_H
