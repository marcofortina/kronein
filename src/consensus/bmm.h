// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CONSENSUS_BMM_H
#define BITCOIN_CONSENSUS_BMM_H

#include <consensus/chainregistry.h>
#include <primitives/block.h>
#include <primitives/bmm.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <ios>
#include <optional>
#include <vector>

namespace chainregistry {

inline constexpr std::array<uint8_t, 4> BMM_PROOF_MAGIC{'K', 'B', 'P', 'R'};
inline constexpr uint8_t BMM_PROOF_VERSION{3};
inline constexpr uint64_t MAX_BMM_PROOF_MERKLE_BRANCH{32};

/**
 * Compact evidence that a BMM proposal transaction and the active child
 * registry record were committed by an already-authenticated main header.
 */
struct BmmAnchorProof {
    uint8_t version{BMM_PROOF_VERSION};
    uint256 main_genesis_hash;
    uint32_t block_height{0};
    CBlockHeader block_header;
    CMutableTransaction anchor_transaction;
    uint32_t transaction_index{0};
    std::vector<uint256> transaction_merkle_branch;
    CMutableTransaction coinbase_transaction;
    std::vector<uint256> coinbase_merkle_branch;
    ChainRecord chain_record;
    RegistryInclusionProof registry_proof;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        if (transaction_merkle_branch.size() > MAX_BMM_PROOF_MERKLE_BRANCH ||
            coinbase_merkle_branch.size() > MAX_BMM_PROOF_MERKLE_BRANCH ||
            registry_proof.siblings.size() > MAX_BMM_PROOF_MERKLE_BRANCH) {
            throw std::ios_base::failure("BMM proof branch is too long.");
        }
        stream << BMM_PROOF_MAGIC;
        stream << version;
        stream << main_genesis_hash;
        stream << block_height;
        stream << block_header;
        stream << TX_BASE(anchor_transaction);
        stream << transaction_index;
        WriteCompactSize(stream, transaction_merkle_branch.size());
        for (const auto& hash : transaction_merkle_branch) stream << hash;
        stream << TX_BASE(coinbase_transaction);
        WriteCompactSize(stream, coinbase_merkle_branch.size());
        for (const auto& hash : coinbase_merkle_branch) stream << hash;
        stream << chain_record;
        stream << registry_proof.leaf_count;
        stream << registry_proof.leaf_index;
        WriteCompactSize(stream, registry_proof.siblings.size());
        for (const auto& hash : registry_proof.siblings) stream << hash;
        if (version >= 2) {
            stream << registry_proof.dealer_root;
            stream << registry_proof.authority_sequence;
        }
        if (version >= 3) stream << registry_proof.authority_state_hash;
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        std::array<uint8_t, BMM_PROOF_MAGIC.size()> magic;
        stream >> magic;
        if (magic != BMM_PROOF_MAGIC) {
            throw std::ios_base::failure("Invalid BMM proof magic bytes.");
        }
        stream >> version;
        stream >> main_genesis_hash;
        stream >> block_height;
        stream >> block_header;
        stream >> TX_BASE(anchor_transaction);
        stream >> transaction_index;

        const auto read_branch = [&stream](std::vector<uint256>& branch) {
            const uint64_t size{ReadCompactSize(stream)};
            if (size > MAX_BMM_PROOF_MERKLE_BRANCH) {
                throw std::ios_base::failure("BMM proof branch is too long.");
            }
            branch.resize(size);
            for (auto& hash : branch) stream >> hash;
        };
        read_branch(transaction_merkle_branch);
        stream >> TX_BASE(coinbase_transaction);
        read_branch(coinbase_merkle_branch);
        stream >> chain_record;
        stream >> registry_proof.leaf_count;
        stream >> registry_proof.leaf_index;
        read_branch(registry_proof.siblings);
        if (version >= 2) {
            stream >> registry_proof.dealer_root;
            stream >> registry_proof.authority_sequence;
        }
        if (version >= 3) stream >> registry_proof.authority_state_hash;
    }
};

enum class BmmProofValidationError : uint8_t {
    NONE,
    UNSUPPORTED_VERSION,
    WRONG_MAIN_NETWORK,
    WRONG_CHILD_CHAIN,
    INVALID_ANCHOR_TRANSACTION,
    INVALID_TRANSACTION_POSITION,
    TRANSACTION_MERKLE_ROOT_MISMATCH,
    INVALID_COINBASE,
    COINBASE_MERKLE_ROOT_MISMATCH,
    INVALID_REGISTRY_COMMITMENT,
    INACTIVE_CHAIN,
    INVALID_REGISTRY_PROOF,
};

struct BmmProofValidationResult {
    BmmProofValidationError error{BmmProofValidationError::NONE};
    std::optional<BmmAnchor> anchor;
    uint256 registry_root;

    bool IsValid() const { return error == BmmProofValidationError::NONE; }
};

struct BlockBmmAnchor {
    uint32_t transaction_index{0};
    uint32_t output_index{0};
    BmmAnchor anchor;

    friend bool operator==(const BlockBmmAnchor&, const BlockBmmAnchor&) = default;
};

enum class BmmBlockValidationError : uint8_t {
    NONE,
    EMPTY_BLOCK,
    INVALID_COINBASE,
    COINBASE_ANCHOR,
    INVALID_PROPOSAL,
    TOO_MANY_ANCHORS,
    DUPLICATE_CHAIN,
    UNKNOWN_CHAIN,
    INACTIVE_CHAIN,
};

struct BmmBlockValidationResult {
    BmmBlockValidationError error{BmmBlockValidationError::NONE};
    TxBmmAnchorError transaction_error{TxBmmAnchorError::NONE};
    BmmAnchorParseError parse_error{BmmAnchorParseError::NONE};
    std::optional<uint32_t> transaction_index;
    std::optional<ChainId> chain_id;
    std::vector<BlockBmmAnchor> anchors;

    bool IsValid() const { return error == BmmBlockValidationError::NONE; }
};

/**
 * Validate proof structure against an already-authenticated main header.
 * Header PoW, height, chainwork, finality and canonical-chain membership are
 * deliberately checked by the main-header light client.
 */
BmmProofValidationResult ValidateBmmAnchorProofStructure(
    const BmmAnchorProof& proof,
    const uint256& expected_main_genesis_hash,
    std::optional<ChainId> expected_child_chain = std::nullopt);

/**
 * Validate all KBMM proposals in one main-chain block against the final
 * registry state committed by that same block.
 */
BmmBlockValidationResult ValidateBlockBmmAnchors(
    const CBlock& block,
    const ChainRegistry& final_registry,
    uint32_t maximum_anchors);

} // namespace chainregistry

#endif // BITCOIN_CONSENSUS_BMM_H
