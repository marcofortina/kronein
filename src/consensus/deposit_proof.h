// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef KRONEIN_CONSENSUS_DEPOSIT_PROOF_H
#define KRONEIN_CONSENSUS_DEPOSIT_PROOF_H

#include <consensus/chainregistry.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <ios>
#include <optional>
#include <vector>

namespace chainregistry {

inline constexpr std::array<uint8_t, 4> DEPOSIT_PROOF_MAGIC{'K', 'D', 'P', 'R'};
inline constexpr uint8_t DEPOSIT_PROOF_VERSION{1};
inline constexpr uint64_t MAX_DEPOSIT_PROOF_MERKLE_BRANCH{32};

/**
 * Canonical evidence for one main-chain FUND_CHAIN output.
 *
 * Header-chain synchronization is deliberately external: a child light client
 * first authenticates block_header at block_height, then validates this compact
 * package against that header.
 */
struct DepositProof {
    uint8_t version{DEPOSIT_PROOF_VERSION};
    uint256 main_genesis_hash;
    uint32_t block_height{0};
    CBlockHeader block_header;
    CMutableTransaction funding_transaction;
    uint32_t funding_vout{0};
    uint32_t transaction_index{0};
    std::vector<uint256> transaction_merkle_branch;
    CMutableTransaction coinbase_transaction;
    std::vector<uint256> coinbase_merkle_branch;
    ChainRecord chain_record;
    RegistryInclusionProof registry_proof;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        if (transaction_merkle_branch.size() > MAX_DEPOSIT_PROOF_MERKLE_BRANCH ||
            coinbase_merkle_branch.size() > MAX_DEPOSIT_PROOF_MERKLE_BRANCH ||
            registry_proof.siblings.size() > MAX_DEPOSIT_PROOF_MERKLE_BRANCH) {
            throw std::ios_base::failure("Deposit proof branch is too long.");
        }
        stream << DEPOSIT_PROOF_MAGIC;
        stream << version;
        stream << main_genesis_hash;
        stream << block_height;
        stream << block_header;
        stream << TX_BASE(funding_transaction);
        stream << funding_vout;
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
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        std::array<uint8_t, DEPOSIT_PROOF_MAGIC.size()> magic;
        stream >> magic;
        if (magic != DEPOSIT_PROOF_MAGIC) {
            throw std::ios_base::failure("Invalid deposit proof magic bytes.");
        }
        stream >> version;
        stream >> main_genesis_hash;
        stream >> block_height;
        stream >> block_header;
        stream >> TX_BASE(funding_transaction);
        stream >> funding_vout;
        stream >> transaction_index;

        const auto read_branch = [&stream](std::vector<uint256>& branch) {
            const uint64_t size{ReadCompactSize(stream)};
            if (size > MAX_DEPOSIT_PROOF_MERKLE_BRANCH) {
                throw std::ios_base::failure("Deposit proof branch is too long.");
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
    }
};

enum class DepositProofValidationError : uint8_t {
    NONE,
    UNSUPPORTED_VERSION,
    WRONG_MAIN_NETWORK,
    WRONG_CHILD_CHAIN,
    INVALID_FUNDING_TRANSACTION,
    INVALID_FUNDING_OUTPUT,
    INVALID_TRANSACTION_POSITION,
    TRANSACTION_MERKLE_ROOT_MISMATCH,
    INVALID_COINBASE,
    COINBASE_MERKLE_ROOT_MISMATCH,
    INVALID_REGISTRY_COMMITMENT,
    INACTIVE_CHAIN,
    INVALID_REGISTRY_PROOF,
};

struct DepositProofValidationResult {
    DepositProofValidationError error{DepositProofValidationError::NONE};
    DepositId deposit_id;
    std::optional<FundOutput> fund;
    uint256 registry_root;

    bool IsValid() const { return error == DepositProofValidationError::NONE; }
};

/**
 * Validate proof structure against an already authenticated main-network
 * header. This does not perform PoW, ASERT, chainwork, or finality checks.
 */
DepositProofValidationResult ValidateDepositProofStructure(
    const DepositProof& proof,
    const uint256& expected_main_genesis_hash,
    std::optional<ChainId> expected_child_chain = std::nullopt);

} // namespace chainregistry

#endif // KRONEIN_CONSENSUS_DEPOSIT_PROOF_H
