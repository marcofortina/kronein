// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/bmm.h>

#include <hash.h>

namespace chainregistry {
namespace {

BmmProofValidationResult ProofError(BmmProofValidationError error)
{
    BmmProofValidationResult result;
    result.error = error;
    return result;
}

std::optional<uint256> ComputeMerkleRootFromBranch(
    uint256 hash,
    const std::vector<uint256>& branch,
    uint32_t position)
{
    if (branch.size() > MAX_BMM_PROOF_MERKLE_BRANCH) return std::nullopt;
    for (const auto& sibling : branch) {
        hash = position & 1 ? Hash(sibling, hash) : Hash(hash, sibling);
        position >>= 1;
    }
    if (position != 0) return std::nullopt;
    return hash;
}

} // namespace

BmmProofValidationResult ValidateBmmAnchorProofStructure(
    const BmmAnchorProof& proof,
    const uint256& expected_main_genesis_hash,
    std::optional<ChainId> expected_child_chain)
{
    if (proof.version != BMM_PROOF_VERSION) {
        return ProofError(BmmProofValidationError::UNSUPPORTED_VERSION);
    }
    if (expected_main_genesis_hash.IsNull() ||
        proof.main_genesis_hash != expected_main_genesis_hash) {
        return ProofError(BmmProofValidationError::WRONG_MAIN_NETWORK);
    }

    const CTransaction anchor_transaction{proof.anchor_transaction};
    const auto extracted{ExtractTransactionBmmAnchor(anchor_transaction)};
    if (!extracted.IsValid() || !extracted.anchor) {
        return ProofError(BmmProofValidationError::INVALID_ANCHOR_TRANSACTION);
    }
    if (expected_child_chain &&
        extracted.anchor->chain_id != *expected_child_chain) {
        return ProofError(BmmProofValidationError::WRONG_CHILD_CHAIN);
    }
    if (proof.transaction_index == 0 || anchor_transaction.IsCoinBase()) {
        return ProofError(BmmProofValidationError::INVALID_TRANSACTION_POSITION);
    }
    const auto transaction_root{ComputeMerkleRootFromBranch(
        anchor_transaction.GetHash().ToUint256(),
        proof.transaction_merkle_branch,
        proof.transaction_index)};
    if (!transaction_root ||
        *transaction_root != proof.block_header.hashMerkleRoot) {
        return ProofError(
            BmmProofValidationError::TRANSACTION_MERKLE_ROOT_MISMATCH);
    }

    const CTransaction coinbase{proof.coinbase_transaction};
    if (!coinbase.IsCoinBase()) {
        return ProofError(BmmProofValidationError::INVALID_COINBASE);
    }
    const auto coinbase_root{ComputeMerkleRootFromBranch(
        coinbase.GetHash().ToUint256(), proof.coinbase_merkle_branch, 0)};
    if (!coinbase_root || *coinbase_root != proof.block_header.hashMerkleRoot) {
        return ProofError(
            BmmProofValidationError::COINBASE_MERKLE_ROOT_MISMATCH);
    }

    const auto commitment{ExtractRegistryCommitment(coinbase)};
    if (!commitment.IsValid() || !commitment.root) {
        return ProofError(BmmProofValidationError::INVALID_REGISTRY_COMMITMENT);
    }
    if (proof.chain_record.chain_id != extracted.anchor->chain_id) {
        return ProofError(BmmProofValidationError::WRONG_CHILD_CHAIN);
    }
    if (proof.chain_record.status != ChainStatus::ACTIVE) {
        return ProofError(BmmProofValidationError::INACTIVE_CHAIN);
    }
    if (!VerifyRegistryInclusion(
            proof.chain_record, proof.registry_proof, *commitment.root)) {
        return ProofError(BmmProofValidationError::INVALID_REGISTRY_PROOF);
    }

    BmmProofValidationResult result;
    result.anchor = *extracted.anchor;
    result.registry_root = *commitment.root;
    return result;
}

} // namespace chainregistry
