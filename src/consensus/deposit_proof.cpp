// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/deposit_proof.h>

#include <hash.h>
#include <primitives/deposit.h>

namespace chainregistry {
namespace {

DepositProofValidationResult ProofError(DepositProofValidationError error)
{
    DepositProofValidationResult result;
    result.error = error;
    return result;
}

std::optional<uint256> ComputeMerkleRootFromBranch(uint256 hash,
                                                   const std::vector<uint256>& branch,
                                                   uint32_t position)
{
    if (branch.size() > MAX_DEPOSIT_PROOF_MERKLE_BRANCH) return std::nullopt;
    for (const auto& sibling : branch) {
        hash = position & 1 ? Hash(sibling, hash) : Hash(hash, sibling);
        position >>= 1;
    }
    if (position != 0) return std::nullopt;
    return hash;
}

} // namespace

DepositProofValidationResult ValidateDepositProofStructure(
    const DepositProof& proof,
    const uint256& expected_main_genesis_hash,
    std::optional<ChainId> expected_child_chain)
{
    if (proof.version != DEPOSIT_PROOF_VERSION) {
        return ProofError(DepositProofValidationError::UNSUPPORTED_VERSION);
    }
    if (expected_main_genesis_hash.IsNull() ||
        proof.main_genesis_hash != expected_main_genesis_hash) {
        return ProofError(DepositProofValidationError::WRONG_MAIN_NETWORK);
    }

    const CTransaction funding_transaction{proof.funding_transaction};
    const auto funds{ExtractTransactionFunds(funding_transaction)};
    if (!funds.IsValid()) {
        return ProofError(DepositProofValidationError::INVALID_FUNDING_TRANSACTION);
    }
    const FundOutput* fund{nullptr};
    for (const auto& candidate : funds.funds) {
        if (candidate.output_index == proof.funding_vout) {
            fund = &candidate;
            break;
        }
    }
    if (!fund) return ProofError(DepositProofValidationError::INVALID_FUNDING_OUTPUT);
    if (expected_child_chain && fund->fund.chain_id != *expected_child_chain) {
        return ProofError(DepositProofValidationError::WRONG_CHILD_CHAIN);
    }
    if (funding_transaction.IsCoinBase() != (proof.transaction_index == 0)) {
        return ProofError(DepositProofValidationError::INVALID_TRANSACTION_POSITION);
    }
    const auto transaction_root{ComputeMerkleRootFromBranch(
        funding_transaction.GetHash().ToUint256(),
        proof.transaction_merkle_branch,
        proof.transaction_index)};
    if (!transaction_root || *transaction_root != proof.block_header.hashMerkleRoot) {
        return ProofError(DepositProofValidationError::TRANSACTION_MERKLE_ROOT_MISMATCH);
    }

    const CTransaction coinbase{proof.coinbase_transaction};
    if (!coinbase.IsCoinBase() ||
        (proof.transaction_index == 0 && coinbase.GetHash() != funding_transaction.GetHash())) {
        return ProofError(DepositProofValidationError::INVALID_COINBASE);
    }
    const auto coinbase_root{ComputeMerkleRootFromBranch(
        coinbase.GetHash().ToUint256(), proof.coinbase_merkle_branch, 0)};
    if (!coinbase_root || *coinbase_root != proof.block_header.hashMerkleRoot) {
        return ProofError(DepositProofValidationError::COINBASE_MERKLE_ROOT_MISMATCH);
    }

    const auto commitment{ExtractRegistryCommitment(coinbase)};
    if (!commitment.IsValid() || !commitment.root) {
        return ProofError(DepositProofValidationError::INVALID_REGISTRY_COMMITMENT);
    }
    if (proof.chain_record.chain_id != fund->fund.chain_id) {
        return ProofError(DepositProofValidationError::WRONG_CHILD_CHAIN);
    }
    if (proof.chain_record.status != ChainStatus::ACTIVE) {
        return ProofError(DepositProofValidationError::INACTIVE_CHAIN);
    }
    if (!VerifyRegistryInclusion(
            proof.chain_record, proof.registry_proof, *commitment.root)) {
        return ProofError(DepositProofValidationError::INVALID_REGISTRY_PROOF);
    }

    DepositProofValidationResult result;
    result.deposit_id = DeriveDepositId(
        expected_main_genesis_hash,
        COutPoint{funding_transaction.GetHash(), proof.funding_vout});
    result.fund = *fund;
    result.registry_root = *commitment.root;
    return result;
}

} // namespace chainregistry
