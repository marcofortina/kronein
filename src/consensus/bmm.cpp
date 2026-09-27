// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/bmm.h>

#include <hash.h>

#include <set>
#include <utility>

namespace chainregistry {
namespace {

BmmProofValidationResult ProofError(BmmProofValidationError error)
{
    BmmProofValidationResult result;
    result.error = error;
    return result;
}

BmmBlockValidationResult BlockError(
    BmmBlockValidationError error,
    std::optional<uint32_t> transaction_index = std::nullopt,
    std::optional<ChainId> chain_id = std::nullopt,
    TxBmmAnchorError transaction_error = TxBmmAnchorError::NONE,
    BmmAnchorParseError parse_error = BmmAnchorParseError::NONE)
{
    BmmBlockValidationResult result;
    result.error = error;
    result.transaction_error = transaction_error;
    result.parse_error = parse_error;
    result.transaction_index = transaction_index;
    result.chain_id = std::move(chain_id);
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

BmmBlockValidationResult ValidateBlockBmmAnchors(
    const CBlock& block,
    const ChainRegistry& final_registry,
    uint32_t maximum_anchors)
{
    if (block.vtx.empty()) {
        return BlockError(BmmBlockValidationError::EMPTY_BLOCK);
    }
    if (!block.vtx.front()->IsCoinBase()) {
        return BlockError(BmmBlockValidationError::INVALID_COINBASE, 0);
    }

    const auto coinbase_anchor{
        ExtractTransactionBmmAnchor(*block.vtx.front())};
    if (!coinbase_anchor.IsValid() || coinbase_anchor.anchor) {
        return BlockError(BmmBlockValidationError::COINBASE_ANCHOR,
                          0,
                          coinbase_anchor.anchor
                              ? std::optional{coinbase_anchor.anchor->chain_id}
                              : std::nullopt,
                          coinbase_anchor.error,
                          coinbase_anchor.parse_error);
    }

    BmmBlockValidationResult result;
    std::set<ChainId> seen_chains;
    for (size_t transaction_index{1}; transaction_index < block.vtx.size();
         ++transaction_index) {
        const CTransaction& transaction{*block.vtx[transaction_index]};
        if (transaction.IsCoinBase()) {
            return BlockError(
                BmmBlockValidationError::INVALID_COINBASE,
                static_cast<uint32_t>(transaction_index));
        }
        const auto extracted{ExtractTransactionBmmAnchor(transaction)};
        if (!extracted.IsValid()) {
            return BlockError(BmmBlockValidationError::INVALID_PROPOSAL,
                              static_cast<uint32_t>(transaction_index),
                              std::nullopt,
                              extracted.error,
                              extracted.parse_error);
        }
        if (!extracted.anchor) continue;
        const ChainId& chain_id{extracted.anchor->chain_id};
        if (!seen_chains.insert(chain_id).second) {
            return BlockError(BmmBlockValidationError::DUPLICATE_CHAIN,
                              static_cast<uint32_t>(transaction_index),
                              chain_id);
        }
        const ChainRecord* record{final_registry.Find(chain_id)};
        if (!record) {
            return BlockError(BmmBlockValidationError::UNKNOWN_CHAIN,
                              static_cast<uint32_t>(transaction_index),
                              chain_id);
        }
        if (record->status != ChainStatus::ACTIVE) {
            return BlockError(BmmBlockValidationError::INACTIVE_CHAIN,
                              static_cast<uint32_t>(transaction_index),
                              chain_id);
        }
        if (result.anchors.size() >= maximum_anchors) {
            return BlockError(BmmBlockValidationError::TOO_MANY_ANCHORS,
                              static_cast<uint32_t>(transaction_index),
                              chain_id);
        }
        result.anchors.push_back(BlockBmmAnchor{
            .transaction_index = static_cast<uint32_t>(transaction_index),
            .output_index = *extracted.output_index,
            .anchor = *extracted.anchor,
        });
    }
    return result;
}

} // namespace chainregistry
