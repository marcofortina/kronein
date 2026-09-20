// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_block.h>

#include <chain.h>
#include <chainregistry/child_sighash.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <hash.h>
#include <primitives/block.h>
#include <script/interpreter.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <type_traits>
#include <utility>
#include <vector>

namespace chainregistry {
namespace {

static_assert(std::is_nothrow_move_assignable_v<DepositImportState>);

ReferenceChildBlockResult BlockError(
    ReferenceChildBlockError error,
    std::optional<size_t> failed_transaction = std::nullopt)
{
    ReferenceChildBlockResult result;
    result.error = error;
    result.failed_transaction = failed_transaction;
    return result;
}

bool IsValidDefinition(const ReferenceChildDefinition& definition)
{
    const auto rebuilt{ValidateReferenceChildManifest(
        definition.genesis.main_genesis_hash,
        definition.genesis.registration_anchor,
        definition.manifest)};
    return rebuilt.IsValid() && *rebuilt.definition == definition;
}

bool CheckWitnessCommitment(const CBlock& block)
{
    const int commitment_index{GetWitnessCommitmentIndex(block)};
    if (commitment_index == NO_WITNESS_COMMITMENT || block.vtx.empty() ||
        block.vtx.front()->vin.empty()) {
        return false;
    }
    const auto& witness_stack{
        block.vtx.front()->vin.front().scriptWitness.stack};
    if (witness_stack.size() != 1 || witness_stack.front().size() != 32) {
        return false;
    }

    uint256 commitment{BlockWitnessMerkleRoot(block)};
    CHash256()
        .Write(commitment)
        .Write(witness_stack.front())
        .Finalize(commitment);
    return std::memcmp(
               commitment.begin(),
               &block.vtx.front()->vout[commitment_index].scriptPubKey[6],
               uint256::size()) == 0;
}

bool HasExpectedCoinbaseHeight(const CTransaction& coinbase, int height)
{
    const CScript expected{CScript{} << height};
    const CScript& script_sig{coinbase.vin.front().scriptSig};
    return script_sig.size() >= expected.size() &&
           std::equal(expected.begin(), expected.end(), script_sig.begin());
}

bool RestoreCoin(CCoinsViewCache& view,
                 const COutPoint& outpoint,
                 Coin&& coin)
{
    if (view.HaveCoin(outpoint) || coin.IsSpent()) return false;
    view.AddCoin(outpoint, std::move(coin), /*possible_overwrite=*/false);
    return true;
}

} // namespace

ReferenceChildBlockResult ConnectReferenceChildBlock(
    const CBlock& block,
    const CBlockIndex& parent,
    int64_t current_time,
    const ReferenceChildDefinition& definition,
    const MainHeaderChain& main_headers,
    CCoinsViewCache& coins,
    DepositImportState& imports)
{
    if (!IsValidDefinition(definition)) {
        return BlockError(ReferenceChildBlockError::INVALID_DEFINITION);
    }
    if (imports.ChildChain() != definition.chain_id ||
        imports.MinimumConfirmations() != definition.parameters.deposit_maturity ||
        main_headers.Params().hashGenesisBlock !=
            definition.genesis.main_genesis_hash ||
        !main_headers.IsInitialized() || current_time < 0) {
        return BlockError(ReferenceChildBlockError::INVALID_RUNTIME_CONTEXT);
    }
    if (imports.IsSafeHalted()) {
        return BlockError(ReferenceChildBlockError::SAFE_HALT);
    }
    if (!parent.phashBlock || parent.nHeight < 0 ||
        coins.GetBestBlock() != parent.GetBlockHash() ||
        block.hashPrevBlock != parent.GetBlockHash()) {
        return BlockError(ReferenceChildBlockError::INVALID_PARENT);
    }
    const CBlockIndex* genesis{parent.GetAncestor(0)};
    if (!genesis || genesis->GetBlockHash() != definition.genesis_hash) {
        return BlockError(ReferenceChildBlockError::INVALID_PARENT);
    }
    if (parent.nHeight >= std::numeric_limits<int32_t>::max() - 1) {
        return BlockError(ReferenceChildBlockError::HEIGHT_OVERFLOW);
    }
    const int height{parent.nHeight + 1};
    if (block.nVersion != CBlockHeader::CURRENT_VERSION ||
        block.nBits != 0 || block.nNonce != 0) {
        return BlockError(ReferenceChildBlockError::INVALID_HEADER);
    }
    if (block.GetBlockTime() <= parent.GetMedianTimePast()) {
        return BlockError(ReferenceChildBlockError::TIME_TOO_OLD);
    }
    if (block.GetBlockTime() < parent.GetBlockTime()) {
        return BlockError(ReferenceChildBlockError::TIME_MOVED_BACKWARDS);
    }
    if (block.GetBlockTime() > current_time + MAX_FUTURE_BLOCK_TIME) {
        return BlockError(ReferenceChildBlockError::TIME_TOO_NEW);
    }
    if (block.vtx.empty()) {
        return BlockError(ReferenceChildBlockError::EMPTY_BLOCK);
    }

    bool mutated{false};
    const uint256 merkle_root{BlockMerkleRoot(block, &mutated)};
    if (block.hashMerkleRoot != merkle_root) {
        return BlockError(ReferenceChildBlockError::INVALID_MERKLE_ROOT);
    }
    if (mutated) {
        return BlockError(ReferenceChildBlockError::MUTATED_MERKLE_TREE);
    }
    if (block.vtx.size() * WITNESS_SCALE_FACTOR >
            definition.parameters.max_block_weight ||
        GetBlockWeight(block) >
            static_cast<int64_t>(definition.parameters.max_block_weight)) {
        return BlockError(ReferenceChildBlockError::BLOCK_TOO_HEAVY);
    }
    if (!block.vtx.front()->IsCoinBase() ||
        !HasExpectedCoinbaseHeight(*block.vtx.front(), height)) {
        return BlockError(ReferenceChildBlockError::INVALID_COINBASE, 0);
    }
    for (size_t index{1}; index < block.vtx.size(); ++index) {
        if (block.vtx[index]->IsCoinBase()) {
            return BlockError(ReferenceChildBlockError::INVALID_COINBASE, index);
        }
    }
    if (!CheckWitnessCommitment(block)) {
        return BlockError(ReferenceChildBlockError::INVALID_WITNESS_COMMITMENT);
    }

    std::set<Txid> transaction_ids;
    std::vector<DepositProof> proofs;
    std::vector<size_t> proof_transactions;
    for (size_t index{0}; index < block.vtx.size(); ++index) {
        const CTransaction& transaction{*block.vtx[index]};
        TxValidationState tx_state;
        if (!CheckTransaction(transaction, tx_state) ||
            !CheckNativeTransaction(transaction, tx_state)) {
            auto result{BlockError(
                ReferenceChildBlockError::INVALID_TRANSACTION, index)};
            result.transaction_error = tx_state.GetResult();
            return result;
        }
        if (!transaction_ids.insert(transaction.GetHash()).second) {
            return BlockError(
                ReferenceChildBlockError::DUPLICATE_TRANSACTION, index);
        }
        if (!IsFinalTx(transaction, height, parent.GetMedianTimePast())) {
            return BlockError(
                ReferenceChildBlockError::NONFINAL_TRANSACTION, index);
        }
        if (index > 0 && IsReferenceChildImport(transaction)) {
            const auto parsed{ParseReferenceChildImportTransaction(
                transaction, definition)};
            if (!parsed.IsValid()) {
                auto result{BlockError(
                    ReferenceChildBlockError::INVALID_IMPORT, index)};
                result.import_error = parsed.error;
                result.authentication_error =
                    AuthenticatedDepositError::STRUCTURAL_PROOF_INVALID;
                return result;
            }
            proofs.push_back(*parsed.proof);
            proof_transactions.push_back(index);
        }
    }

    DepositImportState candidate_imports{imports};
    const uint256 block_hash{block.GetHash()};
    const auto imported{candidate_imports.ImportProofs(
        proofs, main_headers, block_hash, static_cast<uint32_t>(height))};
    if (!imported.IsValid()) {
        const std::optional<size_t> failed_transaction{
            imported.failed_proof
                ? std::optional<size_t>{proof_transactions[*imported.failed_proof]}
                : std::nullopt};
        auto result{BlockError(
            imported.error == DepositImportError::SAFE_HALT
                ? ReferenceChildBlockError::SAFE_HALT
                : ReferenceChildBlockError::IMPORT_REJECTED,
            failed_transaction)};
        result.deposit_error = imported.error;
        result.authentication_error = imported.authentication_error;
        return result;
    }

    CoinsViewOverlay view{&coins};
    CBlockUndo coin_undo;
    coin_undo.vtxundo.reserve(block.vtx.size() - 1);
    CAmount total_fees{0};
    CBlockIndex current{block};
    current.pprev = const_cast<CBlockIndex*>(&parent);
    current.nHeight = height;
    current.phashBlock = &block_hash;
    current.BuildSkip();

    for (size_t index{0}; index < block.vtx.size(); ++index) {
        const CTransaction& transaction{*block.vtx[index]};
        for (size_t output_index{0};
             output_index < transaction.vout.size();
             ++output_index) {
            if (view.HaveCoin(COutPoint{
                    transaction.GetHash(),
                    static_cast<uint32_t>(output_index)})) {
                return BlockError(
                    ReferenceChildBlockError::UTXO_OVERWRITE, index);
            }
        }

        if (index == 0) {
            AddCoins(view, transaction, height);
            continue;
        }

        coin_undo.vtxundo.emplace_back();
        CTxUndo& transaction_undo{coin_undo.vtxundo.back()};
        if (IsReferenceChildImport(transaction)) {
            AddCoins(view, transaction, height);
            continue;
        }

        CAmount fee{0};
        TxValidationState tx_state;
        if (!Consensus::CheckTxInputs(
                transaction, tx_state, view, height, fee)) {
            auto result{BlockError(
                ReferenceChildBlockError::INPUTS_REJECTED, index)};
            result.transaction_error = tx_state.GetResult();
            return result;
        }
        if (fee > MAX_MONEY - total_fees) {
            return BlockError(
                ReferenceChildBlockError::FEE_OUT_OF_RANGE, index);
        }
        total_fees += fee;

        std::vector<int> previous_heights;
        std::vector<CTxOut> spent_outputs;
        previous_heights.reserve(transaction.vin.size());
        spent_outputs.reserve(transaction.vin.size());
        for (const CTxIn& input : transaction.vin) {
            const Coin& coin{view.AccessCoin(input.prevout)};
            previous_heights.push_back(coin.nHeight);
            spent_outputs.push_back(coin.out);
        }
        if (!SequenceLocks(transaction,
                           LOCKTIME_VERIFY_SEQUENCE,
                           previous_heights,
                           current)) {
            return BlockError(
                ReferenceChildBlockError::SEQUENCE_LOCKED, index);
        }

        PrecomputedTransactionData txdata;
        txdata.Init(transaction, std::move(spent_outputs));
        for (size_t input_index{0};
             input_index < transaction.vin.size();
             ++input_index) {
            ScriptError script_error{SCRIPT_ERR_UNKNOWN_ERROR};
            const CTxIn& input{transaction.vin[input_index]};
            const Coin& coin{view.AccessCoin(input.prevout)};
            const ReferenceChildTransactionSignatureChecker checker{
                definition.chain_id,
                &transaction,
                static_cast<unsigned int>(input_index),
                txdata,
                MissingDataBehavior::ASSERT_FAIL};
            if (!VerifyScript(input.scriptSig,
                              coin.out.scriptPubKey,
                              &input.scriptWitness,
                              SCRIPT_VERIFY_NONE,
                              checker,
                              &script_error)) {
                auto result{BlockError(
                    ReferenceChildBlockError::SCRIPT_REJECTED, index)};
                result.script_error = script_error;
                return result;
            }
        }

        transaction_undo.vprevout.reserve(transaction.vin.size());
        for (const CTxIn& input : transaction.vin) {
            transaction_undo.vprevout.emplace_back();
            if (!view.SpendCoin(
                    input.prevout, &transaction_undo.vprevout.back())) {
                return BlockError(
                    ReferenceChildBlockError::UTXO_MISMATCH, index);
            }
        }
        AddCoins(view, transaction, height);
    }

    if (block.vtx.front()->GetValueOut() > total_fees) {
        return BlockError(
            ReferenceChildBlockError::COINBASE_PAYS_TOO_MUCH, 0);
    }

    ReferenceChildBlockUndo undo{
        .block_hash = block_hash,
        .parent_hash = parent.GetBlockHash(),
        .block_height = static_cast<uint32_t>(height),
        .coins = std::move(coin_undo),
        .imports = imported.undo,
    };
    view.SetBestBlock(block_hash);
    view.Flush(/*reallocate_cache=*/false);
    imports = std::move(candidate_imports);

    ReferenceChildBlockResult result;
    result.total_fees = total_fees;
    result.undo = std::move(undo);
    return result;
}

ReferenceChildBlockResult DisconnectReferenceChildBlock(
    const CBlock& block,
    const ReferenceChildBlockUndo& undo,
    CCoinsViewCache& coins,
    DepositImportState& imports)
{
    const uint256 block_hash{block.GetHash()};
    if (undo.version != REFERENCE_CHILD_BLOCK_UNDO_VERSION ||
        undo.block_hash != block_hash ||
        undo.parent_hash != block.hashPrevBlock || undo.parent_hash.IsNull() ||
        undo.block_height == 0 ||
        undo.coins.vtxundo.size() + 1 != block.vtx.size() ||
        coins.GetBestBlock() != block_hash) {
        return BlockError(ReferenceChildBlockError::INVALID_UNDO);
    }

    std::vector<DepositId> expected_imports;
    for (size_t index{1}; index < block.vtx.size(); ++index) {
        const CTransaction& transaction{*block.vtx[index]};
        if (IsReferenceChildImport(transaction)) {
            expected_imports.push_back(DepositId::FromUint256(
                transaction.vin.front().prevout.hash.ToUint256()));
        }
    }
    if (expected_imports != undo.imports.imports) {
        return BlockError(ReferenceChildBlockError::INVALID_UNDO);
    }

    DepositImportState candidate_imports{imports};
    if (!candidate_imports.DisconnectImports(block_hash, undo.imports)) {
        return BlockError(ReferenceChildBlockError::INVALID_UNDO);
    }

    CoinsViewOverlay view{&coins};
    for (size_t reverse_index{block.vtx.size()}; reverse_index > 0;) {
        const size_t index{--reverse_index};
        const CTransaction& transaction{*block.vtx[index]};
        for (size_t output_index{0};
             output_index < transaction.vout.size();
             ++output_index) {
            const CTxOut& expected{transaction.vout[output_index]};
            if (expected.scriptPubKey.IsUnspendable()) continue;

            Coin removed;
            if (!view.SpendCoin(
                    COutPoint{transaction.GetHash(),
                              static_cast<uint32_t>(output_index)},
                    &removed) ||
                removed.out != expected ||
                removed.nHeight != undo.block_height ||
                removed.IsCoinBase() != transaction.IsCoinBase()) {
                return BlockError(
                    ReferenceChildBlockError::UTXO_MISMATCH, index);
            }
        }

        if (index == 0) continue;
        const CTxUndo& transaction_undo{undo.coins.vtxundo[index - 1]};
        if (IsReferenceChildImport(transaction)) {
            if (!transaction_undo.vprevout.empty()) {
                return BlockError(
                    ReferenceChildBlockError::INVALID_UNDO, index);
            }
            continue;
        }
        if (transaction_undo.vprevout.size() != transaction.vin.size()) {
            return BlockError(
                ReferenceChildBlockError::INVALID_UNDO, index);
        }
        for (size_t reverse_input{transaction.vin.size()};
             reverse_input > 0;) {
            const size_t input_index{--reverse_input};
            if (!RestoreCoin(
                    view,
                    transaction.vin[input_index].prevout,
                    Coin{transaction_undo.vprevout[input_index]})) {
                return BlockError(
                    ReferenceChildBlockError::UTXO_MISMATCH, index);
            }
        }
    }

    view.SetBestBlock(undo.parent_hash);
    view.Flush(/*reallocate_cache=*/false);
    imports = std::move(candidate_imports);
    return {};
}

} // namespace chainregistry
