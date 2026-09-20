// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainregistry/child_import.h>

#include <addresstype.h>
#include <consensus/validation.h>
#include <pubkey.h>
#include <streams.h>

#include <ios>
#include <span>
#include <utility>
#include <vector>

namespace chainregistry {
namespace {

ChildImportResult ImportError(
    ChildImportError error,
    DepositProofValidationError proof_error = DepositProofValidationError::NONE)
{
    ChildImportResult result;
    result.error = error;
    result.proof_error = proof_error;
    return result;
}

ChildImportBuildResult BuildError(
    ChildImportError error,
    DepositProofValidationError proof_error = DepositProofValidationError::NONE)
{
    ChildImportBuildResult result;
    result.error = error;
    result.proof_error = proof_error;
    return result;
}

CScript RecipientScript(std::span<const unsigned char> recipient)
{
    return GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{recipient}});
}

std::vector<unsigned char> SerializeProof(const DepositProof& proof)
{
    std::vector<unsigned char> encoded;
    VectorWriter{encoded, 0} << proof;
    return encoded;
}

bool IsValidDefinition(const ReferenceChildDefinition& definition)
{
    const auto rebuilt{ValidateReferenceChildManifest(
        definition.genesis.main_genesis_hash,
        definition.genesis.registration_anchor,
        definition.manifest)};
    return rebuilt.IsValid() && *rebuilt.definition == definition;
}

} // namespace

bool IsReferenceChildImport(const CTransaction& transaction)
{
    return transaction.vin.size() == 1 &&
           transaction.vin.front().prevout.n == CHILD_IMPORT_PREVOUT_INDEX &&
           !transaction.vin.front().prevout.hash.IsNull();
}

ChildImportBuildResult BuildReferenceChildImportTransaction(
    const DepositProof& proof,
    const ReferenceChildDefinition& definition)
{
    if (ValidateReferenceChildParameters(definition.parameters) !=
        ReferenceChildParametersError::NONE) {
        return BuildError(ChildImportError::INVALID_PARAMETERS);
    }
    if (!IsValidDefinition(definition)) {
        return BuildError(ChildImportError::INVALID_DEFINITION);
    }
    const auto validated{ValidateDepositProofStructure(
        proof,
        definition.genesis.main_genesis_hash,
        definition.chain_id)};
    if (!validated.IsValid() || !validated.fund) {
        return BuildError(ChildImportError::INVALID_PROOF, validated.error);
    }
    if (proof.chain_record.manifest_hash != definition.manifest_hash ||
        proof.chain_record.template_id != REFERENCE_CHILD_TEMPLATE_ID ||
        proof.chain_record.template_version != REFERENCE_CHILD_TEMPLATE_VERSION) {
        return BuildError(ChildImportError::MANIFEST_MISMATCH);
    }
    const auto& fund{*validated.fund};
    if (!IsValidReferenceChildRecipient(
            fund.fund.recipient_type, fund.fund.recipient)) {
        return BuildError(ChildImportError::INVALID_RECIPIENT);
    }

    std::vector<unsigned char> encoded;
    try {
        encoded = SerializeProof(proof);
    } catch (const std::ios_base::failure&) {
        return BuildError(ChildImportError::PROOF_ENCODE_FAILED);
    }
    if (encoded.size() > definition.parameters.max_block_weight) {
        return BuildError(ChildImportError::PROOF_TOO_LARGE);
    }

    CMutableTransaction transaction;
    transaction.vin.emplace_back(COutPoint{
        Txid::FromUint256(validated.deposit_id.ToUint256()),
        CHILD_IMPORT_PREVOUT_INDEX});
    transaction.vin.front().scriptWitness.stack.emplace_back(std::move(encoded));
    transaction.vout.emplace_back(
        fund.amount, RecipientScript(fund.fund.recipient));

    if (GetTransactionWeight(CTransaction{transaction}) >
        static_cast<int64_t>(definition.parameters.max_block_weight)) {
        return BuildError(ChildImportError::TRANSACTION_TOO_HEAVY);
    }

    ChildImportBuildResult result;
    result.transaction = std::move(transaction);
    result.deposit_id = validated.deposit_id;
    return result;
}

ChildImportResult ParseReferenceChildImportTransaction(
    const CTransaction& transaction,
    const ReferenceChildDefinition& definition)
{
    if (ValidateReferenceChildParameters(definition.parameters) !=
        ReferenceChildParametersError::NONE) {
        return ImportError(ChildImportError::INVALID_PARAMETERS);
    }
    if (!IsValidDefinition(definition)) {
        return ImportError(ChildImportError::INVALID_DEFINITION);
    }
    if (!IsReferenceChildImport(transaction)) {
        return ImportError(ChildImportError::NOT_IMPORT);
    }
    if (transaction.version != CTransaction::CURRENT_VERSION ||
        transaction.nLockTime != 0 || transaction.vout.size() != 1 ||
        !transaction.vin.front().scriptSig.empty() ||
        transaction.vin.front().nSequence != CTxIn::SEQUENCE_FINAL) {
        return ImportError(ChildImportError::INVALID_SHAPE);
    }
    if (transaction.vin.front().scriptWitness.stack.size() != 1) {
        return ImportError(ChildImportError::INVALID_WITNESS);
    }
    const auto& encoded{transaction.vin.front().scriptWitness.stack.front()};
    if (encoded.empty()) return ImportError(ChildImportError::INVALID_WITNESS);
    if (encoded.size() > definition.parameters.max_block_weight) {
        return ImportError(ChildImportError::PROOF_TOO_LARGE);
    }
    if (GetTransactionWeight(transaction) >
        static_cast<int64_t>(definition.parameters.max_block_weight)) {
        return ImportError(ChildImportError::TRANSACTION_TOO_HEAVY);
    }

    DepositProof proof;
    try {
        SpanReader reader{encoded};
        reader >> proof;
        if (!reader.empty()) {
            return ImportError(ChildImportError::PROOF_TRAILING_DATA);
        }
    } catch (const std::ios_base::failure&) {
        return ImportError(ChildImportError::PROOF_DECODE_FAILED);
    }

    const auto validated{ValidateDepositProofStructure(
        proof,
        definition.genesis.main_genesis_hash,
        definition.chain_id)};
    if (!validated.IsValid() || !validated.fund) {
        return ImportError(ChildImportError::INVALID_PROOF, validated.error);
    }
    if (proof.chain_record.manifest_hash != definition.manifest_hash ||
        proof.chain_record.template_id != REFERENCE_CHILD_TEMPLATE_ID ||
        proof.chain_record.template_version != REFERENCE_CHILD_TEMPLATE_VERSION) {
        return ImportError(ChildImportError::MANIFEST_MISMATCH);
    }
    if (transaction.vin.front().prevout.hash.ToUint256() !=
        validated.deposit_id.ToUint256()) {
        return ImportError(ChildImportError::DEPOSIT_ID_MISMATCH);
    }
    const auto& fund{*validated.fund};
    if (!IsValidReferenceChildRecipient(
            fund.fund.recipient_type, fund.fund.recipient)) {
        return ImportError(ChildImportError::INVALID_RECIPIENT);
    }
    const CTxOut& output{transaction.vout.front()};
    if (output.nValue != fund.amount ||
        output.scriptPubKey != RecipientScript(fund.fund.recipient)) {
        return ImportError(ChildImportError::INVALID_OUTPUT);
    }

    ChildImportResult result;
    result.proof = std::move(proof);
    result.deposit_id = validated.deposit_id;
    return result;
}

} // namespace chainregistry
