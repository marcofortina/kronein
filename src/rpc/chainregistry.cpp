// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <chainregistry/child_template.h>
#include <consensus/bmm.h>
#include <consensus/chainregistry.h>
#include <consensus/consensus.h>
#include <core_io.h>
#include <node/chain_manager.h>
#include <node/child_chain_notifications.h>
#include <node/child_net_events.h>
#include <node/child_network_manager.h>
#include <node/context.h>
#include <primitives/chainregistry.h>
#include <primitives/deposit.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <ios>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace {

uint32_t ParseUint32(const UniValue& value, std::string_view name, bool allow_max = true)
{
    const int64_t parsed{value.getInt<int64_t>()};
    const uint64_t maximum{allow_max ? std::numeric_limits<uint32_t>::max()
                                     : std::numeric_limits<uint32_t>::max() - 1ULL};
    if (parsed < 0 || static_cast<uint64_t>(parsed) > maximum) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must be between 0 and %u", name, maximum));
    }
    return static_cast<uint32_t>(parsed);
}

chainregistry::ChainId ParseChainId(const UniValue& value)
{
    const auto chain_id{chainregistry::ChainId::FromHex(value.get_str())};
    if (!chain_id) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must be exactly 32 bytes encoded as hexadecimal");
    }
    if (chain_id->IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    }
    return *chain_id;
}

std::string DepositSafeHaltReasonName(
    chainregistry::DepositSafeHaltReason reason)
{
    switch (reason) {
    case chainregistry::DepositSafeHaltReason::IMPORTED_DEPOSIT_LEFT_MAIN_CHAIN:
        return "imported_deposit_left_main_chain";
    }
    return "unknown";
}

uint256 ParseNonNullHash(const UniValue& value, std::string_view name)
{
    const uint256 hash{ParseHashV(value, name)};
    if (hash.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER, strprintf("%s must not be null", name));
    }
    return hash;
}

chainregistry::MetadataHash ParseMetadataHash(const UniValue& value)
{
    const auto metadata_hash{chainregistry::MetadataHash::FromHex(value.get_str())};
    if (!metadata_hash) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "metadata_hash must be exactly 32 bytes encoded as hexadecimal");
    }
    if (metadata_hash->IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "metadata_hash must not be null");
    }
    return *metadata_hash;
}

std::vector<unsigned char> ParseBoundedHex(const UniValue& value,
                                           std::string_view name,
                                           size_t maximum_size)
{
    const std::string encoded{value.get_str()};
    if (!IsHex(encoded)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("%s must be a non-empty hexadecimal string", name));
    }
    if (encoded.size() / 2 > maximum_size) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("%s exceeds the maximum size of %u bytes",
                      name,
                      maximum_size));
    }
    return ParseHex(encoded);
}

chainregistry::BmmAnchorProof ParseBmmProof(const UniValue& value)
{
    const auto bytes{ParseBoundedHex(
        value,
        "bmm_proof",
        node::MAX_CHILD_PENDING_BMM_PROOF_SIZE)};
    chainregistry::BmmAnchorProof proof;
    try {
        SpanReader reader{bytes};
        reader >> proof;
        if (!reader.empty()) {
            throw std::ios_base::failure("Trailing data after BMM proof.");
        }
    } catch (const std::ios_base::failure& error) {
        throw JSONRPCError(
            RPC_DESERIALIZATION_ERROR,
            strprintf("BMM proof decode failed: %s", error.what()));
    }
    return proof;
}

chainregistry::DepositProof ParseDepositProof(const UniValue& value)
{
    const auto bytes{ParseBoundedHex(
        value, "deposit_proof", MAX_BLOCK_SERIALIZED_SIZE)};
    chainregistry::DepositProof proof;
    try {
        SpanReader reader{bytes};
        reader >> proof;
        if (!reader.empty()) {
            throw std::ios_base::failure(
                "Trailing data after deposit proof.");
        }
    } catch (const std::ios_base::failure& error) {
        throw JSONRPCError(
            RPC_DESERIALIZATION_ERROR,
            strprintf("deposit proof decode failed: %s", error.what()));
    }
    return proof;
}

std::vector<chainregistry::DepositProof> ParseDepositProofs(
    const UniValue& value)
{
    const auto& values{value.getValues()};
    if (values.empty()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "deposit_proofs must contain at least one proof");
    }
    if (values.size() > node::MAX_CHILD_IMPORTS_PER_BLOCK) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("deposit_proofs may contain at most %u proofs",
                      node::MAX_CHILD_IMPORTS_PER_BLOCK));
    }

    size_t encoded_size{0};
    std::vector<chainregistry::DepositProof> proofs;
    proofs.reserve(values.size());
    for (const UniValue& value : values) {
        const std::string& encoded{value.get_str()};
        if (encoded.size() / 2 >
            MAX_BLOCK_SERIALIZED_SIZE - encoded_size) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("deposit_proofs exceed the combined maximum size of %u bytes",
                          MAX_BLOCK_SERIALIZED_SIZE));
        }
        encoded_size += encoded.size() / 2;
        proofs.push_back(ParseDepositProof(value));
    }
    return proofs;
}

std::vector<CTransactionRef> ParseChildTransactions(const UniValue& value)
{
    const auto& values{value.getValues()};
    if (values.empty()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "transactions must contain at least one transaction");
    }

    size_t encoded_size{0};
    std::vector<CTransactionRef> transactions;
    transactions.reserve(values.size());
    for (size_t index{0}; index < values.size(); ++index) {
        const std::string& encoded{values[index].get_str()};
        if (encoded.empty() || !IsHex(encoded)) {
            throw JSONRPCError(
                RPC_DESERIALIZATION_ERROR,
                strprintf("transaction %u is not valid hexadecimal", index));
        }
        const size_t transaction_size{encoded.size() / 2};
        if (transaction_size > MAX_BLOCK_SERIALIZED_SIZE - encoded_size) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("transactions exceed the combined maximum size of %u bytes",
                          MAX_BLOCK_SERIALIZED_SIZE));
        }
        encoded_size += transaction_size;

        CMutableTransaction transaction;
        if (!DecodeHexTx(transaction, encoded)) {
            throw JSONRPCError(
                RPC_DESERIALIZATION_ERROR,
                strprintf("transaction %u decode failed", index));
        }
        transactions.push_back(MakeTransactionRef(std::move(transaction)));
    }
    return transactions;
}

std::pair<std::optional<CScript>, std::optional<std::string>>
ParseChildFeeRecipient(const UniValue* value)
{
    if (!value || value->isNull()) return {};
    const std::vector<unsigned char> recipient{
        ParseHexV(*value, "fee_recipient")};
    if (!chainregistry::IsValidReferenceChildRecipient(
            chainregistry::REFERENCE_CHILD_P2TR_RECIPIENT,
            recipient)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "fee_recipient must be a valid 32-byte reference-child P2TR output key");
    }
    return {
        GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{recipient}}),
        HexStr(recipient),
    };
}

std::string_view AuthenticatedDepositErrorName(
    chainregistry::AuthenticatedDepositError error)
{
    using enum chainregistry::AuthenticatedDepositError;
    switch (error) {
    case NONE: return "none";
    case INVALID_CONFIRMATION_POLICY: return "invalid-confirmation-policy";
    case STRUCTURAL_PROOF_INVALID: return "structural-proof-invalid";
    case HEADER_UNKNOWN: return "header-unknown";
    case HEADER_HEIGHT_MISMATCH: return "header-height-mismatch";
    case HEADER_NOT_ACTIVE: return "header-not-active";
    case INSUFFICIENT_CHAINWORK: return "insufficient-chainwork";
    case IMMATURE: return "immature";
    }
    return "unknown";
}

void PushChildStorageStats(UniValue& object,
                           const node::ChainManagerEntry& entry)
{
    object.pushKV("bmm_anchor_count", entry.anchor_count);
    object.pushKV("pending_bmm_anchor_count", entry.pending_anchor_count);
    object.pushKV("pending_bmm_anchor_bytes", entry.pending_anchor_bytes);
    object.pushKV("pending_child_block_count", entry.pending_block_count);
    object.pushKV("local_proposal_count", entry.local_proposal_count);
    object.pushKV("local_proposal_bytes", entry.local_proposal_bytes);
    object.pushKV("local_proposal_limit", node::MAX_CHILD_LOCAL_PROPOSALS);
    object.pushKV("local_proposal_bytes_limit",
                  node::MAX_CHILD_LOCAL_PROPOSAL_BYTES);
    object.pushKV("pending_bmm_anchor_limit", node::MAX_CHILD_PENDING_BMM_ANCHORS);
    object.pushKV("pending_bmm_anchor_bytes_limit", node::MAX_CHILD_PENDING_BMM_BYTES);
    object.pushKV("side_candidate_count", entry.side_candidate_count);
    object.pushKV("side_candidate_bytes", entry.side_candidate_bytes);
    object.pushKV("side_candidate_limit", node::MAX_CHILD_SIDE_CANDIDATES);
    object.pushKV("side_candidate_bytes_limit", node::MAX_CHILD_SIDE_CANDIDATE_BYTES);
    object.pushKV("candidate_bmm_anchor_count", entry.candidate_anchor_count);
    object.pushKV("candidate_bmm_anchor_bytes", entry.candidate_anchor_bytes);
    object.pushKV("candidate_bmm_anchor_limit", node::MAX_CHILD_CANDIDATE_BMM_ANCHORS);
    object.pushKV("candidate_bmm_anchor_bytes_limit", node::MAX_CHILD_CANDIDATE_BMM_BYTES);
}

CBlock ParseChildBlock(const UniValue& value)
{
    const auto bytes{ParseBoundedHex(
        value, "block", MAX_BLOCK_SERIALIZED_SIZE)};
    CBlock block;
    try {
        SpanReader reader{bytes};
        reader >> TX_WITH_WITNESS(block);
        if (!reader.empty()) {
            throw std::ios_base::failure("Trailing data after child block.");
        }
    } catch (const std::ios_base::failure& error) {
        throw JSONRPCError(
            RPC_DESERIALIZATION_ERROR,
            strprintf("Child block decode failed: %s", error.what()));
    }
    return block;
}

COutPoint ParseOutPoint(const UniValue& value, std::string_view name)
{
    const UniValue& object{value.get_obj()};
    RPCTypeCheckObj(object,
                    {
                        {"txid", UniValueType{UniValue::VSTR}},
                        {"vout", UniValueType{UniValue::VNUM}},
                    },
                    /*fAllowNull=*/false,
                    /*fStrict=*/true);
    const Txid txid{Txid::FromUint256(ParseHashO(object, "txid"))};
    const uint32_t vout{ParseUint32(object.find_value("vout"), strprintf("%s.vout", name))};
    const COutPoint outpoint{txid, vout};
    if (outpoint.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must not be null", name));
    }
    return outpoint;
}

void CheckOperationParameters(const UniValue& parameters,
                              std::initializer_list<std::string_view> allowed)
{
    for (const auto& key : parameters.getKeys()) {
        if (std::none_of(allowed.begin(), allowed.end(), [&](std::string_view candidate) {
                return candidate == key;
            })) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("unexpected parameter %s for this operation", key));
        }
    }
}

chainregistry::ChainSpec ParseChainSpec(const UniValue& value)
{
    const UniValue& object{value.get_obj()};
    RPCTypeCheckObj(object,
                    {
                        {"protocol_version", UniValueType{UniValue::VNUM}},
                        {"template_id", UniValueType{UniValue::VNUM}},
                        {"template_version", UniValueType{UniValue::VNUM}},
                        {"consensus_parameters", UniValueType{UniValue::VSTR}},
                        {"anchoring_policy", UniValueType{UniValue::VSTR}},
                    },
                    /*fAllowNull=*/true,
                    /*fStrict=*/true);
    if (!object.exists("template_id") || !object.exists("template_version") ||
        !object.exists("consensus_parameters")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "spec requires template_id, template_version, and consensus_parameters");
    }
    if (object.exists("protocol_version") &&
        ParseUint32(object.find_value("protocol_version"), "spec.protocol_version") !=
            chainregistry::PROTOCOL_VERSION) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "spec.protocol_version is not supported");
    }

    const std::string anchoring_policy{object.exists("anchoring_policy")
                                           ? object.find_value("anchoring_policy").get_str()
                                           : "bmm_v1"};
    if (anchoring_policy != "bmm_v1") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "anchoring_policy must be bmm_v1");
    }

    chainregistry::ChainSpec spec{
        .protocol_version = chainregistry::PROTOCOL_VERSION,
        .template_id = ParseUint32(object.find_value("template_id"), "spec.template_id"),
        .template_version = ParseUint32(object.find_value("template_version"), "spec.template_version"),
        .consensus_parameters = ParseHexO(object, "consensus_parameters"),
        .anchoring_policy = chainregistry::AnchoringPolicy::BMM_V1,
    };
    switch (chainregistry::ValidateChainSpec(spec)) {
    case chainregistry::ManifestValidationError::NONE:
        return spec;
    case chainregistry::ManifestValidationError::INVALID_TEMPLATE_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "spec.template_id must be greater than zero");
    case chainregistry::ManifestValidationError::INVALID_TEMPLATE_VERSION:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "spec.template_version must be greater than zero");
    case chainregistry::ManifestValidationError::CONSENSUS_PARAMETERS_TOO_LARGE:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("spec.consensus_parameters exceeds %u bytes",
                                     chainregistry::MAX_CONSENSUS_PARAMETERS_SIZE));
    default:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid child-chain specification");
    }
}

chainregistry::ChainManifest ParseManifest(const UniValue& parameters)
{
    const auto spec{ParseChainSpec(parameters.find_value("spec"))};
    const uint256 child_genesis_hash{ParseHashO(parameters, "child_genesis_hash")};
    if (child_genesis_hash.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "child_genesis_hash must not be null");
    }
    return chainregistry::ChainManifest{
        .spec = spec,
        .child_genesis_hash = child_genesis_hash,
        .initial_metadata_hash = ParseMetadataHash(parameters.find_value("metadata_hash")),
    };
}

template <typename T>
std::string SerializeHex(const T& value)
{
    DataStream stream;
    stream << value;
    return HexStr(stream);
}

UniValue ChainSpecToUniv(const chainregistry::ChainSpec& spec)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("protocol_version", spec.protocol_version);
    result.pushKV("template_id", spec.template_id);
    result.pushKV("template_version", spec.template_version);
    result.pushKV("consensus_parameters", HexStr(spec.consensus_parameters));
    result.pushKV("anchoring_policy", "bmm_v1");
    return result;
}

UniValue ManifestToUniv(const chainregistry::ChainManifest& manifest)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("spec", ChainSpecToUniv(manifest.spec));
    result.pushKV("child_genesis_hash", manifest.child_genesis_hash.GetHex());
    result.pushKV("metadata_hash", manifest.initial_metadata_hash.GetHex());
    return result;
}

UniValue OutPointToUniv(const COutPoint& outpoint)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("txid", outpoint.hash.GetHex());
    result.pushKV("vout", outpoint.n);
    return result;
}

std::vector<unsigned char> OpReturnData(const CScript& script)
{
    auto cursor{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    Assume(script.GetOp(cursor, opcode) && opcode == OP_RETURN);
    Assume(script.GetOp(cursor, opcode, data) && cursor == script.end());
    return data;
}

UniValue FundToUniv(const chainregistry::FundChain& fund)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", fund.chain_id.GetHex());
    result.pushKV("recipient_type", fund.recipient_type);
    result.pushKV("recipient", HexStr(fund.recipient));
    return result;
}

UniValue OperationToUniv(const chainregistry::RegistryOperation& operation)
{
    return std::visit([](const auto& payload) {
        using Payload = std::decay_t<decltype(payload)>;
        UniValue result{UniValue::VOBJ};
        if constexpr (std::is_same_v<Payload, chainregistry::RegisterChain>) {
            result.pushKV("operation", "register");
            result.pushKV("anchor_input", payload.anchor_input);
            result.pushKV("control_output", payload.control_output);
            result.pushKV("manifest", ManifestToUniv(payload.manifest));
            result.pushKV("chain_spec_hash", chainregistry::ComputeChainSpecHash(payload.manifest.spec).GetHex());
            result.pushKV("manifest_hash", chainregistry::ComputeManifestHash(payload.manifest).GetHex());
        } else if constexpr (std::is_same_v<Payload, chainregistry::UpdateChain>) {
            result.pushKV("operation", "update");
            result.pushKV("chain_id", payload.chain_id.GetHex());
            result.pushKV("control_output", payload.control_output);
            result.pushKV("metadata_hash", payload.metadata_hash.GetHex());
        } else {
            result.pushKV("operation", "retire");
            result.pushKV("chain_id", payload.chain_id.GetHex());
        }
        return result;
    }, operation);
}

std::vector<RPCArg> ChainSpecArgs()
{
    return {
        {"template_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "Non-zero consensus template identifier"},
        {"template_version", RPCArg::Type::NUM, RPCArg::Optional::NO, "Non-zero template version"},
        {"consensus_parameters", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical template parameters (maximum 1024 bytes)"},
        {"anchoring_policy", RPCArg::Type::STR, RPCArg::Default{"bmm_v1"}, "Anchoring policy; only bmm_v1 is defined"},
        {"protocol_version", RPCArg::Type::NUM, RPCArg::Default{chainregistry::PROTOCOL_VERSION}, "Registry protocol version"},
    };
}

std::vector<RPCArg> OutPointArgs()
{
    return {
        {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction id"},
        {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index"},
    };
}

const std::vector<RPCResult> CHAIN_SPEC_RESULT{
    {RPCResult::Type::NUM, "protocol_version", "Registry protocol version"},
    {RPCResult::Type::NUM, "template_id", "Consensus template identifier"},
    {RPCResult::Type::NUM, "template_version", "Consensus template version"},
    {RPCResult::Type::STR_HEX, "consensus_parameters", "Canonical template parameters"},
    {RPCResult::Type::STR, "anchoring_policy", "Anchoring policy"},
};

const std::vector<RPCResult> CHAIN_MANIFEST_RESULT{
    {RPCResult::Type::OBJ, "spec", "Immutable child-chain specification", CHAIN_SPEC_RESULT},
    {RPCResult::Type::STR_HEX, "child_genesis_hash", "Derived child genesis hash"},
    {RPCResult::Type::STR_HEX, "metadata_hash", "Initial metadata commitment"},
};

struct MainRegistrySnapshot {
    uint256 best_block;
    uint32_t height{0};
    uint256 root;
    std::map<chainregistry::ChainId, chainregistry::ChainRecord> records;
};

struct ActiveMainHeaders {
    uint256 tip;
    std::vector<CBlockHeader> headers;
};

ActiveMainHeaders GetActiveMainHeaders(ChainstateManager& chainman)
{
    LOCK(cs_main);
    const CChain& active{chainman.ActiveChain()};
    ActiveMainHeaders result;
    if (!active.Tip()) return result;
    result.tip = active.Tip()->GetBlockHash();
    result.headers.reserve(active.Height());
    for (int height{1}; height <= active.Height(); ++height) {
        result.headers.push_back(Assert(active[height])->GetBlockHeader());
    }
    return result;
}

MainRegistrySnapshot GetMainRegistrySnapshot(ChainstateManager& chainman)
{
    LOCK(cs_main);
    const auto& registry_state{
        chainman.ActiveChainstate().ChainRegistryState()};
    return {
        .best_block = registry_state.State().best_block,
        .height = registry_state.State().height,
        .root = registry_state.State().registry_root,
        .records = registry_state.Registry().Records(),
    };
}

std::string RegistryStatusName(chainregistry::ChainStatus status)
{
    return status == chainregistry::ChainStatus::ACTIVE ? "active" : "retired";
}

void EnsureRegistryMatchesDefinition(
    const MainRegistrySnapshot& snapshot,
    const chainregistry::ReferenceChildDefinition& definition,
    bool require_active)
{
    const auto found{snapshot.records.find(definition.chain_id)};
    if (found == snapshot.records.end()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not registered on the active main chain");
    }
    const auto& record{found->second};
    if (record.manifest_hash != definition.manifest_hash ||
        record.template_id != definition.manifest.spec.template_id ||
        record.template_version != definition.manifest.spec.template_version) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "local child manifest does not match the active main-chain registry record");
    }
    if (require_active && record.status != chainregistry::ChainStatus::ACTIVE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is retired on the active main chain");
    }
}

[[noreturn]] void ThrowChainManagerError(
    const node::ChainManagerResult& result)
{
    switch (result.error) {
    case node::ChainManagerError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerError::INVALID_DEFINITION:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid child-chain definition");
    case node::ChainManagerError::WRONG_MAIN_GENESIS:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child definition belongs to another main network");
    case node::ChainManagerError::DEFINITION_CONFLICT:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "a different manifest is already configured for chain_id");
    case node::ChainManagerError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerError::CHAIN_LOADED:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "unload the child chain before forgetting it");
    case node::ChainManagerError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not loaded");
    case node::ChainManagerError::TOO_MANY_LOADED_CHAINS:
        throw JSONRPCError(
            RPC_MISC_ERROR,
            strprintf("at most %u child chains may be loaded at once",
                      node::MAX_LOADED_CHILD_CHAINS));
    case node::ChainManagerError::INITIALIZATION_FAILED:
        throw JSONRPCError(
            RPC_MISC_ERROR,
            strprintf("failed to initialize child runtime (error %u)",
                      static_cast<unsigned>(result.runtime.error)));
    case node::ChainManagerError::RUNTIME_REJECTED:
        if (result.runtime.error ==
            node::ReferenceChildRuntimeError::LOCAL_PROPOSAL_NOT_FOUND) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               "local child proposal was not found");
        }
        if (result.runtime.error ==
            node::ReferenceChildRuntimeError::LOCAL_PROPOSAL_PERSIST_FAILED) {
            throw JSONRPCError(
                RPC_DATABASE_ERROR,
                "failed to persist local child proposal; storage limits may have been reached");
        }
        if (result.runtime.error ==
            node::ReferenceChildRuntimeError::BMM_ANCHOR_UNAVAILABLE) {
            throw JSONRPCError(
                RPC_VERIFY_REJECTED,
                "no authenticated pending BMM anchor commits to this child block");
        }
        if (result.runtime.error ==
            node::ReferenceChildRuntimeError::SAFE_HALT) {
            throw JSONRPCError(RPC_VERIFY_REJECTED,
                               "child chain is in SAFE_HALT");
        }
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            strprintf("child runtime rejected request (runtime error %u, BMM error %u, block error %u)",
                      static_cast<unsigned>(result.runtime.error),
                      static_cast<unsigned>(result.runtime.bmm_anchor.error),
                      static_cast<unsigned>(result.runtime.child_block.error)));
    case node::ChainManagerError::CATALOG_UNAVAILABLE:
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "child chain catalog is unavailable");
    case node::ChainManagerError::DATABASE_WRITE_FAILED:
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "failed to update child chain catalog");
    case node::ChainManagerError::NONE:
        break;
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR, "unknown child chain manager error");
}

[[noreturn]] void ThrowChildNetworkError(
    const node::ChildNetworkResult& result)
{
    switch (result.error) {
    case node::ChildNetworkError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChildNetworkError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChildNetworkError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_MISC_ERROR, "child chain is not loaded");
    case node::ChildNetworkError::ALREADY_RUNNING:
        throw JSONRPCError(RPC_MISC_ERROR, "child network is already running");
    case node::ChildNetworkError::NOT_RUNNING:
        throw JSONRPCError(RPC_MISC_ERROR, "child network is not running");
    case node::ChildNetworkError::NULL_TRANSACTION:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child transaction must not be null");
    case node::ChildNetworkError::TOO_MANY_ENDPOINTS:
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("at most %u child connect endpoints are allowed",
                      node::MAX_CHILD_CONNECT_NODES));
    case node::ChildNetworkError::INVALID_ENDPOINT:
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("child endpoint must include an explicit non-zero port: %s",
                      result.detail));
    case node::ChildNetworkError::TOO_MANY_BIND_ENDPOINTS:
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("at most %u child bind endpoints are allowed",
                      node::MAX_CHILD_BIND_ENDPOINTS));
    case node::ChildNetworkError::INVALID_BIND_ENDPOINT:
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("child bind endpoint must be a numeric address with an explicit non-zero port: %s",
                      result.detail));
    case node::ChildNetworkError::TOO_MANY_BOOTSTRAP_ENDPOINTS:
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("at most %u child bootstrap endpoints are allowed",
                      node::MAX_CHILD_BOOTSTRAP_NODES));
    case node::ChildNetworkError::INVALID_BOOTSTRAP_ENDPOINT:
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("child bootstrap endpoint must be a numeric address with an explicit non-zero port: %s",
                      result.detail));
    case node::ChildNetworkError::DATA_DIRECTORY_ERROR:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            strprintf("failed to create child network directory: %s",
                      result.detail));
    case node::ChildNetworkError::PEER_STORE_ERROR:
        throw JSONRPCError(RPC_DATABASE_ERROR, result.detail);
    case node::ChildNetworkError::CONFIG_READ_ERROR:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            strprintf("failed to read child network configuration: %s",
                      result.detail));
    case node::ChildNetworkError::CONFIG_WRITE_ERROR:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            strprintf("failed to persist child network configuration: %s",
                      result.detail));
    case node::ChildNetworkError::CONFIG_INVALID:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            strprintf("invalid child network configuration: %s",
                      result.detail));
    case node::ChildNetworkError::START_FAILED:
        throw JSONRPCError(
            RPC_MISC_ERROR,
            result.detail.empty()
                ? "failed to start isolated child network"
                : strprintf("failed to start isolated child network: %s",
                            result.detail));
    case node::ChildNetworkError::NODE_ALREADY_ADDED:
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("child endpoint is already configured: %s", result.detail));
    case node::ChildNetworkError::NODE_NOT_ADDED:
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("child endpoint is not configured: %s", result.detail));
    case node::ChildNetworkError::NONE:
        break;
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR, "unknown child network error");
}

[[noreturn]] void ThrowProposalsViewError(
    node::ChainManagerProposalsViewError error)
{
    switch (error) {
    case node::ChainManagerProposalsViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerProposalsViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerProposalsViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is not loaded");
    case node::ChainManagerProposalsViewError::PROPOSAL_NOT_FOUND:
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "local child proposal was not found");
    case node::ChainManagerProposalsViewError::DATA_UNAVAILABLE:
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "local child proposals are unavailable");
    case node::ChainManagerProposalsViewError::NONE:
        break;
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unknown child proposal view error");
}

[[noreturn]] void ThrowBmmStatusViewError(
    node::ChainManagerBmmStatusViewError error)
{
    switch (error) {
    case node::ChainManagerBmmStatusViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerBmmStatusViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerBmmStatusViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is not loaded");
    case node::ChainManagerBmmStatusViewError::DATA_UNAVAILABLE:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "consistent child BMM status is unavailable");
    case node::ChainManagerBmmStatusViewError::NONE:
        break;
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR, "unknown child BMM status error");
}

[[noreturn]] void ThrowChildAnchorCatchUpError(
    node::ChildAnchorCatchUpError error)
{
    switch (error) {
    case node::ChildAnchorCatchUpError::PROPOSALS_UNAVAILABLE:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "failed to read durable child proposals during BMM anchor catch-up");
    case node::ChildAnchorCatchUpError::ANCHOR_INDEX_UNAVAILABLE:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "active main-chain BMM anchor index is unavailable");
    case node::ChildAnchorCatchUpError::ANCHOR_INDEX_INCONSISTENT:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "active main-chain BMM anchor index is inconsistent");
    case node::ChildAnchorCatchUpError::PROOF_BUILD_FAILED:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "failed to rebuild a historical BMM anchor proof");
    case node::ChildAnchorCatchUpError::NONE:
        break;
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unknown child BMM anchor catch-up error");
}

[[noreturn]] void ThrowChildDepositProposalError(
    node::ChildDepositProposalError error)
{
    switch (error) {
    case node::ChildDepositProposalError::CHILD_STATE_UNAVAILABLE:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "consistent child proposer state is unavailable");
    case node::ChildDepositProposalError::DEPOSIT_INDEX_UNAVAILABLE:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "active main-chain child deposit index is unavailable");
    case node::ChildDepositProposalError::DEPOSIT_INDEX_INCONSISTENT:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "active main-chain child deposit index is inconsistent");
    case node::ChildDepositProposalError::PROOF_BUILD_FAILED:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "failed to rebuild an indexed child deposit proof");
    case node::ChildDepositProposalError::IMPORT_AUTHENTICATION_FAILED:
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            "indexed child deposit was rejected by the child light client");
    case node::ChildDepositProposalError::PROPOSAL_BUILD_FAILED:
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            "failed to build or persist the automatic child proposal");
    case node::ChildDepositProposalError::NONE:
        break;
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR,
                       "unknown automatic child proposer error");
}

node::ChildNetworkConfig ParseChildNetworkConfig(const UniValue& options)
{
    node::ChildNetworkConfig config;
    if (options.isNull()) return config;
    const UniValue& connect{options.find_value("connect")};
    if (!connect.isNull()) {
        for (const UniValue& endpoint : connect.getValues()) {
            config.connect.push_back(endpoint.get_str());
        }
    }
    const UniValue& bind{options.find_value("bind")};
    if (!bind.isNull()) {
        for (const UniValue& endpoint : bind.getValues()) {
            config.bind.push_back(endpoint.get_str());
        }
    }
    const UniValue& bootstrap{options.find_value("bootstrap")};
    if (!bootstrap.isNull()) {
        for (const UniValue& endpoint : bootstrap.getValues()) {
            config.bootstrap.push_back(endpoint.get_str());
        }
    }
    const UniValue& discovery{options.find_value("discovery")};
    if (!discovery.isNull()) config.discovery = discovery.get_bool();
    const UniValue& active{options.find_value("network_active")};
    if (!active.isNull()) config.network_active = active.get_bool();
    return config;
}

void PushChildNetworkStats(UniValue& object,
                           const node::ChildNetworkStats& stats)
{
    object.pushKV("network_running", stats.running);
    object.pushKV("network_active", stats.network_active);
    object.pushKV("connections", stats.connections);
    object.pushKV("handshaken_peers", stats.handshaken);
    object.pushKV("known_addresses", stats.known_addresses);
    object.pushKV("max_known_addresses", node::MAX_CHILD_KNOWN_ADDRESSES);
    object.pushKV(
        "rate_limited_block_requests", stats.rate_limited_requests);
    object.pushKV("discovery_enabled", stats.discovery);
    UniValue added_nodes{UniValue::VARR};
    for (const auto& endpoint : stats.added_nodes) {
        added_nodes.push_back(endpoint);
    }
    object.pushKV("added_nodes", std::move(added_nodes));
    UniValue bind_endpoints{UniValue::VARR};
    for (const auto& endpoint : stats.bind_endpoints) {
        bind_endpoints.push_back(endpoint);
    }
    object.pushKV("binds", std::move(bind_endpoints));
    UniValue bootstrap_nodes{UniValue::VARR};
    for (const auto& endpoint : stats.bootstrap_nodes) {
        bootstrap_nodes.push_back(endpoint);
    }
    object.pushKV("bootstrap_nodes", std::move(bootstrap_nodes));
}

void PushChildBandwidthStats(UniValue& object,
                             const node::ChildBandwidthStats& stats)
{
    object.pushKV("aggregate_upload_target", stats.target);
    object.pushKV("aggregate_upload_bytes_sent", stats.bytes_sent);
    object.pushKV("aggregate_upload_bytes_left", stats.bytes_left);
    object.pushKV("aggregate_upload_timeframe", stats.timeframe.count());
    object.pushKV("aggregate_upload_time_left", stats.time_left.count());
    object.pushKV("aggregate_upload_target_reached", stats.target_reached);
}

RPCHelpMan derivechildchainid()
{
    return RPCHelpMan{
        "derivechildchainid",
        "Derive a child chain_id from this main network, a registration anchor, and a canonical chain specification.\n",
        {
            {"registration_anchor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Pre-existing UTXO consumed by REGISTER", OutPointArgs()},
            {"spec", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Immutable pre-genesis consensus specification", ChainSpecArgs()},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "main_genesis_hash", "Genesis hash domain separating the main network"},
            {RPCResult::Type::OBJ, "registration_anchor", "Registration anchor", {
                {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                {RPCResult::Type::NUM, "vout", "Output index"},
            }},
            {RPCResult::Type::OBJ, "spec", "Validated canonical specification", CHAIN_SPEC_RESULT},
            {RPCResult::Type::STR_HEX, "spec_hex", "Canonical serialized specification"},
            {RPCResult::Type::STR_HEX, "chain_spec_hash", "Tagged specification hash"},
            {RPCResult::Type::STR_HEX, "chain_id", "Derived child-chain identifier"},
        }},
        RPCExamples{
            HelpExampleCli("derivechildchainid", "'{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0}' '{\"template_id\":1,\"template_version\":1,\"consensus_parameters\":\"\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const COutPoint anchor{ParseOutPoint(self.Arg<UniValue>("registration_anchor"), "registration_anchor")};
    const auto spec{ParseChainSpec(self.Arg<UniValue>("spec"))};
    const auto spec_hash{chainregistry::ComputeChainSpecHash(spec)};
    const uint256& main_genesis_hash{EnsureAnyChainman(request.context).GetConsensus().hashGenesisBlock};

    UniValue result{UniValue::VOBJ};
    result.pushKV("main_genesis_hash", main_genesis_hash.GetHex());
    result.pushKV("registration_anchor", OutPointToUniv(anchor));
    result.pushKV("spec", ChainSpecToUniv(spec));
    result.pushKV("spec_hex", SerializeHex(spec));
    result.pushKV("chain_spec_hash", spec_hash.GetHex());
    result.pushKV("chain_id", chainregistry::DeriveChainId(main_genesis_hash, anchor, spec_hash).GetHex());
    return result;
}
    };
}

RPCHelpMan createreferencechildmanifest()
{
    return RPCHelpMan{
        "createreferencechildmanifest",
        "Create the complete deterministic manifest for the supported reference child template. The result can be committed by REGISTER and later passed unchanged to addchildchain.\n",
        {
            {"registration_anchor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Pre-existing UTXO that REGISTER will consume", OutPointArgs()},
            {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Initial external metadata commitment"},
            {"max_block_weight", RPCArg::Type::NUM, RPCArg::Default{chainregistry::MAX_CHILD_BLOCK_WEIGHT}, "Child block weight limit"},
            {"deposit_maturity", RPCArg::Type::NUM, RPCArg::Default{chainregistry::DEFAULT_DEPOSIT_MATURITY}, "Required main-chain confirmations before import"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Deterministic reference-child definition", {
            {RPCResult::Type::STR_HEX, "main_genesis_hash", "Main-network genesis domain"},
            {RPCResult::Type::OBJ, "registration_anchor", "Registration anchor", {
                {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                {RPCResult::Type::NUM, "vout", "Output index"},
            }},
            {RPCResult::Type::STR_HEX, "chain_id", "Derived full child-chain identifier"},
            {RPCResult::Type::STR_HEX, "chain_spec_hash", "Tagged specification hash"},
            {RPCResult::Type::STR_HEX, "manifest_hash", "Tagged complete manifest hash"},
            {RPCResult::Type::STR_HEX, "genesis_hash", "Deterministic child genesis hash"},
            {RPCResult::Type::OBJ, "manifest", "Complete canonical manifest", CHAIN_MANIFEST_RESULT},
            {RPCResult::Type::STR_HEX, "manifest_hex", "Canonical serialized manifest"},
        }},
        RPCExamples{
            HelpExampleCli("createreferencechildmanifest", "'{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0}' \"1111111111111111111111111111111111111111111111111111111111111111\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const COutPoint anchor{ParseOutPoint(
        self.Arg<UniValue>("registration_anchor"), "registration_anchor")};
    const chainregistry::ReferenceChildParameters parameters{
        .max_block_weight = ParseUint32(
            self.Arg<UniValue>("max_block_weight"), "max_block_weight"),
        .deposit_maturity = ParseUint32(
            self.Arg<UniValue>("deposit_maturity"), "deposit_maturity"),
    };
    const auto main_genesis_hash{
        EnsureAnyChainman(request.context).GetConsensus().hashGenesisBlock};
    const auto definition{chainregistry::BuildReferenceChildDefinition(
        main_genesis_hash,
        anchor,
        chainregistry::MakeReferenceChildSpec(parameters),
        ParseMetadataHash(self.Arg<UniValue>("metadata_hash")))};
    if (!definition.IsValid() || !definition.definition) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("invalid reference-child parameters (error %u, parameters %u)",
                      static_cast<unsigned>(definition.error),
                      static_cast<unsigned>(definition.parameters_error)));
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("main_genesis_hash", main_genesis_hash.GetHex());
    result.pushKV("registration_anchor", OutPointToUniv(anchor));
    result.pushKV("chain_id", definition.definition->chain_id.GetHex());
    result.pushKV("chain_spec_hash", definition.definition->chain_spec_hash.GetHex());
    result.pushKV("manifest_hash", definition.definition->manifest_hash.GetHex());
    result.pushKV("genesis_hash", definition.definition->genesis_hash.GetHex());
    result.pushKV("manifest", ManifestToUniv(definition.definition->manifest));
    result.pushKV("manifest_hex", SerializeHex(definition.definition->manifest));
    return result;
}
    };
}

RPCHelpMan createfundchainoutput()
{
    return RPCHelpMan{
        "createfundchainoutput",
        "Create a canonical, provably unspendable KFND script for a one-way child-chain deposit. The amount is the value assigned to this output by the containing transaction and is not duplicated in the payload.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Active child-chain identifier"},
            {"recipient_type", RPCArg::Type::NUM, RPCArg::Optional::NO, "Non-zero recipient namespace defined by the child template"},
            {"recipient", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical child recipient bytes (1-64 bytes)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "version", "KFND envelope version"},
            {RPCResult::Type::STR_HEX, "chain_id", "Destination child-chain identifier"},
            {RPCResult::Type::NUM, "recipient_type", "Child-template recipient namespace"},
            {RPCResult::Type::STR_HEX, "recipient", "Canonical raw child recipient"},
            {RPCResult::Type::STR_HEX, "script", "Canonical OP_RETURN scriptPubKey"},
            {RPCResult::Type::STR_HEX, "data", "Raw KFND envelope, suitable for a createrawtransaction data output"},
        }},
        RPCExamples{
            HelpExampleCli("createfundchainoutput", "\"1111111111111111111111111111111111111111111111111111111111111111\" 1 \"001122\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest&) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const uint32_t recipient_type{ParseUint32(
        self.Arg<UniValue>("recipient_type"), "recipient_type")};
    if (recipient_type == 0 || recipient_type > std::numeric_limits<uint16_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "recipient_type must be between 1 and 65535");
    }
    const UniValue recipient_arg{self.Arg<UniValue>("recipient")};
    if (recipient_arg.get_str().empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "recipient must contain at least 1 byte");
    }
    chainregistry::FundChain fund{
        .chain_id = chain_id,
        .recipient_type = static_cast<uint16_t>(recipient_type),
        .recipient = ParseHexV(recipient_arg, "recipient"),
    };
    switch (chainregistry::ValidateFund(fund)) {
    case chainregistry::FundValidationError::NONE:
        break;
    case chainregistry::FundValidationError::EMPTY_RECIPIENT:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "recipient must contain at least 1 byte");
    case chainregistry::FundValidationError::RECIPIENT_TOO_LARGE:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "recipient must not exceed 64 bytes");
    default:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid FUND_CHAIN destination");
    }

    const CScript script{chainregistry::BuildFundScript(fund)};
    UniValue result{FundToUniv(fund)};
    result.pushKV("version", chainregistry::FUND_ENVELOPE_VERSION);
    result.pushKV("script", HexStr(script));
    result.pushKV("data", HexStr(OpReturnData(script)));
    return result;
}
    };
}

RPCHelpMan decodefundchainoutput()
{
    return RPCHelpMan{
        "decodefundchainoutput",
        "Decode and validate a canonical KFND script. The deposit amount is carried by the transaction output value and is therefore not returned by this script-only decoder.\n",
        {
            {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded scriptPubKey"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Decoded FUND_CHAIN destination", {
            {RPCResult::Type::NUM, "version", "KFND envelope version"},
            {RPCResult::Type::STR_HEX, "chain_id", "Destination child-chain identifier"},
            {RPCResult::Type::NUM, "recipient_type", "Child-template recipient namespace"},
            {RPCResult::Type::STR_HEX, "recipient", "Canonical raw child recipient"},
            {RPCResult::Type::STR_HEX, "script", "Canonical OP_RETURN scriptPubKey"},
            {RPCResult::Type::STR_HEX, "data", "Raw KFND envelope"},
        }},
        RPCExamples{
            HelpExampleCli("decodefundchainoutput", "\"6a...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest&) -> UniValue
{
    const auto script_bytes{ParseHexV(self.Arg<UniValue>("script"), "script")};
    const CScript script{script_bytes.begin(), script_bytes.end()};
    const auto parsed{chainregistry::ParseFundScript(script)};
    if (!parsed) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           strprintf("invalid FUND_CHAIN output (parse error %u)",
                                     static_cast<unsigned>(parsed.error)));
    }

    UniValue result{FundToUniv(*parsed.fund)};
    result.pushKV("version", chainregistry::FUND_ENVELOPE_VERSION);
    result.pushKV("script", HexStr(script));
    result.pushKV("data", HexStr(OpReturnData(script)));
    return result;
}
    };
}

RPCHelpMan createchainregistryoperation()
{
    return RPCHelpMan{
        "createchainregistryoperation",
        "Create a canonical KREG script for a register, update, or retire operation.\n"
        "The caller must place the script in exactly one transaction output. For register, anchor_input must spend registration_anchor and the operation output value must meet the consensus burn minimum.\n",
        {
            {"operation", RPCArg::Type::STR, RPCArg::Optional::NO, "Operation type: register, update, or retire"},
            {"parameters", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Fields required by the selected operation", {
                {"anchor_input", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "REGISTER: input index consuming registration_anchor"},
                {"control_output", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "REGISTER/UPDATE: P2TR successor output index"},
                {"registration_anchor", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "REGISTER: pre-existing anchor UTXO", OutPointArgs()},
                {"spec", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "REGISTER: immutable chain specification", ChainSpecArgs()},
                {"child_genesis_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "REGISTER: derived child genesis hash"},
                {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "REGISTER/UPDATE: metadata commitment"},
                {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "UPDATE/RETIRE: registered child-chain identifier"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "operation", "Operation type"},
            {RPCResult::Type::NUM, "anchor_input", /*optional=*/true, "REGISTER anchor input index"},
            {RPCResult::Type::NUM, "control_output", /*optional=*/true, "REGISTER/UPDATE successor output index"},
            {RPCResult::Type::OBJ, "manifest", /*optional=*/true, "REGISTER manifest", CHAIN_MANIFEST_RESULT},
            {RPCResult::Type::STR_HEX, "metadata_hash", /*optional=*/true, "UPDATE metadata hash"},
            {RPCResult::Type::STR_HEX, "script", "Canonical scriptPubKey"},
            {RPCResult::Type::STR_HEX, "data", "Raw KREG envelope, suitable for a createrawtransaction data output"},
            {RPCResult::Type::STR_HEX, "chain_id", "Affected or derived child-chain identifier"},
            {RPCResult::Type::STR_HEX, "chain_spec_hash", /*optional=*/true, "REGISTER: tagged specification hash"},
            {RPCResult::Type::STR_HEX, "manifest_hash", /*optional=*/true, "REGISTER: tagged manifest hash"},
            {RPCResult::Type::STR_HEX, "manifest_hex", /*optional=*/true, "REGISTER: canonical serialized manifest"},
            {RPCResult::Type::STR_HEX, "main_genesis_hash", /*optional=*/true, "REGISTER: main-network genesis domain"},
        }},
        RPCExamples{
            HelpExampleCli("createchainregistryoperation", "\"retire\" '{\"chain_id\":\"1111111111111111111111111111111111111111111111111111111111111111\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string operation_name{self.Arg<std::string_view>("operation")};
    const UniValue parameters{self.Arg<UniValue>("parameters").get_obj()};
    RPCTypeCheckObj(parameters,
                    {
                        {"anchor_input", UniValueType{UniValue::VNUM}},
                        {"control_output", UniValueType{UniValue::VNUM}},
                        {"registration_anchor", UniValueType{UniValue::VOBJ}},
                        {"spec", UniValueType{UniValue::VOBJ}},
                        {"child_genesis_hash", UniValueType{UniValue::VSTR}},
                        {"metadata_hash", UniValueType{UniValue::VSTR}},
                        {"chain_id", UniValueType{UniValue::VSTR}},
                    },
                    /*fAllowNull=*/true,
                    /*fStrict=*/true);

    std::optional<COutPoint> registration_anchor;
    chainregistry::RegistryOperation operation;
    if (operation_name == "register") {
        CheckOperationParameters(parameters,
                                 {"anchor_input", "control_output", "registration_anchor", "spec",
                                  "child_genesis_hash", "metadata_hash"});
        for (const std::string_view key : {"anchor_input", "control_output", "registration_anchor", "spec", "child_genesis_hash", "metadata_hash"}) {
            if (!parameters.exists(std::string{key})) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("register requires %s", key));
            }
        }
        registration_anchor = ParseOutPoint(parameters.find_value("registration_anchor"), "registration_anchor");
        operation = chainregistry::RegisterChain{
            .anchor_input = ParseUint32(parameters.find_value("anchor_input"), "anchor_input", /*allow_max=*/false),
            .control_output = ParseUint32(parameters.find_value("control_output"), "control_output", /*allow_max=*/false),
            .manifest = ParseManifest(parameters),
        };
    } else if (operation_name == "update") {
        CheckOperationParameters(parameters, {"chain_id", "control_output", "metadata_hash"});
        for (const std::string_view key : {"chain_id", "control_output", "metadata_hash"}) {
            if (!parameters.exists(std::string{key})) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("update requires %s", key));
            }
        }
        operation = chainregistry::UpdateChain{
            .chain_id = ParseChainId(parameters.find_value("chain_id")),
            .control_output = ParseUint32(parameters.find_value("control_output"), "control_output", /*allow_max=*/false),
            .metadata_hash = ParseMetadataHash(parameters.find_value("metadata_hash")),
        };
    } else if (operation_name == "retire") {
        CheckOperationParameters(parameters, {"chain_id"});
        if (!parameters.exists("chain_id")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "retire requires chain_id");
        }
        operation = chainregistry::RetireChain{.chain_id = ParseChainId(parameters.find_value("chain_id"))};
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "operation must be register, update, or retire");
    }

    const CScript script{chainregistry::BuildOperationScript(operation)};
    UniValue result{OperationToUniv(operation)};
    result.pushKV("script", HexStr(script));
    result.pushKV("data", HexStr(OpReturnData(script)));
    if (const auto* registration{std::get_if<chainregistry::RegisterChain>(&operation)}) {
        const auto spec_hash{chainregistry::ComputeChainSpecHash(registration->manifest.spec)};
        const uint256& main_genesis_hash{EnsureAnyChainman(request.context).GetConsensus().hashGenesisBlock};
        result.pushKV("chain_id", chainregistry::DeriveChainId(main_genesis_hash, *registration_anchor, spec_hash).GetHex());
        result.pushKV("manifest_hex", SerializeHex(registration->manifest));
        result.pushKV("main_genesis_hash", main_genesis_hash.GetHex());
    }
    return result;
}
    };
}

RPCHelpMan decodechainregistryoperation()
{
    return RPCHelpMan{
        "decodechainregistryoperation",
        "Decode and validate a canonical KREG script. A registration anchor is needed only to derive chain_id for a register operation.\n",
        {
            {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded scriptPubKey"},
            {"registration_anchor", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Anchor used to derive a REGISTER chain_id", OutPointArgs()},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Decoded operation fields", {
            {RPCResult::Type::STR, "operation", "Operation type"},
            {RPCResult::Type::NUM, "anchor_input", /*optional=*/true, "REGISTER anchor input index"},
            {RPCResult::Type::NUM, "control_output", /*optional=*/true, "REGISTER/UPDATE successor output index"},
            {RPCResult::Type::OBJ, "manifest", /*optional=*/true, "REGISTER manifest", CHAIN_MANIFEST_RESULT},
            {RPCResult::Type::STR_HEX, "chain_spec_hash", /*optional=*/true, "REGISTER specification hash"},
            {RPCResult::Type::STR_HEX, "manifest_hash", /*optional=*/true, "REGISTER manifest hash"},
            {RPCResult::Type::STR_HEX, "chain_id", /*optional=*/true, "Affected chain ID, or derived REGISTER ID when an anchor is supplied"},
            {RPCResult::Type::STR_HEX, "metadata_hash", /*optional=*/true, "UPDATE metadata hash"},
            {RPCResult::Type::STR_HEX, "script", "Canonical scriptPubKey"},
            {RPCResult::Type::STR_HEX, "data", "Raw KREG envelope"},
        }},
        RPCExamples{
            HelpExampleCli("decodechainregistryoperation", "\"6a264b52454701031111111111111111111111111111111111111111111111111111111111111111\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto script_bytes{ParseHexV(self.Arg<UniValue>("script"), "script")};
    const CScript script{script_bytes.begin(), script_bytes.end()};
    const auto parsed{chainregistry::ParseOperationScript(script)};
    if (!parsed) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           strprintf("invalid chain registry operation (parse error %u)",
                                     static_cast<unsigned>(parsed.error)));
    }

    UniValue result{OperationToUniv(*parsed.operation)};
    result.pushKV("script", HexStr(script));
    result.pushKV("data", HexStr(OpReturnData(script)));
    if (const auto* registration{std::get_if<chainregistry::RegisterChain>(&*parsed.operation)}) {
        if (const UniValue* anchor_arg{self.MaybeArg<UniValue>("registration_anchor")}) {
            const COutPoint anchor{ParseOutPoint(*anchor_arg, "registration_anchor")};
            const uint256& main_genesis_hash{EnsureAnyChainman(request.context).GetConsensus().hashGenesisBlock};
            result.pushKV("chain_id", chainregistry::DeriveChainId(
                                          main_genesis_hash,
                                          anchor,
                                          chainregistry::ComputeChainSpecHash(registration->manifest.spec)).GetHex());
        }
    }
    return result;
}
    };
}

RPCHelpMan addchildchain()
{
    return RPCHelpMan{
        "addchildchain",
        "Persist a complete manifest in the local child-chain catalog. This does not register a chain on consensus and does not load or synchronize it. The derived definition must exactly match a record on the active main chain.\n",
        {
            {"registration_anchor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Pre-existing UTXO consumed by the confirmed REGISTER operation", OutPointArgs()},
            {"manifest", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Complete canonical child manifest", {
                {"spec", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Immutable consensus specification", ChainSpecArgs()},
                {"child_genesis_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Derived child genesis hash"},
                {"metadata_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Initial metadata commitment"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Locally configured child chain", {
            {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
            {RPCResult::Type::STR_HEX, "manifest_hash", "Validated manifest hash"},
            {RPCResult::Type::STR_HEX, "genesis_hash", "Derived child genesis hash"},
            {RPCResult::Type::BOOL, "already_configured", "Whether the identical definition was already present"},
            {RPCResult::Type::BOOL, "loaded", "Whether the child runtime is loaded"},
            {RPCResult::Type::STR, "registry_status", "Current main-chain registry status"},
        }},
        RPCExamples{
            HelpExampleCli("addchildchain", "'{\"txid\":\"...\",\"vout\":0}' '{\"spec\":{...},\"child_genesis_hash\":\"...\",\"metadata_hash\":\"...\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman{EnsureAnyChainman(request.context)};
    node::ChainManager& manager{EnsureAnyChildChainman(request.context)};
    const COutPoint anchor{ParseOutPoint(
        self.Arg<UniValue>("registration_anchor"), "registration_anchor")};
    const UniValue manifest_value{self.Arg<UniValue>("manifest").get_obj()};
    RPCTypeCheckObj(manifest_value,
                    {
                        {"spec", UniValueType{UniValue::VOBJ}},
                        {"child_genesis_hash", UniValueType{UniValue::VSTR}},
                        {"metadata_hash", UniValueType{UniValue::VSTR}},
                    },
                    /*fAllowNull=*/false,
                    /*fStrict=*/true);
    const auto validated{chainregistry::ValidateReferenceChildManifest(
        chainman.GetConsensus().hashGenesisBlock,
        anchor,
        ParseManifest(manifest_value))};
    if (!validated.IsValid() || !validated.definition) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("invalid reference-child manifest (error %u, parameters %u, manifest %u)",
                      static_cast<unsigned>(validated.error),
                      static_cast<unsigned>(validated.parameters_error),
                      static_cast<unsigned>(validated.manifest_error)));
    }

    const auto registry{GetMainRegistrySnapshot(chainman)};
    EnsureRegistryMatchesDefinition(
        registry, *validated.definition, /*require_active=*/false);
    const auto registered{manager.RegisterChain(*validated.definition)};
    if (!registered.IsValid()) ThrowChainManagerError(registered);

    const auto entries{manager.List()};
    const auto entry{std::find_if(entries.begin(), entries.end(), [&](const auto& candidate) {
        return candidate.chain_id == validated.definition->chain_id;
    })};
    Assume(entry != entries.end());
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", entry->chain_id.GetHex());
    result.pushKV("manifest_hash", entry->manifest_hash.GetHex());
    result.pushKV("genesis_hash", entry->genesis_hash.GetHex());
    result.pushKV("already_configured", registered.already_registered);
    result.pushKV("loaded", entry->loaded);
    result.pushKV("registry_status", RegistryStatusName(
        registry.records.at(entry->chain_id).status));
    return result;
}
    };
}

RPCHelpMan listchildchainruntimes()
{
    return RPCHelpMan{
        "listchildchainruntimes",
        "List every child record in the active main-chain registry together with local configuration and runtime state. Unconfigured records remain catalog-visible and are never synchronized automatically.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "Registry and local runtime view", {
            {RPCResult::Type::STR_HEX, "bestblockhash", "Main-chain block committing the registry view"},
            {RPCResult::Type::NUM, "height", "Main-chain registry height"},
            {RPCResult::Type::STR_HEX, "root", "Committed registry root"},
            {RPCResult::Type::NUM, "loaded", "Number of locally loaded child runtimes"},
            {RPCResult::Type::NUM, "max_loaded", "Maximum child runtimes this process permits"},
            {RPCResult::Type::NUM, "aggregate_upload_target", "Process-wide child block-serving target in bytes per cycle; zero means unlimited"},
            {RPCResult::Type::NUM, "aggregate_upload_bytes_sent", "Serialized child block bytes reserved in the current cycle"},
            {RPCResult::Type::NUM, "aggregate_upload_bytes_left", "Bytes remaining in the aggregate target; zero when unlimited or exhausted"},
            {RPCResult::Type::NUM, "aggregate_upload_timeframe", "Upload target cycle length in seconds"},
            {RPCResult::Type::NUM, "aggregate_upload_time_left", "Seconds remaining in the current cycle"},
            {RPCResult::Type::BOOL, "aggregate_upload_target_reached", "Whether child block serving is currently exhausted"},
            {RPCResult::Type::ARR, "chains", "Known child chains", {
                {RPCResult::Type::OBJ, "", "One child-chain view", {
                    {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
                    {RPCResult::Type::STR, "state", "available, configured, loaded, retired, unsupported-template, manifest-mismatch, or orphaned"},
                    {RPCResult::Type::BOOL, "registry_found", "Whether the active main registry contains this chain"},
                    {RPCResult::Type::STR, "registry_status", /*optional=*/true, "active or retired"},
                    {RPCResult::Type::STR_HEX, "manifest_hash", "Complete manifest commitment"},
                    {RPCResult::Type::STR_HEX, "metadata_hash", /*optional=*/true, "Current registry metadata commitment"},
                    {RPCResult::Type::NUM, "template_id", "Consensus template identifier"},
                    {RPCResult::Type::NUM, "template_version", "Consensus template version"},
                    {RPCResult::Type::STR_HEX, "genesis_hash", /*optional=*/true, "Locally validated child genesis hash"},
                    {RPCResult::Type::BOOL, "supported", "Whether this node supports the registered template"},
                    {RPCResult::Type::BOOL, "configured", "Whether a complete manifest is stored locally"},
                    {RPCResult::Type::BOOL, "manifest_matches_registry", /*optional=*/true, "Whether the local manifest matches this active registry record"},
                    {RPCResult::Type::BOOL, "loaded", "Whether the runtime is loaded"},
                    {RPCResult::Type::BOOL, "failed", /*optional=*/true, "Whether the loaded runtime has failed"},
                    {RPCResult::Type::BOOL, "safe_halt", /*optional=*/true, "Whether irreversible main reorg protection is active"},
                    {RPCResult::Type::NUM, "child_height", /*optional=*/true, "Loaded child height"},
                    {RPCResult::Type::STR_HEX, "bestblockhash", /*optional=*/true, "Loaded child tip"},
                    {RPCResult::Type::NUM, "main_height", /*optional=*/true, "Main-header light-client height"},
                    {RPCResult::Type::STR_HEX, "main_bestblockhash", /*optional=*/true, "Main-header light-client tip"},
                    {RPCResult::Type::NUM, "bmm_anchor_count", /*optional=*/true, "Canonical child blocks with persisted BMM anchors"},
                    {RPCResult::Type::NUM, "pending_bmm_anchor_count", /*optional=*/true, "Authenticated BMM anchors waiting for child block data"},
                    {RPCResult::Type::NUM, "pending_bmm_anchor_bytes", /*optional=*/true, "Serialized bytes used by pending BMM anchors"},
                    {RPCResult::Type::NUM, "pending_child_block_count", /*optional=*/true, "Distinct child blocks requested by pending authenticated anchors"},
                    {RPCResult::Type::NUM, "local_proposal_count", /*optional=*/true, "Validated local block proposals awaiting BMM submission"},
                    {RPCResult::Type::NUM, "local_proposal_bytes", /*optional=*/true, "Serialized bytes used by local block proposals"},
                    {RPCResult::Type::NUM, "local_proposal_limit", /*optional=*/true, "Maximum local block proposals"},
                    {RPCResult::Type::NUM, "local_proposal_bytes_limit", /*optional=*/true, "Maximum serialized bytes for local block proposals"},
                    {RPCResult::Type::NUM, "pending_bmm_anchor_limit", /*optional=*/true, "Maximum pending BMM anchor records"},
                    {RPCResult::Type::NUM, "pending_bmm_anchor_bytes_limit", /*optional=*/true, "Maximum serialized bytes for pending BMM anchors"},
                    {RPCResult::Type::NUM, "side_candidate_count", /*optional=*/true, "Validated non-canonical candidates retained in the fork DAG"},
                    {RPCResult::Type::NUM, "side_candidate_bytes", /*optional=*/true, "Serialized bytes used by retained non-canonical candidates"},
                    {RPCResult::Type::NUM, "side_candidate_limit", /*optional=*/true, "Maximum retained non-canonical candidates"},
                    {RPCResult::Type::NUM, "side_candidate_bytes_limit", /*optional=*/true, "Maximum serialized bytes for retained non-canonical candidates"},
                    {RPCResult::Type::NUM, "candidate_bmm_anchor_count", /*optional=*/true, "BMM anchors retained for non-canonical candidates"},
                    {RPCResult::Type::NUM, "candidate_bmm_anchor_bytes", /*optional=*/true, "Serialized bytes used by non-canonical candidate anchors"},
                    {RPCResult::Type::NUM, "candidate_bmm_anchor_limit", /*optional=*/true, "Maximum BMM anchors retained for non-canonical candidates"},
                    {RPCResult::Type::NUM, "candidate_bmm_anchor_bytes_limit", /*optional=*/true, "Maximum serialized bytes for non-canonical candidate anchors"},
                    {RPCResult::Type::STR, "data_path", /*optional=*/true, "Local chain directory"},
                    {RPCResult::Type::BOOL, "network_running", "Whether the isolated child network stack is running"},
                    {RPCResult::Type::BOOL, "network_active", "Whether new child-network connections are enabled"},
                    {RPCResult::Type::NUM, "connections", "Current child-network connection count"},
                    {RPCResult::Type::NUM, "handshaken_peers", "Authenticated peers serving this exact child chain"},
                    {RPCResult::Type::NUM, "known_addresses", "Routable endpoints in this child's isolated peer store"},
                    {RPCResult::Type::NUM, "max_known_addresses", "Maximum routable endpoints retained in this child's isolated peer store"},
                    {RPCResult::Type::NUM, "rate_limited_block_requests", "Block requests rejected by this child stack's per-peer rate limit"},
                    {RPCResult::Type::BOOL, "discovery_enabled", "Whether bounded automatic outbound connections from the isolated child peer store are enabled"},
                    {RPCResult::Type::ARR, "bootstrap_nodes", "Numeric bootstrap endpoints kept in the isolated child peer store", {
                        {RPCResult::Type::STR, "", "Numeric address and explicit port"},
                    }},
                    {RPCResult::Type::ARR, "added_nodes", "Explicit child endpoints", {
                        {RPCResult::Type::STR, "", "Host and explicit port"},
                    }},
                    {RPCResult::Type::ARR, "binds", "Numeric child listen endpoints", {
                        {RPCResult::Type::STR, "", "Numeric address and explicit port"},
                    }},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("listchildchainruntimes", "")
            + HelpExampleRpc("listchildchainruntimes", "")
        },
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman{EnsureAnyChainman(request.context)};
    node::ChainManager& manager{EnsureAnyChildChainman(request.context)};
    node::ChildNetworkManager& networks{
        EnsureAnyChildNetworkman(request.context)};
    const auto registry{GetMainRegistrySnapshot(chainman)};
    const auto local_entries{manager.List()};
    std::map<chainregistry::ChainId, node::ChainManagerEntry> local;
    for (const auto& entry : local_entries) local.emplace(entry.chain_id, entry);

    UniValue chains{UniValue::VARR};
    for (const auto& [chain_id, record] : registry.records) {
        const auto configured{local.find(chain_id)};
        const bool supported{
            record.template_id == chainregistry::REFERENCE_CHILD_TEMPLATE_ID &&
            record.template_version == chainregistry::REFERENCE_CHILD_TEMPLATE_VERSION};
        const bool manifest_matches{
            configured != local.end() &&
            configured->second.manifest_hash == record.manifest_hash &&
            configured->second.template_id == record.template_id &&
            configured->second.template_version == record.template_version};
        UniValue chain{UniValue::VOBJ};
        chain.pushKV("chain_id", chain_id.GetHex());
        chain.pushKV("registry_found", true);
        chain.pushKV("registry_status", RegistryStatusName(record.status));
        chain.pushKV("manifest_hash", record.manifest_hash.GetHex());
        chain.pushKV("metadata_hash", record.metadata_hash.GetHex());
        chain.pushKV("template_id", record.template_id);
        chain.pushKV("template_version", record.template_version);
        chain.pushKV("supported", supported);
        chain.pushKV("configured", configured != local.end());
        chain.pushKV("loaded", configured != local.end() && configured->second.loaded);
        if (configured != local.end()) {
            chain.pushKV("manifest_matches_registry", manifest_matches);
        }
        if (record.status == chainregistry::ChainStatus::RETIRED) {
            chain.pushKV("state", "retired");
        } else if (!supported) {
            chain.pushKV("state", "unsupported-template");
        } else if (configured != local.end() && !manifest_matches) {
            chain.pushKV("state", "manifest-mismatch");
        } else if (configured != local.end() && configured->second.loaded) {
            chain.pushKV("state", "loaded");
        } else if (configured != local.end()) {
            chain.pushKV("state", "configured");
        } else {
            chain.pushKV("state", "available");
        }
        node::ChildNetworkStats network_stats;
        network_stats.chain_id = chain_id;
        if (configured != local.end()) {
            chain.pushKV("genesis_hash", configured->second.genesis_hash.GetHex());
            chain.pushKV("data_path", fs::PathToString(configured->second.data_path));
            chain.pushKV("failed", configured->second.failed);
            chain.pushKV("safe_halt", configured->second.safe_halt);
            chain.pushKV("child_height", configured->second.height);
            if (configured->second.loaded) {
                chain.pushKV("bestblockhash", configured->second.tip.GetHex());
                chain.pushKV("main_height", configured->second.main_height);
                chain.pushKV("main_bestblockhash", configured->second.main_tip.GetHex());
                PushChildStorageStats(chain, configured->second);
            }
            const auto network_info{networks.GetInfo(chain_id)};
            if (!network_info.IsValid()) {
                ThrowChildNetworkError(network_info.result);
            }
            network_stats = network_info.stats;
            local.erase(configured);
        }
        PushChildNetworkStats(chain, network_stats);
        chains.push_back(std::move(chain));
    }
    for (const auto& [chain_id, entry] : local) {
        UniValue chain{UniValue::VOBJ};
        chain.pushKV("chain_id", chain_id.GetHex());
        chain.pushKV("manifest_hash", entry.manifest_hash.GetHex());
        chain.pushKV("template_id", entry.template_id);
        chain.pushKV("template_version", entry.template_version);
        chain.pushKV("genesis_hash", entry.genesis_hash.GetHex());
        chain.pushKV("data_path", fs::PathToString(entry.data_path));
        chain.pushKV("registry_found", false);
        chain.pushKV("supported", true);
        chain.pushKV("configured", true);
        chain.pushKV("loaded", entry.loaded);
        chain.pushKV("failed", entry.failed);
        chain.pushKV("safe_halt", entry.safe_halt);
        chain.pushKV("state", "orphaned");
        chain.pushKV("child_height", entry.height);
        if (entry.loaded) {
            chain.pushKV("bestblockhash", entry.tip.GetHex());
            chain.pushKV("main_height", entry.main_height);
            chain.pushKV("main_bestblockhash", entry.main_tip.GetHex());
            PushChildStorageStats(chain, entry);
        }
        const auto network_info{networks.GetInfo(chain_id)};
        if (!network_info.IsValid()) {
            ThrowChildNetworkError(network_info.result);
        }
        PushChildNetworkStats(chain, network_info.stats);
        chains.push_back(std::move(chain));
    }

    UniValue result{UniValue::VOBJ};
    result.pushKV("bestblockhash", registry.best_block.GetHex());
    result.pushKV("height", registry.height);
    result.pushKV("root", registry.root.GetHex());
    result.pushKV("loaded", manager.LoadedCount());
    result.pushKV("max_loaded", node::MAX_LOADED_CHILD_CHAINS);
    PushChildBandwidthStats(result, networks.GetBandwidthStats());
    result.pushKV("chains", std::move(chains));
    return result;
}
    };
}

RPCHelpMan loadchildchain()
{
    return RPCHelpMan{
        "loadchildchain",
        "Load one locally configured active child chain. This is always opt-in; catalog entries are not automatically loaded after restart.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"network", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "Isolated child-network startup options (used only when the network is not already running)", {
                {"connect", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Explicit outbound endpoints; each must include a non-zero port", {
                    {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Host and port"},
                }},
                {"bind", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Numeric listen endpoints with explicit non-zero ports", {
                    {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Numeric address and port"},
                }},
                {"bootstrap", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Numeric bootstrap endpoints inserted only into this child's peer store", {
                    {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Numeric address and explicit port"},
                }},
                {"discovery", RPCArg::Type::BOOL, RPCArg::Default{false}, "Allow at most four automatic outbound connections from this child's isolated peer store"},
                {"network_active", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether child peer connections are enabled"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Loaded child runtime", {
            {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
            {RPCResult::Type::BOOL, "loaded", "Whether the runtime is loaded"},
            {RPCResult::Type::BOOL, "already_loaded", "Whether it was loaded before this call"},
            {RPCResult::Type::NUM, "height", "Current child height"},
            {RPCResult::Type::STR_HEX, "bestblockhash", "Current child tip"},
            {RPCResult::Type::BOOL, "safe_halt", "Whether irreversible reorg protection is active"},
            {RPCResult::Type::NUM, "main_height", "Current main-header light-client height"},
            {RPCResult::Type::STR_HEX, "main_bestblockhash", "Current main-header light-client tip"},
            {RPCResult::Type::BOOL, "historical_anchor_index_complete", "Whether the bounded historical BMM lookup examined every indexed anchor for the durable local proposals"},
            {RPCResult::Type::NUM, "historical_anchor_lookups", "Historical child-block anchor index entries examined"},
            {RPCResult::Type::NUM, "local_proposals_checked", "Durable local proposals considered for historical anchor catch-up"},
            {RPCResult::Type::NUM, "historical_anchors_found", "Active historical main-chain anchors found for local proposals"},
            {RPCResult::Type::NUM, "historical_anchor_block_data_unavailable", "Matching anchors whose containing main block is pruned or unreadable"},
            {RPCResult::Type::NUM, "historical_anchor_proofs_built", "Historical anchor proofs rebuilt from locally available main blocks"},
            {RPCResult::Type::NUM, "historical_anchors_staged", "Historical anchor proofs accepted by the child runtime"},
            {RPCResult::Type::NUM, "historical_proposals_activated", "Durable local proposals activated by historical anchors"},
            {RPCResult::Type::NUM, "historical_proposal_activation_failures", "Local proposals found but rejected during historical activation"},
            {RPCResult::Type::NUM, "historical_anchor_stage_failures", "Historical proofs rejected by the child runtime, normally because of a concurrent main-chain change"},
            {RPCResult::Type::BOOL, "deposit_index_complete", "Whether the bounded automatic proposer scan reached the end of this child's deposit index"},
            {RPCResult::Type::NUM, "deposit_index_lookups", "Indexed deposits examined by the automatic proposer"},
            {RPCResult::Type::NUM, "deposits_indexed", "Deposits returned by the bounded index page"},
            {RPCResult::Type::NUM, "deposits_immature", "Indexed deposits skipped because they have not reached child maturity"},
            {RPCResult::Type::NUM, "deposits_already_imported", "Indexed deposits already consumed by this child"},
            {RPCResult::Type::NUM, "deposit_block_data_unavailable", "Mature deposits whose main block is pruned or unreadable"},
            {RPCResult::Type::NUM, "deposit_proofs_built", "Mature unconsumed deposits authenticated for a proposal"},
            {RPCResult::Type::BOOL, "deposit_proposal_pending", "Whether an existing durable proposal prevented a competing candidate"},
            {RPCResult::Type::BOOL, "deposit_proposal_stored", "Whether this load created a durable import proposal"},
            {RPCResult::Type::STR_HEX, "deposit_proposal_hash", /*optional=*/true, "New automatic child proposal hash"},
            {RPCResult::Type::BOOL, "network_running", "Whether the isolated child network is running"},
            {RPCResult::Type::BOOL, "network_already_running", "Whether the network was running before this call"},
            {RPCResult::Type::BOOL, "network_active", "Whether new child-network connections are enabled"},
            {RPCResult::Type::NUM, "connections", "Current child-network connection count"},
            {RPCResult::Type::NUM, "handshaken_peers", "Authenticated peers serving this exact child chain"},
            {RPCResult::Type::NUM, "known_addresses", "Routable endpoints in this child's isolated peer store"},
            {RPCResult::Type::NUM, "max_known_addresses", "Maximum routable endpoints retained in this child's isolated peer store"},
            {RPCResult::Type::NUM, "rate_limited_block_requests", "Block requests rejected by this child stack's per-peer rate limit"},
            {RPCResult::Type::BOOL, "discovery_enabled", "Whether bounded automatic outbound connections from the isolated child peer store are enabled"},
            {RPCResult::Type::ARR, "bootstrap_nodes", "Numeric bootstrap endpoints kept in the isolated child peer store", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
            {RPCResult::Type::ARR, "added_nodes", "Explicit child endpoints", {
                {RPCResult::Type::STR, "", "Host and explicit port"},
            }},
            {RPCResult::Type::ARR, "binds", "Numeric child listen endpoints", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("loadchildchain", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const UniValue* network_options{
        self.MaybeArg<UniValue>("network")};
    const auto network_config{
        ParseChildNetworkConfig(network_options ? *network_options : UniValue{})};
    ChainstateManager& chainman{EnsureAnyChainman(request.context)};
    node::ChainManager& manager{EnsureAnyChildChainman(request.context)};
    node::ChildNetworkManager& networks{
        EnsureAnyChildNetworkman(request.context)};
    const auto definition{manager.Definition(chain_id)};
    if (!definition) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    }
    EnsureRegistryMatchesDefinition(
        GetMainRegistrySnapshot(chainman), *definition, /*require_active=*/true);
    const auto active_headers{GetActiveMainHeaders(chainman)};
    const auto loaded{manager.LoadChain(
        chain_id,
        Now<NodeSeconds>().time_since_epoch().count(),
        /*wipe_data=*/false,
        /*sync=*/true,
        active_headers.headers)};
    if (!loaded.IsValid()) ThrowChainManagerError(loaded);

    const auto refreshed_headers{GetActiveMainHeaders(chainman)};
    if (refreshed_headers.tip != active_headers.tip) {
        const auto update{manager.SynchronizeMainChain(
            refreshed_headers.headers,
            refreshed_headers.tip,
            Now<NodeSeconds>().time_since_epoch().count(),
            /*sync=*/true)};
        if (std::any_of(
                update.unloaded.begin(), update.unloaded.end(),
                [&](const auto& event) { return event.chain_id == chain_id; })) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "child runtime failed while synchronizing the active main-header chain");
        }
    }

    try {
        EnsureRegistryMatchesDefinition(
            GetMainRegistrySnapshot(chainman), *definition, /*require_active=*/true);
    } catch (...) {
        if (!loaded.already_loaded) manager.UnloadChain(chain_id);
        throw;
    }
    node::NodeContext& node_context{EnsureAnyNodeContext(request.context)};
    const auto catch_up{Assert(node_context.child_chain_notifications)
                            ->CatchUpBmmAnchors(chain_id)};
    if (!catch_up.IsValid()) {
        if (!loaded.already_loaded) manager.UnloadChain(chain_id);
        ThrowChildAnchorCatchUpError(catch_up.error);
    }
    const auto deposit_proposal{
        Assert(node_context.child_chain_notifications)
            ->BuildDepositProposal(chain_id)};
    if (!deposit_proposal.IsValid()) {
        if (!loaded.already_loaded) manager.UnloadChain(chain_id);
        ThrowChildDepositProposalError(deposit_proposal.error);
    }
    const bool network_already_running{networks.IsRunning(chain_id)};
    if (!network_already_running) {
        const auto started{networks.Start(
            chain_id,
            network_options
                ? std::optional<node::ChildNetworkConfig>{network_config}
                : std::nullopt)};
        if (!started.IsValid()) {
            if (!loaded.already_loaded) manager.UnloadChain(chain_id);
            ThrowChildNetworkError(started);
        }
    }
    const auto entries{manager.List()};
    const auto entry{std::find_if(entries.begin(), entries.end(), [&](const auto& candidate) {
        return candidate.chain_id == chain_id;
    })};
    Assume(entry != entries.end() && entry->loaded);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", entry->chain_id.GetHex());
    result.pushKV("loaded", entry->loaded);
    result.pushKV("already_loaded", loaded.already_loaded);
    result.pushKV("height", entry->height);
    result.pushKV("bestblockhash", entry->tip.GetHex());
    result.pushKV("safe_halt", entry->safe_halt);
    result.pushKV("main_height", entry->main_height);
    result.pushKV("main_bestblockhash", entry->main_tip.GetHex());
    result.pushKV("historical_anchor_index_complete", catch_up.index_complete);
    result.pushKV("historical_anchor_lookups", catch_up.index_lookups);
    result.pushKV("local_proposals_checked", catch_up.proposals);
    result.pushKV("historical_anchors_found", catch_up.anchors_found);
    result.pushKV("historical_anchor_block_data_unavailable",
                  catch_up.block_data_unavailable);
    result.pushKV("historical_anchor_proofs_built", catch_up.proofs_built);
    result.pushKV("historical_anchors_staged", catch_up.anchors_staged);
    result.pushKV("historical_proposals_activated",
                  catch_up.proposals_activated);
    result.pushKV("historical_proposal_activation_failures",
                  catch_up.activation_failures);
    result.pushKV("historical_anchor_stage_failures",
                  catch_up.stage_failures);
    result.pushKV("deposit_index_complete", deposit_proposal.index_complete);
    result.pushKV("deposit_index_lookups", deposit_proposal.index_lookups);
    result.pushKV("deposits_indexed", deposit_proposal.indexed);
    result.pushKV("deposits_immature", deposit_proposal.immature);
    result.pushKV("deposits_already_imported",
                  deposit_proposal.already_imported);
    result.pushKV("deposit_block_data_unavailable",
                  deposit_proposal.block_data_unavailable);
    result.pushKV("deposit_proofs_built", deposit_proposal.proofs_built);
    result.pushKV("deposit_proposal_pending",
                  deposit_proposal.proposal_pending);
    result.pushKV("deposit_proposal_stored",
                  deposit_proposal.proposal_stored);
    if (deposit_proposal.proposal_stored) {
        result.pushKV("deposit_proposal_hash",
                      deposit_proposal.proposal_hash.GetHex());
    }
    result.pushKV("network_already_running", network_already_running);
    PushChildNetworkStats(result, networks.GetStats(chain_id));
    return result;
}
    };
}

RPCHelpMan unloadchildchain()
{
    return RPCHelpMan{
        "unloadchildchain",
        "Stop and close one loaded child runtime without removing its manifest or data.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Unload result", {
            {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
            {RPCResult::Type::BOOL, "loaded", "False after a successful unload"},
            {RPCResult::Type::BOOL, "network_running", "False after a successful unload"},
        }},
        RPCExamples{
            HelpExampleCli("unloadchildchain", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    node::ChildNetworkManager& networks{
        EnsureAnyChildNetworkman(request.context)};
    if (networks.IsRunning(chain_id)) {
        const auto stopped{networks.Stop(chain_id)};
        if (!stopped.IsValid()) ThrowChildNetworkError(stopped);
    }
    const auto unloaded{
        EnsureAnyChildChainman(request.context).UnloadChain(chain_id)};
    if (!unloaded.IsValid()) ThrowChainManagerError(unloaded);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("loaded", false);
    result.pushKV("network_running", false);
    return result;
}
    };
}

RPCHelpMan getchildnetworkinfo()
{
    return RPCHelpMan{
        "getchildnetworkinfo",
        "Return isolated P2P state and persistent endpoint configuration for one locally configured child chain.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Child network state", {
            {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
            {RPCResult::Type::BOOL, "network_running", "Whether the isolated connection manager is running"},
            {RPCResult::Type::BOOL, "network_active", "Whether new child-network connections are enabled"},
            {RPCResult::Type::NUM, "connections", "Current connection count"},
            {RPCResult::Type::NUM, "handshaken_peers", "Peers authenticated for this exact child chain"},
            {RPCResult::Type::NUM, "known_addresses", "Routable endpoints in this child's isolated peer store"},
            {RPCResult::Type::NUM, "max_known_addresses", "Maximum routable endpoints retained in this child's isolated peer store"},
            {RPCResult::Type::NUM, "rate_limited_block_requests", "Block requests rejected by this child stack's per-peer rate limit"},
            {RPCResult::Type::BOOL, "discovery_enabled", "Whether bounded automatic outbound connections from the isolated child peer store are enabled"},
            {RPCResult::Type::ARR, "bootstrap_nodes", "Numeric bootstrap endpoints kept in the isolated child peer store", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
            {RPCResult::Type::NUM, "max_added_nodes", "Maximum number of explicit endpoints"},
            {RPCResult::Type::NUM, "max_bind_endpoints", "Maximum number of child listen endpoints"},
            {RPCResult::Type::NUM, "max_bootstrap_nodes", "Maximum number of child bootstrap endpoints"},
            {RPCResult::Type::NUM, "max_automatic_connections", "Maximum automatic outbound connections when discovery is enabled"},
            {RPCResult::Type::NUM, "aggregate_upload_target", "Process-wide child block-serving target in bytes per cycle; zero means unlimited"},
            {RPCResult::Type::NUM, "aggregate_upload_bytes_sent", "Serialized child block bytes reserved in the current cycle"},
            {RPCResult::Type::NUM, "aggregate_upload_bytes_left", "Bytes remaining in the aggregate target; zero when unlimited or exhausted"},
            {RPCResult::Type::NUM, "aggregate_upload_timeframe", "Upload target cycle length in seconds"},
            {RPCResult::Type::NUM, "aggregate_upload_time_left", "Seconds remaining in the current cycle"},
            {RPCResult::Type::BOOL, "aggregate_upload_target_reached", "Whether child block serving is currently exhausted"},
            {RPCResult::Type::ARR, "added_nodes", "Persistent explicit endpoints", {
                {RPCResult::Type::STR, "", "Host and explicit port"},
            }},
            {RPCResult::Type::ARR, "binds", "Persistent numeric listen endpoints", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getchildnetworkinfo", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    node::ChildNetworkManager& networks{
        EnsureAnyChildNetworkman(request.context)};
    const auto info{networks.GetInfo(chain_id)};
    if (!info.IsValid()) ThrowChildNetworkError(info.result);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    PushChildNetworkStats(result, info.stats);
    PushChildBandwidthStats(result, networks.GetBandwidthStats());
    result.pushKV("max_added_nodes", node::MAX_CHILD_CONNECT_NODES);
    result.pushKV("max_bind_endpoints", node::MAX_CHILD_BIND_ENDPOINTS);
    result.pushKV("max_bootstrap_nodes", node::MAX_CHILD_BOOTSTRAP_NODES);
    result.pushKV("max_automatic_connections",
                  node::MAX_CHILD_AUTOMATIC_CONNECTIONS);
    return result;
}
    };
}

RPCHelpMan addchildnode()
{
    return RPCHelpMan{
        "addchildnode",
        "Persist and connect to one explicit endpoint on a running child network. The endpoint must include a non-zero port.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"endpoint", RPCArg::Type::STR, RPCArg::Optional::NO, "Child peer as host:port or [IPv6]:port"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Updated child network state", {
            {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
            {RPCResult::Type::BOOL, "network_running", "Whether the isolated connection manager is running"},
            {RPCResult::Type::BOOL, "network_active", "Whether new child-network connections are enabled"},
            {RPCResult::Type::NUM, "connections", "Current connection count"},
            {RPCResult::Type::NUM, "handshaken_peers", "Peers authenticated for this exact child chain"},
            {RPCResult::Type::NUM, "known_addresses", "Routable endpoints in this child's isolated peer store"},
            {RPCResult::Type::NUM, "max_known_addresses", "Maximum routable endpoints retained in this child's isolated peer store"},
            {RPCResult::Type::NUM, "rate_limited_block_requests", "Block requests rejected by this child stack's per-peer rate limit"},
            {RPCResult::Type::BOOL, "discovery_enabled", "Whether bounded automatic outbound connections from the isolated child peer store are enabled"},
            {RPCResult::Type::ARR, "bootstrap_nodes", "Numeric bootstrap endpoints kept in the isolated child peer store", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
            {RPCResult::Type::ARR, "added_nodes", "Persistent explicit endpoints", {
                {RPCResult::Type::STR, "", "Host and explicit port"},
            }},
            {RPCResult::Type::ARR, "binds", "Persistent numeric listen endpoints", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("addchildnode", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"127.0.0.1:29843\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    node::ChildNetworkManager& networks{
        EnsureAnyChildNetworkman(request.context)};
    const auto added{networks.AddNode(
        chain_id, self.Arg<UniValue>("endpoint").get_str())};
    if (!added.IsValid()) ThrowChildNetworkError(added);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    PushChildNetworkStats(result, networks.GetStats(chain_id));
    return result;
}
    };
}

RPCHelpMan removechildnode()
{
    return RPCHelpMan{
        "removechildnode",
        "Disconnect and remove one persistent explicit endpoint from a running child network.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"endpoint", RPCArg::Type::STR, RPCArg::Optional::NO, "Configured child peer endpoint"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Updated child network state", {
            {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
            {RPCResult::Type::BOOL, "network_running", "Whether the isolated connection manager is running"},
            {RPCResult::Type::BOOL, "network_active", "Whether new child-network connections are enabled"},
            {RPCResult::Type::NUM, "connections", "Current connection count"},
            {RPCResult::Type::NUM, "handshaken_peers", "Peers authenticated for this exact child chain"},
            {RPCResult::Type::NUM, "known_addresses", "Routable endpoints in this child's isolated peer store"},
            {RPCResult::Type::NUM, "max_known_addresses", "Maximum routable endpoints retained in this child's isolated peer store"},
            {RPCResult::Type::NUM, "rate_limited_block_requests", "Block requests rejected by this child stack's per-peer rate limit"},
            {RPCResult::Type::BOOL, "discovery_enabled", "Whether bounded automatic outbound connections from the isolated child peer store are enabled"},
            {RPCResult::Type::ARR, "bootstrap_nodes", "Numeric bootstrap endpoints kept in the isolated child peer store", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
            {RPCResult::Type::ARR, "added_nodes", "Persistent explicit endpoints", {
                {RPCResult::Type::STR, "", "Host and explicit port"},
            }},
            {RPCResult::Type::ARR, "binds", "Persistent numeric listen endpoints", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("removechildnode", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"127.0.0.1:29843\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    node::ChildNetworkManager& networks{
        EnsureAnyChildNetworkman(request.context)};
    const auto removed{networks.RemoveNode(
        chain_id, self.Arg<UniValue>("endpoint").get_str())};
    if (!removed.IsValid()) ThrowChildNetworkError(removed);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    PushChildNetworkStats(result, networks.GetStats(chain_id));
    return result;
}
    };
}

RPCHelpMan setchildnetworkactive()
{
    return RPCHelpMan{
        "setchildnetworkactive",
        "Enable or disable all peer connections for one running child network and persist the setting.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"active", RPCArg::Type::BOOL, RPCArg::Optional::NO, "True to enable child connections; false to disconnect and pause"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Updated child network state", {
            {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
            {RPCResult::Type::BOOL, "network_running", "Whether the isolated connection manager is running"},
            {RPCResult::Type::BOOL, "network_active", "Whether new child-network connections are enabled"},
            {RPCResult::Type::NUM, "connections", "Current connection count"},
            {RPCResult::Type::NUM, "handshaken_peers", "Peers authenticated for this exact child chain"},
            {RPCResult::Type::NUM, "known_addresses", "Routable endpoints in this child's isolated peer store"},
            {RPCResult::Type::NUM, "max_known_addresses", "Maximum routable endpoints retained in this child's isolated peer store"},
            {RPCResult::Type::NUM, "rate_limited_block_requests", "Block requests rejected by this child stack's per-peer rate limit"},
            {RPCResult::Type::BOOL, "discovery_enabled", "Whether bounded automatic outbound connections from the isolated child peer store are enabled"},
            {RPCResult::Type::ARR, "bootstrap_nodes", "Numeric bootstrap endpoints kept in the isolated child peer store", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
            {RPCResult::Type::ARR, "added_nodes", "Persistent explicit endpoints", {
                {RPCResult::Type::STR, "", "Host and explicit port"},
            }},
            {RPCResult::Type::ARR, "binds", "Persistent numeric listen endpoints", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("setchildnetworkactive", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    node::ChildNetworkManager& networks{
        EnsureAnyChildNetworkman(request.context)};
    const auto updated{networks.SetNetworkActive(
        chain_id, self.Arg<bool>("active"))};
    if (!updated.IsValid()) ThrowChildNetworkError(updated);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    PushChildNetworkStats(result, networks.GetStats(chain_id));
    return result;
}
    };
}

RPCHelpMan setchildnetworkbinds()
{
    return RPCHelpMan{
        "setchildnetworkbinds",
        "Replace the persistent listen endpoints for one running child network. "
        "Only the isolated child P2P stack is restarted. If a new bind fails, the previous configuration is restored.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"binds", RPCArg::Type::ARR, RPCArg::Optional::NO, "Numeric listen endpoints with explicit non-zero ports; an empty array disables inbound child connections", {
                {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Numeric address and port"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Updated child network state", {
            {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
            {RPCResult::Type::BOOL, "network_running", "Whether the isolated connection manager is running"},
            {RPCResult::Type::BOOL, "network_active", "Whether new child-network connections are enabled"},
            {RPCResult::Type::NUM, "connections", "Current connection count"},
            {RPCResult::Type::NUM, "handshaken_peers", "Peers authenticated for this exact child chain"},
            {RPCResult::Type::NUM, "known_addresses", "Routable endpoints in this child's isolated peer store"},
            {RPCResult::Type::NUM, "max_known_addresses", "Maximum routable endpoints retained in this child's isolated peer store"},
            {RPCResult::Type::NUM, "rate_limited_block_requests", "Block requests rejected by this child stack's per-peer rate limit"},
            {RPCResult::Type::BOOL, "discovery_enabled", "Whether bounded automatic outbound connections from the isolated child peer store are enabled"},
            {RPCResult::Type::ARR, "bootstrap_nodes", "Numeric bootstrap endpoints kept in the isolated child peer store", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
            {RPCResult::Type::ARR, "added_nodes", "Persistent explicit endpoints", {
                {RPCResult::Type::STR, "", "Host and explicit port"},
            }},
            {RPCResult::Type::ARR, "binds", "Persistent numeric listen endpoints", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("setchildnetworkbinds", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" '[\"127.0.0.1:29844\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    std::vector<std::string> endpoints;
    const UniValue bind_values{
        self.Arg<UniValue>("binds")};
    for (const UniValue& endpoint : bind_values.getValues()) {
        endpoints.push_back(endpoint.get_str());
    }
    node::ChildNetworkManager& networks{
        EnsureAnyChildNetworkman(request.context)};
    const auto updated{
        networks.SetBindEndpoints(chain_id, std::move(endpoints))};
    if (!updated.IsValid()) ThrowChildNetworkError(updated);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    PushChildNetworkStats(result, networks.GetStats(chain_id));
    return result;
}
    };
}

RPCHelpMan setchildnetworkdiscovery()
{
    return RPCHelpMan{
        "setchildnetworkdiscovery",
        "Replace the numeric bootstrap set and enable or disable bounded automatic outbound connections for one running child network. "
        "Only that isolated child P2P stack is restarted; the child runtime remains loaded and failures restore the previous network configuration.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"enabled", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Whether this child's isolated peer store may create automatic outbound connections"},
            {"bootstrap_nodes", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "Numeric bootstrap endpoints with explicit non-zero ports", {
                {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Numeric address and port"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Updated child network state", {
            {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
            {RPCResult::Type::BOOL, "network_running", "Whether the isolated connection manager is running"},
            {RPCResult::Type::BOOL, "network_active", "Whether new child-network connections are enabled"},
            {RPCResult::Type::NUM, "connections", "Current connection count"},
            {RPCResult::Type::NUM, "handshaken_peers", "Peers authenticated for this exact child chain"},
            {RPCResult::Type::NUM, "known_addresses", "Routable endpoints in this child's isolated peer store"},
            {RPCResult::Type::NUM, "max_known_addresses", "Maximum routable endpoints retained in this child's isolated peer store"},
            {RPCResult::Type::NUM, "rate_limited_block_requests", "Block requests rejected by this child stack's per-peer rate limit"},
            {RPCResult::Type::BOOL, "discovery_enabled", "Whether bounded automatic outbound connections from the isolated child peer store are enabled"},
            {RPCResult::Type::ARR, "bootstrap_nodes", "Numeric bootstrap endpoints kept in the isolated child peer store", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
            {RPCResult::Type::ARR, "added_nodes", "Persistent explicit endpoints", {
                {RPCResult::Type::STR, "", "Host and explicit port"},
            }},
            {RPCResult::Type::ARR, "binds", "Persistent numeric listen endpoints", {
                {RPCResult::Type::STR, "", "Numeric address and explicit port"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("setchildnetworkdiscovery", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" true '[\"203.0.113.10:29843\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    std::vector<std::string> bootstrap;
    const UniValue bootstrap_values{
        self.Arg<UniValue>("bootstrap_nodes")};
    for (const UniValue& endpoint : bootstrap_values.getValues()) {
        bootstrap.push_back(endpoint.get_str());
    }
    node::ChildNetworkManager& networks{
        EnsureAnyChildNetworkman(request.context)};
    const auto updated{networks.SetDiscovery(
        chain_id, self.Arg<bool>("enabled"), std::move(bootstrap))};
    if (!updated.IsValid()) ThrowChildNetworkError(updated);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    PushChildNetworkStats(result, networks.GetStats(chain_id));
    return result;
}
    };
}

RPCHelpMan submitchildanchor()
{
    return RPCHelpMan{
        "submitchildanchor",
        "Authenticate and persist one BMM anchor proof for a loaded child chain. If the referenced block is a stored local proposal, it is validated and admitted automatically. If it is already in the candidate DAG, the additional main-chain work may immediately select and activate its branch.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"bmm_proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical serialized BMM anchor proof"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Anchor submission result", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::STR_HEX, "child_block_hash", "Child block committed by the proof"},
            {RPCResult::Type::BOOL, "already_known", "Whether this exact main-chain anchor was already stored"},
            {RPCResult::Type::BOOL, "local_proposal_found", "Whether a durable local proposal matched the committed block"},
            {RPCResult::Type::BOOL, "local_proposal_activated", "Whether the matching local proposal was admitted automatically"},
            {RPCResult::Type::NUM, "local_proposal_activation_error", /*optional=*/true, "Runtime error code when opportunistic proposal activation failed; the authenticated anchor remains stored"},
            {RPCResult::Type::NUM, "local_proposal_block_error", /*optional=*/true, "Child block validation error code when opportunistic proposal activation failed"},
            {RPCResult::Type::STR_HEX, "selected_head", /*optional=*/true, "Fork-choice result when the referenced child block is known"},
            {RPCResult::Type::STR_HEX, "bestblockhash", "Active child-chain tip after processing"},
            {RPCResult::Type::ARR, "disconnected", "Child blocks disconnected by an immediate reorganization", {
                {RPCResult::Type::STR_HEX, "", "Disconnected child block hash"},
            }},
            {RPCResult::Type::ARR, "pruned", "Losing side-candidate leaves removed to enforce the per-child storage budget", {
                {RPCResult::Type::STR_HEX, "", "Pruned child candidate hash"},
            }},
            {RPCResult::Type::ARR, "pruned_proposals", "Local proposals removed because they no longer extend the authenticated active state", {
                {RPCResult::Type::STR_HEX, "", "Pruned local proposal hash"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("submitchildanchor", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"4b425052...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const auto proof{ParseBmmProof(self.Arg<UniValue>("bmm_proof"))};
    node::ChainManager& manager{EnsureAnyChildChainman(request.context)};
    const auto submitted{manager.StageBmmAnchor(
        chain_id,
        proof,
        Now<NodeSeconds>().time_since_epoch().count(),
        /*sync=*/true)};
    if (!submitted.IsValid()) ThrowChainManagerError(submitted);
    Assume(submitted.runtime.bmm_anchor.proof.anchor);
    const auto view{manager.GetChainView(chain_id)};
    Assume(view.IsValid());

    UniValue disconnected{UniValue::VARR};
    for (const auto& hash : submitted.runtime.disconnected_child_blocks) {
        disconnected.push_back(hash.GetHex());
    }
    UniValue pruned{UniValue::VARR};
    for (const auto& hash : submitted.runtime.pruned_child_candidates) {
        pruned.push_back(hash.GetHex());
    }
    UniValue pruned_proposals{UniValue::VARR};
    for (const auto& hash : submitted.runtime.pruned_local_proposals) {
        pruned_proposals.push_back(hash.GetHex());
    }
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("child_block_hash", submitted.runtime.bmm_anchor.proof.anchor->child_block_hash.GetHex());
    result.pushKV("already_known", submitted.runtime.bmm_anchor_already_known);
    result.pushKV("local_proposal_found", submitted.runtime.local_proposal_found);
    result.pushKV("local_proposal_activated", submitted.runtime.local_proposal_activated);
    if (submitted.runtime.local_proposal_activation_error !=
        node::ReferenceChildRuntimeError::NONE) {
        result.pushKV(
            "local_proposal_activation_error",
            static_cast<unsigned>(
                submitted.runtime.local_proposal_activation_error));
        result.pushKV(
            "local_proposal_block_error",
            static_cast<unsigned>(submitted.runtime.child_block.error));
    }
    if (!submitted.runtime.selected_child_head.IsNull()) {
        result.pushKV("selected_head", submitted.runtime.selected_child_head.GetHex());
    }
    result.pushKV("bestblockhash", view.entry.tip.GetHex());
    result.pushKV("disconnected", std::move(disconnected));
    result.pushKV("pruned", std::move(pruned));
    result.pushKV("pruned_proposals", std::move(pruned_proposals));
    return result;
}
    };
}

RPCHelpMan getchildbmmstatus()
{
    return RPCHelpMan{
        "getchildbmmstatus",
        "Return one lock-consistent operational BMM snapshot for a loaded child chain. This combines its canonical anchor, durable proposals, pending block requests and bounded fork storage without racing separate RPC calls.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Child BMM operational status", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::STR, "health", "idle, awaiting_anchor, anchor_ready, awaiting_block_data, anchored, safe_halt, or failed"},
            {RPCResult::Type::BOOL, "safe_halt", "Whether irreversible import safety has halted the child"},
            {RPCResult::Type::STR, "safe_halt_reason", /*optional=*/true, "Machine-readable reason for the permanent safety halt"},
            {RPCResult::Type::STR_HEX, "safe_halt_observed_main_tip", /*optional=*/true, "Authenticated main-chain tip that first exposed the safety violation"},
            {RPCResult::Type::ARR, "safe_halt_affected_deposits", /*optional=*/true, "Imported deposits no longer present on the authenticated active main chain", {
                {RPCResult::Type::STR_HEX, "deposit_id", "Affected deposit identifier"},
            }},
            {RPCResult::Type::BOOL, "failed", "Whether the child runtime has entered a failed state"},
            {RPCResult::Type::NUM, "child_height", "Active child height"},
            {RPCResult::Type::STR_HEX, "bestblockhash", "Active child tip"},
            {RPCResult::Type::NUM, "main_height", "Authenticated main-chain height"},
            {RPCResult::Type::STR_HEX, "main_bestblockhash", "Authenticated main-chain tip"},
            {RPCResult::Type::NUM, "canonical_anchor_count", "Canonical child anchors retained"},
            {RPCResult::Type::BOOL, "has_tip_anchor", "Whether the non-genesis child tip has a canonical BMM anchor"},
            {RPCResult::Type::STR_HEX, "tip_anchor_main_block_hash", /*optional=*/true, "Main block anchoring the active child tip"},
            {RPCResult::Type::NUM, "tip_anchor_main_height", /*optional=*/true, "Height of the main block anchoring the active child tip"},
            {RPCResult::Type::NUM, "tip_anchor_confirmations", /*optional=*/true, "Authenticated main-chain confirmations for the tip anchor"},
            {RPCResult::Type::NUM, "tip_anchor_gap", /*optional=*/true, "Authenticated main-chain blocks after the tip anchor"},
            {RPCResult::Type::NUM, "pending_block_count", "Child blocks requested by authenticated pending anchors"},
            {RPCResult::Type::NUM, "pending_anchor_count", "Authenticated pending anchor records"},
            {RPCResult::Type::NUM, "pending_anchor_bytes", "Serialized bytes used by pending anchors"},
            {RPCResult::Type::NUM, "proposal_count", "Durable local block proposals"},
            {RPCResult::Type::NUM, "proposal_bytes", "Serialized child block bytes retained as proposals"},
            {RPCResult::Type::NUM, "proposals_with_anchor", "Local proposals with an authenticated anchor staged"},
            {RPCResult::Type::NUM, "proposals_without_anchor", "Local proposals still waiting for an anchor"},
            {RPCResult::Type::NUM_TIME, "oldest_proposal_time", /*optional=*/true, "Creation time of the oldest local proposal"},
            {RPCResult::Type::NUM_TIME, "newest_proposal_time", /*optional=*/true, "Creation time of the newest local proposal"},
            {RPCResult::Type::NUM, "side_candidate_count", "Retained competing child block candidates"},
            {RPCResult::Type::NUM, "side_candidate_bytes", "Serialized bytes used by competing child candidates"},
            {RPCResult::Type::NUM, "candidate_anchor_count", "BMM anchors retained for competing candidates"},
            {RPCResult::Type::NUM, "candidate_anchor_bytes", "Serialized bytes used by candidate anchors"},
            {RPCResult::Type::ARR, "pending_blocks", "Authenticated anchors awaiting exact child block data", {
                {RPCResult::Type::OBJ, "", "One pending child block", {
                    {RPCResult::Type::STR_HEX, "blockhash", "Requested child block"},
                    {RPCResult::Type::NUM, "oldest_anchor_height", "Oldest active main anchor height"},
                    {RPCResult::Type::NUM, "newest_anchor_height", "Newest active main anchor height"},
                    {RPCResult::Type::NUM, "anchor_count", "Authenticated anchors for this child block"},
                }},
            }},
            {RPCResult::Type::ARR, "proposals", "Durable local proposals", {
                {RPCResult::Type::OBJ, "", "One local proposal", {
                    {RPCResult::Type::STR_HEX, "blockhash", "Child block hash"},
                    {RPCResult::Type::STR_HEX, "previousblockhash", "Proposed parent block"},
                    {RPCResult::Type::NUM_TIME, "created_time", "Local proposal creation time"},
                    {RPCResult::Type::NUM, "size", "Serialized block size including witness"},
                    {RPCResult::Type::BOOL, "anchor_available", "Whether an authenticated pending anchor is staged"},
                    {RPCResult::Type::NUM, "anchor_count", "Authenticated pending anchors for this proposal"},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getchildbmmstatus", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const auto view{
        EnsureAnyChildChainman(request.context).GetBmmStatusView(chain_id)};
    if (!view.IsValid()) ThrowBmmStatusViewError(view.error);

    std::map<uint256, uint64_t> anchor_counts;
    uint64_t pending_anchor_count{0};
    UniValue pending_blocks{UniValue::VARR};
    for (const auto& block : view.pending_blocks) {
        anchor_counts.emplace(block.block_hash, block.anchor_count);
        pending_anchor_count += block.anchor_count;
        UniValue object{UniValue::VOBJ};
        object.pushKV("blockhash", block.block_hash.GetHex());
        object.pushKV("oldest_anchor_height", block.oldest_anchor_height);
        object.pushKV("newest_anchor_height", block.newest_anchor_height);
        object.pushKV("anchor_count", block.anchor_count);
        pending_blocks.push_back(std::move(object));
    }

    uint64_t proposal_bytes{0};
    uint64_t proposals_with_anchor{0};
    std::optional<int64_t> oldest_proposal_time;
    std::optional<int64_t> newest_proposal_time;
    UniValue proposals{UniValue::VARR};
    for (const auto& proposal : view.proposals) {
        proposal_bytes += proposal.serialized_size;
        const uint256 block_hash{proposal.block.GetHash()};
        const uint64_t anchor_count{anchor_counts[block_hash]};
        if (anchor_count != 0) ++proposals_with_anchor;
        oldest_proposal_time = std::min(
            oldest_proposal_time.value_or(proposal.created_time),
            proposal.created_time);
        newest_proposal_time = std::max(
            newest_proposal_time.value_or(proposal.created_time),
            proposal.created_time);
        UniValue object{UniValue::VOBJ};
        object.pushKV("blockhash", block_hash.GetHex());
        object.pushKV("previousblockhash", proposal.block.hashPrevBlock.GetHex());
        object.pushKV("created_time", proposal.created_time);
        object.pushKV("size", proposal.serialized_size);
        object.pushKV("anchor_available", anchor_count != 0);
        object.pushKV("anchor_count", anchor_count);
        proposals.push_back(std::move(object));
    }

    const char* health{
        view.entry.safe_halt
            ? "safe_halt"
            : view.entry.failed
                ? "failed"
                : !view.pending_blocks.empty()
                    ? "awaiting_block_data"
                    : proposals_with_anchor != 0
                        ? "anchor_ready"
                        : !view.proposals.empty()
                            ? "awaiting_anchor"
                            : view.entry.height != 0 ? "anchored" : "idle"};
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("health", health);
    result.pushKV("safe_halt", view.entry.safe_halt);
    if (view.safe_halt) {
        UniValue affected_deposits{UniValue::VARR};
        for (const auto& deposit_id : view.safe_halt->affected_imports) {
            affected_deposits.push_back(deposit_id.GetHex());
        }
        result.pushKV("safe_halt_reason",
                      DepositSafeHaltReasonName(view.safe_halt->reason));
        result.pushKV("safe_halt_observed_main_tip",
                      view.safe_halt->observed_main_tip.GetHex());
        result.pushKV("safe_halt_affected_deposits",
                      std::move(affected_deposits));
    }
    result.pushKV("failed", view.entry.failed);
    result.pushKV("child_height", view.entry.height);
    result.pushKV("bestblockhash", view.entry.tip.GetHex());
    result.pushKV("main_height", view.entry.main_height);
    result.pushKV("main_bestblockhash", view.entry.main_tip.GetHex());
    result.pushKV("canonical_anchor_count", view.entry.anchor_count);
    result.pushKV("has_tip_anchor", view.tip_anchor.has_value());
    if (view.tip_anchor) {
        const auto& proof{view.tip_anchor->proof};
        result.pushKV("tip_anchor_main_block_hash",
                      proof.block_header.GetHash().GetHex());
        result.pushKV("tip_anchor_main_height", proof.block_height);
        result.pushKV("tip_anchor_confirmations",
                      view.entry.main_height - proof.block_height + 1);
        result.pushKV("tip_anchor_gap",
                      view.entry.main_height - proof.block_height);
    }
    result.pushKV("pending_block_count", view.pending_blocks.size());
    result.pushKV("pending_anchor_count", pending_anchor_count);
    result.pushKV("pending_anchor_bytes", view.entry.pending_anchor_bytes);
    result.pushKV("proposal_count", view.proposals.size());
    result.pushKV("proposal_bytes", proposal_bytes);
    result.pushKV("proposals_with_anchor", proposals_with_anchor);
    result.pushKV("proposals_without_anchor",
                  view.proposals.size() - proposals_with_anchor);
    if (oldest_proposal_time) {
        result.pushKV("oldest_proposal_time", *oldest_proposal_time);
        result.pushKV("newest_proposal_time", *newest_proposal_time);
    }
    result.pushKV("side_candidate_count", view.entry.side_candidate_count);
    result.pushKV("side_candidate_bytes", view.entry.side_candidate_bytes);
    result.pushKV("candidate_anchor_count", view.entry.candidate_anchor_count);
    result.pushKV("candidate_anchor_bytes", view.entry.candidate_anchor_bytes);
    result.pushKV("pending_blocks", std::move(pending_blocks));
    result.pushKV("proposals", std::move(proposals));
    return result;
},
    };
}

RPCHelpMan getchildpendingblocks()
{
    return RPCHelpMan{
        "getchildpendingblocks",
        "List child blocks committed by authenticated active-main-chain BMM anchors whose block data has not been received yet. Multiple anchors for the same block are aggregated.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Pending child block data", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::NUM, "block_count", "Distinct child blocks awaiting data"},
            {RPCResult::Type::NUM, "anchor_count", "Authenticated pending anchors represented by this result"},
            {RPCResult::Type::ARR, "blocks", "Blocks ordered by oldest main-chain anchor height", {
                {RPCResult::Type::OBJ, "", "Pending block", {
                    {RPCResult::Type::STR_HEX, "blockhash", "Committed child block hash"},
                    {RPCResult::Type::NUM, "oldest_anchor_height", "Oldest active main-chain anchor height"},
                    {RPCResult::Type::NUM, "newest_anchor_height", "Newest active main-chain anchor height"},
                    {RPCResult::Type::NUM, "anchor_count", "Active anchors committing to this block"},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("getchildpendingblocks", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const auto pending{
        EnsureAnyChildChainman(request.context).GetPendingBlocksView(chain_id)};
    switch (pending.error) {
    case node::ChainManagerPendingBlocksViewError::NONE:
        break;
    case node::ChainManagerPendingBlocksViewError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerPendingBlocksViewError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerPendingBlocksViewError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not loaded");
    case node::ChainManagerPendingBlocksViewError::DATA_UNAVAILABLE:
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "pending child block data is unavailable");
    }

    uint64_t anchor_count{0};
    UniValue blocks{UniValue::VARR};
    for (const auto& block : pending.blocks) {
        anchor_count += block.anchor_count;
        UniValue object{UniValue::VOBJ};
        object.pushKV("blockhash", block.block_hash.GetHex());
        object.pushKV("oldest_anchor_height", block.oldest_anchor_height);
        object.pushKV("newest_anchor_height", block.newest_anchor_height);
        object.pushKV("anchor_count", block.anchor_count);
        blocks.push_back(std::move(object));
    }
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("block_count", pending.blocks.size());
    result.pushKV("anchor_count", anchor_count);
    result.pushKV("blocks", std::move(blocks));
    return result;
}
    };
}

RPCHelpMan submitchildblock()
{
    return RPCHelpMan{
        "submitchildblock",
        "Validate and persist one child block. If bmm_proof is omitted, the newest authenticated pending anchor for the exact block hash is used. The block may extend the active tip or enter the bounded competing-branch DAG; fork choice can reorganize the child chain immediately.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"block", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized child block, including witness data"},
            {"bmm_proof", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Canonical serialized BMM anchor proof committing to this child block; omit only after submitchildanchor staged one"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Child block submission result", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::STR_HEX, "blockhash", "Submitted child block hash"},
            {RPCResult::Type::BOOL, "accepted", "True after validation and durable persistence"},
            {RPCResult::Type::STR, "anchor_source", "supplied or staged"},
            {RPCResult::Type::BOOL, "candidate_stored", "Whether the block was first persisted on a competing branch"},
            {RPCResult::Type::STR_HEX, "selected_head", "Fork-choice result"},
            {RPCResult::Type::STR_HEX, "bestblockhash", "Active child-chain tip after processing"},
            {RPCResult::Type::ARR, "disconnected", "Child blocks disconnected by a reorganization", {
                {RPCResult::Type::STR_HEX, "", "Disconnected child block hash"},
            }},
            {RPCResult::Type::ARR, "pruned", "Losing side-candidate leaves removed to enforce the per-child storage budget", {
                {RPCResult::Type::STR_HEX, "", "Pruned child candidate hash"},
            }},
            {RPCResult::Type::ARR, "pruned_proposals", "Local proposals removed because they no longer extend the authenticated active state", {
                {RPCResult::Type::STR_HEX, "", "Pruned local proposal hash"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("submitchildblock", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"blockhex\" \"4b425052...\"")
            + HelpExampleCli("submitchildblock", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"blockhex\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const CBlock block{ParseChildBlock(self.Arg<UniValue>("block"))};
    node::ChainManager& manager{EnsureAnyChildChainman(request.context)};
    const UniValue* proof_arg{self.MaybeArg<UniValue>("bmm_proof")};
    const int64_t current_time{Now<NodeSeconds>().time_since_epoch().count()};
    const auto submitted{proof_arg
        ? manager.SubmitBlock(
              chain_id,
              block,
              ParseBmmProof(*proof_arg),
              current_time,
              /*sync=*/true)
        : manager.SubmitBlockData(
              chain_id,
              block,
              current_time,
              /*sync=*/true)};
    if (!submitted.IsValid()) ThrowChainManagerError(submitted);
    const auto view{manager.GetChainView(chain_id)};
    Assume(view.IsValid());

    UniValue disconnected{UniValue::VARR};
    for (const auto& hash : submitted.runtime.disconnected_child_blocks) {
        disconnected.push_back(hash.GetHex());
    }
    UniValue pruned{UniValue::VARR};
    for (const auto& hash : submitted.runtime.pruned_child_candidates) {
        pruned.push_back(hash.GetHex());
    }
    UniValue pruned_proposals{UniValue::VARR};
    for (const auto& hash : submitted.runtime.pruned_local_proposals) {
        pruned_proposals.push_back(hash.GetHex());
    }
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("blockhash", block.GetHash().GetHex());
    result.pushKV("accepted", true);
    result.pushKV("anchor_source", proof_arg ? "supplied" : "staged");
    result.pushKV("candidate_stored", submitted.runtime.candidate_stored);
    result.pushKV("selected_head", submitted.runtime.selected_child_head.GetHex());
    result.pushKV("bestblockhash", view.entry.tip.GetHex());
    result.pushKV("disconnected", std::move(disconnected));
    result.pushKV("pruned", std::move(pruned));
    result.pushKV("pruned_proposals", std::move(pruned_proposals));
    return result;
}
    };
}

RPCHelpMan createchildimporttransaction()
{
    return RPCHelpMan{
        "createchildimporttransaction",
        "Build a canonical child IMPORT transaction from a KDPR proof. The exact child must be loaded; its local main-header light client authenticates the proof, active branch and configured maturity before any transaction is returned. This RPC does not submit a child block.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null destination child-chain identifier"},
            {"deposit_proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical serialized KDPR v1 proof"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Authenticated child IMPORT transaction", {
            {RPCResult::Type::STR_HEX, "chain_id", "Destination child-chain identifier"},
            {RPCResult::Type::STR_HEX, "deposit_id", "Network-bound imported deposit identifier"},
            {RPCResult::Type::STR_HEX, "transaction", "Serialized canonical IMPORT transaction including witness"},
            {RPCResult::Type::STR_HEX, "txid", "IMPORT transaction identifier"},
            {RPCResult::Type::STR_HEX, "wtxid", "IMPORT witness transaction identifier"},
            {RPCResult::Type::STR_AMOUNT, "amount", "Amount credited by the IMPORT"},
            {RPCResult::Type::NUM, "recipient_type", "Child-template recipient namespace"},
            {RPCResult::Type::STR_HEX, "recipient", "Canonical child recipient bytes"},
            {RPCResult::Type::STR_HEX, "main_block_hash", "Authenticated containing main-chain block"},
            {RPCResult::Type::NUM, "main_block_height", "Authenticated containing main-chain height"},
            {RPCResult::Type::NUM, "confirmations", "Confirmations observed by the child light client"},
            {RPCResult::Type::NUM, "required_confirmations", "Deposit maturity configured by the child manifest"},
            {RPCResult::Type::BOOL, "authenticated", "Always true when the RPC succeeds"},
        }},
        RPCExamples{
            HelpExampleCli("createchildimporttransaction", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"4b445052...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const auto proof{ParseDepositProof(self.Arg<UniValue>("deposit_proof"))};
    const auto built{EnsureAnyChildChainman(request.context)
                         .BuildImportTransaction(chain_id, proof)};
    switch (built.error) {
    case node::ChainManagerImportBuildError::NONE:
        break;
    case node::ChainManagerImportBuildError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerImportBuildError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerImportBuildError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is not loaded");
    case node::ChainManagerImportBuildError::SAFE_HALT:
        throw JSONRPCError(RPC_VERIFY_REJECTED,
                           "child chain is in SAFE_HALT");
    case node::ChainManagerImportBuildError::PROOF_REJECTED:
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            strprintf(
                "deposit proof rejected by child light client: %s (%d/%u confirmations)",
                AuthenticatedDepositErrorName(built.authenticated.error),
                built.authenticated.confirmations,
                built.minimum_confirmations));
    case node::ChainManagerImportBuildError::ALREADY_IMPORTED:
        throw JSONRPCError(RPC_VERIFY_ERROR,
                           "deposit is already imported by this child chain");
    case node::ChainManagerImportBuildError::BUILD_FAILED:
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            strprintf("failed to build canonical child IMPORT (error %u, proof error %u)",
                      static_cast<unsigned>(built.import.error),
                      static_cast<unsigned>(built.import.proof_error)));
    }

    Assume(built.authenticated.proof.fund);
    Assume(built.import.transaction);
    Assume(built.import.deposit_id);
    const auto& fund{*built.authenticated.proof.fund};
    const CTransaction transaction{*built.import.transaction};
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("deposit_id", built.import.deposit_id->GetHex());
    result.pushKV("transaction", EncodeHexTx(transaction));
    result.pushKV("txid", transaction.GetHash().GetHex());
    result.pushKV("wtxid", transaction.GetWitnessHash().GetHex());
    result.pushKV("amount", ValueFromAmount(fund.amount));
    result.pushKV("recipient_type", fund.fund.recipient_type);
    result.pushKV("recipient", HexStr(fund.fund.recipient));
    result.pushKV("main_block_hash", proof.block_header.GetHash().GetHex());
    result.pushKV("main_block_height", proof.block_height);
    result.pushKV("confirmations", built.authenticated.confirmations);
    result.pushKV("required_confirmations", built.minimum_confirmations);
    result.pushKV("authenticated", true);
    return result;
},
    };
}

RPCHelpMan createchildimportblock()
{
    return RPCHelpMan{
        "createchildimportblock",
        "Build and contextually validate an import-only block extending the active tip of one loaded child chain. Every KDPR proof is authenticated against the child light client's active main-header chain and maturity policy. The returned block has no independent PoW or subsidy and must be committed by a main-chain BMM anchor before submission.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null destination child-chain identifier"},
            {"deposit_proofs", RPCArg::Type::ARR, RPCArg::Optional::NO, "One or more canonical serialized KDPR v1 proofs", {
                {"", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Canonical serialized KDPR v1 proof"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Validated child block awaiting BMM anchoring", {
            {RPCResult::Type::STR_HEX, "chain_id", "Destination child-chain identifier"},
            {RPCResult::Type::STR_HEX, "block", "Serialized child block including witness data"},
            {RPCResult::Type::STR_HEX, "blockhash", "Child block hash to commit on the main chain"},
            {RPCResult::Type::STR_HEX, "previousblockhash", "Active child tip extended by this block"},
            {RPCResult::Type::STR_HEX, "merkleroot", "Child transaction Merkle root"},
            {RPCResult::Type::NUM, "height", "Candidate child block height"},
            {RPCResult::Type::NUM_TIME, "time", "Candidate child block timestamp"},
            {RPCResult::Type::NUM, "size", "Serialized block size including witness"},
            {RPCResult::Type::NUM, "weight", "Candidate block weight"},
            {RPCResult::Type::ARR, "transactions", "IMPORT transaction identifiers in block order", {
                {RPCResult::Type::STR_HEX, "", "IMPORT txid"},
            }},
            {RPCResult::Type::ARR, "deposits", "Authenticated deposits imported by this block", {
                {RPCResult::Type::OBJ, "", "Authenticated import", {
                    {RPCResult::Type::STR_HEX, "deposit_id", "Network-bound deposit identifier"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "Amount credited on the child"},
                    {RPCResult::Type::NUM, "recipient_type", "Child-template recipient namespace"},
                    {RPCResult::Type::STR_HEX, "recipient", "Canonical child recipient bytes"},
                    {RPCResult::Type::NUM, "confirmations", "Main-chain confirmations authenticated by the child light client"},
                }},
            }},
            {RPCResult::Type::STR_HEX, "bmm_anchor_script", "Zero-valued main-chain output script committing to this child block"},
            {RPCResult::Type::BOOL, "requires_bmm_anchor", "Always true; this call does not submit or anchor the block"},
            {RPCResult::Type::BOOL, "proposal_stored", "Always true after the validated block is durably queued locally"},
            {RPCResult::Type::BOOL, "contextually_valid", "Always true when the RPC succeeds"},
            {RPCResult::Type::ARR, "pruned_proposals", "Older local proposals removed because they no longer extend the authenticated active state", {
                {RPCResult::Type::STR_HEX, "", "Pruned local proposal hash"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("createchildimportblock", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" '[\"4b445052...\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const auto proofs{ParseDepositProofs(
        self.Arg<UniValue>("deposit_proofs"))};
    const auto built{EnsureAnyChildChainman(request.context).BuildImportBlock(
        chain_id,
        proofs,
        Now<NodeSeconds>().time_since_epoch().count(),
        /*sync=*/true)};
    switch (built.error) {
    case node::ChainManagerImportBlockBuildError::NONE:
        break;
    case node::ChainManagerImportBlockBuildError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerImportBlockBuildError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerImportBlockBuildError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is not loaded");
    case node::ChainManagerImportBlockBuildError::EMPTY_PROOFS:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "deposit_proofs must not be empty");
    case node::ChainManagerImportBlockBuildError::TOO_MANY_PROOFS:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "too many deposit proofs");
    case node::ChainManagerImportBlockBuildError::PROPOSAL_PENDING:
        throw JSONRPCError(
            RPC_VERIFY_ERROR,
            "a local child proposal already extends the active tip");
    case node::ChainManagerImportBlockBuildError::PROPOSAL_QUEUE_UNAVAILABLE:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "local child proposal state is unavailable");
    case node::ChainManagerImportBlockBuildError::TIME_OUT_OF_RANGE:
        throw JSONRPCError(RPC_MISC_ERROR,
                           "candidate child block time is out of range");
    case node::ChainManagerImportBlockBuildError::IMPORT_REJECTED: {
        Assume(built.failed_proof);
        Assume(*built.failed_proof < built.imports.size());
        const auto& imported{built.imports[*built.failed_proof]};
        const std::string reason{
            imported.error == node::ChainManagerImportBuildError::PROOF_REJECTED
                ? std::string{AuthenticatedDepositErrorName(
                      imported.authenticated.error)}
                : strprintf("import-error-%u",
                            static_cast<unsigned>(imported.error))};
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            strprintf("deposit proof %u rejected: %s",
                      *built.failed_proof,
                      reason));
    }
    case node::ChainManagerImportBlockBuildError::DUPLICATE_DEPOSIT:
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("deposit proof %u duplicates an earlier deposit",
                      *Assert(built.failed_proof)));
    case node::ChainManagerImportBlockBuildError::BUILD_FAILED:
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            strprintf("failed to build canonical child block (error %u)",
                      static_cast<unsigned>(built.build.error)));
    case node::ChainManagerImportBlockBuildError::CONTEXT_REJECTED:
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            strprintf("candidate child block failed contextual validation (error %u, transaction %s)",
                      static_cast<unsigned>(built.validation.error),
                      built.validation.failed_transaction
                          ? util::ToString(*built.validation.failed_transaction)
                          : "none"));
    case node::ChainManagerImportBlockBuildError::PROPOSAL_PERSIST_FAILED:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "validated child block could not be persisted as a local proposal");
    case node::ChainManagerImportBlockBuildError::SAFE_HALT:
        throw JSONRPCError(RPC_VERIFY_REJECTED,
                           "child chain is in SAFE_HALT");
    }

    Assume(built.build.block);
    const CBlock& block{*built.build.block};
    DataStream encoded;
    encoded << TX_WITH_WITNESS(block);

    UniValue transactions{UniValue::VARR};
    for (size_t index{1}; index < block.vtx.size(); ++index) {
        transactions.push_back(block.vtx[index]->GetHash().GetHex());
    }
    UniValue deposits{UniValue::VARR};
    for (const auto& imported : built.imports) {
        Assume(imported.import.deposit_id);
        Assume(imported.authenticated.proof.fund);
        const auto& fund{*imported.authenticated.proof.fund};
        UniValue deposit{UniValue::VOBJ};
        deposit.pushKV("deposit_id", imported.import.deposit_id->GetHex());
        deposit.pushKV("amount", ValueFromAmount(fund.amount));
        deposit.pushKV("recipient_type", fund.fund.recipient_type);
        deposit.pushKV("recipient", HexStr(fund.fund.recipient));
        deposit.pushKV("confirmations", imported.authenticated.confirmations);
        deposits.push_back(std::move(deposit));
    }
    const CScript anchor_script{chainregistry::BuildBmmAnchorScript({
        .chain_id = chain_id,
        .child_block_hash = block.GetHash(),
    })};

    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("block", HexStr(encoded));
    result.pushKV("blockhash", block.GetHash().GetHex());
    result.pushKV("previousblockhash", block.hashPrevBlock.GetHex());
    result.pushKV("merkleroot", block.hashMerkleRoot.GetHex());
    result.pushKV("height", built.block_height);
    result.pushKV("time", block.GetBlockTime());
    result.pushKV("size", GetSerializeSize(TX_WITH_WITNESS(block)));
    result.pushKV("weight", GetBlockWeight(block));
    result.pushKV("transactions", std::move(transactions));
    result.pushKV("deposits", std::move(deposits));
    result.pushKV("bmm_anchor_script", HexStr(anchor_script));
    result.pushKV("requires_bmm_anchor", true);
    result.pushKV("proposal_stored", true);
    result.pushKV("contextually_valid", true);
    UniValue pruned_proposals{UniValue::VARR};
    for (const auto& hash : built.pruned_local_proposals) {
        pruned_proposals.push_back(hash.GetHex());
    }
    result.pushKV("pruned_proposals", std::move(pruned_proposals));
    return result;
},
    };
}

RPCHelpMan createchildblock()
{
    return RPCHelpMan{
        "createchildblock",
        "Build, contextually validate, and durably store a block of finalized transactions extending the active tip of one loaded child chain. Omit transactions to select the current child mempool in admission order. Explicit transactions are validated against the child UTXO set and signature domain. An optional P2TR fee recipient claims the block's transaction fees; otherwise the fees remain unclaimed. The block still requires a main-chain BMM anchor before activation.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"transactions", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "One or more finalized serialized child transactions including witness data; omit to use the child mempool", {
                {"transaction", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Serialized child transaction"},
            }},
            {"fee_recipient", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional valid 32-byte reference-child P2TR output key receiving all transaction fees in the zero-subsidy coinbase"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Validated and stored child block proposal", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::STR_HEX, "block", "Serialized child block including witness data"},
            {RPCResult::Type::STR_HEX, "blockhash", "Child block hash"},
            {RPCResult::Type::STR_HEX, "previousblockhash", "Active child parent hash"},
            {RPCResult::Type::STR_HEX, "merkleroot", "Child block Merkle root"},
            {RPCResult::Type::NUM, "height", "Proposed child height"},
            {RPCResult::Type::NUM_TIME, "time", "Child block timestamp"},
            {RPCResult::Type::NUM, "size", "Serialized block size including witness"},
            {RPCResult::Type::NUM, "weight", "Child block weight"},
            {RPCResult::Type::NUM, "fees", "Total transaction fees"},
            {RPCResult::Type::NUM, "claimed_fees", "Fees assigned to the optional coinbase output, or zero"},
            {RPCResult::Type::STR_HEX, "fee_recipient", /*optional=*/true, "P2TR output key receiving claimed fees"},
            {RPCResult::Type::ARR, "transactions", "Transaction ids in block order, excluding coinbase", {
                {RPCResult::Type::STR_HEX, "", "Transaction id"},
            }},
            {RPCResult::Type::STR_HEX, "bmm_anchor_script", "Canonical main-chain BMM commitment script"},
            {RPCResult::Type::BOOL, "requires_bmm_anchor", "Always true"},
            {RPCResult::Type::BOOL, "proposal_stored", "Always true after durable persistence"},
            {RPCResult::Type::BOOL, "contextually_valid", "Always true when the RPC succeeds"},
            {RPCResult::Type::ARR, "pruned_proposals", "Older local proposals removed because they no longer extend the active state", {
                {RPCResult::Type::STR_HEX, "", "Pruned local proposal hash"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("createchildblock", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" '[\"02000000...\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    node::ChainManager& manager{EnsureAnyChildChainman(request.context)};
    std::vector<CTransactionRef> transactions;
    if (request.params[1].isNull()) {
        const auto mempool{manager.GetMempool(chain_id)};
        switch (mempool.error) {
        case node::ChainManagerMempoolViewError::NONE:
            break;
        case node::ChainManagerMempoolViewError::NULL_CHAIN_ID:
            throw JSONRPCError(
                RPC_INVALID_PARAMETER, "chain_id must not be null");
        case node::ChainManagerMempoolViewError::UNKNOWN_CHAIN:
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "child chain is not configured locally");
        case node::ChainManagerMempoolViewError::CHAIN_NOT_LOADED:
            throw JSONRPCError(
                RPC_INVALID_PARAMETER, "child chain is not loaded");
        }
        transactions.reserve(mempool.runtime.entries.size());
        for (const auto& entry : mempool.runtime.entries) {
            transactions.push_back(entry.transaction);
        }
    } else {
        transactions = ParseChildTransactions(request.params[1]);
    }
    const auto [fee_recipient_script, fee_recipient]{
        ParseChildFeeRecipient(self.MaybeArg<UniValue>("fee_recipient"))};
    const auto built{manager.BuildTransactionBlock(
        chain_id,
        transactions,
        fee_recipient_script,
        Now<NodeSeconds>().time_since_epoch().count(),
        /*sync=*/true)};
    switch (built.error) {
    case node::ChainManagerTransactionBlockBuildError::NONE:
        break;
    case node::ChainManagerTransactionBlockBuildError::NULL_CHAIN_ID:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must not be null");
    case node::ChainManagerTransactionBlockBuildError::UNKNOWN_CHAIN:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "child chain is not configured locally");
    case node::ChainManagerTransactionBlockBuildError::CHAIN_NOT_LOADED:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "child chain is not loaded");
    case node::ChainManagerTransactionBlockBuildError::EMPTY_TRANSACTIONS:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "transactions must not be empty");
    case node::ChainManagerTransactionBlockBuildError::TOO_MANY_TRANSACTIONS:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "too many child transactions");
    case node::ChainManagerTransactionBlockBuildError::PROPOSAL_PENDING:
        throw JSONRPCError(
            RPC_VERIFY_ERROR,
            "a local child proposal already extends the active tip");
    case node::ChainManagerTransactionBlockBuildError::PROPOSAL_QUEUE_UNAVAILABLE:
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "local child proposal state is unavailable");
    case node::ChainManagerTransactionBlockBuildError::TIME_OUT_OF_RANGE:
        throw JSONRPCError(RPC_MISC_ERROR,
                           "candidate child block time is out of range");
    case node::ChainManagerTransactionBlockBuildError::BUILD_FAILED:
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            strprintf("failed to build canonical child block (error %u, transaction %s)",
                      static_cast<unsigned>(built.build.error),
                      built.build.failed_transaction
                          ? util::ToString(*built.build.failed_transaction)
                          : "none"));
    case node::ChainManagerTransactionBlockBuildError::CONTEXT_REJECTED:
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            strprintf("candidate child block failed contextual validation (error %u, block transaction %s)",
                      static_cast<unsigned>(built.validation.error),
                      built.validation.failed_transaction
                          ? util::ToString(*built.validation.failed_transaction)
                          : "none"));
    case node::ChainManagerTransactionBlockBuildError::PROPOSAL_PERSIST_FAILED:
        throw JSONRPCError(
            RPC_DATABASE_ERROR,
            "validated child block could not be persisted as a local proposal");
    case node::ChainManagerTransactionBlockBuildError::SAFE_HALT:
        throw JSONRPCError(RPC_VERIFY_REJECTED,
                           "child chain is in SAFE_HALT");
    }

    Assume(built.build.block);
    const CBlock& block{*built.build.block};
    DataStream encoded;
    encoded << TX_WITH_WITNESS(block);
    UniValue transaction_ids{UniValue::VARR};
    for (size_t index{1}; index < block.vtx.size(); ++index) {
        transaction_ids.push_back(block.vtx[index]->GetHash().GetHex());
    }
    const CAmount claimed_fees{block.vtx.front()->GetValueOut()};
    const CScript anchor_script{chainregistry::BuildBmmAnchorScript({
        .chain_id = chain_id,
        .child_block_hash = block.GetHash(),
    })};

    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("block", HexStr(encoded));
    result.pushKV("blockhash", block.GetHash().GetHex());
    result.pushKV("previousblockhash", block.hashPrevBlock.GetHex());
    result.pushKV("merkleroot", block.hashMerkleRoot.GetHex());
    result.pushKV("height", built.block_height);
    result.pushKV("time", block.GetBlockTime());
    result.pushKV("size", GetSerializeSize(TX_WITH_WITNESS(block)));
    result.pushKV("weight", GetBlockWeight(block));
    result.pushKV("fees", ValueFromAmount(built.validation.total_fees));
    result.pushKV("claimed_fees", ValueFromAmount(claimed_fees));
    if (fee_recipient) result.pushKV("fee_recipient", *fee_recipient);
    result.pushKV("transactions", std::move(transaction_ids));
    result.pushKV("bmm_anchor_script", HexStr(anchor_script));
    result.pushKV("requires_bmm_anchor", true);
    result.pushKV("proposal_stored", true);
    result.pushKV("contextually_valid", true);
    UniValue pruned_proposals{UniValue::VARR};
    for (const auto& hash : built.pruned_local_proposals) {
        pruned_proposals.push_back(hash.GetHex());
    }
    result.pushKV("pruned_proposals", std::move(pruned_proposals));
    return result;
},
    };
}

RPCHelpMan storechildproposal()
{
    return RPCHelpMan{
        "storechildproposal",
        "Contextually validate and durably store a child block extending the active tip while it waits for a BMM anchor. Re-storing the identical block is idempotent.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"block", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized child block including witness data"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Persisted local proposal", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::STR_HEX, "blockhash", "Stored child block hash"},
            {RPCResult::Type::NUM, "size", "Serialized block size including witness"},
            {RPCResult::Type::BOOL, "stored", "True after durable persistence"},
            {RPCResult::Type::ARR, "pruned_proposals", "Older local proposals removed because they no longer extend the authenticated active state", {
                {RPCResult::Type::STR_HEX, "", "Pruned local proposal hash"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("storechildproposal", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"blockhex\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const CBlock block{ParseChildBlock(self.Arg<UniValue>("block"))};
    const auto stored{EnsureAnyChildChainman(request.context).StoreProposal(
        chain_id,
        block,
        Now<NodeSeconds>().time_since_epoch().count(),
        /*sync=*/true)};
    if (!stored.IsValid()) ThrowChainManagerError(stored);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("blockhash", block.GetHash().GetHex());
    result.pushKV("size", GetSerializeSize(TX_WITH_WITNESS(block)));
    result.pushKV("stored", true);
    UniValue pruned_proposals{UniValue::VARR};
    for (const auto& hash : stored.runtime.pruned_local_proposals) {
        pruned_proposals.push_back(hash.GetHex());
    }
    result.pushKV("pruned_proposals", std::move(pruned_proposals));
    return result;
},
    };
}

RPCHelpMan listchildproposals()
{
    return RPCHelpMan{
        "listchildproposals",
        "List durable local block proposals for one loaded child chain and whether an authenticated BMM anchor is already staged for each proposal.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Local child proposal queue", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::NUM, "proposal_count", "Number of stored local proposals"},
            {RPCResult::Type::NUM, "proposal_limit", "Maximum stored proposals per child"},
            {RPCResult::Type::NUM, "proposal_bytes", "Serialized child block bytes retained"},
            {RPCResult::Type::NUM, "proposal_bytes_limit", "Maximum serialized proposal bytes per child"},
            {RPCResult::Type::ARR, "proposals", "Stored proposals in creation order", {
                {RPCResult::Type::OBJ, "", "One local proposal", {
                    {RPCResult::Type::STR_HEX, "blockhash", "Child block hash"},
                    {RPCResult::Type::STR_HEX, "previousblockhash", "Proposed parent block"},
                    {RPCResult::Type::NUM_TIME, "created_time", "Local proposal creation time"},
                    {RPCResult::Type::NUM, "size", "Serialized block size including witness"},
                    {RPCResult::Type::BOOL, "anchor_available", "Whether at least one authenticated pending anchor is staged"},
                    {RPCResult::Type::NUM, "anchor_count", "Authenticated pending anchors for this block"},
                }},
            }},
        }},
        RPCExamples{
            HelpExampleCli("listchildproposals", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    node::ChainManager& manager{EnsureAnyChildChainman(request.context)};
    const auto view{manager.GetProposalsView(chain_id)};
    if (!view.IsValid()) ThrowProposalsViewError(view.error);
    const auto pending{manager.GetPendingBlocksView(chain_id)};
    if (!pending.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR,
                           "pending BMM anchor state is unavailable");
    }
    std::map<uint256, uint64_t> anchor_counts;
    for (const auto& block : pending.blocks) {
        anchor_counts.emplace(block.block_hash, block.anchor_count);
    }

    uint64_t bytes{0};
    UniValue proposals{UniValue::VARR};
    for (const auto& proposal : view.proposals) {
        bytes += proposal.serialized_size;
        const uint64_t anchor_count{anchor_counts[proposal.block.GetHash()]};
        UniValue object{UniValue::VOBJ};
        object.pushKV("blockhash", proposal.block.GetHash().GetHex());
        object.pushKV("previousblockhash", proposal.block.hashPrevBlock.GetHex());
        object.pushKV("created_time", proposal.created_time);
        object.pushKV("size", proposal.serialized_size);
        object.pushKV("anchor_available", anchor_count != 0);
        object.pushKV("anchor_count", anchor_count);
        proposals.push_back(std::move(object));
    }
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("proposal_count", view.proposals.size());
    result.pushKV("proposal_limit", node::MAX_CHILD_LOCAL_PROPOSALS);
    result.pushKV("proposal_bytes", bytes);
    result.pushKV("proposal_bytes_limit", node::MAX_CHILD_LOCAL_PROPOSAL_BYTES);
    result.pushKV("proposals", std::move(proposals));
    return result;
},
    };
}

RPCHelpMan getchildproposal()
{
    return RPCHelpMan{
        "getchildproposal",
        "Return one durable local child block proposal.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Non-null child block hash"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Stored child proposal", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::STR_HEX, "blockhash", "Child block hash"},
            {RPCResult::Type::STR_HEX, "previousblockhash", "Proposed parent block"},
            {RPCResult::Type::STR_HEX, "block", "Serialized child block including witness"},
            {RPCResult::Type::NUM_TIME, "created_time", "Local proposal creation time"},
            {RPCResult::Type::NUM, "size", "Serialized block size including witness"},
        }},
        RPCExamples{
            HelpExampleCli("getchildproposal", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"blockhash\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const uint256 block_hash{ParseNonNullHash(
        self.Arg<UniValue>("blockhash"), "blockhash")};
    const auto view{EnsureAnyChildChainman(request.context).GetProposalsView(
        chain_id, block_hash)};
    if (!view.IsValid()) ThrowProposalsViewError(view.error);
    Assume(view.proposals.size() == 1);
    const auto& proposal{view.proposals.front()};
    DataStream encoded;
    encoded << TX_WITH_WITNESS(proposal.block);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("blockhash", proposal.block.GetHash().GetHex());
    result.pushKV("previousblockhash", proposal.block.hashPrevBlock.GetHex());
    result.pushKV("block", HexStr(encoded));
    result.pushKV("created_time", proposal.created_time);
    result.pushKV("size", proposal.serialized_size);
    return result;
},
    };
}

RPCHelpMan removechildproposal()
{
    return RPCHelpMan{
        "removechildproposal",
        "Remove one unsubmitted local child proposal. Consensus child blocks and candidates are never affected.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Non-null child block hash"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Removal result", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::STR_HEX, "blockhash", "Removed child block hash"},
            {RPCResult::Type::BOOL, "removed", "True after durable removal"},
        }},
        RPCExamples{
            HelpExampleCli("removechildproposal", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"blockhash\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const uint256 block_hash{ParseNonNullHash(
        self.Arg<UniValue>("blockhash"), "blockhash")};
    const auto removed{EnsureAnyChildChainman(request.context).RemoveProposal(
        chain_id, block_hash, /*sync=*/true)};
    if (!removed.IsValid()) ThrowChainManagerError(removed);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("blockhash", block_hash.GetHex());
    result.pushKV("removed", true);
    return result;
},
    };
}

RPCHelpMan submitchildproposal()
{
    return RPCHelpMan{
        "submitchildproposal",
        "Validate and submit one stored local child proposal. If bmm_proof is omitted, the newest staged authenticated anchor for the exact block is used. A successful submission removes the proposal atomically.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Stored non-null child block hash"},
            {"bmm_proof", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Canonical serialized BMM anchor proof; omit after submitchildanchor"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Stored proposal submission result", {
            {RPCResult::Type::STR_HEX, "chain_id", "Child-chain identifier"},
            {RPCResult::Type::STR_HEX, "blockhash", "Submitted child block hash"},
            {RPCResult::Type::BOOL, "accepted", "True after validation and durable persistence"},
            {RPCResult::Type::STR, "anchor_source", "supplied or staged"},
            {RPCResult::Type::STR_HEX, "selected_head", "Fork-choice result"},
            {RPCResult::Type::STR_HEX, "bestblockhash", "Active child tip after processing"},
            {RPCResult::Type::ARR, "pruned_proposals", "Competing local proposals removed because they no longer extend the active tip", {
                {RPCResult::Type::STR_HEX, "", "Pruned local proposal hash"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("submitchildproposal", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"blockhash\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const uint256 block_hash{ParseNonNullHash(
        self.Arg<UniValue>("blockhash"), "blockhash")};
    const UniValue* proof_arg{self.MaybeArg<UniValue>("bmm_proof")};
    const std::optional<chainregistry::BmmAnchorProof> proof{
        proof_arg ? std::optional{ParseBmmProof(*proof_arg)} : std::nullopt};
    node::ChainManager& manager{EnsureAnyChildChainman(request.context)};
    const auto submitted{manager.SubmitProposal(
        chain_id,
        block_hash,
        proof,
        Now<NodeSeconds>().time_since_epoch().count(),
        /*sync=*/true)};
    if (!submitted.IsValid()) ThrowChainManagerError(submitted);
    const auto view{manager.GetChainView(chain_id)};
    Assume(view.IsValid());
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("blockhash", block_hash.GetHex());
    result.pushKV("accepted", true);
    result.pushKV("anchor_source", proof ? "supplied" : "staged");
    result.pushKV("selected_head", submitted.runtime.selected_child_head.GetHex());
    result.pushKV("bestblockhash", view.entry.tip.GetHex());
    UniValue pruned_proposals{UniValue::VARR};
    for (const auto& hash : submitted.runtime.pruned_local_proposals) {
        pruned_proposals.push_back(hash.GetHex());
    }
    result.pushKV("pruned_proposals", std::move(pruned_proposals));
    return result;
},
    };
}

RPCHelpMan forgetchildchain()
{
    return RPCHelpMan{
        "forgetchildchain",
        "Remove one unloaded manifest from the local catalog. Existing child-chain data is deliberately preserved and can be reopened by adding the same manifest again.\n",
        {
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Full, non-null child-chain identifier"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Catalog removal result", {
            {RPCResult::Type::STR_HEX, "chain_id", "Full child-chain identifier"},
            {RPCResult::Type::BOOL, "configured", "False after successful removal"},
            {RPCResult::Type::BOOL, "data_preserved", "Always true; this RPC never deletes chain data"},
        }},
        RPCExamples{
            HelpExampleCli("forgetchildchain", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto chain_id{ParseChainId(self.Arg<UniValue>("chain_id"))};
    const auto forgotten{
        EnsureAnyChildChainman(request.context).ForgetChain(chain_id)};
    if (!forgotten.IsValid()) ThrowChainManagerError(forgotten);
    UniValue result{UniValue::VOBJ};
    result.pushKV("chain_id", chain_id.GetHex());
    result.pushKV("configured", false);
    result.pushKV("data_preserved", true);
    return result;
}
    };
}

} // namespace

void RegisterChainRegistryRPCCommands(CRPCTable& table)
{
    static const CRPCCommand commands[]{
        {"util", &derivechildchainid},
        {"util", &createreferencechildmanifest},
        {"util", &createfundchainoutput},
        {"util", &decodefundchainoutput},
        {"util", &createchainregistryoperation},
        {"util", &decodechainregistryoperation},
        {"control", &addchildchain},
        {"control", &listchildchainruntimes},
        {"control", &loadchildchain},
        {"control", &unloadchildchain},
        {"network", &getchildnetworkinfo},
        {"network", &addchildnode},
        {"network", &removechildnode},
        {"network", &setchildnetworkactive},
        {"network", &setchildnetworkbinds},
        {"network", &setchildnetworkdiscovery},
        {"blockchain", &getchildbmmstatus},
        {"blockchain", &getchildpendingblocks},
        {"blockchain", &listchildproposals},
        {"blockchain", &getchildproposal},
        {"rawtransactions", &createchildimporttransaction},
        {"mining", &createchildimportblock},
        {"mining", &createchildblock},
        {"mining", &storechildproposal},
        {"mining", &submitchildanchor},
        {"mining", &submitchildblock},
        {"mining", &submitchildproposal},
        {"mining", &removechildproposal},
        {"control", &forgetchildchain},
    };
    for (const auto& command : commands) table.appendCommand(&command);
}
