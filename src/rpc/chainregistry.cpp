// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <primitives/chainregistry.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <validation.h>

#include <algorithm>
#include <cstdint>
#include <initializer_list>
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

std::vector<unsigned char> OperationData(const CScript& script)
{
    auto cursor{script.begin()};
    opcodetype opcode;
    std::vector<unsigned char> data;
    Assume(script.GetOp(cursor, opcode) && opcode == OP_RETURN);
    Assume(script.GetOp(cursor, opcode, data) && cursor == script.end());
    return data;
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
    result.pushKV("data", HexStr(OperationData(script)));
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
    result.pushKV("data", HexStr(OperationData(script)));
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

} // namespace

void RegisterChainRegistryRPCCommands(CRPCTable& table)
{
    static const CRPCCommand commands[]{
        {"util", &derivechildchainid},
        {"util", &createchainregistryoperation},
        {"util", &decodechainregistryoperation},
    };
    for (const auto& command : commands) table.appendCommand(&command);
}
