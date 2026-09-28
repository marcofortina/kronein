// Copyright (c) 2012-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <node/chain_manager.h>
#include <node/child_network_manager.h>
#include <node/context.h>
#include <pow.h>
#include <primitives/bmm.h>
#include <primitives/chainregistry.h>
#include <rpc/blockchain.h>
#include <rpc/client.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <streams.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/time.h>

#include <any>
#include <string_view>

#include <boost/test/unit_test.hpp>

using util::SplitString;

static UniValue JSON(std::string_view json)
{
    UniValue value;
    BOOST_CHECK(value.read(json));
    return value;
}

static chainregistry::ReferenceChildDefinition RpcChildDefinition()
{
    const auto result{chainregistry::BuildReferenceChildDefinition(
        Params().GetConsensus().hashGenesisBlock,
        COutPoint{Txid::FromUint256(uint256{1}), 0},
        chainregistry::MakeReferenceChildSpec({}),
        chainregistry::MetadataHash{
            "4444444444444444444444444444444444444444444444444444444444444444"})};
    BOOST_REQUIRE(result.IsValid());
    return *result.definition;
}

static CBlock RpcChildBlock(
    const chainregistry::ReferenceChildDefinition& definition)
{
    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vin.front().scriptSig =
        CScript{} << int64_t{1} << std::vector<unsigned char>{0};
    coinbase.vin.front().scriptWitness.stack = {
        std::vector<unsigned char>(32)};
    coinbase.vout.emplace_back(
        0, CScript{} << OP_1 << std::vector<unsigned char>(32, 1));

    CBlock block;
    block.nVersion = CBlockHeader::CURRENT_VERSION;
    block.hashPrevBlock = definition.genesis_hash;
    block.nTime = Params().GenesisBlock().nTime + 1;
    block.vtx = {MakeTransactionRef(std::move(coinbase))};
    const auto& reserved{
        block.vtx.front()->vin.front().scriptWitness.stack.front()};
    uint256 commitment{BlockWitnessMerkleRoot(block)};
    CHash256().Write(commitment).Write(reserved).Finalize(commitment);
    std::vector<unsigned char> payload{0xaa, 0x21, 0xa9, 0xed};
    payload.insert(payload.end(), commitment.begin(), commitment.end());
    CMutableTransaction committed_coinbase{*block.vtx.front()};
    committed_coinbase.vout.emplace_back(
        0, CScript{} << OP_RETURN << payload);
    block.vtx.front() = MakeTransactionRef(std::move(committed_coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

static chainregistry::BmmAnchorProof RpcBmmProof(
    CBlock& main_block,
    const chainregistry::ReferenceChildDefinition& definition,
    const uint256& child_block_hash)
{
    const auto& params{Params().GetConsensus()};
    const chainregistry::ChainRecord record{
        .record_version = chainregistry::CHAIN_RECORD_VERSION,
        .chain_id = definition.chain_id,
        .manifest_hash = definition.manifest_hash,
        .template_id = definition.manifest.spec.template_id,
        .template_version = definition.manifest.spec.template_version,
        .control_outpoint = COutPoint{
            Txid{"2222222222222222222222222222222222222222222222222222222222222222"}, 0},
        .metadata_hash = definition.manifest.initial_metadata_hash,
        .status = chainregistry::ChainStatus::ACTIVE,
    };
    chainregistry::ChainRegistry registry;
    BOOST_REQUIRE(registry.LoadRecords({record}).IsValid());

    CMutableTransaction coinbase;
    coinbase.vin.emplace_back(COutPoint{});
    coinbase.vout.emplace_back(
        0, chainregistry::BuildRegistryCommitment(registry.ComputeRoot()));
    CMutableTransaction proposal;
    proposal.vin.emplace_back(COutPoint{
        Txid{"3333333333333333333333333333333333333333333333333333333333333333"}, 0});
    proposal.vout.emplace_back(
        0,
        chainregistry::BuildBmmAnchorScript({
            .chain_id = definition.chain_id,
            .child_block_hash = child_block_hash,
        }));

    CBlockIndex main_parent{Params().GenesisBlock()};
    main_parent.phashBlock = &params.hashGenesisBlock;
    main_parent.nHeight = 0;
    main_parent.nChainWork = GetBlockProof(main_parent);
    main_parent.nTimeMax = main_parent.nTime;
    main_block.nVersion = CBlockHeader::CURRENT_VERSION;
    main_block.hashPrevBlock = main_parent.GetBlockHash();
    main_block.nTime = main_parent.nTime + 1;
    main_block.nBits = GetNextWorkRequired(&main_parent, &main_block, params);
    main_block.vtx = {
        MakeTransactionRef(coinbase), MakeTransactionRef(proposal)};
    main_block.hashMerkleRoot = BlockMerkleRoot(main_block);
    const auto seed{GetRandomXSeed(&main_parent, 1, params)};
    BOOST_REQUIRE(seed);
    uint64_t max_tries{1'000'000};
    BOOST_REQUIRE(MineProofOfWork(
        main_block,
        *seed,
        params,
        max_tries,
        /*threads=*/1,
        /*use_full_memory=*/false));

    return {
        .main_genesis_hash = params.hashGenesisBlock,
        .block_height = 1,
        .block_header = main_block,
        .anchor_transaction = proposal,
        .transaction_index = 1,
        .transaction_merkle_branch = TransactionMerklePath(main_block, 1),
        .coinbase_transaction = coinbase,
        .coinbase_merkle_branch = TransactionMerklePath(main_block, 0),
        .chain_record = record,
        .registry_proof = *registry.GetInclusionProof(definition.chain_id),
    };
}

class HasJSON
{
public:
    explicit HasJSON(std::string json) : m_json(std::move(json)) {}
    bool operator()(const UniValue& value) const
    {
        std::string json{value.write()};
        BOOST_CHECK_EQUAL(json, m_json);
        return json == m_json;
    };

private:
    const std::string m_json;
};

class RPCTestingSetup : public TestingSetup
{
public:
    RPCTestingSetup()
    {
        m_node.child_chainman = std::make_unique<node::ChainManager>(
            Params().GetConsensus(),
            Params().GenesisBlock(),
            m_args.GetDataDirNet() / "chains",
            node::DEFAULT_CHILD_CHAIN_DB_CACHE);
        BOOST_REQUIRE(m_node.child_chainman->IsCatalogReady());
        m_node.child_networkman = std::make_unique<node::ChildNetworkManager>(
            *m_node.child_chainman, Params(), *m_node.scheduler);
    }

    UniValue TransformParams(const UniValue& params, std::vector<std::pair<std::string, bool>> arg_names) const;
    UniValue CallRPC(std::string args);
};

UniValue RPCTestingSetup::TransformParams(const UniValue& params, std::vector<std::pair<std::string, bool>> arg_names) const
{
    UniValue transformed_params;
    CRPCTable table;
    CRPCCommand command{"category", "method", [&](const JSONRPCRequest& request, UniValue&, bool) -> bool { transformed_params = request.params; return true; }, arg_names, /*unique_id=*/0};
    table.appendCommand(&command);
    JSONRPCRequest request;
    request.strMethod = "method";
    request.params = params;
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    table.execute(request);
    return transformed_params;
}

UniValue RPCTestingSetup::CallRPC(std::string args)
{
    std::vector<std::string> vArgs{SplitString(args, ' ')};
    std::string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    JSONRPCRequest request;
    request.context = &m_node;
    request.strMethod = strMethod;
    request.params = RPCConvertValues(strMethod, vArgs);
    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
    try {
        UniValue result = tableRPC.execute(request);
        return result;
    }
    catch (const UniValue& objError) {
        throw std::runtime_error(objError.find_value("message").get_str());
    }
}


BOOST_FIXTURE_TEST_SUITE(rpc_tests, RPCTestingSetup)

BOOST_AUTO_TEST_CASE(child_chain_lifecycle_rpc)
{
    const auto result{CallRPC("listchildchainruntimes")};
    BOOST_CHECK(result.isObject());
    BOOST_CHECK(result.find_value("chains").isArray());
    BOOST_CHECK_EQUAL(result.find_value("chains").size(), 0U);

    const std::string null_id(64, '0');
    BOOST_CHECK_EXCEPTION(
        CallRPC("loadchildchain " + null_id),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find("must not be null") !=
                   std::string_view::npos;
        });

    const std::string unknown_id(64, '1');
    for (const std::string command : {
             "loadchildchain ", "unloadchildchain ", "forgetchildchain ",
             "getchildnetworkinfo "}) {
        BOOST_CHECK_EXCEPTION(
            CallRPC(command + unknown_id),
            std::runtime_error,
            [](const std::runtime_error& error) {
                return std::string_view{error.what()}.find(
                           "not configured locally") != std::string_view::npos;
            });
    }
}

BOOST_AUTO_TEST_CASE(blockchain_rpc_routes_explicit_child_chain)
{
    const auto definition{RpcChildDefinition()};
    auto& manager{*m_node.child_chainman};
    BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    BOOST_REQUIRE(manager.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());

    const std::string chain_id{definition.chain_id.GetHex()};
    const int main_height{CallRPC("getblockcount").getInt<int>()};
    const std::string main_tip{CallRPC("getbestblockhash").get_str()};
    const auto main_info{CallRPC("getblockchaininfo")};
    BOOST_CHECK_NE(main_info.find_value("chain").get_str(), "child");
    BOOST_CHECK(main_info.find_value("chain_id").isNull());
    const auto main_tips{CallRPC("getchaintips")};
    BOOST_REQUIRE(!main_tips.empty());
    BOOST_CHECK(main_tips[0].find_value("chain_id").isNull());
    BOOST_CHECK_EQUAL(CallRPC("getblockcount " + chain_id).getInt<int>(), 0);
    BOOST_CHECK_EQUAL(CallRPC("getbestblockhash " + chain_id).get_str(),
                      definition.genesis_hash.GetHex());
    BOOST_CHECK_EQUAL(CallRPC("getblockhash 0 " + chain_id).get_str(),
                      definition.genesis_hash.GetHex());
    const auto child_info{CallRPC("getblockchaininfo " + chain_id)};
    BOOST_CHECK_EQUAL(child_info.find_value("chain").get_str(), "child");
    BOOST_CHECK_EQUAL(child_info.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK_EQUAL(child_info.find_value("genesis_hash").get_str(),
                      definition.genesis_hash.GetHex());
    BOOST_CHECK_EQUAL(child_info.find_value("context_state").get_str(),
                      "loaded");
    BOOST_CHECK_EQUAL(child_info.find_value("blocks").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(child_info.find_value("headers").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(child_info.find_value("bestblockhash").get_str(),
                      definition.genesis_hash.GetHex());
    BOOST_CHECK(!child_info.find_value("network_sync_available").get_bool());
    BOOST_CHECK(!child_info.find_value("safe_halt").get_bool());
    BOOST_CHECK(child_info.find_value("size_on_disk").isNull());
    BOOST_CHECK_EQUAL(child_info.find_value("bmm_anchor_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(child_info.find_value("pending_bmm_anchor_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(child_info.find_value("side_candidate_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(child_info.find_value("candidate_bmm_anchor_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(child_info.find_value("side_candidate_limit").getInt<int>(),
                      node::MAX_CHILD_SIDE_CANDIDATES);
    BOOST_CHECK_EQUAL(child_info.find_value("candidate_bmm_anchor_limit").getInt<int>(),
                      node::MAX_CHILD_CANDIDATE_BMM_ANCHORS);
    const auto runtimes{CallRPC("listchildchainruntimes")};
    BOOST_REQUIRE_EQUAL(runtimes.find_value("chains").size(), 1U);
    const auto& runtime{runtimes.find_value("chains")[0]};
    BOOST_CHECK(runtime.find_value("loaded").get_bool());
    BOOST_CHECK_EQUAL(runtime.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK_EQUAL(runtime.find_value("side_candidate_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(runtime.find_value("candidate_bmm_anchor_count").getInt<int>(), 0);
    const auto child_tips{CallRPC("getchaintips " + chain_id)};
    BOOST_REQUIRE_EQUAL(child_tips.size(), 1U);
    BOOST_CHECK_EQUAL(child_tips[0].find_value("chain_id").get_str(),
                      chain_id);
    BOOST_CHECK_EQUAL(child_tips[0].find_value("hash").get_str(),
                      definition.genesis_hash.GetHex());
    BOOST_CHECK_EQUAL(child_tips[0].find_value("status").get_str(), "active");
    BOOST_CHECK(!child_tips[0].find_value("bmm_eligible").get_bool());
    const auto child_utxo_stats{CallRPC(
        "gettxoutsetinfo muhash null true " + chain_id)};
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("bestblock").get_str(),
        definition.genesis_hash.GetHex());
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("height").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("txouts").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("transactions").getInt<int>(), 0);
    BOOST_CHECK(!child_utxo_stats.find_value("muhash").get_str().empty());
    BOOST_CHECK(CallRPC("verifychain 4 0 " + chain_id).get_bool());
    const auto child_header{CallRPC(
        "getblockheader " + definition.genesis_hash.GetHex() +
        " true " + chain_id)};
    BOOST_CHECK_EQUAL(child_header.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK_EQUAL(child_header.find_value("hash").get_str(),
                      definition.genesis_hash.GetHex());
    BOOST_CHECK(child_header.find_value("virtual").get_bool());
    BOOST_CHECK_EQUAL(child_header.find_value("height").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(child_header.find_value("confirmations").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(CallRPC("getblockcount").getInt<int>(), main_height);
    BOOST_CHECK_EQUAL(CallRPC("getbestblockhash").get_str(), main_tip);
    BOOST_CHECK_EQUAL(CallRPC("getblockheader " + main_tip + " false").get_str().size(), 160U);
    BOOST_CHECK(CallRPC(
        "gettxout " + std::string(64, 'f') + " 0").isNull());

    for (const std::string& command : {
             "getblockheader " + definition.genesis_hash.GetHex() + " false " + chain_id,
             "getblock " + definition.genesis_hash.GetHex() + " 0 " + chain_id}) {
        BOOST_CHECK_EXCEPTION(
            CallRPC(command),
            std::runtime_error,
            [](const std::runtime_error& error) {
                return std::string_view{error.what()}.find(
                           "virtual descriptor") != std::string_view::npos;
            });
    }
    BOOST_CHECK_EXCEPTION(
        CallRPC("getblockheader " + std::string(64, '2') + " true " + chain_id),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                       "Child block not found") != std::string_view::npos;
        });

    BOOST_CHECK_EXCEPTION(
        CallRPC("getblockhash 1 " + chain_id),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find("height out of range") !=
                   std::string_view::npos;
        });
    BOOST_REQUIRE(manager.UnloadChain(definition.chain_id).IsValid());
    BOOST_CHECK_EXCEPTION(
        CallRPC("getblockcount " + chain_id),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find("not loaded") !=
                   std::string_view::npos;
        });
    BOOST_CHECK_EXCEPTION(
        CallRPC("gettxout " + std::string(64, 'f') + " 0 true " + chain_id),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find("not loaded") !=
                   std::string_view::npos;
        });
    BOOST_CHECK_EXCEPTION(
        CallRPC("getbestblockhash " + std::string(64, '0')),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find("non-null bytes") !=
                   std::string_view::npos;
        });
    BOOST_CHECK_EXCEPTION(
        CallRPC("getblockcount " + std::string(64, '1')),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find("not configured") !=
                   std::string_view::npos;
        });
}

BOOST_AUTO_TEST_CASE(child_submission_rpc_bounds_and_routes_requests)
{
    const auto definition{RpcChildDefinition()};
    auto& manager{*m_node.child_chainman};
    const std::string chain_id{definition.chain_id.GetHex()};
    const std::string unknown_id(64, '1');

    BOOST_CHECK_EXCEPTION(
        CallRPC("submitchildanchor " + chain_id + " zz"),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                       "non-empty hexadecimal") != std::string_view::npos;
        });
    BOOST_CHECK_EXCEPTION(
        CallRPC("submitchildanchor " + chain_id + " 00"),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                       "BMM proof decode failed") != std::string_view::npos;
        });

    const chainregistry::BmmAnchorProof proof;
    DataStream proof_stream;
    proof_stream << proof;
    const std::string proof_hex{HexStr(proof_stream)};
    CBlock block;
    DataStream block_stream;
    block_stream << TX_WITH_WITNESS(block);
    const std::string block_hex{HexStr(block_stream)};

    BOOST_CHECK_EXCEPTION(
        CallRPC("submitchildanchor " + unknown_id + " " + proof_hex),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                   "not configured locally") != std::string_view::npos;
        });
    BOOST_CHECK_EXCEPTION(
        CallRPC("getchildpendingblocks " + unknown_id),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                       "not configured locally") != std::string_view::npos;
        });
    BOOST_REQUIRE(manager.RegisterChain(definition).IsValid());
    BOOST_CHECK_EXCEPTION(
        CallRPC("getchildpendingblocks " + chain_id),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find("not loaded") !=
                   std::string_view::npos;
        });
    for (const std::string& command : {
             "submitchildanchor " + chain_id + " " + proof_hex,
             "submitchildblock " + chain_id + " " + block_hex + " " + proof_hex}) {
        BOOST_CHECK_EXCEPTION(
            CallRPC(command),
            std::runtime_error,
            [](const std::runtime_error& error) {
                return std::string_view{error.what()}.find(
                           "not loaded") != std::string_view::npos;
            });
    }

    BOOST_REQUIRE(manager.LoadChain(
        definition.chain_id,
        Params().GenesisBlock().nTime,
        /*wipe_data=*/true,
        /*sync=*/true).IsValid());
    const auto initially_pending{
        CallRPC("getchildpendingblocks " + chain_id)};
    BOOST_CHECK_EQUAL(
        initially_pending.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK_EQUAL(
        initially_pending.find_value("block_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(
        initially_pending.find_value("anchor_count").getInt<int>(), 0);
    BOOST_CHECK(initially_pending.find_value("blocks").isArray());
    BOOST_CHECK_EXCEPTION(
        CallRPC("submitchildblock " + chain_id + " 00 " + proof_hex),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                       "Child block decode failed") != std::string_view::npos;
        });
    BOOST_CHECK_EXCEPTION(
        CallRPC("submitchildanchor " + chain_id + " " + proof_hex),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                       "child runtime rejected request") !=
                   std::string_view::npos;
        });
    BOOST_CHECK_EXCEPTION(
        CallRPC("submitchildblock " + chain_id + " " + block_hex),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                       "no authenticated pending BMM anchor") !=
                   std::string_view::npos;
        });

    const CBlock child_block{RpcChildBlock(definition)};
    CBlock main_anchor;
    const auto valid_proof{
        RpcBmmProof(main_anchor, definition, child_block.GetHash())};
    const auto main_update{manager.AddMainHeader(
        main_anchor, main_anchor.nTime, /*sync=*/true)};
    BOOST_REQUIRE_EQUAL(main_update.unloaded.size(), 0U);
    BOOST_REQUIRE_EQUAL(main_update.advanced.size(), 1U);
    DataStream valid_proof_stream;
    valid_proof_stream << valid_proof;
    DataStream child_block_stream;
    child_block_stream << TX_WITH_WITNESS(child_block);
    const std::string valid_proof_hex{HexStr(valid_proof_stream)};
    const std::string child_block_hex{HexStr(child_block_stream)};
    const auto staged{CallRPC(
        "submitchildanchor " + chain_id + " " + valid_proof_hex)};
    BOOST_CHECK_EQUAL(staged.find_value("child_block_hash").get_str(),
                      child_block.GetHash().GetHex());
    const auto awaiting_data{
        CallRPC("getchildpendingblocks " + chain_id)};
    BOOST_CHECK_EQUAL(
        awaiting_data.find_value("block_count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(
        awaiting_data.find_value("anchor_count").getInt<int>(), 1);
    const UniValue& pending_blocks{awaiting_data.find_value("blocks")};
    BOOST_REQUIRE_EQUAL(pending_blocks.size(), 1U);
    BOOST_CHECK_EQUAL(
        pending_blocks[0].find_value("blockhash").get_str(),
        child_block.GetHash().GetHex());
    BOOST_CHECK_EQUAL(
        pending_blocks[0].find_value("oldest_anchor_height").getInt<int>(),
        1);
    BOOST_CHECK_EQUAL(
        pending_blocks[0].find_value("newest_anchor_height").getInt<int>(),
        1);
    BOOST_CHECK_EQUAL(
        pending_blocks[0].find_value("anchor_count").getInt<int>(), 1);
    const auto submitted{CallRPC(
        "submitchildblock " + chain_id + " " + child_block_hex)};
    BOOST_CHECK(submitted.find_value("accepted").get_bool());
    BOOST_CHECK_EQUAL(submitted.find_value("anchor_source").get_str(),
                      "staged");
    BOOST_CHECK_EQUAL(submitted.find_value("blockhash").get_str(),
                      child_block.GetHash().GetHex());
    BOOST_CHECK_EQUAL(submitted.find_value("bestblockhash").get_str(),
                      child_block.GetHash().GetHex());
    BOOST_CHECK(submitted.find_value("pruned").isArray());
    BOOST_CHECK_EQUAL(submitted.find_value("pruned").size(), 0U);
    const auto recovered{CallRPC("getchildpendingblocks " + chain_id)};
    BOOST_CHECK_EQUAL(recovered.find_value("block_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(recovered.find_value("anchor_count").getInt<int>(), 0);

    DataStream child_header_stream;
    child_header_stream << static_cast<const CBlockHeader&>(child_block);
    BOOST_CHECK_EQUAL(
        CallRPC("getblockheader " + child_block.GetHash().GetHex() +
                " false " + chain_id).get_str(),
        HexStr(child_header_stream));
    const auto child_header{CallRPC(
        "getblockheader " + child_block.GetHash().GetHex() +
        " true " + chain_id)};
    BOOST_CHECK_EQUAL(child_header.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK(!child_header.find_value("virtual").get_bool());
    BOOST_CHECK(child_header.find_value("bmm_eligible").get_bool());
    BOOST_CHECK_EQUAL(child_header.find_value("height").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(child_header.find_value("confirmations").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(
        CallRPC("getblock " + child_block.GetHash().GetHex() +
                " 0 " + chain_id).get_str(),
        child_block_hex);
    const auto verbose_block{CallRPC(
        "getblock " + child_block.GetHash().GetHex() + " 2 " + chain_id)};
    BOOST_CHECK_EQUAL(verbose_block.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK_EQUAL(verbose_block.find_value("tx").size(), 1U);
    BOOST_CHECK(verbose_block.find_value("tx")[0].isObject());
    const auto child_info{CallRPC("getblockchaininfo " + chain_id)};
    BOOST_CHECK_EQUAL(child_info.find_value("blocks").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(child_info.find_value("headers").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(child_info.find_value("bestblockhash").get_str(),
                      child_block.GetHash().GetHex());
    BOOST_CHECK(child_info.find_value("bmm_eligible").get_bool());
    BOOST_CHECK_EQUAL(child_info.find_value("bmm_anchor_count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(child_info.find_value("side_candidate_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(child_info.find_value("candidate_bmm_anchor_count").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(child_info.find_value("chainwork").get_str(),
                      child_info.find_value("bmm_cumulative_work").get_str());
    const auto child_tips{CallRPC("getchaintips " + chain_id)};
    BOOST_REQUIRE_EQUAL(child_tips.size(), 1U);
    BOOST_CHECK_EQUAL(child_tips[0].find_value("hash").get_str(),
                      child_block.GetHash().GetHex());
    BOOST_CHECK_EQUAL(child_tips[0].find_value("status").get_str(), "active");
    BOOST_CHECK(child_tips[0].find_value("bmm_eligible").get_bool());

    const std::string coinbase_txid{
        child_block.vtx.front()->GetHash().GetHex()};
    BOOST_CHECK_EQUAL(
        CallRPC("getrawtransaction " + coinbase_txid + " 0 " +
                child_block.GetHash().GetHex() + " " + chain_id).get_str(),
        EncodeHexTx(*child_block.vtx.front()));
    const auto child_transaction{CallRPC(
        "getrawtransaction " + coinbase_txid + " 2 " +
        child_block.GetHash().GetHex() + " " + chain_id)};
    BOOST_CHECK_EQUAL(
        child_transaction.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK_EQUAL(
        child_transaction.find_value("blockhash").get_str(),
        child_block.GetHash().GetHex());
    BOOST_CHECK(child_transaction.find_value("in_active_chain").get_bool());
    BOOST_CHECK_EQUAL(
        child_transaction.find_value("confirmations").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(
        child_transaction.find_value("txid").get_str(), coinbase_txid);
    BOOST_CHECK(child_transaction.find_value("bmm_eligible").get_bool());
    JSONRPCRequest missing_block_request;
    missing_block_request.context = &m_node;
    missing_block_request.strMethod = "getrawtransaction";
    missing_block_request.params = UniValue{UniValue::VOBJ};
    missing_block_request.params.pushKV("txid", coinbase_txid);
    missing_block_request.params.pushKV("verbosity", 1);
    missing_block_request.params.pushKV("chain_id", chain_id);
    BOOST_CHECK_EXCEPTION(
        tableRPC.execute(missing_block_request),
        UniValue,
        [](const UniValue& error) {
            const UniValue& message{error.find_value("message")};
            return message.isStr() &&
                std::string_view{message.get_str()}.find(
                    "blockhash is required") != std::string_view::npos;
        });
    BOOST_CHECK_EXCEPTION(
        CallRPC("getrawtransaction " + std::string(64, 'f') + " 1 " +
                child_block.GetHash().GetHex() + " " + chain_id),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                       "provided child block") != std::string_view::npos;
        });
    const auto child_stats{CallRPC(
        "getblockstats " + child_block.GetHash().GetHex() + " [] " +
        chain_id)};
    BOOST_CHECK_EQUAL(child_stats.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK_EQUAL(child_stats.find_value("blockhash").get_str(),
                      child_block.GetHash().GetHex());
    BOOST_CHECK_EQUAL(child_stats.find_value("height").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(child_stats.find_value("subsidy").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(child_stats.find_value("totalfee").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(child_stats.find_value("txs").getInt<int>(), 1);
    const auto child_utxo_stats{CallRPC(
        "gettxoutsetinfo muhash null true " + chain_id)};
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("bestblock").get_str(),
        child_block.GetHash().GetHex());
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("height").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("txouts").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("transactions").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(
        child_utxo_stats.find_value("total_amount").getValStr(),
        "0.00000000");
    const auto selected_child_utxo_stats{CallRPC(
        "gettxoutsetinfo none 1 false " + chain_id)};
    BOOST_CHECK_EQUAL(
        selected_child_utxo_stats.find_value("bestblock").get_str(),
        child_block.GetHash().GetHex());
    BOOST_CHECK(selected_child_utxo_stats.find_value("muhash").isNull());
    BOOST_CHECK_EXCEPTION(
        CallRPC("gettxoutsetinfo none 0 true " + chain_id),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                       "only for the current tip") != std::string_view::npos;
        });
    BOOST_CHECK(CallRPC("verifychain 0 1 " + chain_id).get_bool());
    const auto selected_child_stats{CallRPC(
        "getblockstats 1 [\"height\",\"subsidy\"] " + chain_id)};
    BOOST_CHECK_EQUAL(selected_child_stats.find_value("chain_id").get_str(),
                      chain_id);
    BOOST_CHECK_EQUAL(
        selected_child_stats.find_value("height").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(
        selected_child_stats.find_value("subsidy").getInt<int64_t>(), 0);
    BOOST_CHECK_EXCEPTION(
        CallRPC("getblockstats " + definition.genesis_hash.GetHex() +
                " [] " + chain_id),
        std::runtime_error,
        [](const std::runtime_error& error) {
            return std::string_view{error.what()}.find(
                       "virtual child genesis") != std::string_view::npos;
        });
    const auto child_coin{CallRPC(
        "gettxout " + coinbase_txid + " 0 true " + chain_id)};
    BOOST_CHECK_EQUAL(child_coin.find_value("chain_id").get_str(), chain_id);
    BOOST_CHECK_EQUAL(child_coin.find_value("bestblock").get_str(),
                      child_block.GetHash().GetHex());
    BOOST_CHECK_EQUAL(child_coin.find_value("confirmations").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(child_coin.find_value("value").getValStr(), "0.00000000");
    BOOST_CHECK(child_coin.find_value("coinbase").get_bool());
    BOOST_CHECK_EQUAL(
        child_coin.find_value("scriptPubKey").find_value("hex").get_str(),
        HexStr(CScript{} << OP_1 << std::vector<unsigned char>(32, 1)));
    BOOST_CHECK(CallRPC(
        "gettxout " + coinbase_txid + " 2 true " + chain_id).isNull());
}

BOOST_AUTO_TEST_CASE(rpc_namedparams)
{
    const std::vector<std::pair<std::string, bool>> arg_names{{"arg1", false}, {"arg2", false}, {"arg3", false}, {"arg4", false}, {"arg5", false}};

    // Make sure named arguments are transformed into positional arguments in correct places separated by nulls
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg2": 2, "arg4": 4})"), arg_names).write(), "[null,2,null,4,null]");

    // Make sure named argument specified multiple times raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg2": 2, "arg2": 4})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter arg2 specified multiple times"})"));

    // Make sure named and positional arguments can be combined.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg5": 5, "args": [1, 2], "arg4": 4})"), arg_names).write(), "[1,2,null,4,5]");

    // Make sure a unknown named argument raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg2": 2, "unknown": 6})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Unknown named parameter unknown"})"));

    // Make sure an overlap between a named argument and positional argument raises an exception
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"args": [1,2,3], "arg4": 4, "arg2": 2})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter arg2 specified twice both as positional and named argument"})"));

    // Make sure extra positional arguments can be passed through to the method implementation, as long as they don't overlap with named arguments.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"args": [1,2,3,4,5,6,7,8,9,10]})"), arg_names).write(), "[1,2,3,4,5,6,7,8,9,10]");
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"([1,2,3,4,5,6,7,8,9,10])"), arg_names).write(), "[1,2,3,4,5,6,7,8,9,10]");
}

BOOST_AUTO_TEST_CASE(rpc_namedonlyparams)
{
    const std::vector<std::pair<std::string, bool>> arg_names{{"arg1", false}, {"arg2", false}, {"opt1", true}, {"opt2", true}, {"options", false}};

    // Make sure optional parameters are really optional.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2})"), arg_names).write(), "[1,2,null]");

    // Make sure named-only parameters are passed as options.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "opt1": 10, "opt2": 20})"), arg_names).write(), R"([1,2,{"opt1":10,"opt2":20}])");

    // Make sure options can be passed directly.
    BOOST_CHECK_EQUAL(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "options":{"opt1": 10, "opt2": 20}})"), arg_names).write(), R"([1,2,{"opt1":10,"opt2":20}])");

    // Make sure options and named parameters conflict.
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"arg1": 1, "arg2": 2, "opt1": 10, "options":{"opt1": 10}})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter options conflicts with parameter opt1"})"));

    // Make sure options object specified through args array conflicts.
    BOOST_CHECK_EXCEPTION(TransformParams(JSON(R"({"args": [1, 2, {"opt1": 10}], "opt2": 20})"), arg_names), UniValue,
                          HasJSON(R"({"code":-8,"message":"Parameter options specified twice both as positional and named argument"})"));
}

BOOST_AUTO_TEST_CASE(rpc_rawparams)
{
    // Test raw transaction API argument handling
    UniValue r;

    BOOST_CHECK_THROW(CallRPC("getrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction not_hex"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed not_int"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("createrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction null null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction not_array"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction {} {}"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [] [{\"data\":\"00\"}]"));
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] [{\"data\":\"00\"}] extra"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("decoderawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction DEADBEEF"), std::runtime_error);
    std::string rawtx = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac0000000000";
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx));
    BOOST_CHECK_EQUAL(r.get_obj().find_value("size").getInt<int>(), 194);
    BOOST_CHECK_EQUAL(r.get_obj().find_value("version").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(r.get_obj().find_value("locktime").getInt<int>(), 0);
    BOOST_CHECK_THROW(CallRPC(std::string("decoderawtransaction ")+rawtx+" extra"), std::runtime_error);
    BOOST_CHECK_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx+" false"), std::runtime_error);
    BOOST_CHECK_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx+" false extra"), std::runtime_error);

    // Only check failure cases for sendrawtransaction, there's no network to send to...
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction DEADBEEF"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC(std::string("sendrawtransaction ")+rawtx+" extra"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_togglenetwork)
{
    UniValue r;

    r = CallRPC("getnetworkinfo");
    bool netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, true);

    BOOST_CHECK_NO_THROW(CallRPC("setnetworkactive false"));
    r = CallRPC("getnetworkinfo");
    int numConnection = r.get_obj().find_value("connections").getInt<int>();
    BOOST_CHECK_EQUAL(numConnection, 0);

    netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, false);

    BOOST_CHECK_NO_THROW(CallRPC("setnetworkactive true"));
    r = CallRPC("getnetworkinfo");
    netState = r.get_obj().find_value("networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, true);
}

BOOST_AUTO_TEST_CASE(rpc_rawsign)
{
    UniValue r;
    // The input and output use the x-only public key directly as a P2TR
    // output key, allowing the supplied private key to sign the key path.
    std::string prevout =
      "[{\"txid\":\"b4cc287e58f87cdae59417329f710f3ecd75a4ee1d2872b7248f50977c8493f3\","
      "\"vout\":1,\"scriptPubKey\":\"5120debedc17b3df2badbcdd86d5feb4562b86fe182e5998abd8bcd4f122c6155b1b\","
      "\"amount\":11}]";
    r = CallRPC(std::string("createrawtransaction ")+prevout+" "+
      "[{\"kne1pm6ldc9anmu46m0xasm2ladzk9wr0uxpwtxv2hk9u6ncj93s4tvds5qs6re\":10}]");
    std::string notsigned = r.get_str();
    std::string privkey1 = "\"Th2KhzYvqWjD3zLhGwqvMUKS5u9oZg6JaKCdnZF1cbGs9NZwXGWY\"";
    r = CallRPC(std::string("signrawtransactionwithkey ")+notsigned+" [] "+prevout);
    BOOST_CHECK(r.get_obj().find_value("complete").get_bool() == false);
    r = CallRPC(std::string("signrawtransactionwithkey ")+notsigned+" ["+privkey1+"] "+prevout);
    BOOST_CHECK(r.get_obj().find_value("complete").get_bool() == true);
}

BOOST_AUTO_TEST_CASE(rpc_createraw_op_return)
{
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] [{\"data\":\"68656c6c6f776f726c64\"}]"));

    // Key not "data" (bad address)
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] [{\"somedata\":\"68656c6c6f776f726c64\"}]"), std::runtime_error);

    // Bad hex encoding of data output
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] [{\"data\":\"12345\"}]"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] [{\"data\":\"12345g\"}]"), std::runtime_error);

    // Data 81 bytes long
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] [{\"data\":\"010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081\"}]"));
}

BOOST_AUTO_TEST_CASE(rpc_format_monetary_values)
{
    BOOST_CHECK(ValueFromAmount(0LL).write() == "0.00000000");
    BOOST_CHECK(ValueFromAmount(1LL).write() == "0.00000001");
    BOOST_CHECK(ValueFromAmount(17622195LL).write() == "0.17622195");
    BOOST_CHECK(ValueFromAmount(50000000LL).write() == "0.50000000");
    BOOST_CHECK(ValueFromAmount(89898989LL).write() == "0.89898989");
    BOOST_CHECK(ValueFromAmount(100000000LL).write() == "1.00000000");
    BOOST_CHECK(ValueFromAmount(2099999999999990LL).write() == "20999999.99999990");
    BOOST_CHECK(ValueFromAmount(2099999999999999LL).write() == "20999999.99999999");

    BOOST_CHECK_EQUAL(ValueFromAmount(0).write(), "0.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount((COIN/10000)*123456789).write(), "12345.67890000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN).write(), "-1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN/10).write(), "-0.10000000");

    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000000).write(), "100000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000000).write(), "10000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000000).write(), "1000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000).write(), "100000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000).write(), "10000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000).write(), "1000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100).write(), "100.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10).write(), "10.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN).write(), "1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10).write(), "0.10000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100).write(), "0.01000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000).write(), "0.00100000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000).write(), "0.00010000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000).write(), "0.00001000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000000).write(), "0.00000100");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000000).write(), "0.00000010");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000000).write(), "0.00000001");

    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max()).write(), "92233720368.54775807");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 1).write(), "92233720368.54775806");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 2).write(), "92233720368.54775805");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::max() - 3).write(), "92233720368.54775804");
    // ...
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 3).write(), "-92233720368.54775805");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 2).write(), "-92233720368.54775806");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min() + 1).write(), "-92233720368.54775807");
    BOOST_CHECK_EQUAL(ValueFromAmount(std::numeric_limits<CAmount>::min()).write(), "-92233720368.54775808");
}

static UniValue ValueFromString(const std::string& str) noexcept
{
    UniValue value;
    value.setNumStr(str);
    return value;
}

BOOST_AUTO_TEST_CASE(rpc_parse_monetary_values)
{
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("-0.00000001")), UniValue);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000000")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001")), 1LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.17622195")), 17622195LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.5")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.50000000")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.89898989")), 89898989LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1.00000000")), 100000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.9999999")), 2099999999999990LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.99999999")), 2099999999999999LL);

    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1e-8")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.1e-7")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.01e-6")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000000000000000000000000000000000001e+30")), 1);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.0000000000000000000000000000000000000000000000000000000000000000000000000001e+68")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("10000000000000000000000000000000000000000000000000000000000000000e-64")), COIN);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000e64")), COIN);

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e-9")), UniValue); //should fail
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("0.000000019")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001000000")), 1LL); //should pass, cut trailing 0
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("19e-9")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.19e-6")), 19); //should pass, leading 0 is present
    BOOST_CHECK_EXCEPTION(AmountFromValue(".19e-6"), UniValue, HasJSON(R"({"code":-3,"message":"Invalid amount"})")); //should fail, no leading 0

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("92233720368.54775808")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e+11")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e11")), UniValue); //overflow error signless
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("93e+9")), UniValue); //overflow error
}

BOOST_AUTO_TEST_CASE(rpc_ban)
{
    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.0:8334")), std::runtime_error); //portnumber for setban not allowed
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    UniValue ar = r.get_array();
    UniValue o1 = ar[0].get_obj();
    UniValue adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/32");
    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 9907731200 true")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    int64_t banned_until{o1.find_value("banned_until").getInt<int64_t>()};
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until, 9907731200); // absolute time check

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    auto now = 10'000s;
    SetMockTime(now);
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 200")));
    SetMockTime(now += 2s);
    const int64_t time_remaining_expected{198};
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    banned_until = o1.find_value("banned_until").getInt<int64_t>();
    const int64_t ban_created{o1.find_value("ban_created").getInt<int64_t>()};
    const int64_t ban_duration{o1.find_value("ban_duration").getInt<int64_t>()};
    const int64_t time_remaining{o1.find_value("time_remaining").getInt<int64_t>()};
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until, time_remaining_expected + now.count());
    BOOST_CHECK_EQUAL(ban_duration, banned_until - ban_created);
    BOOST_CHECK_EQUAL(time_remaining, time_remaining_expected);

    // must throw an exception because 127.0.0.1 is in already banned subnet range
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0/24 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/255.255.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.1.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0U);


    BOOST_CHECK_THROW(r = CallRPC(std::string("setban test add")), std::runtime_error); //invalid IP

    //IPv6 tests
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban FE80:0000:0000:0000:0202:B3FF:FE1E:8329 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "fe80::202:b3ff:fe1e:8329/128");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:db8::/ffff:fffc:0:0:0:0:0:0 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:db8::/30");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = o1.find_value("address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128");
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_generatetoaddress)
{
    UniValue result;

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"1", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a", "9"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");
    BOOST_CHECK_EQUAL(result[2].getInt<int>(), 9);

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"1", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU", "9"}));
    BOOST_CHECK_EQUAL(result[0].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");
    BOOST_CHECK_EQUAL(result[2].getInt<int>(), 9);
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_loadchildchain)
{
    const std::string chain_id(64, '1');
    const UniValue result{RPCConvertValues(
        "loadchildchain",
        {chain_id,
         R"({"connect":["127.0.0.1:19843"],"bind":["127.0.0.1:19844"],"network_active":false})"})};
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK_EQUAL(result[0].get_str(), chain_id);
    BOOST_REQUIRE(result[1].isObject());
    BOOST_CHECK(!result[1].find_value("network_active").get_bool());
    BOOST_REQUIRE_EQUAL(result[1].find_value("connect").size(), 1U);
    BOOST_CHECK_EQUAL(
        result[1].find_value("connect")[0].get_str(),
        "127.0.0.1:19843");
    BOOST_REQUIRE_EQUAL(result[1].find_value("bind").size(), 1U);
    BOOST_CHECK_EQUAL(
        result[1].find_value("bind")[0].get_str(),
        "127.0.0.1:19844");

    const UniValue active{RPCConvertValues(
        "setchildnetworkactive", {chain_id, "false"})};
    BOOST_REQUIRE_EQUAL(active.size(), 2U);
    BOOST_CHECK_EQUAL(active[0].get_str(), chain_id);
    BOOST_CHECK(!active[1].get_bool());

    const UniValue binds{RPCConvertValues(
        "setchildnetworkbinds",
        {chain_id, R"(["127.0.0.1:19844","[::1]:19844"])"})};
    BOOST_REQUIRE_EQUAL(binds.size(), 2U);
    BOOST_CHECK_EQUAL(binds[0].get_str(), chain_id);
    BOOST_REQUIRE_EQUAL(binds[1].size(), 2U);
    BOOST_CHECK_EQUAL(binds[1][0].get_str(), "127.0.0.1:19844");
    BOOST_CHECK_EQUAL(binds[1][1].get_str(), "[::1]:19844");
}

BOOST_AUTO_TEST_CASE(rpc_getblockstats_calculate_percentiles_by_weight)
{
    int64_t total_weight = 200;
    std::vector<std::pair<CAmount, int64_t>> feerates;
    feerates.reserve(200);
    CAmount result[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };

    for (int64_t i = 0; i < 100; i++) {
        feerates.emplace_back(1 ,1);
    }

    for (int64_t i = 0; i < 100; i++) {
        feerates.emplace_back(2 ,1);
    }

    CalculatePercentilesByWeight(result, feerates, total_weight);
    BOOST_CHECK_EQUAL(result[0], 1);
    BOOST_CHECK_EQUAL(result[1], 1);
    BOOST_CHECK_EQUAL(result[2], 1);
    BOOST_CHECK_EQUAL(result[3], 2);
    BOOST_CHECK_EQUAL(result[4], 2);

    // Test with more pairs, and two pairs overlapping 2 percentiles.
    total_weight = 100;
    CAmount result2[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 9);
    feerates.emplace_back(2 , 16); //10th + 25th percentile
    feerates.emplace_back(4 ,50); //50th + 75th percentile
    feerates.emplace_back(5 ,10);
    feerates.emplace_back(9 ,15);  // 90th percentile

    CalculatePercentilesByWeight(result2, feerates, total_weight);

    BOOST_CHECK_EQUAL(result2[0], 2);
    BOOST_CHECK_EQUAL(result2[1], 2);
    BOOST_CHECK_EQUAL(result2[2], 4);
    BOOST_CHECK_EQUAL(result2[3], 4);
    BOOST_CHECK_EQUAL(result2[4], 9);

    // Same test as above, but one of the percentile-overlapping pairs is split in 2.
    total_weight = 100;
    CAmount result3[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 9);
    feerates.emplace_back(2 , 11); // 10th percentile
    feerates.emplace_back(2 , 5); // 25th percentile
    feerates.emplace_back(4 ,50); //50th + 75th percentile
    feerates.emplace_back(5 ,10);
    feerates.emplace_back(9 ,15); // 90th percentile

    CalculatePercentilesByWeight(result3, feerates, total_weight);

    BOOST_CHECK_EQUAL(result3[0], 2);
    BOOST_CHECK_EQUAL(result3[1], 2);
    BOOST_CHECK_EQUAL(result3[2], 4);
    BOOST_CHECK_EQUAL(result3[3], 4);
    BOOST_CHECK_EQUAL(result3[4], 9);

    // Test with one transaction spanning all percentiles.
    total_weight = 104;
    CAmount result4[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(1, 100);
    feerates.emplace_back(2, 1);
    feerates.emplace_back(3, 1);
    feerates.emplace_back(3, 1);
    feerates.emplace_back(999999, 1);

    CalculatePercentilesByWeight(result4, feerates, total_weight);

    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        BOOST_CHECK_EQUAL(result4[i], 1);
    }
}

// Make sure errors are triggered appropriately if parameters have the same names.
BOOST_AUTO_TEST_CASE(check_dup_param_names)
{
    enum ParamType { POSITIONAL, NAMED, NAMED_ONLY };
    auto make_rpc = [](std::vector<std::tuple<std::string, ParamType>> param_names) {
        std::vector<RPCArg> params;
        std::vector<RPCArg> options;
        auto push_options = [&] { if (!options.empty()) params.emplace_back(strprintf("options%i", params.size()), RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", std::move(options)); };
        for (auto& [param_name, param_type] : param_names) {
            if (param_type == POSITIONAL) {
                push_options();
                params.emplace_back(std::move(param_name), RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "description");
            } else {
                options.emplace_back(std::move(param_name), RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "description", RPCArgOptions{.also_positional = param_type == NAMED});
            }
        }
        push_options();
        return RPCHelpMan{"method_name", "description", params, RPCResults{}, RPCExamples{""}};
    };

    // No errors if parameter names are unique.
    make_rpc({{"p1", POSITIONAL}, {"p2", POSITIONAL}});
    make_rpc({{"p1", POSITIONAL}, {"p2", NAMED}});
    make_rpc({{"p1", POSITIONAL}, {"p2", NAMED_ONLY}});
    make_rpc({{"p1", NAMED}, {"p2", POSITIONAL}});
    make_rpc({{"p1", NAMED}, {"p2", NAMED}});
    make_rpc({{"p1", NAMED}, {"p2", NAMED_ONLY}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", POSITIONAL}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", NAMED}});
    make_rpc({{"p1", NAMED_ONLY}, {"p2", NAMED_ONLY}});

    {
        test_only_CheckFailuresAreExceptionsNotAborts mock_checks{};
        // Error if parameter names are duplicates, unless one parameter is
        // positional and the other is named and .also_positional is true.
        BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p1", POSITIONAL}}), NonFatalCheckError);
        make_rpc({{"p1", POSITIONAL}, {"p1", NAMED}});
        BOOST_CHECK_THROW(make_rpc({{"p1", POSITIONAL}, {"p1", NAMED_ONLY}}), NonFatalCheckError);
        make_rpc({{"p1", NAMED}, {"p1", POSITIONAL}});
        BOOST_CHECK_THROW(make_rpc({{"p1", NAMED}, {"p1", NAMED}}), NonFatalCheckError);
        BOOST_CHECK_THROW(make_rpc({{"p1", NAMED}, {"p1", NAMED_ONLY}}), NonFatalCheckError);
        BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", POSITIONAL}}), NonFatalCheckError);
        BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", NAMED}}), NonFatalCheckError);
        BOOST_CHECK_THROW(make_rpc({{"p1", NAMED_ONLY}, {"p1", NAMED_ONLY}}), NonFatalCheckError);
    }
}

BOOST_AUTO_TEST_CASE(help_example)
{
    // test different argument types
    const RPCArgList& args = {{"foo", "bar"}, {"b", true}, {"n", 1}};
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", args), "> kronein-cli -named test foo=bar b=true n=1\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", args), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"foo\":\"bar\",\"b\":true,\"n\":1}}' -H 'content-type: application/json' http://127.0.0.1:26761/\n");

    // test shell escape
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b'ar"}}), "> kronein-cli -named test foo='b'''ar'\n");
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b\"ar"}}), "> kronein-cli -named test foo='b\"ar'\n");
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"foo", "b ar"}}), "> kronein-cli -named test foo='b ar'\n");

    // test object params
    UniValue obj_value(UniValue::VOBJ);
    obj_value.pushKV("foo", "bar");
    obj_value.pushKV("b", false);
    obj_value.pushKV("n", 1);
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"name", obj_value}}), "> kronein-cli -named test name='{\"foo\":\"bar\",\"b\":false,\"n\":1}'\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", {{"name", obj_value}}), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"name\":{\"foo\":\"bar\",\"b\":false,\"n\":1}}}' -H 'content-type: application/json' http://127.0.0.1:26761/\n");

    // test array params
    UniValue arr_value(UniValue::VARR);
    arr_value.push_back("bar");
    arr_value.push_back(false);
    arr_value.push_back(1);
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("test", {{"name", arr_value}}), "> kronein-cli -named test name='[\"bar\",false,1]'\n");
    BOOST_CHECK_EQUAL(HelpExampleRpcNamed("test", {{"name", arr_value}}), "> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"test\", \"params\": {\"name\":[\"bar\",false,1]}}' -H 'content-type: application/json' http://127.0.0.1:26761/\n");

    // test types don't matter for shell
    BOOST_CHECK_EQUAL(HelpExampleCliNamed("foo", {{"arg", true}}), HelpExampleCliNamed("foo", {{"arg", "true"}}));

    // test types matter for Rpc
    BOOST_CHECK_NE(HelpExampleRpcNamed("foo", {{"arg", true}}), HelpExampleRpcNamed("foo", {{"arg", "true"}}));
}

static void CheckRpc(const std::vector<RPCArg>& params, const UniValue& args, RPCHelpMan::RPCMethodImpl test_impl)
{
    auto null_result{RPCResult{RPCResult::Type::NONE, "", "None"}};
    const RPCHelpMan rpc{"dummy", "dummy description", params, null_result, RPCExamples{""}, test_impl};
    JSONRPCRequest req;
    req.params = args;

    rpc.HandleRequest(req);
}

BOOST_AUTO_TEST_CASE(rpc_arg_helper)
{
    constexpr bool DEFAULT_BOOL = true;
    constexpr auto DEFAULT_STRING = "default";
    constexpr uint64_t DEFAULT_UINT64_T = 3;

    //! Parameters with which the RPCHelpMan is instantiated
    const std::vector<RPCArg> params{
        // Required arg
        {"req_int", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
        {"req_str", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
        // Default arg
        {"def_uint64_t", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_UINT64_T}, ""},
        {"def_string", RPCArg::Type::STR, RPCArg::Default{DEFAULT_STRING}, ""},
        {"def_bool", RPCArg::Type::BOOL, RPCArg::Default{DEFAULT_BOOL}, ""},
        // Optional arg without default
        {"opt_double", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, ""},
        {"opt_string", RPCArg::Type::STR, RPCArg::Optional::OMITTED, ""}
    };

    //! Check that `self.Arg` returns the same value as the `request.params` accessors
    RPCHelpMan::RPCMethodImpl check_positional = [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            BOOST_CHECK_EQUAL(self.Arg<int>("req_int"), request.params[0].getInt<int>());
            BOOST_CHECK_EQUAL(self.Arg<std::string_view>("req_str"), request.params[1].get_str());
            BOOST_CHECK_EQUAL(self.Arg<uint64_t>("def_uint64_t"), request.params[2].isNull() ? DEFAULT_UINT64_T : request.params[2].getInt<uint64_t>());
            BOOST_CHECK_EQUAL(self.Arg<std::string_view>("def_string"), request.params[3].isNull() ? DEFAULT_STRING : request.params[3].get_str());
            BOOST_CHECK_EQUAL(self.Arg<bool>("def_bool"), request.params[4].isNull() ? DEFAULT_BOOL : request.params[4].get_bool());
            if (!request.params[5].isNull()) {
                BOOST_CHECK_EQUAL(self.MaybeArg<double>("opt_double").value(), request.params[5].get_real());
            } else {
                BOOST_CHECK(!self.MaybeArg<double>("opt_double"));
            }
            if (!request.params[6].isNull()) {
                BOOST_CHECK_EQUAL(self.MaybeArg<std::string_view>("opt_string"), request.params[6].get_str());
            } else {
                BOOST_CHECK(!self.MaybeArg<std::string_view>("opt_string"));
            }
            return UniValue{};
        };
    CheckRpc(params, UniValue{JSON(R"([5, "hello", null, null, null, null, null])")}, check_positional);
    CheckRpc(params, UniValue{JSON(R"([5, "hello", 4, "test", true, 1.23, "world"])")}, check_positional);
}

BOOST_AUTO_TEST_SUITE_END()
