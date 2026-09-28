// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <index/txindex.h>
#include <merkleblock.h>
#include <node/blockstorage.h>
#include <node/chain_manager.h>
#include <primitives/transaction.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

using node::GetTransaction;

static std::string BuildTxOutProof(
    const CBlock& block,
    const std::set<Txid>& txids)
{
    size_t transactions_found{0};
    for (const auto& transaction : block.vtx) {
        if (txids.contains(transaction->GetHash())) ++transactions_found;
    }
    if (transactions_found != txids.size()) {
        throw JSONRPCError(
            RPC_INVALID_ADDRESS_OR_KEY,
            "Not all transactions found in specified or retrieved block");
    }

    DataStream proof_stream;
    proof_stream << CMerkleBlock{block, txids};
    return HexStr(proof_stream);
}

static RPCHelpMan gettxoutproof()
{
    return RPCHelpMan{
        "gettxoutproof",
        "Returns a hex-encoded proof that \"txid\" was included in a block.\n"
        "\nNOTE: By default this function only works sometimes. This is when there is an\n"
        "unspent output in the utxo for this transaction. To make it always work,\n"
        "you need to maintain a transaction index, using the -txindex command line option or\n"
        "specify the block in which the transaction is included manually (by blockhash).\n"
        "For a child chain, blockhash is required because child txindex and mempool lookup\n"
        "are not available. The returned proof uses the standard merkleblock encoding.\n",
        {
            {"txids", RPCArg::Type::ARR, RPCArg::Optional::NO, "The txids to filter",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A transaction hash"},
                },
            },
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "If specified, looks for txid in the block with this hash"},
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
        },
        RPCResult{
            RPCResult::Type::STR, "data", "A string that is a serialized, hex-encoded data for the proof."
        },
        RPCExamples{
            HelpExampleCli("gettxoutproof", "'[\"txid\"]' blockhash")
            + HelpExampleCli("gettxoutproof", "'[\"txid\"]' blockhash chain_id")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::set<Txid> setTxids;
            UniValue txids = request.params[0].get_array();
            if (txids.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Parameter 'txids' cannot be empty");
            }
            for (unsigned int idx = 0; idx < txids.size(); idx++) {
                auto ret{setTxids.insert(Txid::FromUint256(ParseHashV(txids[idx], "txid")))};
                if (!ret.second) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated txid: ") + txids[idx].get_str());
                }
            }

            if (!request.params[2].isNull()) {
                if (request.params[1].isNull()) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "blockhash is required for child-chain transaction proofs because child txindex and mempool lookup are not available");
                }
                const uint256 block_hash{
                    ParseHashV(request.params[1], "blockhash")};
                const node::ChainManagerBlockView view{
                    GetLoadedChildBlockView(
                        request.context,
                        request.params[2].get_str(),
                        block_hash)};
                if (view.block.virtual_genesis || !view.block.block) {
                    throw JSONRPCError(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "The virtual child genesis does not contain ordinary transactions");
                }
                return BuildTxOutProof(*view.block.block, setTxids);
            }

            const CBlockIndex* pblockindex = nullptr;
            uint256 hashBlock;
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            if (!request.params[1].isNull()) {
                LOCK(cs_main);
                hashBlock = ParseHashV(request.params[1], "blockhash");
                pblockindex = chainman.m_blockman.LookupBlockIndex(hashBlock);
                if (!pblockindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
            } else {
                LOCK(cs_main);
                Chainstate& active_chainstate = chainman.ActiveChainstate();

                // Loop through txids and try to find which block they're in. Exit loop once a block is found.
                for (const auto& tx : setTxids) {
                    const Coin& coin{AccessByTxid(active_chainstate.CoinsTip(), tx)};
                    if (!coin.IsSpent()) {
                        pblockindex = active_chainstate.m_chain[coin.nHeight];
                        break;
                    }
                }
            }


            // Allow txindex to catch up if we need to query it and before we acquire cs_main.
            if (g_txindex && !pblockindex) {
                g_txindex->BlockUntilSyncedToCurrentChain();
            }

            if (pblockindex == nullptr) {
                const CTransactionRef tx = GetTransaction(/*block_index=*/nullptr, /*mempool=*/nullptr, *setTxids.begin(), chainman.m_blockman, hashBlock);
                if (!tx || hashBlock.IsNull()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
                }

                LOCK(cs_main);
                pblockindex = chainman.m_blockman.LookupBlockIndex(hashBlock);
                if (!pblockindex) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
                }
            }

            {
                LOCK(cs_main);
                CheckBlockDataAvailability(chainman.m_blockman, *pblockindex, /*check_for_undo=*/false);
            }
            CBlock block;
            if (!chainman.m_blockman.ReadBlock(block, *pblockindex)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
            }

            return BuildTxOutProof(block, setTxids);
        },
    };
}

static RPCHelpMan verifytxoutproof()
{
    return RPCHelpMan{
        "verifytxoutproof",
        "Verifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
        "and throwing an RPC error if the block is not in the selected chain's active branch.\n"
        "Omitting chain_id preserves the main-chain behavior.\n",
        {
            {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded proof generated by gettxoutproof"},
            {"chain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Full, non-null child-chain identifier; omit for the main chain"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The txid(s) which the proof commits to, or empty array if the proof cannot be validated."},
            }
        },
        RPCExamples{
            HelpExampleCli("verifytxoutproof", "proof")
            + HelpExampleCli("verifytxoutproof", "proof chain_id")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            CMerkleBlock merkleBlock;
            SpanReader{ParseHexV(request.params[0], "proof")} >> merkleBlock;

            UniValue res(UniValue::VARR);

            std::vector<Txid> vMatch;
            std::vector<unsigned int> vIndex;
            if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot)
                return res;

            if (!request.params[1].isNull()) {
                const node::ChainManagerBlockView view{
                    GetLoadedChildBlockView(
                        request.context,
                        request.params[1].get_str(),
                        merkleBlock.header.GetHash())};
                if (!view.block.active || view.block.virtual_genesis ||
                    !view.block.block) {
                    throw JSONRPCError(
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Block not found in active child chain");
                }

                if (view.block.block->vtx.size() ==
                    merkleBlock.txn.GetNumTransactions()) {
                    for (const auto& txid : vMatch) {
                        res.push_back(txid.GetHex());
                    }
                }
                return res;
            }

            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);

            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(merkleBlock.header.GetHash());
            if (!pindex || !chainman.ActiveChain().Contains(pindex) || pindex->nTx == 0) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");
            }

            // Check if proof is valid, only add results if so
            if (pindex->nTx == merkleBlock.txn.GetNumTransactions()) {
                for (const auto& txid : vMatch) {
                    res.push_back(txid.GetHex());
                }
            }

            return res;
        },
    };
}

void RegisterTxoutProofRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &gettxoutproof},
        {"blockchain", &verifytxoutproof},
    };
    for (const auto& c : commands) {
        t.appendCommand(&c);
    }
}
