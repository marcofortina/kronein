// Copyright (c) 2020-present The Bitcoin Core developers
// Copyright (c) 2026 The Kronein Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <hash.h>
#include <kernel/coinstats.h>
#include <node/miner.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <util/chaintype.h>
#include <util/time.h>
#include <validation.h>

using node::BlockAssembler;

FUZZ_TARGET(utxo_total_supply)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    SetMockTime(ConsumeTime(fuzzed_data_provider, /*min=*/1789776000)); // Kronein regtest genesis timestamp
    /** The testing setup that creates a chainman only (no chainstate) */
    ChainTestingSetup test_setup{ChainType::REGTEST};
    // Create chainstate
    test_setup.LoadVerifyActivateChainstate();
    auto& node{test_setup.m_node};
    auto& chainman{*Assert(test_setup.m_node.chainman)};

    const auto ActiveHeight = [&]() {
        LOCK(chainman.GetMutex());
        return chainman.ActiveHeight();
    };
    BlockAssembler::Options options;
    options.coinbase_output_script = P2TR_OP_TRUE;
    options.include_dummy_extranonce = true;
    const auto PrepareNextBlock = [&]() {
        return PrepareBlock(node, options);
    };

    /** The block template this fuzzer is working on */
    auto current_block = PrepareNextBlock();
    /** Append-only set of tx outpoints, entries are not removed when spent */
    std::vector<std::pair<COutPoint, CTxOut>> txos;
    /** The utxo stats at the chain tip */
    kernel::CCoinsStats utxo_stats;
    /** Commitment to every outpoint and coin in database iteration order. */
    uint256 utxo_hash;
    /** The total amount of coins in the utxo set */
    CAmount circulation{0};


    // Keep every spendable output, including the coinbase payout before the
    // registry and witness commitments. Retain spent and rejected outpoints
    // too, so the fuzzer can try double spends and nonexistent inputs.
    const auto StoreTxos = [&](const CTransaction& tx) {
        for (uint32_t i = 0; i < tx.vout.size(); ++i) {
            if (!tx.vout[i].scriptPubKey.IsUnspendable()) {
                txos.emplace_back(COutPoint{tx.GetHash(), i}, tx.vout[i]);
            }
        }
    };
    const auto AppendRandomTxo = [&](CMutableTransaction& tx) {
        const auto& txo = txos.at(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, txos.size() - 1));
        tx.vin.emplace_back(txo.first);
        tx.vin.back().scriptWitness.stack = P2TR_OP_TRUE_WITNESS_STACK;
        tx.vout.emplace_back(txo.second.nValue, txo.second.scriptPubKey); // "Forward" coin with no fee
    };
    const auto UpdateUtxoStats = [&](bool wipe_cache) {
        LOCK(chainman.GetMutex());
        chainman.ActiveChainstate().ForceFlushStateToDisk(wipe_cache);
        utxo_stats = std::move(
            *Assert(kernel::ComputeUTXOStats(kernel::CoinStatsHashType::NONE, &chainman.ActiveChainstate().CoinsDB(), chainman.m_blockman, {})));
        // Keep a full-state commitment: equal totals alone cannot detect a
        // changed outpoint, script, height, or coinbase flag. Database cursors
        // have deterministic key order, so this needs no unordered MuHash.
        HashWriter hash;
        auto cursor{chainman.ActiveChainstate().CoinsDB().Cursor()};
        assert(cursor);
        while (cursor->Valid()) {
            COutPoint outpoint;
            Coin coin;
            assert(cursor->GetKey(outpoint));
            assert(cursor->GetValue(coin));
            hash << outpoint << coin;
            cursor->Next();
        }
        utxo_hash = hash.GetHash();
        // Check that miner can't print more money than they are allowed to
        assert(circulation == utxo_stats.total_amount);
    };


    // Update internal state to chain tip
    UpdateUtxoStats(/*wipe_cache=*/fuzzed_data_provider.ConsumeBool());
    assert(ActiveHeight() == 0);
    // Get at which height we duplicate the coinbase
    // Assuming that the fuzzer will mine relatively short chains (less than 200 blocks), we want the duplicate coinbase to be not too high.
    // Up to 300 seems reasonable.
    const int duplicate_coinbase_height = fuzzed_data_provider.ConsumeIntegralInRange(2, 300);
    bool duplicate_coinbase_tested{false};
    // Kronein enforces the coinbase height from block one. Start with a valid
    // coinbase, then attempt to reuse it at a different height (which must fail).
    const CTransactionRef first_coinbase{current_block->vtx.front()};
    assert(!MineBlock(node, current_block).IsNull());
    StoreTxos(*current_block->vtx.front());
    circulation += GetBlockSubsidy(ActiveHeight(), Params().GetConsensus());

    assert(ActiveHeight() == 1);
    UpdateUtxoStats(/*wipe_cache=*/fuzzed_data_provider.ConsumeBool());
    current_block = PrepareNextBlock();
    StoreTxos(*current_block->vtx.back());

    // Limit to avoid timeout, but enough to cover duplicate_coinbase_height
    // and CVE-2018-17144.
    LIMITED_WHILE(fuzzed_data_provider.remaining_bytes(), 2'00)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                // Append an input-output pair to the last tx in the current block
                CMutableTransaction tx{*current_block->vtx.back()};
                AppendRandomTxo(tx);
                current_block->vtx.back() = MakeTransactionRef(tx);
                StoreTxos(*current_block->vtx.back());
            },
            [&] {
                // Append a tx to the list of txs in the current block
                CMutableTransaction tx{};
                AppendRandomTxo(tx);
                current_block->vtx.push_back(MakeTransactionRef(tx));
                StoreTxos(*current_block->vtx.back());
            },
            [&] {
                // No registry operations are generated here, so retain its
                // commitment from the template. Refresh only the witness
                // commitment: RegenerateCommitments rejects malformed
                // coinbases that this fuzzer must send through validation.
                CMutableTransaction coinbase{*current_block->vtx.front()};
                if (const int index{GetWitnessCommitmentIndex(*current_block)}; index != NO_WITNESS_COMMITMENT) {
                    coinbase.vout.erase(coinbase.vout.begin() + index);
                }
                current_block->vtx.front() = MakeTransactionRef(std::move(coinbase));
                {
                    LOCK(chainman.GetMutex());
                    chainman.GenerateCoinbaseCommitment(*current_block, chainman.ActiveChain().Tip());
                }
                const bool duplicate_coinbase{!duplicate_coinbase_tested && ActiveHeight() + 1 == duplicate_coinbase_height};
                if (duplicate_coinbase) {
                    // Replace after regenerating commitments to preserve the
                    // exact old transaction, not just its height prefix.
                    current_block->vtx.front() = first_coinbase;
                    duplicate_coinbase_tested = true;
                }
                current_block->hashMerkleRoot = BlockMerkleRoot(*current_block);
                const bool was_valid = !MineBlock(node, current_block).IsNull();
                if (duplicate_coinbase) assert(!was_valid);

                const uint256 prev_utxo_hash{utxo_hash};
                if (was_valid) {
                    circulation += GetBlockSubsidy(ActiveHeight(), Params().GetConsensus());
                    StoreTxos(*current_block->vtx.front());
                }

                UpdateUtxoStats(/*wipe_cache=*/fuzzed_data_provider.ConsumeBool());

                if (!was_valid) {
                    // utxo stats must not change
                    assert(prev_utxo_hash == utxo_hash);
                }

                current_block = PrepareNextBlock();
                StoreTxos(*current_block->vtx.back());
            });
    }
}
