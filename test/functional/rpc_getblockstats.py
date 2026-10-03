#!/usr/bin/env python3
# Copyright (c) 2017-present The Bitcoin Core developers
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test getblockstats rpc call
#

from test_framework.blocktools import COINBASE_MATURITY, TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
import json
import os

TESTSDIR = os.path.dirname(os.path.realpath(__file__))

class GetblockstatsTest(BitcoinTestFramework):

    start_height = 101
    max_stat_pos = 2

    def add_options(self, parser):
        parser.add_argument('--gen-test-data', dest='gen_test_data',
                            default=False, action='store_true',
                            help='Generate test data')
        parser.add_argument('--test-data', dest='test_data',
                            default='data/rpc_getblockstats.json',
                            action='store', metavar='FILE',
                            help='Test data file')

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def get_stats(self):
        return [self.nodes[0].getblockstats(hash_or_height=self.start_height + i) for i in range(self.max_stat_pos+1)]

    def generate_test_data(self, filename):
        mocktime = TIME_GENESIS_BLOCK + 24 * 60 * 60
        self.nodes[0].setmocktime(mocktime)
        wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        self.generate(self.nodes[0], COINBASE_MATURITY + 1)

        address = self.nodes[0].get_deterministic_priv_key().address
        wallet.sendtoaddress(address=address, amount=10, subtractfeefromamount=True)
        self.generate(self.nodes[0], 1)

        wallet.sendtoaddress(address=address, amount=10, subtractfeefromamount=True)
        wallet.sendtoaddress(address=address, amount=10, subtractfeefromamount=False)
        self.fee_rate=300
        wallet.sendtoaddress(address=address, amount=1, subtractfeefromamount=True, fee_rate=self.fee_rate)
        # Send to OP_RETURN output to test its exclusion from statistics
        wallet.send(outputs=[{"data": "21"}], fee_rate=self.fee_rate)
        self.sync_all()
        self.generate(self.nodes[0], 1)

        self.expected_stats = self.get_stats()

        blocks = []
        tip = self.nodes[0].getbestblockhash()
        blockhash = None
        # Genesis is already present on a clean chain and is not part of this
        # native transaction-format fixture.
        height = 1
        while tip != blockhash:
            blockhash = self.nodes[0].getblockhash(height)
            blocks.append(self.nodes[0].getblock(blockhash, 0))
            height += 1

        to_dump = {
            'blocks': blocks,
            'mocktime': int(mocktime),
            'stats': self.expected_stats,
        }
        with open(filename, 'w') as f:
            json.dump(to_dump, f, sort_keys=True, indent=2)

    def load_test_data(self, filename):
        with open(filename, 'r') as f:
            d = json.load(f)
            blocks = d['blocks']
            mocktime = d['mocktime']
            self.expected_stats = d['stats']

        # Set the timestamps from the file so that the nodes can get out of Initial Block Download
        self.nodes[0].setmocktime(mocktime)
        self.sync_all()

        for b in blocks:
            assert_equal(self.nodes[0].submitblock(b), None)


    def run_test(self):
        test_data = os.path.join(TESTSDIR, self.options.test_data)
        if self.options.gen_test_data:
            self.generate_test_data(test_data)
        else:
            self.load_test_data(test_data)

        self.sync_all()
        stats = self.get_stats()

        # Make sure all valid statistics are included but nothing else is
        expected_keys = self.expected_stats[0].keys()
        assert_equal(set(stats[0].keys()), set(expected_keys))

        assert_equal(stats[0]['height'], self.start_height)
        assert_equal(stats[self.max_stat_pos]['height'], self.start_height + self.max_stat_pos)

        for i in range(self.max_stat_pos+1):
            self.log.info('Checking block %d' % (i))
            assert_equal(stats[i], self.expected_stats[i])

            # Check selecting block by hash too
            blockhash = self.expected_stats[i]['blockhash']
            stats_by_hash = self.nodes[0].getblockstats(hash_or_height=blockhash)
            assert_equal(stats_by_hash, self.expected_stats[i])

        # Make sure each stat can be queried on its own
        for stat in expected_keys:
            for i in range(self.max_stat_pos+1):
                result = self.nodes[0].getblockstats(hash_or_height=self.start_height + i, stats=[stat])
                assert_equal(list(result.keys()), [stat])
                if result[stat] != self.expected_stats[i][stat]:
                    self.log.info('result[%s] (%d) failed, %r != %r' % (
                        stat, i, result[stat], self.expected_stats[i][stat]))
                assert_equal(result[stat], self.expected_stats[i][stat])

        # Make sure only the selected statistics are included (more than one)
        some_stats = {'minfee', 'maxfee'}
        stats = self.nodes[0].getblockstats(hash_or_height=1, stats=list(some_stats))
        assert_equal(set(stats.keys()), some_stats)

        # Test invalid parameters raise the proper json exceptions
        tip = self.start_height + self.max_stat_pos
        assert_raises_rpc_error(-8, 'Target block height %d after current tip %d' % (tip+1, tip),
                                self.nodes[0].getblockstats, hash_or_height=tip+1)
        assert_raises_rpc_error(-8, 'Target block height %d is negative' % (-1),
                                self.nodes[0].getblockstats, hash_or_height=-1)

        # Make sure not valid stats aren't allowed
        inv_sel_stat = 'asdfghjkl'
        inv_stats = [
            [inv_sel_stat],
            ['minfee', inv_sel_stat],
            [inv_sel_stat, 'minfee'],
            ['minfee', inv_sel_stat, 'maxfee'],
        ]
        for inv_stat in inv_stats:
            assert_raises_rpc_error(-8, f"Invalid selected statistic '{inv_sel_stat}'",
                                    self.nodes[0].getblockstats, hash_or_height=1, stats=inv_stat)

        # Make sure we aren't always returning inv_sel_stat as the culprit stat
        assert_raises_rpc_error(-8, f"Invalid selected statistic 'aaa{inv_sel_stat}'",
                                self.nodes[0].getblockstats, hash_or_height=1, stats=['minfee', f'aaa{inv_sel_stat}'])
        # Kronein mainnet's genesis block shouldn't be found on regtest
        assert_raises_rpc_error(-5, 'Block not found', self.nodes[0].getblockstats,
                                hash_or_height='bea1a7f1a3fc9781084a7629584cc89c459a9c8e9acd2dc0d7fe1316cc71bc09')

        # Invalid number of args
        assert_raises_rpc_error(-1, 'getblockstats hash_or_height ( stats "chain_id" )', self.nodes[0].getblockstats, '00', [], None, 2)
        assert_raises_rpc_error(-1, 'getblockstats hash_or_height ( stats "chain_id" )', self.nodes[0].getblockstats)

        self.log.info('Test block height 0')
        genesis_stats = self.nodes[0].getblockstats(0)
        assert_equal(genesis_stats["blockhash"], "a55bf2cd9513e5203827b029e15153769d596b0ad29e6ebca232eaba07c95f73")
        assert_equal(genesis_stats["utxo_increase"], 1)
        assert_equal(genesis_stats["utxo_size_inc"], 97)
        assert_equal(genesis_stats["utxo_increase_actual"], 0)
        assert_equal(genesis_stats["utxo_size_inc_actual"], 0)

        self.log.info('Test tip including OP_RETURN')
        tip_stats = self.nodes[0].getblockstats(tip)
        # Registry adds one unspendable output, but no actual UTXO.
        assert_equal(tip_stats["utxo_increase"], 7)
        assert_equal(tip_stats["utxo_size_inc"], 566)
        assert_equal(tip_stats["utxo_increase_actual"], 4)
        assert_equal(tip_stats["utxo_size_inc_actual"], 336)

        self.log.info("Test when only header is known")
        block = self.generateblock(self.nodes[0], output="rawtr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)", transactions=[], submit=False)
        self.nodes[0].submitheader(block["hex"])
        assert_raises_rpc_error(-1, "Block not available (not fully downloaded)", lambda: self.nodes[0].getblockstats(block['hash']))

        self.log.info('Test when block is missing')
        (self.nodes[0].blocks_path / 'blk00000.dat').rename(self.nodes[0].blocks_path / 'blk00000.dat.backup')
        assert_raises_rpc_error(-1, 'Block not found on disk', self.nodes[0].getblockstats, hash_or_height=1)
        (self.nodes[0].blocks_path / 'blk00000.dat.backup').rename(self.nodes[0].blocks_path / 'blk00000.dat')


if __name__ == '__main__':
    GetblockstatsTest(__file__).main()
