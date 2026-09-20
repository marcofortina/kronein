#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test logic for setting -maxtipage on command line.

Nodes don't consider themselves out of "initial block download" as long as
their best known block header time is more than -maxtipage in the past.
"""

import time

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


DEFAULT_MAX_TIP_AGE = 24 * 60 * 60


class MaxTipAgeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def test_maxtipage(self, maxtipage, set_parameter=True, test_deltas=True):
        node_miner = self.nodes[0]
        node_ibd = self.nodes[1]

        cur_time = max(int(time.time()), TIME_GENESIS_BLOCK + DEFAULT_MAX_TIP_AGE + 10)
        node_args = [f'-mocktime={cur_time}']
        if set_parameter:
            node_args.append(f'-maxtipage={maxtipage}')
        self.restart_node(1, node_args)
        self.connect_nodes(0, 1)

        if test_deltas:
            # tips older than maximum age -> stay in IBD
            node_ibd.setmocktime(cur_time)
            for delta in [5, 4, 3, 2, 1]:
                node_miner.setmocktime(cur_time - maxtipage - delta)
                self.generate(node_miner, 1)
                assert_equal(node_ibd.getblockchaininfo()['initialblockdownload'], True)

        # tip within maximum age -> leave IBD
        block_time = cur_time if not test_deltas else max(cur_time - maxtipage, 0)
        node_miner.setmocktime(block_time)
        self.generate(node_miner, 1)
        assert_equal(node_ibd.getblockchaininfo()['initialblockdownload'], False)

        # reset time to system time so we don't have a time offset with the ibd node the next
        # time we connect to it, ensuring TimeOffsets::WarnIfOutOfSync() doesn't output to stderr
        node_miner.setmocktime(0)

    def run_test(self):
        self.log.info("Test IBD with maximum tip age of 24 hours (default).")
        self.test_maxtipage(DEFAULT_MAX_TIP_AGE, set_parameter=False)

        for hours in [20, 10, 5, 2, 1]:
            maxtipage = hours * 60 * 60
            self.log.info(f"Test IBD with maximum tip age of {hours} hours (-maxtipage={maxtipage}).")
            self.test_maxtipage(maxtipage)

        max_long_val = 9223372036854775807
        self.log.info(f"Test IBD with highest allowable maximum tip age ({max_long_val}).")
        self.test_maxtipage(max_long_val, test_deltas=False)


if __name__ == '__main__':
    MaxTipAgeTest(__file__).main()
