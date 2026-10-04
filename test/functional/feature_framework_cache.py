#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Check the premined functional cache, independent copies and subsequent mining."""

import json

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import create_coinbase
from test_framework.chaincache import CACHE_BLOCK_COUNT, CACHE_FIXTURE, cache_addresses
from test_framework.messages import CBlock, from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class CacheTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.uses_wallet = self.is_wallet_compiled()

    def run_test(self):
        with CACHE_FIXTURE.open(encoding="utf-8") as fixture_file:
            fixture = json.load(fixture_file)
        scripts = [address_to_scriptpubkey(address) for address in cache_addresses()]
        reward_counts = [0] * 4
        node = self.nodes[0]
        self.log.info("Check all cached blocks and the original coinbase distribution")
        for height, raw_block in enumerate(fixture["blocks"], start=1):
            block = from_hex(CBlock(), raw_block)
            assert_equal(node.getblock(node.getblockhash(height), 0), raw_block)
            assert_equal(len(block.vtx), 1)
            coinbase = block.vtx[0]
            recipient = ((height - 1) // 25) % 4
            assert_equal(coinbase.vout[0].scriptPubKey, scripts[recipient])
            assert_equal(coinbase.vout[0].nValue, create_coinbase(height).vout[0].nValue)
            reward_counts[recipient] += 1
        assert_equal(reward_counts, [50, 50, 50, 49])

        for index, cached_node in enumerate(self.nodes):
            assert_equal(cached_node.getblockhash(CACHE_BLOCK_COUNT), fixture["tip"])
            assert_equal(cached_node.getblockcount(), 200)
            assert_equal(cached_node.getblockchaininfo()["initialblockdownload"], False)
            registry = cached_node.getchainregistryinfo()
            assert_equal(registry["root"], fixture["registry_root"])
            assert_equal(registry["height"], 200)
            assert_equal(registry["bestblockhash"], cached_node.getbestblockhash())
            if self.uses_wallet:
                balances = cached_node.getbalances()["mine"]
                assert_equal(balances["trusted"], 1250)
                # Regtest halves its subsidy at height 150, including block 200.
                assert_equal(balances["immature"], 1275 if index == 0 else 1225)

        self.log.info("Check persistence, independent cache copies and real mining after setup")
        self.disconnect_nodes(1, 0)
        self.restart_node(1)
        assert_equal(self.nodes[1].getblockcount(), 200)
        assert_equal(self.nodes[1].getchainregistryinfo()["root"], fixture["registry_root"])
        self.generate(self.nodes[1], 1, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 200)
        assert_equal(self.nodes[1].getblockcount(), 201)
        self.connect_nodes(1, 0)
        self.sync_blocks()


if __name__ == '__main__':
    CacheTest(__file__).main()
