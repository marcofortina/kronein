#!/usr/bin/env python3
# Copyright (c) 2016-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Create a blockchain cache.

Creating a cache of the blockchain speeds up test execution when running
multiple functional tests. This helper script is executed by test_runner when multiple
tests are being run in parallel.
"""

import json
from pathlib import Path

from test_framework.chaincache import CACHE_BLOCK_COUNT, cache_addresses
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class CreateCache(BitcoinTestFramework):
    # Test network and test nodes are not required:

    def set_test_params(self):
        self.num_nodes = 1 if self.options.generate_fixture else 0
        self.uses_wallet = True
        self.setup_clean_chain = bool(self.options.generate_fixture)

    def add_options(self, parser):
        parser.add_argument("--generate-fixture", type=Path, metavar="FILE",
                            help="Explicitly mine the 199 cache blocks and write a new JSON file; never used by CI")

    def setup_network(self):
        if self.options.generate_fixture:
            self.add_nodes(1)
            self.start_nodes()

    def run_test(self):
        if not self.options.generate_fixture:
            return
        node = self.nodes[0]
        assert_equal(self.chain, "regtest")
        assert_equal(node.getblockcount(), 0)
        genesis = node.getblockhash(0)
        node.setmocktime(node.getblockheader(genesis)["time"])
        addresses = cache_addresses()
        hashes = []
        # Original cache recipe: 25 mature and 25 immature rewards for each
        # of the first three destinations, 25 mature and 24 immature for #4.
        for i in range(8):
            hashes.extend(self.generatetoaddress(node, 25 if i != 7 else 24, addresses[i % 4]))
        assert_equal(len(hashes), CACHE_BLOCK_COUNT)
        fixture = {
            "format": 1,
            "network": self.chain,
            "genesis": genesis,
            "addresses": addresses,
            "tip": node.getbestblockhash(),
            "registry_root": node.getchainregistryinfo()["root"],
            "blocks": [node.getblock(block_hash, 0) for block_hash in hashes],
        }
        # Refuse to overwrite existing data; regeneration must be reviewed.
        with self.options.generate_fixture.open("x", encoding="utf-8") as fixture_file:
            json.dump(fixture, fixture_file, indent=2)
            fixture_file.write("\n")

if __name__ == '__main__':
    CreateCache(__file__).main()
