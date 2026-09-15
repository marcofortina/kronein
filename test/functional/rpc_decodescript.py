#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test decoding native output scripts via the decodescript RPC."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class DecodeScriptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        self.log.info("Decode a Taproot output")
        xonly_public_key = "01" * 32
        result = self.nodes[0].decodescript("5120" + xonly_public_key)
        assert_equal(result["asm"], "1 " + xonly_public_key)
        assert_equal(result["type"], "witness_v1_taproot")
        assert_equal(result["address"], "bcrt1pqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs7r922v")
        assert "segwit" not in result

        self.log.info("Decode an OP_RETURN output")
        result = self.nodes[0].decodescript("6a04deadbeef")
        assert_equal(result["type"], "nulldata")
        assert "address" not in result

        self.log.info("Decode an ephemeral anchor output")
        result = self.nodes[0].decodescript("51024e73")
        assert_equal(result["asm"], "1 29518")
        assert_equal(result["type"], "anchor")
        assert "address" not in result


if __name__ == "__main__":
    DecodeScriptTest(__file__).main()
