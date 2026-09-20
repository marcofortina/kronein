#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test the verified child-chain registry read RPCs."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class ChainRegistryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-chainregistryactivationheight=1",
            "-chainregistryminregistrationburn=1",
            "-chainregistrymaxoperations=4",
        ]]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Check configured registry state before activation")
        info = node.getchainregistryinfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["active"], False)
        assert_equal(info["active_for_next_block"], True)
        assert_equal(info["activation_height"], 1)
        assert_equal(info["minimum_registration_burn"], Decimal("1.00000000"))
        assert_equal(info["maximum_operations"], 4)
        assert_equal(info["height"], 0)
        assert_equal(info["bestblockhash"], node.getbestblockhash())
        assert_equal(info["size"], 0)

        self.log.info("Activate registry consensus and verify the empty committed view")
        self.generate(node, 1)
        info = node.getchainregistryinfo()
        assert_equal(info["active"], True)
        assert_equal(info["active_for_next_block"], True)
        assert_equal(info["height"], 1)
        assert_equal(info["bestblockhash"], node.getbestblockhash())
        assert_equal(info["size"], 0)
        assert_equal(len(info["root"]), 64)

        page = node.listchildchains()
        assert_equal(page["bestblockhash"], info["bestblockhash"])
        assert_equal(page["height"], info["height"])
        assert_equal(page["root"], info["root"])
        assert_equal(page["size"], 0)
        assert_equal(page["returned"], 0)
        assert_equal(page["has_more"], False)
        assert_equal(page["chains"], [])

        missing_id = "01" + "00" * 31
        missing = node.getchildchain(missing_id, True)
        assert_equal(missing["bestblockhash"], info["bestblockhash"])
        assert_equal(missing["height"], info["height"])
        assert_equal(missing["root"], info["root"])
        assert_equal(missing["found"], False)
        assert "chain" not in missing
        assert "inclusion_proof" not in missing
        assert_equal(missing["non_inclusion_proof"], {"leaf_count": 0})

        self.log.info("Reject malformed identifiers and invalid pagination bounds")
        assert_raises_rpc_error(-8, "chain_id must be exactly 32 bytes", node.getchildchain, "01")
        assert_raises_rpc_error(-8, "chain_id must be exactly 32 bytes", node.listchildchains, "zz" * 32)
        assert_raises_rpc_error(-8, "limit must be between 1 and 1000", node.listchildchains, None, 0)
        assert_raises_rpc_error(-8, "limit must be between 1 and 1000", node.listchildchains, None, 1001)


if __name__ == "__main__":
    ChainRegistryTest(__file__).main()
