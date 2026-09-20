#!/usr/bin/env python3
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the scantxoutset RPC with native Taproot outputs."""

from decimal import Decimal

from test_framework.address import address_to_scriptpubkey
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet, getnewdestination


MASTER_PRIVATE_KEY = "KrprvXJ7sdXeAaebXiey7yvDXgmhNCdCzN1Y36DXgM2RACzavCQ9XHZMve7dsUoSCAVrvH2cnVH5b2oCtgDsATtXKyhvUSurRftNtHnke6h3P4VP"
MASTER_PUBLIC_KEY = "KrpubTX7E33B4R29pw93b5wkY3ue6kf3UmUFtTSTH9QpmmL7u5CUfq6gBBuxML4Eov9RNfbmZLFHSXrWCyApiZif8p1AiwyGxrXuBi6M3jbkjJdo"


def descriptors(out):
    return sorted(u["desc"] for u in out["unspents"])


def tr(key, path):
    return f"tr({key}/{path})"


class ScantxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def sendtodestination(self, destination, amount):
        self.wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=address_to_scriptpubkey(destination),
            amount=int(COIN * amount),
        )

    def descriptor_with_checksum(self, descriptor):
        checksum = self.nodes[0].getdescriptorinfo(descriptor)["checksum"]
        return f"{descriptor}#{checksum}"

    def send_to_descriptor(self, descriptor, amount):
        address = self.nodes[0].deriveaddresses(self.descriptor_with_checksum(descriptor))[0]
        self.sendtodestination(address, amount)

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.log.info("Test if we find coinbase outputs")
        coinbase_scan = node.scantxoutset("start", [self.wallet.get_descriptor()])
        assert_equal(sum(u["coinbase"] for u in coinbase_scan["unspents"]), 49)

        self.log.info("Create native Taproot UTXOs")
        direct_destinations = [getnewdestination() for _ in range(3)]
        for (_, _, address), amount in zip(direct_destinations, [0.001, 0.002, 0.004]):
            self.sendtodestination(address, amount)

        derived_outputs = [
            ("0'/0'/0'", 0.008),
            ("0'/0'/1'", 0.016),
            ("0'/0'/1500'", 0.032),
            ("0'/0'/0", 0.064),
            ("0'/0'/1", 0.128),
            ("0'/0'/1500", 0.256),
            ("1/1/0'", 0.512),
            ("1/1/1'", 1.024),
            ("1/1/1500'", 2.048),
            ("1/1/0", 4.096),
            ("1/1/1", 8.192),
            ("1/1/1500", 16.384),
        ]
        for path, amount in derived_outputs:
            self.send_to_descriptor(tr(MASTER_PRIVATE_KEY, path), amount)

        self.generate(node, 1)

        scan = node.scantxoutset("start", [])
        info = node.gettxoutsetinfo()
        assert scan["success"]
        assert_equal(scan["height"], info["height"])
        assert_equal(scan["txouts"], info["txouts"])
        assert_equal(scan["bestblock"], info["bestblock"])

        self.log.info("Find direct Taproot outputs by current descriptors")
        addresses = [destination[2] for destination in direct_destinations]
        scripts = [destination[1] for destination in direct_destinations]
        output_keys = [destination[0] for destination in direct_destinations]
        assert_equal(node.scantxoutset("start", [f"addr({address})" for address in addresses])["total_amount"], Decimal("0.007"))
        assert_equal(node.scantxoutset("start", [f"raw({script.hex()})" for script in scripts])["total_amount"], Decimal("0.007"))
        assert_equal(node.scantxoutset("start", [f"rawtr({key.hex()})" for key in output_keys])["total_amount"], Decimal("0.007"))

        self.log.info("Test range validation")
        assert_raises_rpc_error(-8, "End of range is too high", node.scantxoutset, "start", [{"desc": "desc", "range": -1}])
        assert_raises_rpc_error(-8, "Range should be greater or equal than 0", node.scantxoutset, "start", [{"desc": "desc", "range": [-1, 10]}])
        assert_raises_rpc_error(-8, "End of range is too high", node.scantxoutset, "start", [{"desc": "desc", "range": [(2 << 31 + 1) - 1000000, (2 << 31 + 1)]}])
        assert_raises_rpc_error(-8, "Range specified as [begin,end] must not have begin after end", node.scantxoutset, "start", [{"desc": "desc", "range": [2, 1]}])
        assert_raises_rpc_error(-8, "Range is too large", node.scantxoutset, "start", [{"desc": "desc", "range": [0, 1000001]}])

        self.log.info("Test Taproot extended-key derivation")
        for path, amount in derived_outputs:
            key = MASTER_PUBLIC_KEY if "'" not in path else MASTER_PRIVATE_KEY
            assert_equal(node.scantxoutset("start", [tr(key, path)])["total_amount"], Decimal(str(amount)))

        range_cases = [
            (tr(MASTER_PRIVATE_KEY, "0'/0'/*'"), 1499, "0.024"),
            (tr(MASTER_PRIVATE_KEY, "0'/0'/*'"), 1500, "0.056"),
            (tr(MASTER_PRIVATE_KEY, "0'/0'/*"), 1499, "0.192"),
            (tr(MASTER_PRIVATE_KEY, "0'/0'/*"), 1500, "0.448"),
            (tr(MASTER_PRIVATE_KEY, "1/1/*'"), 1499, "1.536"),
            (tr(MASTER_PRIVATE_KEY, "1/1/*'"), 1500, "3.584"),
            (tr(MASTER_PRIVATE_KEY, "1/1/*"), 1499, "12.288"),
            (tr(MASTER_PRIVATE_KEY, "1/1/*"), 1500, "28.672"),
            (tr(MASTER_PUBLIC_KEY, "1/1/*"), 1499, "12.288"),
            (tr(MASTER_PUBLIC_KEY, "1/1/*"), 1500, "28.672"),
        ]
        for descriptor, end, amount in range_cases:
            scan = node.scantxoutset("start", [{"desc": descriptor, "range": end}])
            assert_equal(scan["total_amount"], Decimal(amount))

        scan = node.scantxoutset("start", [{"desc": tr(MASTER_PUBLIC_KEY, "1/1/*"), "range": [1500, 1500]}])
        assert_equal(scan["total_amount"], Decimal("16.384"))
        multipath = f"tr({MASTER_PUBLIC_KEY}/1/1/<0;1>)"
        assert_equal(node.scantxoutset("start", [multipath])["total_amount"], Decimal("12.288"))

        self.log.info("Test reported Taproot descriptors")
        reported = descriptors(node.scantxoutset("start", [{"desc": tr(MASTER_PRIVATE_KEY, "0'/0'/*'"), "range": 1}]))
        assert_equal(len(reported), 2)
        assert all(desc.startswith("tr([0c5f9a1e/0h/0h/") for desc in reported)

        reported = descriptors(node.scantxoutset("start", [{"desc": tr(MASTER_PUBLIC_KEY, "1/1/*"), "range": 1500}]))
        assert_equal(len(reported), 3)
        for path in ("0", "1", "1500"):
            assert any(f"[0c5f9a1e/1/1/{path}]" in desc for desc in reported)

        assert_equal(node.scantxoutset("status"), None)
        assert_equal(node.scantxoutset("abort"), False)

        self.log.info("Check blockhash and confirmation fields")
        self.generate(node, 2)
        confirmation_scan = node.scantxoutset("start", [tr(MASTER_PUBLIC_KEY, "1/1/1500")])
        unspent = confirmation_scan["unspents"][0]
        assert_equal(unspent["height"], info["height"])
        assert_equal(unspent["blockhash"], node.getblockhash(info["height"]))
        assert_equal(unspent["confirmations"], 3)

        assert_raises_rpc_error(-1, 'scantxoutset "action" ( [scanobjects,...] )', node.scantxoutset)
        assert_raises_rpc_error(-1, "scanobjects argument is required for the start action", node.scantxoutset, "start")
        assert_raises_rpc_error(-8, "Invalid action 'invalid_command'", node.scantxoutset, "invalid_command")


if __name__ == "__main__":
    ScantxoutsetTest(__file__).main()
