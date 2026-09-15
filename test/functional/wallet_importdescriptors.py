#!/usr/bin/env python3
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test native Taproot descriptor imports."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class ImportDescriptorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        node.createwallet(wallet_name="source")
        source = node.get_wallet_rpc("source")
        source.generatetoaddress(101, source.getnewaddress())
        exported = source.listdescriptors()["descriptors"]
        assert_equal(len(exported), 2)
        assert all(item["desc"].startswith("tr(") for item in exported)

        node.createwallet(wallet_name="watch", disable_private_keys=True, blank=True)
        watch = node.get_wallet_rpc("watch")
        requests = []
        for item in exported:
            request = {
                "desc": item["desc"],
                "timestamp": "now",
                "active": True,
                "range": [0, 100],
                "next_index": item["next_index"],
            }
            if item.get("internal", False):
                request["internal"] = True
            requests.append(request)

        result = watch.importdescriptors(requests)
        assert_equal(result, [{"success": True}, {"success": True}])

        assert_equal(source.getnewaddress(), watch.getnewaddress())
        assert_equal(source.getrawchangeaddress(), watch.getrawchangeaddress())

        receive_address = watch.getnewaddress()
        source.sendtoaddress(receive_address, 1)
        self.generate(node, 1)
        assert_equal(watch.getreceivedbyaddress(receive_address), 1)

        taproot_descriptor = exported[0]["desc"].split("#")[0]
        legacy = descsum_create(f"wpkh({taproot_descriptor[3:-1]})")
        error = watch.importdescriptors([{
            "desc": legacy,
            "timestamp": "now",
            "active": True,
            "range": [0, 1],
        }])[0]
        assert_equal(error["success"], False)
        assert_equal(error["error"]["message"], "Only Taproot descriptors can be active")

        assert_raises_rpc_error(-3, "Missing required timestamp field", watch.importdescriptors, [{"desc": exported[0]["desc"]}])


if __name__ == '__main__':
    ImportDescriptorsTest(__file__).main()
