#!/usr/bin/env python3
# Copyright (c) 2023-present The Bitcoin Core developers
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test validation of native Taproot addresses."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


VALID_DATA = [
    (
        "kne1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqd564ll",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
    (
        "kne1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvses3m0mc8",
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
]

INVALID_DATA = [
    "kne1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqd564lq",
    "tkne1p35n52jy6xkm4wd905tdy8qtagrn73kqdz73xe4zxpvq9t3fp50aq95vvqg",
    "kne1pw5mdw5yk",
]


class ValidateAddressMainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.chain = ""
        self.num_nodes = 1
        self.extra_args = [["-prune=899"]]

    def run_test(self):
        for address, script_pub_key in VALID_DATA:
            result = self.nodes[0].validateaddress(address)
            assert_equal(result["isvalid"], True)
            assert_equal(result["address"].lower(), address)
            assert_equal(result["scriptPubKey"], script_pub_key)
            assert_equal(result["witness_version"], 1)
            assert_equal(result["witness_program"], script_pub_key[4:])
            assert "isscript" not in result
            assert "iswitness" not in result
            assert "error" not in result

        for address in INVALID_DATA:
            result = self.nodes[0].validateaddress(address)
            assert_equal(result["isvalid"], False)
            assert result["error"]


if __name__ == "__main__":
    ValidateAddressMainTest(__file__).main()
