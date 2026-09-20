#!/usr/bin/env python3
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that getdescriptorinfo only accepts native output descriptors."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import generate_keypair


class DescriptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-disablewallet"]]
        self.wallet_names = []

    def test_desc(self, desc, isrange, issolvable, hasprivatekeys, expanded_descs=None):
        info = self.nodes[0].getdescriptorinfo(desc)
        assert_equal(info, self.nodes[0].getdescriptorinfo(descsum_create(desc)))
        if expanded_descs is not None:
            assert_equal(info["descriptor"], descsum_create(expanded_descs[0]))
            assert_equal(info["multipath_expansion"], [descsum_create(x) for x in expanded_descs])
        else:
            assert_equal(info["descriptor"], descsum_create(desc))
            assert "multipath_expansion" not in info
        assert_equal(info["isrange"], isrange)
        assert_equal(info["issolvable"], issolvable)
        assert_equal(info["hasprivatekeys"], hasprivatekeys)

    def run_test(self):
        node = self.nodes[0]
        assert_raises_rpc_error(-1, "getdescriptorinfo", node.getdescriptorinfo)
        if not self.options.usecli:
            assert_raises_rpc_error(-3, "JSON value of type number is not of expected type string", node.getdescriptorinfo, 1)
        assert_raises_rpc_error(-5, "'' is not a valid descriptor function", node.getdescriptorinfo, "")

        internal_key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        script_key = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        assert_raises_rpc_error(-5, f"tr(): Key ' {internal_key}' is invalid due to whitespace", node.getdescriptorinfo, f"tr( {internal_key})")
        assert_raises_rpc_error(-5, f"tr(): Key '{internal_key} ' is invalid due to whitespace", node.getdescriptorinfo, f"tr({internal_key} )")

        self.test_desc(f"tr({internal_key})", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"rawtr({internal_key})", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"tr({internal_key},pk({script_key}))", isrange=False, issolvable=True, hasprivatekeys=False)
        self.test_desc(f"raw(5120{internal_key})", isrange=False, issolvable=False, hasprivatekeys=False)
        self.test_desc("raw(6a0464617461)", isrange=False, issolvable=False, hasprivatekeys=False)

        compressed_key = f"02{internal_key}"
        for unsupported in [
            f"pkh({compressed_key})",
            f"wpkh({compressed_key})",
            f"combo({compressed_key})",
            f"sh(wpkh({compressed_key}))",
            f"wsh(pk({compressed_key}))",
            f"multi(1,{compressed_key})",
            f"sortedmulti(1,{compressed_key})",
        ]:
            assert_raises_rpc_error(-5, "is not a valid descriptor function", node.getdescriptorinfo, unsupported)

        assert_raises_rpc_error(-5, "Address is not valid", node.getdescriptorinfo, "addr(mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn)")
        for unsupported_script in [
            f"21{compressed_key}ac",  # P2PK
            f"76a914{'01' * 20}88ac",  # P2PKH
            f"a914{'01' * 20}87",  # P2SH
            f"0014{'01' * 20}",  # P2WPKH
            f"0020{'01' * 32}",  # P2WSH
        ]:
            assert_raises_rpc_error(-5, "Raw script is not a native output", node.getdescriptorinfo, f"raw({unsupported_script})")

        priv_key = generate_keypair(wif=True)[0]
        assert_raises_rpc_error(-5, f"tr(): Key ' {priv_key}' is invalid due to whitespace", node.getdescriptorinfo, f"tr( {priv_key})")
        private_info = node.getdescriptorinfo(f"tr({priv_key})")
        assert_equal(private_info["hasprivatekeys"], True)
        assert priv_key not in private_info["descriptor"]

        xpub = "KrpubTX7E33B4R29pw93b5wkY3ue6kf3UmUFtTSTH9QpmmL7u5CUfq6gBBuxML4Eov9RNfbmZLFHSXrWCyApiZif8p1AiwyGxrXuBi6M3jbkjJdo"
        self.test_desc(f"tr({xpub}/0/*)", isrange=True, issolvable=True, hasprivatekeys=False)
        self.test_desc(
            f"tr({xpub}/<0;1>/*)",
            isrange=True,
            issolvable=True,
            hasprivatekeys=False,
            expanded_descs=[f"tr({xpub}/0/*)", f"tr({xpub}/1/*)"],
        )

        assert_raises_rpc_error(-5, "pk() can only be used inside tr()", node.getdescriptorinfo, f"pk(02{internal_key})")

if __name__ == "__main__":
    DescriptorTest(__file__).main()
