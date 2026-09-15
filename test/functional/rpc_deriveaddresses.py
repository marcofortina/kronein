#!/usr/bin/env python3
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test deriving Taproot addresses."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


XPRV = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK"
XPUB = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"


class DeriveAddressesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        assert_raises_rpc_error(-5, "Missing checksum", node.deriveaddresses, "a")

        address = "bcrt1pgm99qkxzgc9y50c0u2kwttupdy6kvc8kaph57wuxz3hldxvv9p3szqhs4y"
        descriptor = descsum_create(f"tr({XPRV}/1/1/0)")
        assert_equal(node.deriveaddresses(descriptor), [address])
        assert_raises_rpc_error(-5, "Missing checksum", node.deriveaddresses, descriptor[:-9])
        assert_equal(node.deriveaddresses(descsum_create(f"tr({XPUB}/1/1/0)")), [address])

        ranged_descriptor = descsum_create(f"tr({XPRV}/1/1/*)")
        addresses = [
            address,
            "bcrt1phx9zzer4nc664ezstjp9ww3ted2985qlm0sdxrpf6tcqsgvmcqdshvvkes",
            "bcrt1pzrmz9uxedkg2fnkfc3q6nl005gsa374adaxp54p6ck3uvrzlgg6q5jjsvh",
        ]
        assert_equal(node.deriveaddresses(ranged_descriptor, [1, 2]), addresses[1:])
        assert_equal(node.deriveaddresses(ranged_descriptor, 2), addresses)

        multipath_descriptor = descsum_create(f"tr({XPRV}/1/<0;1>/*)")
        path_zero_addresses = [
            "bcrt1pqwj4pkv7gxvlspc9nq0yku0f7jd7whc0rcel8gdj6s88jkfas0jqev33kp",
            "bcrt1phckyq2f2ugpg4swl34lvdmfuxsrmm86efk2cxsgdl0jsm9nj4a6svcst7z",
            "bcrt1pqze7juqfrshenv4m0ftd3xzlkx094zn2rdjeda3ge6kdxt4qk22qs9hcmv",
        ]
        assert_equal(node.deriveaddresses(multipath_descriptor, [0, 2]), [path_zero_addresses, addresses])

        fixed_descriptor = descsum_create(f"tr({XPRV}/1/1/0)")
        assert_raises_rpc_error(-8, "Range should not be specified for an un-ranged descriptor", node.deriveaddresses, fixed_descriptor, [0, 2])
        assert_raises_rpc_error(-8, "Range must be specified for a ranged descriptor", node.deriveaddresses, ranged_descriptor)
        assert_raises_rpc_error(-8, "End of range is too high", node.deriveaddresses, ranged_descriptor, 10000000000)
        assert_raises_rpc_error(-8, "Range is too large", node.deriveaddresses, ranged_descriptor, [1000000000, 2000000000])
        assert_raises_rpc_error(-8, "Range specified as [begin,end] must not have begin after end", node.deriveaddresses, ranged_descriptor, [2, 0])
        assert_raises_rpc_error(-8, "Range should be greater or equal than 0", node.deriveaddresses, ranged_descriptor, [-1, 0])

        assert_equal(
            node.deriveaddresses(ranged_descriptor, [2147483647, 2147483647]),
            ["bcrt1pl9l22nfw35fh8fsu24rk0fxh27t9zscftnat0l8tve0xvk662wxserv66u"],
        )

        hardened_descriptor = descsum_create(f"tr({XPUB}/1'/1/0)")
        assert_raises_rpc_error(-5, "Cannot derive script without private keys", node.deriveaddresses, hardened_descriptor)


if __name__ == "__main__":
    DeriveAddressesTest(__file__).main()
