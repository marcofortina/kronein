#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise the native RandomX worker, including framing and clean shutdown."""

from concurrent.futures import ThreadPoolExecutor
import os
import subprocess

from test_framework.randomx import hash_v2
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises


class RandomXWorkerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0
        self.setup_clean_chain = True

    def setup_network(self):
        pass

    def run_test(self):
        key = b"test key 000"
        data = b"This is a test"
        expected = "22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f"
        self.log.info("Check the upstream v2 vector and repeated concurrent requests")
        assert_equal(hash_v2(data, key).hex(), expected)
        with ThreadPoolExecutor(max_workers=2) as pool:
            hashes = list(pool.map(lambda _: hash_v2(data, key).hex(), range(4)))
        assert_equal(hashes, [expected] * 4)
        assert_raises(ValueError, hash_v2, b"", key)
        assert_raises(ValueError, hash_v2, data, b"")

        helper = os.environ["KRONEIN_RANDOMX_HELPER"]
        request = f"{key.hex()}\n{data.hex()}\n"
        self.log.info("Check multiple responses and successful shutdown on EOF")
        result = subprocess.run([helper], input=request * 2, text=True, capture_output=True, check=True)
        assert_equal(result.stdout, f"{expected}\n" * 2)
        assert_equal(result.stderr, "")
        self.log.info("Reject malformed, empty and truncated requests without producing a hash")
        for malformed in ("zz\n00\n", "0\n00\n", "\n00\n", "00\n\n", "00\n"):
            result = subprocess.run([helper], input=malformed, text=True, capture_output=True)
            assert_equal(result.returncode, 1)
            assert_equal(result.stdout, "")
            assert_equal(result.stderr, "")


if __name__ == "__main__":
    RandomXWorkerTest(__file__).main()
