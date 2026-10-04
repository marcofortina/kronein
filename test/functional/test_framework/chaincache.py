# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Static, genuinely mined blocks used only to bootstrap the functional cache."""

import json
from pathlib import Path

from .address import create_deterministic_address_rkne1_p2tr_op_true
from .test_node import TestNode
from .util import assert_equal


CACHE_BLOCK_COUNT = 199
CACHE_FIXTURE = Path(__file__).resolve().parent.parent / "data" / "regtest_chain199.json"


def cache_addresses():
    return [k.address for k in TestNode.PRIV_KEYS][:3] + [create_deterministic_address_rkne1_p2tr_op_true()[0]]


def load_cache_fixture(node, chain):
    """Submit immutable block bytes through normal, full consensus validation."""
    with CACHE_FIXTURE.open(encoding="utf-8") as fixture_file:
        fixture = json.load(fixture_file)
    assert_equal(fixture["format"], 1)
    assert_equal(fixture["network"], chain, "regtest")
    assert_equal(fixture["genesis"], node.getblockhash(0))
    assert_equal(fixture["addresses"], cache_addresses())
    assert_equal(len(fixture["blocks"]), CACHE_BLOCK_COUNT)
    assert_equal(node.getblockcount(), 0)
    for height, block in enumerate(fixture["blocks"], start=1):
        result = node.submitblock(block)
        assert result is None, f"Cache fixture block {height} rejected: {result}"
    assert_equal(node.getblockcount(), CACHE_BLOCK_COUNT)
    assert_equal(node.getbestblockhash(), fixture["tip"])
    assert_equal(node.getchainregistryinfo()["root"], fixture["registry_root"])
