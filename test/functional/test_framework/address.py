#!/usr/bin/env python3
# Copyright (c) 2016-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Encode and decode native Bech32m witness-v1 addresses."""

import unittest

from .script import (
    CScript,
    OP_TRUE,
    taproot_construct,
)
from .util import assert_equal
from test_framework.script_util import program_to_witness_script
from test_framework.segwit_addr import (
    decode_segwit_address,
    encode_segwit_address,
)


ADDRESS_BCRT1_UNSPENDABLE = 'bcrt1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm3usuw'
ADDRESS_BCRT1_UNSPENDABLE_DESCRIPTOR = 'addr(bcrt1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm3usuw)#h0u3564j'
# Coins sent to this address can be spent through its deterministic OP_TRUE Taproot script path.
ADDRESS_BCRT1_P2TR_OP_TRUE = 'bcrt1p9yfmy5h72durp7zrhlw9lf7jpwjgvwdg0jr0lqmmjtgg83266lqsekaqka'


def create_deterministic_address_bcrt1_p2tr_op_true(explicit_internal_key=None):
    """
    Generates a deterministic bech32m address (segwit v1 output) that
    can be spent with a witness stack of OP_TRUE and the control block
    with internal public key (script-path spending).

    Returns a tuple with the generated address and the TaprootInfo object.
    """
    internal_key = explicit_internal_key or (1).to_bytes(32, 'big')
    taproot_info = taproot_construct(internal_key, [("only-path", CScript([OP_TRUE]))])
    address = output_key_to_p2tr(taproot_info.output_pubkey)
    if explicit_internal_key is None:
        assert_equal(address, ADDRESS_BCRT1_P2TR_OP_TRUE)
    return (address, taproot_info)


def program_to_witness(version, program, main=False):
    if (type(program) is str):
        program = bytes.fromhex(program)
    assert 0 <= version <= 16
    assert 2 <= len(program) <= 40
    assert version > 0 or len(program) in [20, 32]
    return encode_segwit_address("bc" if main else "bcrt", version, program)

def output_key_to_p2tr(key, main=False):
    assert len(key) == 32
    return program_to_witness(1, key, main)

def p2a(main=False):
    return program_to_witness(1, "4e73", main)

def bech32_to_bytes(address):
    hrp = address.split('1')[0]
    if hrp not in ['bc', 'tb', 'bcrt']:
        return (None, None)
    version, payload = decode_segwit_address(hrp, address)
    if version is None:
        return (None, None)
    return version, bytearray(payload)


def address_to_scriptpubkey(address):
    """Convert a witness-v1 address to its output script (scriptPubKey)."""
    version, payload = bech32_to_bytes(address)
    if version != 1:
        raise ValueError(f"Unsupported non-witness-v1 address: {address}")
    return program_to_witness_script(payload)


class TestFrameworkScript(unittest.TestCase):
    def test_bech32_decode(self):
        def check_bech32_decode(payload, version):
            hrp = "tb"
            self.assertEqual(bech32_to_bytes(encode_segwit_address(hrp, version, payload)), (version, payload))

        check_bech32_decode(bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'), 1)
        check_bech32_decode(bytes.fromhex('39cf8ebd95134f431c39db0220770bd127f5dd3cc103c988b7dcd577ae34e354'), 1)
        check_bech32_decode(bytes.fromhex('708244006d27c757f6f1fc6f853b6ec26268b727866f7ce632886e34eb5839a3'), 1)
