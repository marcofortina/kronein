#!/usr/bin/env python3
# Copyright (c) 2019-present The Bitcoin Core developers
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Useful Script constants and utils."""

from copy import deepcopy

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    ser_compact_size,
)
from test_framework.script import (
    CScript,
    OP_0,
    OP_1,
    OP_DROP,
    OP_RETURN,
    OP_TRUE,
    taproot_construct,
)

from test_framework.util import (
    assert_greater_than_or_equal,
    assert_equal,
)

# To prevent a "tx-size-small" policy rule error, a transaction has to have a
# non-witness size of at least 65 bytes (MIN_STANDARD_TX_NONWITNESS_SIZE in
# src/policy/policy.h). Considering a Tx with the smallest possible single
# input (blank, empty scriptSig), and with an output omitting the scriptPubKey,
# we get to a minimum size of 60 bytes:
#
# Tx Skeleton: 4 [Version] + 1 [InCount] + 1 [OutCount] + 4 [LockTime] = 10 bytes
# Blank Input: 32 [PrevTxHash] + 4 [Index] + 1 [scriptSigLen] + 4 [SeqNo] = 41 bytes
# Output:      8 [Amount] + 1 [scriptPubKeyLen] = 9 bytes
#
# Hence, the scriptPubKey of the single output has to have a size of at
# least 5 bytes.
MIN_STANDARD_TX_NONWITNESS_SIZE = 65
MIN_PADDING = MIN_STANDARD_TX_NONWITNESS_SIZE - 10 - 41 - 9
assert MIN_PADDING == 5

# This script cannot be spent, allowing dust output values under
# standardness checks
DUMMY_MIN_OP_RETURN_SCRIPT = CScript([OP_RETURN] + ([OP_0] * (MIN_PADDING - 1)))
assert len(DUMMY_MIN_OP_RETURN_SCRIPT) == MIN_PADDING

PAY_TO_ANCHOR = CScript([OP_1, bytes.fromhex("4e73")])
ANCHOR_ADDRESS = "rkne1pfeesz3243u"

def program_to_witness_script(program):
    if isinstance(program, str):
        program = bytes.fromhex(program)
    assert len(program) in [2, 32]
    return CScript([OP_1, program])

def bulk_vout(tx, target_vsize):
    if target_vsize < tx.get_vsize():
        raise RuntimeError(f"target_vsize {target_vsize} is less than transaction virtual size {tx.get_vsize()}")
    # determine number of needed padding bytes
    dummy_vbytes = target_vsize - tx.get_vsize()
    # compensate for the increase of the compact-size encoded script length
    # (note that the length encoding of the unpadded output script needs one byte)
    dummy_vbytes -= len(ser_compact_size(dummy_vbytes)) - 1
    tx.vout[-1].scriptPubKey = CScript([OP_RETURN] + [OP_1] * dummy_vbytes)
    assert_equal(tx.get_vsize(), target_vsize)

def output_key_to_p2tr_script(key):
    assert len(key) == 32
    return program_to_witness_script(key)


def build_malleated_tx_package(*, parent: CTransaction, rebalance_parent_output_amount, child_amount):
    """
    Return a transaction package with two valid Taproot script-path spends.

    The child transactions have the same txid but different wtxids because
    they use different leaves of the same Taproot tree.

    Args:
        parent: Transaction with modifiable outputs. Either unsigned (sign after
        calling this function) or anyone-can-spend (e.g., MiniWallet's OP_TRUE).
    """
    taproot_info = taproot_construct(
        (1).to_bytes(32, 'big'),
        [
            ("short-path", CScript([OP_TRUE])),
            ("long-path", CScript([OP_TRUE, OP_DROP, OP_TRUE])),
        ],
    )

    # Append to the transaction the vout containing the script supporting 2 spending conditions
    assert_greater_than_or_equal(len(parent.vout), 1)
    last_output = parent.vout[len(parent.vout) - 1]
    assert_greater_than_or_equal(last_output.nValue, rebalance_parent_output_amount)
    last_output.nValue -= rebalance_parent_output_amount
    parent.vout.append(CTxOut(rebalance_parent_output_amount, taproot_info.scriptPubKey))

    # Create two valid children that differ only in witness data.
    child_one = CTransaction()
    child_one.vin.append(CTxIn(COutPoint(int(parent.txid_hex, 16), len(parent.vout) - 1), b""))
    child_one.vout.append(CTxOut(child_amount, taproot_info.scriptPubKey))
    child_one.wit.vtxinwit.append(CTxInWitness())

    def spend_leaf(tx, name):
        leaf = taproot_info.leaves[name]
        control = bytes([leaf.version | taproot_info.negflag]) + taproot_info.internal_pubkey + leaf.merklebranch
        tx.wit.vtxinwit[0].scriptWitness.stack = [leaf.script, control]

    spend_leaf(child_one, "short-path")
    child_two = deepcopy(child_one)
    spend_leaf(child_two, "long-path")
    return parent, child_one, child_two
