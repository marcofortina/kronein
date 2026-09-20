#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test native block and transaction validation."""

import copy

from test_framework.address import (
    address_to_scriptpubkey,
    create_deterministic_address_rkne1_p2tr_op_true,
)
from test_framework.blocktools import (
    COINBASE_MATURITY,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class NativeBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def make_block(self, *, transactions=None, coinbase_script=None, coinbase_value=50, version=1):
        node = self.nodes[0]
        height = node.getblockcount() + 1
        previous_hash = int(node.getbestblockhash(), 16)
        previous_time = node.getblock(node.getbestblockhash())["time"]
        coinbase = create_coinbase(
            height,
            script_pubkey=coinbase_script or self.native_script,
            nValue=coinbase_value,
        )
        block = create_block(
            previous_hash,
            coinbase,
            previous_time + 1,
            version=version,
            txlist=transactions or [],
        )
        if transactions:
            add_witness_commitment(block)
        block.solve()
        return block

    def set_op_true_witness(self, tx, input_index=0):
        leaf = self.taproot_info.leaves["only-path"]
        control = bytes([leaf.version | self.taproot_info.negflag]) + self.taproot_info.internal_pubkey
        while len(tx.wit.vtxinwit) <= input_index:
            tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[input_index].scriptWitness.stack = [leaf.script, control]

    def spend(self, previous_tx, *, output_script=None, version=1, script_sig=b""):
        tx = CTransaction()
        tx.version = version
        tx.vin = [CTxIn(COutPoint(previous_tx.txid_int, 0), script_sig)]
        tx.vout = [CTxOut(previous_tx.vout[0].nValue - 1_000, output_script or self.native_script)]
        self.set_op_true_witness(tx)
        return tx

    def submit(self, block, expected=None):
        assert_equal(self.nodes[0].submitblock(block.serialize().hex()), expected)

    def run_test(self):
        node = self.nodes[0]
        address, self.taproot_info = create_deterministic_address_rkne1_p2tr_op_true()
        self.native_script = address_to_scriptpubkey(address)
        descriptor = f"raw({self.native_script.hex()})"

        self.log.info("Accept a version 1 block with a native Taproot coinbase")
        first_block = self.make_block()
        first_coinbase = first_block.vtx[0]
        self.submit(first_block)

        self.log.info("Mature and spend the Taproot coinbase through its script path")
        self.generatetodescriptor(node, COINBASE_MATURITY - 1, descriptor)
        spend = self.spend(first_coinbase)
        spend_block = self.make_block(transactions=[spend])
        self.submit(spend_block)

        self.log.info("Accept native OP_RETURN data in a coinbase")
        data_block = self.make_block()
        data_block.vtx[0].vout.append(CTxOut(0, CScript([OP_RETURN, b"native-chain"])))
        data_block.hashMerkleRoot = data_block.calc_merkle_root()
        data_block.solve()
        self.submit(data_block)

        self.log.info("Reject a transaction creating a non-native output")
        non_native = self.spend(spend, output_script=CScript([OP_TRUE]))
        self.submit(self.make_block(transactions=[non_native]), "bad-txns-non-native-output")

        self.log.info("Reject a native spend with a non-empty scriptSig")
        nonempty_scriptsig = self.spend(spend, script_sig=CScript([OP_TRUE]))
        self.submit(self.make_block(transactions=[nonempty_scriptsig]), "bad-txns-scriptsig-not-empty")

        self.log.info("Reject transaction and block versions other than version 1")
        wrong_tx_version = self.spend(spend, version=2)
        self.submit(self.make_block(transactions=[wrong_tx_version]), "bad-tx-version")
        self.submit(self.make_block(version=2), "bad-version(0x00000002)")

        self.log.info("Reject a coinbase that creates a non-native output")
        self.submit(self.make_block(coinbase_script=CScript([OP_TRUE])), "bad-txns-non-native-output")

        self.log.info("Reject malformed block structure and reward")
        bad_merkle = self.make_block()
        bad_merkle.hashMerkleRoot += 1
        bad_merkle.solve()
        self.submit(bad_merkle, "bad-txnmrklroot")

        duplicate_coinbase = self.make_block()
        second_coinbase = copy.deepcopy(duplicate_coinbase.vtx[0])
        second_coinbase.nLockTime += 1
        duplicate_coinbase.vtx.append(second_coinbase)
        duplicate_coinbase.hashMerkleRoot = duplicate_coinbase.calc_merkle_root()
        duplicate_coinbase.solve()
        self.submit(duplicate_coinbase, "bad-cb-multiple")

        self.submit(self.make_block(coinbase_value=51), "bad-cb-amount")


if __name__ == "__main__":
    NativeBlockTest(__file__).main()
