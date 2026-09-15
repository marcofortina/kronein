#!/usr/bin/env python3
# Copyright (c) 2016-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mandatory NULLDUMMY validation."""

import time

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import (
    COINBASE_MATURITY,
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
)
from test_framework.messages import (
    CTransaction,
    tx_from_hex,
)
from test_framework.script import (
    OP_0,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import getnewdestination
from test_framework.wallet_util import generate_keypair

NULLDUMMY_TX_ERROR = "mempool-script-verify-flag-failed (Dummy CHECKMULTISIG argument must be zero)"
NULLDUMMY_BLK_ERROR = "block-script-verify-flag-failed (Dummy CHECKMULTISIG argument must be zero)"


def invalidate_nulldummy_tx(tx):
    assert_equal(tx.vin[0].scriptSig[0], OP_0)
    tx.vin[0].scriptSig = bytes([OP_TRUE]) + tx.vin[0].scriptSig[1:]


class NULLDUMMYTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-addresstype=legacy']]

    def create_transaction(self, *, txid, input_details=None, addr, amount, privkey):
        tx_input = {"txid": txid, "vout": 0}
        rawtx = self.nodes[0].createrawtransaction([tx_input], {addr: amount})
        inputs = None if not input_details else [{**tx_input, **input_details}]
        signedtx = self.nodes[0].signrawtransactionwithkey(rawtx, [privkey], inputs)
        return tx_from_hex(signedtx["hex"])

    def run_test(self):
        node = self.nodes[0]
        privkey, pubkey = generate_keypair(wif=True)
        base_multisig = node.createmultisig(1, [pubkey.hex()])
        witness_multisig = node.createmultisig(1, [pubkey.hex()], 'p2sh-segwit')
        base_address = base_multisig["address"]
        base_unlock = {
            "scriptPubKey": address_to_scriptpubkey(base_address).hex(),
            "redeemScript": base_multisig["redeemScript"],
        }
        witness_address = witness_multisig['address']

        coinbase_blocks = self.generate(node, 2)
        coinbase_txids = [node.getblock(block_hash)['tx'][0] for block_hash in coinbase_blocks]
        self.generate(node, COINBASE_MATURITY)
        self.lastblockhash = node.getbestblockhash()
        self.lastblockheight = COINBASE_MATURITY + 2
        self.lastblocktime = int(time.time()) + self.lastblockheight

        funding_txs = [self.create_transaction(
            txid=coinbase_txids[0],
            addr=base_address,
            amount=49,
            privkey=node.get_deterministic_priv_key().key,
        )]
        base_funding_txid = node.sendrawtransaction(funding_txs[0].serialize_with_witness().hex(), 0)
        funding_txs.append(self.create_transaction(
            txid=base_funding_txid,
            input_details=base_unlock,
            addr=base_address,
            amount=48,
            privkey=privkey,
        ))
        base_spend_txid = node.sendrawtransaction(funding_txs[1].serialize_with_witness().hex(), 0)
        funding_txs.append(self.create_transaction(
            txid=coinbase_txids[1],
            addr=witness_address,
            amount=49,
            privkey=node.get_deterministic_priv_key().key,
        ))
        witness_spend_txid = node.sendrawtransaction(funding_txs[2].serialize_with_witness().hex(), 0)
        self.block_submit(node, funding_txs, accept=True)

        valid_base_tx = self.create_transaction(
            txid=base_spend_txid,
            input_details=base_unlock,
            addr=getnewdestination()[2],
            amount=47,
            privkey=privkey,
        )
        invalid_base_tx = CTransaction(valid_base_tx)
        invalidate_nulldummy_tx(invalid_base_tx)
        assert_raises_rpc_error(-26, NULLDUMMY_TX_ERROR, node.sendrawtransaction, invalid_base_tx.serialize_with_witness().hex(), 0)
        self.block_submit(node, [invalid_base_tx], accept=False)

        witness_unlock = {
            "scriptPubKey": funding_txs[2].vout[0].scriptPubKey.hex(),
            "amount": 49,
            "witnessScript": witness_multisig["redeemScript"],
        }
        valid_witness_tx = self.create_transaction(
            txid=witness_spend_txid,
            input_details=witness_unlock,
            addr=getnewdestination(address_type='p2sh-segwit')[2],
            amount=48,
            privkey=privkey,
        )
        invalid_witness_tx = CTransaction(valid_witness_tx)
        invalid_witness_tx.wit.vtxinwit[0].scriptWitness.stack[0] = b'\x01'
        assert_raises_rpc_error(-26, NULLDUMMY_TX_ERROR, node.sendrawtransaction, invalid_witness_tx.serialize_with_witness().hex(), 0)
        self.block_submit(node, [invalid_witness_tx], with_witness=True, accept=False)

        for tx in (valid_base_tx, valid_witness_tx):
            node.sendrawtransaction(tx.serialize_with_witness().hex(), 0)
        self.block_submit(node, [valid_base_tx, valid_witness_tx], with_witness=True, accept=True)

    def block_submit(self, node, txs, *, with_witness=False, accept):
        template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_equal(template['previousblockhash'], self.lastblockhash)
        assert_equal(template['height'], self.lastblockheight + 1)
        block = create_block(tmpl=template, ntime=self.lastblocktime + 1, txlist=txs)
        if with_witness:
            add_witness_commitment(block)
        block.solve()
        assert_equal(None if accept else NULLDUMMY_BLK_ERROR, node.submitblock(block.serialize().hex()))
        if accept:
            assert_equal(node.getbestblockhash(), block.hash_hex)
            self.lastblockhash = block.hash_hex
            self.lastblocktime += 1
            self.lastblockheight += 1
        else:
            assert_equal(node.getbestblockhash(), self.lastblockhash)


if __name__ == '__main__':
    NULLDUMMYTest(__file__).main()
