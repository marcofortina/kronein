#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mandatory strict-DER signature validation."""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_block,
    create_coinbase,
)
from test_framework.messages import msg_block
from test_framework.p2p import P2PInterface
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)


def make_signature_non_der(tx):
    """Add padding after the S value of the first input signature."""
    script_sig = CScript(tx.vin[0].scriptSig)
    tx.vin[0].scriptSig = CScript([
        item[:-1] + b'\x00' + item[-1:] if index == 0 else item
        for index, item in enumerate(script_sig)
    ])


class DERSIGTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.noban_tx_relay = True
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PInterface())
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)

        coinbase_txids = [node.getblock(block_hash)['tx'][0] for block_hash in self.generate(wallet, COINBASE_MATURITY + 1)]

        def create_tx(input_txid):
            utxo = wallet.get_utxo(txid=input_txid, mark_as_spent=False)
            return wallet.create_self_transfer(utxo_to_spend=utxo)['tx']

        invalid_tx = create_tx(coinbase_txids[0])
        make_signature_non_der(invalid_tx)
        invalid_txid = invalid_tx.txid_hex
        invalid_wtxid = invalid_tx.wtxid_hex
        assert_equal(
            [{
                'txid': invalid_txid,
                'wtxid': invalid_wtxid,
                'allowed': False,
                'reject-reason': 'mempool-script-verify-flag-failed (Non-canonical DER signature)',
                'reject-details': 'mempool-script-verify-flag-failed (Non-canonical DER signature), '
                                  f'input 0 of {invalid_txid} (wtxid {invalid_wtxid}), spending {coinbase_txids[0]}:0',
            }],
            node.testmempoolaccept(rawtxs=[invalid_tx.serialize().hex()], maxfeerate=0),
        )

        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block_time = node.getblockheader(tip)['mediantime'] + 1
        block = create_block(int(tip, 16), create_coinbase(height), block_time, txlist=[invalid_tx])
        block.solve()
        with node.assert_debug_log(expected_msgs=['Block validation error: block-script-verify-flag-failed (Non-canonical DER signature)']):
            peer.send_and_ping(msg_block(block))
            assert_equal(node.getbestblockhash(), tip)

        valid_tx = create_tx(coinbase_txids[0])
        block = create_block(int(tip, 16), create_coinbase(height), block_time, txlist=[valid_tx])
        block.solve()
        peer.send_and_ping(msg_block(block))
        assert_equal(node.getbestblockhash(), block.hash_hex)


if __name__ == '__main__':
    DERSIGTest(__file__).main()
