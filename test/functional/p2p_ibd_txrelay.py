#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test transaction relay behavior during IBD:
- Set fee filters to MAX_MONEY
- Don't request transactions
- Ignore all transaction messages
"""

from decimal import Decimal
import time

from test_framework.blocktools import TIME_GENESIS_BLOCK, create_block, create_coinbase
from test_framework.messages import (
        CInv,
        COIN,
        COutPoint,
        CTransaction,
        CTxIn,
        CTxOut,
        msg_inv,
        msg_tx,
        MSG_WTX,
)
from test_framework.p2p import (
        NONPREF_PEER_TX_DELAY,
        P2PDataStore,
        P2PInterface,
        p2p_lock
)
from test_framework.test_framework import BitcoinTestFramework

MAX_FEE_FILTER = Decimal(9936506) / COIN
NORMAL_FEE_FILTER = Decimal(10) / COIN


class P2PIBDTxRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["-minrelaytxfee={:.8f}".format(NORMAL_FEE_FILTER), "-minimumchainwork=0x6"],
            ["-minrelaytxfee={:.8f}".format(NORMAL_FEE_FILTER), "-minimumchainwork=0x6"],
        ]

    def run_test(self):
        self.log.info("Check that nodes set minfilter to MAX_MONEY while still in IBD")
        for node in self.nodes:
            assert node.getblockchaininfo()['initialblockdownload']
            self.wait_until(lambda: all(peer['minfeefilter'] == MAX_FEE_FILTER for peer in node.getpeerinfo()))

        current_time = max(int(time.time()), TIME_GENESIS_BLOCK + 2 * 24 * 60 * 60 + 1)
        for node in self.nodes:
            node.setmocktime(current_time)
        self.log.info("Mine one old block so we stay in IBD, then remember its coinbase wtxid")
        block = create_block(int(self.nodes[0].getbestblockhash(), 16), create_coinbase(1), current_time - 2 * 24 * 60 * 60)
        block.solve()
        self.nodes[0].submitblock(block.serialize().hex())
        assert self.nodes[0].getblockchaininfo()['initialblockdownload']
        ibd_wtxid = int(self.nodes[0].getblock(f"{block.hash_int:064x}", 2)["tx"][0]["hash"], 16)

        self.log.info("Check that nodes don't send getdatas for transactions while still in IBD")
        peer_inver = self.nodes[0].add_p2p_connection(P2PDataStore())
        txid = 0xdeadbeef
        peer_inver.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=txid)]))
        # The node should not send a getdata, but if it did, it would first delay 2 seconds
        self.nodes[0].bumpmocktime(NONPREF_PEER_TX_DELAY)
        peer_inver.sync_with_ping()
        with p2p_lock:
            assert txid not in peer_inver.getdata_requests
        self.nodes[0].disconnect_p2ps()

        self.log.info("Check that nodes don't process unsolicited transactions while still in IBD")
        # No spendable UTXO exists yet, but this must still be a well-formed
        # native transaction with one witness stack per input.
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(0xDEADBEEF, 0))]
        tx.vout = [CTxOut(COIN, b"\x51")]
        rawhex = tx.serialize().hex()
        assert self.nodes[1].decoderawtransaction(rawhex) # returns a dict, should not throw
        peer_txer = self.nodes[0].add_p2p_connection(P2PInterface())
        with self.nodes[0].assert_debug_log(expected_msgs=["received: tx"], unexpected_msgs=["was not accepted"]):
            peer_txer.send_and_ping(msg_tx(tx))
        self.nodes[0].disconnect_p2ps()

        # Come out of IBD by generating a block
        self.generate(self.nodes[0], 1)

        self.log.info("Check that nodes reset minfilter after coming out of IBD")
        for node in self.nodes:
            assert not node.getblockchaininfo()['initialblockdownload']
            self.wait_until(lambda: all(peer['minfeefilter'] == NORMAL_FEE_FILTER for peer in node.getpeerinfo()))

        self.log.info("Check that txs confirmed during IBD are not in the recently-confirmed filter once out of ibd")
        peer_inver = self.nodes[0].add_p2p_connection(P2PDataStore())
        peer_inver.send_and_ping(msg_inv([CInv(t=MSG_WTX, h=ibd_wtxid)]))
        self.nodes[0].bumpmocktime(NONPREF_PEER_TX_DELAY)
        peer_inver.wait_for_getdata([ibd_wtxid])
        self.nodes[0].disconnect_p2ps()

        self.log.info("Check that nodes process the same transaction, even when unsolicited, when no longer in IBD")
        peer_txer = self.nodes[0].add_p2p_connection(P2PInterface())
        with self.nodes[0].assert_debug_log(expected_msgs=["was not accepted"]):
            peer_txer.send_and_ping(msg_tx(tx))

if __name__ == '__main__':
    P2PIBDTxRelayTest(__file__).main()
