#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mandatory CHECKLOCKTIMEVERIFY validation."""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    TIME_GENESIS_BLOCK,
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    SEQUENCE_FINAL,
    msg_block,
)
from test_framework.p2p import P2PInterface
from test_framework.script import (
    CScript,
    CScriptNum,
    OP_1NEGATE,
    OP_CHECKLOCKTIMEVERIFY,
    OP_DROP,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)


def cltv_modify_tx(tx, prepend_scriptsig, nsequence=None, nlocktime=None):
    assert_equal(len(tx.vin), 1)
    if nsequence is not None:
        tx.vin[0].nSequence = nsequence
        tx.nLockTime = nlocktime
    tx.vin[0].scriptSig = CScript(prepend_scriptsig + list(CScript(tx.vin[0].scriptSig)))


def cltv_invalidate(tx, failure_reason):
    assert failure_reason in range(5)
    scheme = [
        [[OP_CHECKLOCKTIMEVERIFY], None, None],
        [[OP_1NEGATE, OP_CHECKLOCKTIMEVERIFY, OP_DROP], None, None],
        [[CScriptNum(100), OP_CHECKLOCKTIMEVERIFY, OP_DROP], 0, TIME_GENESIS_BLOCK],
        [[CScriptNum(100), OP_CHECKLOCKTIMEVERIFY, OP_DROP], 0, 50],
        [[CScriptNum(50), OP_CHECKLOCKTIMEVERIFY, OP_DROP], SEQUENCE_FINAL, 50],
    ][failure_reason]
    cltv_modify_tx(tx, prepend_scriptsig=scheme[0], nsequence=scheme[1], nlocktime=scheme[2])


def cltv_validate(tx, height):
    cltv_modify_tx(
        tx,
        prepend_scriptsig=[CScriptNum(height), OP_CHECKLOCKTIMEVERIFY, OP_DROP],
        nsequence=0,
        nlocktime=height,
    )


class CLTVTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.noban_tx_relay = True
        self.extra_args = [['-acceptnonstdtxn=1']]
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PInterface())
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_OP_TRUE)
        self.generate(wallet, COINBASE_MATURITY + 10)

        reject_suffixes = [
            ' (Operation not valid with the current stack size)',
            ' (Negative locktime)',
            ' (Locktime requirement not satisfied)',
            ' (Locktime requirement not satisfied)',
            ' (Locktime requirement not satisfied)',
        ]

        for failure_reason, reject_suffix in enumerate(reject_suffixes):
            spend_tx = wallet.create_self_transfer()['tx']
            coin = spend_tx.vin[0].prevout
            cltv_invalidate(spend_tx, failure_reason)
            txid = spend_tx.txid_hex
            wtxid = spend_tx.wtxid_hex
            reject_reason = 'mempool-script-verify-flag-failed' + reject_suffix
            assert_equal(
                [{
                    'txid': txid,
                    'wtxid': wtxid,
                    'allowed': False,
                    'reject-reason': reject_reason,
                    'reject-details': reject_reason + f', input 0 of {txid} (wtxid {wtxid}), spending {coin.hash:064x}:{coin.n}',
                }],
                node.testmempoolaccept(rawtxs=[spend_tx.serialize().hex()], maxfeerate=0),
            )

            tip = node.getbestblockhash()
            height = node.getblockcount() + 1
            block_time = node.getblockheader(tip)['mediantime'] + 1
            block = create_block(int(tip, 16), create_coinbase(height), block_time, txlist=[spend_tx])
            block.solve()
            expected_log = 'Block validation error: block-script-verify-flag-failed' + reject_suffix
            with node.assert_debug_log(expected_msgs=[expected_log]):
                peer.send_and_ping(msg_block(block))
                assert_equal(node.getbestblockhash(), tip)

        valid_tx = wallet.create_self_transfer()['tx']
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        cltv_validate(valid_tx, height - 1)
        block_time = node.getblockheader(tip)['mediantime'] + 1
        block = create_block(int(tip, 16), create_coinbase(height), block_time, txlist=[valid_tx])
        block.solve()
        peer.send_and_ping(msg_block(block))
        assert_equal(node.getbestblockhash(), block.hash_hex)


if __name__ == '__main__':
    CLTVTest(__file__).main()
