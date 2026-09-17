#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mandatory CHECKLOCKTIMEVERIFY validation."""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    TIME_GENESIS_BLOCK,
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
    OP_TRUE,
    taproot_construct,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


INTERNAL_KEY = (1).to_bytes(32, "big")


def cltv_case(failure_reason):
    assert failure_reason in range(5)
    return [
        [[OP_CHECKLOCKTIMEVERIFY], 0, 0],
        [[OP_1NEGATE, OP_CHECKLOCKTIMEVERIFY, OP_DROP], 0, 0],
        [[CScriptNum(100), OP_CHECKLOCKTIMEVERIFY, OP_DROP], 0, TIME_GENESIS_BLOCK],
        [[CScriptNum(100), OP_CHECKLOCKTIMEVERIFY, OP_DROP], 0, 50],
        [[CScriptNum(50), OP_CHECKLOCKTIMEVERIFY, OP_DROP], SEQUENCE_FINAL, 50],
    ][failure_reason]


def create_cltv_spend(funding_tx, taproot_info, script, sequence, locktime, output_script):
    tx = CTransaction()
    tx.vin = [CTxIn(COutPoint(funding_tx.txid_int, 1), nSequence=sequence)]
    tx.vout = [CTxOut(funding_tx.vout[1].nValue - 1_000, output_script)]
    tx.nLockTime = locktime
    leaf = taproot_info.leaves["cltv"]
    control = bytes([leaf.version | taproot_info.negflag]) + taproot_info.internal_pubkey + leaf.merklebranch
    tx.wit.vtxinwit = [CTxInWitness()]
    tx.wit.vtxinwit[0].scriptWitness.stack = [script, control]
    return tx


class CLTVTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.noban_tx_relay = True
        self.extra_args = [['-acceptnonstdtxn=1']]
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PInterface())
        wallet = MiniWallet(node)
        self.generate(wallet, COINBASE_MATURITY + 10)

        reject_suffixes = [
            ' (Operation not valid with the current stack size)',
            ' (Negative locktime)',
            ' (Locktime requirement not satisfied)',
            ' (Locktime requirement not satisfied)',
            ' (Locktime requirement not satisfied)',
        ]

        cases = []
        for failure_reason in range(5):
            ops, sequence, locktime = cltv_case(failure_reason)
            script = CScript(ops + [OP_TRUE])
            taproot_info = taproot_construct(INTERNAL_KEY, [("cltv", script)])
            funding = wallet.send_to(from_node=node, scriptPubKey=taproot_info.scriptPubKey, amount=100_000)
            cases.append((funding["tx"], taproot_info, script, sequence, locktime))

        valid_height = node.getblockcount() + 2
        valid_script = CScript([CScriptNum(valid_height - 1), OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_TRUE])
        valid_taproot = taproot_construct(INTERNAL_KEY, [("cltv", valid_script)])
        valid_funding = wallet.send_to(from_node=node, scriptPubKey=valid_taproot.scriptPubKey, amount=100_000)
        self.generate(wallet, 1)

        for (funding_tx, taproot_info, script, sequence, locktime), reject_suffix in zip(cases, reject_suffixes):
            spend_tx = create_cltv_spend(funding_tx, taproot_info, script, sequence, locktime, wallet.get_output_script())
            coin = spend_tx.vin[0].prevout
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
            add_witness_commitment(block)
            block.solve()
            expected_log = 'Block validation error: block-script-verify-flag-failed' + reject_suffix
            with node.assert_debug_log(expected_msgs=[expected_log]):
                peer.send_and_ping(msg_block(block))
                assert_equal(node.getbestblockhash(), tip)

        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        assert_equal(height, valid_height)
        valid_tx = create_cltv_spend(
            valid_funding["tx"],
            valid_taproot,
            valid_script,
            0,
            height - 1,
            wallet.get_output_script(),
        )
        block_time = node.getblockheader(tip)['mediantime'] + 1
        block = create_block(int(tip, 16), create_coinbase(height), block_time, txlist=[valid_tx])
        add_witness_commitment(block)
        block.solve()
        peer.send_and_ping(msg_block(block))
        assert_equal(node.getbestblockhash(), block.hash_hex)


if __name__ == '__main__':
    CLTVTest(__file__).main()
