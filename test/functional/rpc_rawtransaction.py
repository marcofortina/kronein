#!/usr/bin/env python3
# Copyright (c) 2014-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the rawtransaction RPCs.

Test the following RPCs:
   - getrawtransaction
   - createrawtransaction
   - signrawtransactionwithwallet
   - sendrawtransaction
   - decoderawtransaction
"""

from decimal import Decimal
from itertools import product

from test_framework.messages import (
    MAX_BIP125_RBF_SEQUENCE,
    COIN,
    CTxOut,
    tx_from_hex,
)
from test_framework.script import (
    CScript,
    OP_FALSE,
    OP_INVALIDOPCODE,
    OP_RETURN,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    sync_txindex,
)
from test_framework.wallet import (
    getnewdestination,
    MiniWallet,
)


TXID = "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000"


class RawTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [
            ["-txindex"],
            [],
            ["-fastprune", "-prune=1"],
        ]
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True
        self.supports_cli = False

    def setup_network(self):
        super().setup_network()
        self.connect_nodes(0, 2)

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.getrawtransaction_tests()
        self.createrawtransaction_tests()
        self.sendrawtransaction_tests()
        self.sendrawtransaction_testmempoolaccept_tests()
        self.decoderawtransaction_tests()
        self.getrawtransaction_verbosity_tests()

    def getrawtransaction_tests(self):
        tx = self.wallet.send_self_transfer(from_node=self.nodes[0])
        self.generate(self.nodes[0], 1)
        txId = tx['txid']
        err_msg = (
            "No such mempool transaction. Use -txindex or provide a block hash to enable"
            " blockchain transaction queries. Use gettransaction for wallet transactions."
        )

        for n in [0, 2]:
            self.log.info(f"Test getrawtransaction {'with' if n == 0 else 'without'} -txindex")

            if n == 0:
                sync_txindex(self, self.nodes[n])
                # With -txindex.
                # 1. valid parameters - only supply txid
                assert_equal(self.nodes[n].getrawtransaction(txId), tx['hex'])

                # 2. valid parameters - supply txid and 0 for non-verbose
                assert_equal(self.nodes[n].getrawtransaction(txId, 0), tx['hex'])

                # 3. valid parameters - supply txid and 1 for verbose.
                # We only check the "hex" field of the output so we don't need to update this test every time the output format changes.
                assert_equal(self.nodes[n].getrawtransaction(txId, 1)["hex"], tx['hex'])
                assert_equal(self.nodes[n].getrawtransaction(txId, 2)["hex"], tx['hex'])
            else:
                # Without -txindex, expect to raise.
                for verbosity in [None, 0, 1]:
                    assert_raises_rpc_error(-5, err_msg, self.nodes[n].getrawtransaction, txId, verbosity)

            # 4. invalid parameters - supply txid and invalid verbosity strings
            for value in ["True", "False"]:
                assert_raises_rpc_error(-3, "not of expected type number", self.nodes[n].getrawtransaction, txid=txId, verbosity=value)

            # 5. invalid parameters - supply txid and empty array
            assert_raises_rpc_error(-3, "not of expected type number", self.nodes[n].getrawtransaction, txId, [])

            # 6. invalid parameters - supply txid and empty dict
            assert_raises_rpc_error(-3, "not of expected type number", self.nodes[n].getrawtransaction, txId, {})

        # Make a tx by sending, then generate 2 blocks; block1 has the tx in it
        tx = self.wallet.send_self_transfer(from_node=self.nodes[2])['txid']
        block1, block2 = self.generate(self.nodes[2], 2)
        for n in [0, 2]:
            self.log.info(f"Test getrawtransaction {'with' if n == 0 else 'without'} -txindex, with blockhash")
            # We should be able to get the raw transaction by providing the correct block
            gottx = self.nodes[n].getrawtransaction(txid=tx, verbosity=1, blockhash=block1)
            assert_equal(gottx['txid'], tx)
            assert_equal(gottx['in_active_chain'], True)
            if n == 0:
                self.log.info("Test getrawtransaction with -txindex, without blockhash: 'in_active_chain' should be absent")
                for v in [1,2]:
                    gottx = self.nodes[n].getrawtransaction(txid=tx, verbosity=v)
                    assert_equal(gottx['txid'], tx)
                    assert 'in_active_chain' not in gottx
            else:
                self.log.info("Test getrawtransaction without -txindex, without blockhash: expect the call to raise")
                assert_raises_rpc_error(-5, err_msg, self.nodes[n].getrawtransaction, txid=tx, verbosity=1)
            # We should not get the tx if we provide an unrelated block
            assert_raises_rpc_error(-5, "No such transaction found", self.nodes[n].getrawtransaction, txid=tx, blockhash=block2)
            # An invalid block hash should raise the correct errors
            assert_raises_rpc_error(-3, "JSON value of type bool is not of expected type string", self.nodes[n].getrawtransaction, txid=tx, blockhash=True)
            assert_raises_rpc_error(-8, "parameter 3 must be of length 64 (not 6, for 'foobar')", self.nodes[n].getrawtransaction, txid=tx, blockhash="foobar")
            assert_raises_rpc_error(-8, "parameter 3 must be of length 64 (not 8, for 'abcd1234')", self.nodes[n].getrawtransaction, txid=tx, blockhash="abcd1234")
            foo = "ZZZ0000000000000000000000000000000000000000000000000000000000000"
            assert_raises_rpc_error(-8, f"parameter 3 must be hexadecimal string (not '{foo}')", self.nodes[n].getrawtransaction, txid=tx, blockhash=foo)
            bar = "0000000000000000000000000000000000000000000000000000000000000000"
            assert_raises_rpc_error(-5, "Block hash not found", self.nodes[n].getrawtransaction, txid=tx, blockhash=bar)
            # Undo the blocks and verify that "in_active_chain" is false.
            self.nodes[n].invalidateblock(block1)
            gottx = self.nodes[n].getrawtransaction(txid=tx, verbosity=1, blockhash=block1)
            assert_equal(gottx['in_active_chain'], False)
            self.nodes[n].reconsiderblock(block1)
            assert_equal(self.nodes[n].getbestblockhash(), block2)

        self.log.info("Test getrawtransaction on genesis block coinbase returns an error")
        block = self.nodes[0].getblock(self.nodes[0].getblockhash(0))
        assert_raises_rpc_error(-5, "The genesis block coinbase is not considered an ordinary transaction", self.nodes[0].getrawtransaction, block['merkleroot'])

    def getrawtransaction_verbosity_tests(self):
        tx = self.wallet.send_self_transfer(from_node=self.nodes[1])['txid']
        [block1] = self.generate(self.nodes[1], 1)
        fields = [
            'blockhash',
            'blocktime',
            'confirmations',
            'hash',
            'hex',
            'in_active_chain',
            'locktime',
            'size',
            'time',
            'txid',
            'vin',
            'vout',
            'vsize',
            'weight',
        ]
        prevout_fields = [
            'generated',
            'height',
            'value',
            'scriptPubKey',
        ]
        script_pub_key_fields = [
            'address',
            'asm',
            'hex',
            'type',
        ]
        # node 0 & 2 with verbosity 1 & 2
        for n, v in product([0, 2], [1, 2]):
            self.log.info(f"Test getrawtransaction_verbosity {v} {'with' if n == 0 else 'without'} -txindex, with blockhash")
            gottx = self.nodes[n].getrawtransaction(txid=tx, verbosity=v, blockhash=block1)
            missing_fields = set(fields).difference(gottx.keys())
            if missing_fields:
                raise AssertionError(f"fields {', '.join(missing_fields)} are not in transaction")

            assert len(gottx['vin']) > 0
            if v == 1:
                assert 'fee' not in gottx
                assert 'prevout' not in gottx['vin'][0]
            if v == 2:
                assert isinstance(gottx['fee'], Decimal)
                assert 'prevout' in gottx['vin'][0]
                prevout = gottx['vin'][0]['prevout']
                script_pub_key = prevout['scriptPubKey']

                missing_fields = set(prevout_fields).difference(prevout.keys())
                if missing_fields:
                    raise AssertionError(f"fields {', '.join(missing_fields)} are not in transaction")

                missing_fields = set(script_pub_key_fields).difference(script_pub_key.keys())
                if missing_fields:
                    raise AssertionError(f"fields {', '.join(missing_fields)} are not in transaction")

        # check verbosity 2 without blockhash but with txindex
        assert 'fee' in self.nodes[0].getrawtransaction(txid=tx, verbosity=2)
        # check that coinbase has no fee or does not throw any errors for verbosity 2
        coin_base = self.nodes[1].getblock(block1)['tx'][0]
        gottx = self.nodes[1].getrawtransaction(txid=coin_base, verbosity=2, blockhash=block1)
        assert 'fee' not in gottx
        # check that verbosity 2 for a mempool tx will fallback to verbosity 1
        # Do this with a pruned chain, as a regression test for https://github.com/bitcoin/bitcoin/pull/29003
        self.generate(self.nodes[2], 400)
        assert_greater_than(self.nodes[2].pruneblockchain(250), 0)
        mempool_tx = self.wallet.send_self_transfer(from_node=self.nodes[2])['txid']
        gottx = self.nodes[2].getrawtransaction(txid=mempool_tx, verbosity=2)
        assert 'fee' not in gottx

    def createrawtransaction_tests(self):
        self.log.info("Test createrawtransaction")
        # Test `createrawtransaction` required parameters
        assert_raises_rpc_error(-1, "createrawtransaction", self.nodes[0].createrawtransaction)
        assert_raises_rpc_error(-1, "createrawtransaction", self.nodes[0].createrawtransaction, [])

        # Test `createrawtransaction` invalid extra parameters
        assert_raises_rpc_error(-1, "createrawtransaction", self.nodes[0].createrawtransaction, [], [], 0, False, 2, 3, 'foo')

        # Test `createrawtransaction` invalid `inputs`
        assert_raises_rpc_error(-3, "JSON value of type string is not of expected type array", self.nodes[0].createrawtransaction, 'foo', [])
        assert_raises_rpc_error(-3, "JSON value of type string is not of expected type object", self.nodes[0].createrawtransaction, ['foo'], [])
        assert_raises_rpc_error(-3, "JSON value of type null is not of expected type string", self.nodes[0].createrawtransaction, [{}], [])
        assert_raises_rpc_error(-8, "txid must be of length 64 (not 3, for 'foo')", self.nodes[0].createrawtransaction, [{'txid': 'foo'}], [])
        txid = "ZZZ7bb8b1697ea987f3b223ba7819250cae33efacb068d23dc24859824a77844"
        assert_raises_rpc_error(-8, f"txid must be hexadecimal string (not '{txid}')", self.nodes[0].createrawtransaction, [{'txid': txid}], [])
        assert_raises_rpc_error(-8, "Invalid parameter, missing vout key", self.nodes[0].createrawtransaction, [{'txid': TXID}], [])
        assert_raises_rpc_error(-8, "Invalid parameter, missing vout key", self.nodes[0].createrawtransaction, [{'txid': TXID, 'vout': 'foo'}], [])
        assert_raises_rpc_error(-8, "Invalid parameter, vout cannot be negative", self.nodes[0].createrawtransaction, [{'txid': TXID, 'vout': -1}], [])
        # sequence number out of range
        for invalid_seq in [-1, 4294967296]:
            inputs = [{'txid': TXID, 'vout': 1, 'sequence': invalid_seq}]
            address = getnewdestination()[2]
            outputs = [{address: 1}]
            assert_raises_rpc_error(-8, 'Invalid parameter, sequence number is out of range',
                                    self.nodes[0].createrawtransaction, inputs, outputs)
        # with valid sequence number
        for valid_seq in [1000, 4294967294]:
            inputs = [{'txid': TXID, 'vout': 1, 'sequence': valid_seq}]
            address = getnewdestination()[2]
            outputs = [{address: 1}]
            rawtx = self.nodes[0].createrawtransaction(inputs, outputs)
            decrawtx = self.nodes[0].decoderawtransaction(rawtx)
            assert_equal(decrawtx['vin'][0]['sequence'], valid_seq)

        # Test `createrawtransaction` invalid `outputs`
        address = getnewdestination()[2]
        assert_raises_rpc_error(-3, "JSON value of type string is not of expected type array", self.nodes[0].createrawtransaction, [], 'foo')
        assert_raises_rpc_error(-3, "JSON value of type object is not of expected type array", self.nodes[0].createrawtransaction, [], {})
        assert_raises_rpc_error(-8, "Invalid parameter, outputs cannot be empty", self.nodes[0].createrawtransaction, [], [])
        assert_raises_rpc_error(-8, "Data must be hexadecimal string", self.nodes[0].createrawtransaction, [], [{'data': 'foo'}])
        assert_raises_rpc_error(-5, "Invalid Bitcoin address", self.nodes[0].createrawtransaction, [], [{'foo': 0}])
        assert_raises_rpc_error(-3, "Invalid amount", self.nodes[0].createrawtransaction, [], [{address: 'foo'}])
        assert_raises_rpc_error(-3, "Amount out of range", self.nodes[0].createrawtransaction, [], [{address: -1}])
        assert_raises_rpc_error(-8, "Invalid parameter, duplicated address: %s" % address, self.nodes[0].createrawtransaction, [], [{address: 1}, {address: 1}])
        assert_raises_rpc_error(-8, "Invalid parameter, duplicate key: data", self.nodes[0].createrawtransaction, [], [{"data": 'aa'}, {"data": "bb"}])
        assert_raises_rpc_error(-8, "Invalid parameter, key-value pair must contain exactly one key", self.nodes[0].createrawtransaction, [], [{'a': 1, 'b': 2}])
        assert_raises_rpc_error(-8, "Invalid parameter, key-value pair not an object as expected", self.nodes[0].createrawtransaction, [], [['key-value pair1'], ['2']])

        # Test `createrawtransaction` mismatch between sequence number(s) and `replaceable` option
        assert_raises_rpc_error(-8, "Invalid parameter combination: Sequence number(s) contradict replaceable option",
                                self.nodes[0].createrawtransaction, [{'txid': TXID, 'vout': 0, 'sequence': MAX_BIP125_RBF_SEQUENCE+1}], [{'data': '00'}], 0, True)

        # Test `createrawtransaction` invalid `locktime`
        assert_raises_rpc_error(-3, "JSON value of type string is not of expected type number", self.nodes[0].createrawtransaction, [], [], 'foo')
        assert_raises_rpc_error(-8, "Invalid parameter, locktime out of range", self.nodes[0].createrawtransaction, [], [], -1)
        assert_raises_rpc_error(-8, "Invalid parameter, locktime out of range", self.nodes[0].createrawtransaction, [], [], 4294967296)

        # Test `createrawtransaction` invalid `replaceable`
        assert_raises_rpc_error(-3, "JSON value of type string is not of expected type bool", self.nodes[0].createrawtransaction, [], [], 0, 'foo')

        # Test ordered output arrays.
        tx = tx_from_hex(self.nodes[2].createrawtransaction(inputs=[{'txid': TXID, 'vout': 9}], outputs=[{address: 99}]))
        assert_equal(len(tx.vout), 1)

        address2 = getnewdestination()[2]
        tx = tx_from_hex(self.nodes[2].createrawtransaction(inputs=[{'txid': TXID, 'vout': 9}], outputs=[{address: 99}, {address2: 99}]))
        assert_equal(len(tx.vout), 2)

        tx = tx_from_hex(self.nodes[2].createrawtransaction(inputs=[{'txid': TXID, 'vout': 9}], outputs=[{address: 99}, {address2: 99}, {'data': '99'}]))
        assert_equal(len(tx.vout), 3)

        rawtx = self.nodes[2].createrawtransaction(inputs=[{'txid': TXID, 'vout': 9}], outputs=[{address: 99}, {address2: 99}])
        tx = tx_from_hex(rawtx)
        assert_equal(tx.version, 1)

    def sendrawtransaction_tests(self):
        self.log.info("Test sendrawtransaction with missing input")
        inputs = [{'txid': TXID, 'vout': 1}]  # won't exist
        address = getnewdestination()[2]
        outputs = [{address: 4.998}]
        rawtx = self.nodes[2].createrawtransaction(inputs, outputs)
        assert_raises_rpc_error(-25, "bad-txns-inputs-missingorspent", self.nodes[2].sendrawtransaction, rawtx)

        self.log.info("Test sendrawtransaction exceeding, falling short of, and equaling maxburnamount")
        max_burn_exceeded = "Unspendable output exceeds maximum configured by user (maxburnamount)"


        # Test that spendable transaction with default maxburnamount (0) gets sent
        tx = self.wallet.create_self_transfer()['tx']
        tx_hex = tx.serialize().hex()
        self.nodes[2].sendrawtransaction(hexstring=tx_hex)

        # Test that datacarrier transaction with default maxburnamount (0) does not get sent
        tx = self.wallet.create_self_transfer()['tx']
        tx_val = 0.001
        tx.vout = [CTxOut(int(Decimal(tx_val) * COIN), CScript([OP_RETURN] + [OP_FALSE] * 30))]
        tx_hex = tx.serialize().hex()
        assert_raises_rpc_error(-25, max_burn_exceeded, self.nodes[2].sendrawtransaction, tx_hex)

        # Test that oversized script gets rejected by sendrawtransaction
        tx = self.wallet.create_self_transfer()['tx']
        tx_val = 0.001
        tx.vout = [CTxOut(int(Decimal(tx_val) * COIN), CScript([OP_FALSE] * 10001))]
        tx_hex = tx.serialize().hex()
        assert_raises_rpc_error(-25, max_burn_exceeded, self.nodes[2].sendrawtransaction, tx_hex)

        # Test that script containing invalid opcode gets rejected by sendrawtransaction
        tx = self.wallet.create_self_transfer()['tx']
        tx_val = 0.01
        tx.vout = [CTxOut(int(Decimal(tx_val) * COIN), CScript([OP_INVALIDOPCODE]))]
        tx_hex = tx.serialize().hex()
        assert_raises_rpc_error(-25, max_burn_exceeded, self.nodes[2].sendrawtransaction, tx_hex)

        # Test a transaction where our burn exceeds maxburnamount
        tx = self.wallet.create_self_transfer()['tx']
        tx_val = 0.001
        tx.vout = [CTxOut(int(Decimal(tx_val) * COIN), CScript([OP_RETURN] + [OP_FALSE] * 30))]
        tx_hex = tx.serialize().hex()
        assert_raises_rpc_error(-25, max_burn_exceeded, self.nodes[2].sendrawtransaction, tx_hex, 0, 0.0009)

        # Test a transaction where our burn falls short of maxburnamount
        tx = self.wallet.create_self_transfer()['tx']
        tx_val = 0.001
        tx.vout = [CTxOut(int(Decimal(tx_val) * COIN), CScript([OP_RETURN] + [OP_FALSE] * 30))]
        tx_hex = tx.serialize().hex()
        self.nodes[2].sendrawtransaction(hexstring=tx_hex, maxfeerate='0', maxburnamount='0.0011')

        # Test a transaction where our burn equals maxburnamount
        tx = self.wallet.create_self_transfer()['tx']
        tx_val = 0.001
        tx.vout = [CTxOut(int(Decimal(tx_val) * COIN), CScript([OP_RETURN] + [OP_FALSE] * 30))]
        tx_hex = tx.serialize().hex()
        self.nodes[2].sendrawtransaction(hexstring=tx_hex, maxfeerate='0', maxburnamount='0.001')

    def sendrawtransaction_testmempoolaccept_tests(self):
        self.log.info("Test sendrawtransaction/testmempoolaccept with maxfeerate")
        fee_exceeds_max = "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)"

        # Test a transaction with a small fee.
        # Fee rate is 0.00100000 BTC/kvB
        tx = self.wallet.create_self_transfer(fee_rate=Decimal('0.00100000'))
        # Thus, testmempoolaccept should reject
        testres = self.nodes[2].testmempoolaccept([tx['hex']], 0.00001000)[0]
        assert_equal(testres['allowed'], False)
        assert_equal(testres['reject-reason'], 'max-fee-exceeded')
        # and sendrawtransaction should throw
        assert_raises_rpc_error(-25, fee_exceeds_max, self.nodes[2].sendrawtransaction, tx['hex'], 0.00001000)
        # and the following calls should both succeed
        testres = self.nodes[2].testmempoolaccept(rawtxs=[tx['hex']])[0]
        assert_equal(testres['allowed'], True)
        self.nodes[2].sendrawtransaction(hexstring=tx['hex'])

        # Test a transaction with a large fee.
        # Fee rate is 0.20000000 BTC/kvB
        tx = self.wallet.create_self_transfer(fee_rate=Decimal("0.20000000"))
        # Thus, testmempoolaccept should reject
        testres = self.nodes[2].testmempoolaccept([tx['hex']])[0]
        assert_equal(testres['allowed'], False)
        assert_equal(testres['reject-reason'], 'max-fee-exceeded')
        # and sendrawtransaction should throw
        assert_raises_rpc_error(-25, fee_exceeds_max, self.nodes[2].sendrawtransaction, tx['hex'])
        # and the following calls should both succeed
        testres = self.nodes[2].testmempoolaccept(rawtxs=[tx['hex']], maxfeerate='0.20000000')[0]
        assert_equal(testres['allowed'], True)
        self.nodes[2].sendrawtransaction(hexstring=tx['hex'], maxfeerate='0.20000000')

        self.log.info("Test sendrawtransaction/testmempoolaccept with tx outputs already in the utxo set")
        self.generate(self.nodes[2], 1)
        for node in self.nodes:
            testres = node.testmempoolaccept([tx['hex']])[0]
            assert_equal(testres['allowed'], False)
            assert_equal(testres['reject-reason'], 'txn-already-known')
            assert_raises_rpc_error(-27, 'Transaction outputs already in utxo set', node.sendrawtransaction, tx['hex'])

    def decoderawtransaction_tests(self):
        self.log.info("Test decoderawtransaction")
        # witness transaction
        encrawtx = "01000000010000000000000072c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000000ffffffff0100e1f50500000000000102616100000000"
        decrawtx = self.nodes[0].decoderawtransaction(encrawtx)
        assert_equal(decrawtx['vout'][0]['value'], Decimal('1.00000000'))
        # Transaction with an explicitly empty witness stack.
        encrawtx = "01000000010000000000000072c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000000ffffffff0100e1f50500000000000000000000"
        decrawtx = self.nodes[0].decoderawtransaction(encrawtx)
        assert_equal(decrawtx['vout'][0]['value'], Decimal('1.00000000'))

if __name__ == '__main__':
    RawTransactionsTest(__file__).main()
