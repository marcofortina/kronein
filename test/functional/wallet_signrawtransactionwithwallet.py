#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test transaction signing using the signrawtransactionwithwallet RPC."""

from test_framework.blocktools import (
    COINBASE_MATURITY,
)
from test_framework.address import (
    output_key_to_p2tr,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.messages import (
    tx_from_hex,
)
from test_framework.script import (
    CScript,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    OP_TRUE,
    taproot_construct,
)

from decimal import (
    Decimal,
    getcontext,
)


class SignRawTransactionWithWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def test_with_lock_outputs(self):
        self.log.info("Test correct error reporting when trying to sign a locked output")
        self.nodes[0].encryptwallet("password")
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first", self.nodes[0].signrawtransactionwithwallet, self.raw_tx)
        self.nodes[0].walletpassphrase("password", 9999)

    def test_with_invalid_sighashtype(self):
        self.log.info("Test signrawtransactionwithwallet raises if an invalid sighashtype is passed")
        assert_raises_rpc_error(-8, "'all' is not a valid sighash parameter.", self.nodes[0].signrawtransactionwithwallet, hexstring=self.raw_tx, sighashtype="all")

    def script_verification_error_test(self):
        """Create and sign a raw transaction with three unavailable native inputs.

        Expected results:

        3) The transaction has no complete set of signatures
        4) Three script verification errors occurred
        5) Script verification errors have certain properties ("txid", "vout", "witness", "sequence", "error")
        6) The verification errors refer to every input"""
        self.log.info("Test script verification errors")
        privKeys = ['cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N']
        descriptor = self.nodes[0].getdescriptorinfo(f"rawtr({privKeys[0]})")["descriptor"]
        address = self.nodes[0].deriveaddresses(descriptor)[0]
        taproot_script = self.nodes[0].getaddressinfo(address)["scriptPubKey"]

        inputs = [
            # Valid Taproot output
            {'txid': '9b907ef1e3c26fc71fe4a4b3580bc75264112f95050014157059c736f0202e71', 'vout': 0},
            # Invalid script
            {'txid': '5b8673686910442c644b1f4993d8f7753c7c8fcb5c87ee40d56eaeef25204547', 'vout': 7},
            # Missing scriptPubKey
            {'txid': '9b907ef1e3c26fc71fe4a4b3580bc75264112f95050014157059c736f0202e71', 'vout': 1},
        ]

        scripts = [
            {'txid': '9b907ef1e3c26fc71fe4a4b3580bc75264112f95050014157059c736f0202e71', 'vout': 0,
             'scriptPubKey': taproot_script, 'amount': 1},
            # A native output for which no signing key is available.
            {'txid': '5b8673686910442c644b1f4993d8f7753c7c8fcb5c87ee40d56eaeef25204547', 'vout': 7,
             'scriptPubKey': '5120' + ('00' * 32), 'amount': 1},
        ]

        outputs = {self.nodes[0].getnewaddress(): 0.1}

        rawTx = self.nodes[0].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])

        # Make sure decoderawtransaction is at least marginally sane
        decodedRawTx = self.nodes[0].decoderawtransaction(rawTx)
        for i, inp in enumerate(inputs):
            assert_equal(decodedRawTx["vin"][i]["txid"], inp["txid"])
            assert_equal(decodedRawTx["vin"][i]["vout"], inp["vout"])

        # Make sure decoderawtransaction throws if there is extra data
        assert_raises_rpc_error(-22, "TX decode failed", self.nodes[0].decoderawtransaction, rawTx + "00")

        rawTxSigned = self.nodes[0].signrawtransactionwithkey(rawTx, privKeys, scripts)

        # 3) The transaction has no complete set of signatures
        assert not rawTxSigned['complete']

        # 4) Every unavailable input has a verification error.
        assert 'errors' in rawTxSigned
        assert_equal(len(rawTxSigned['errors']), 3)

        # 5) Script verification errors have certain properties
        assert 'txid' in rawTxSigned['errors'][0]
        assert 'vout' in rawTxSigned['errors'][0]
        assert 'witness' in rawTxSigned['errors'][0]
        assert 'sequence' in rawTxSigned['errors'][0]
        assert 'error' in rawTxSigned['errors'][0]

        # 6) The verification errors refer to all three inputs.
        for error, txin in zip(rawTxSigned['errors'], inputs):
            assert_equal(error['txid'], txin['txid'])
            assert_equal(error['vout'], txin['vout'])
        assert not rawTxSigned['errors'][0]['witness']

        # Now test signing failure for a native transaction with a non-empty
        # witness on one of its unknown inputs.
        witness_tx = self.nodes[0].createrawtransaction(
            inputs[1:],
            [{self.nodes[0].getnewaddress(): 0.1}],
        )
        witness_ctx = tx_from_hex(witness_tx)
        witness_ctx.wit.vtxinwit[1].scriptWitness.stack = [b"existing", b"witness"]
        rawTxSigned = self.nodes[0].signrawtransactionwithwallet(witness_ctx.serialize_with_witness().hex())

        # 7) The transaction has no complete set of signatures
        assert not rawTxSigned['complete']

        # 8) Two script verification errors occurred
        assert 'errors' in rawTxSigned
        assert_equal(len(rawTxSigned['errors']), 2)

        # 9) Script verification errors have certain properties
        assert 'txid' in rawTxSigned['errors'][0]
        assert 'vout' in rawTxSigned['errors'][0]
        assert 'witness' in rawTxSigned['errors'][0]
        assert 'sequence' in rawTxSigned['errors'][0]
        assert 'error' in rawTxSigned['errors'][0]

        # Non-empty witness checked here
        assert_equal(rawTxSigned['errors'][1]['witness'], [b"existing".hex(), b"witness".hex()])
        assert not rawTxSigned['errors'][0]['witness']

    def test_fully_signed_tx(self):
        self.log.info("Test signing a fully signed transaction does nothing")
        self.nodes[0].walletpassphrase("password", 9999)
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)
        rawtx = self.nodes[0].createrawtransaction([], [{self.nodes[0].getnewaddress(): 10}])
        fundedtx = self.nodes[0].fundrawtransaction(rawtx)
        signedtx = self.nodes[0].signrawtransactionwithwallet(fundedtx["hex"])
        assert_equal(signedtx["complete"], True)
        signedtx2 = self.nodes[0].signrawtransactionwithwallet(signedtx["hex"])
        assert_equal(signedtx2["complete"], True)
        assert_equal(signedtx["hex"], signedtx2["hex"])
        self.nodes[0].walletlock()

    def create_taproot_script_output(self, script):
        taproot_info = taproot_construct((1).to_bytes(32, "big"), [("only-path", script)])
        return output_key_to_p2tr(taproot_info.output_pubkey), taproot_info

    def set_taproot_script_witness(self, tx, script, taproot_info):
        ctx = tx_from_hex(tx)
        leaf_info = taproot_info.leaves["only-path"]
        control_block = bytes([leaf_info.version | taproot_info.negflag]) + taproot_info.internal_pubkey
        ctx.wit.vtxinwit[0].scriptWitness.stack = [CScript([OP_TRUE]), script, control_block]
        return ctx.serialize_with_witness().hex()

    def test_signing_with_csv(self):
        self.log.info("Test signing a transaction containing a fully signed CSV input")
        self.nodes[0].walletpassphrase("password", 9999)
        getcontext().prec = 8

        # Create a Taproot script path with CSV
        script = CScript([1, OP_CHECKSEQUENCEVERIFY, OP_DROP])
        address, taproot_info = self.create_taproot_script_output(script)

        # Fund that address and make the spend
        utxo1 = self.create_outpoints(self.nodes[0], outputs=[{address: 1}])[0]
        self.generate(self.nodes[0], 1)
        utxo2 = self.nodes[0].listunspent()[0]
        amt = Decimal(1) + utxo2["amount"] - Decimal(0.00001)
        tx = self.nodes[0].createrawtransaction(
            [{**utxo1, "sequence": 1},{"txid": utxo2["txid"], "vout": utxo2["vout"]}],
            [{self.nodes[0].getnewaddress(): amt}],
            self.nodes[0].getblockcount()
        )

        tx = self.set_taproot_script_witness(tx, script, taproot_info)

        # Sign and send the transaction
        signed = self.nodes[0].signrawtransactionwithwallet(tx)
        assert_equal(signed["complete"], True)
        self.nodes[0].sendrawtransaction(signed["hex"])

    def test_signing_with_cltv(self):
        self.log.info("Test signing a transaction containing a fully signed CLTV input")
        self.nodes[0].walletpassphrase("password", 9999)
        getcontext().prec = 8

        # Create a Taproot script path with CLTV
        script = CScript([100, OP_CHECKLOCKTIMEVERIFY, OP_DROP])
        address, taproot_info = self.create_taproot_script_output(script)

        # Fund that address and make the spend
        utxo1 = self.create_outpoints(self.nodes[0], outputs=[{address: 1}])[0]
        self.generate(self.nodes[0], 1)
        utxo2 = self.nodes[0].listunspent()[0]
        amt = Decimal(1) + utxo2["amount"] - Decimal(0.00001)
        tx = self.nodes[0].createrawtransaction(
            [utxo1, {"txid": utxo2["txid"], "vout": utxo2["vout"]}],
            [{self.nodes[0].getnewaddress(): amt}],
            self.nodes[0].getblockcount()
        )

        tx = self.set_taproot_script_witness(tx, script, taproot_info)

        # Sign and send the transaction
        signed = self.nodes[0].signrawtransactionwithwallet(tx)
        assert_equal(signed["complete"], True)
        self.nodes[0].sendrawtransaction(signed["hex"])

    def test_signing_with_missing_prevtx_info(self):
        txid = "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000"
        self.log.info("Test signing with missing Taproot prevtx info")
        addr = self.nodes[0].getnewaddress()
        pubkey = self.nodes[0].getaddressinfo(addr)["scriptPubKey"]
        inputs = [{'txid': txid, 'vout': 3, 'sequence': 1000}]
        outputs = {self.nodes[0].getnewaddress(): 1}
        rawtx = self.nodes[0].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])

        prevtx = dict(txid=txid, scriptPubKey=pubkey, vout=3, amount=1)
        assert self.nodes[0].signrawtransactionwithwallet(rawtx, [prevtx])["complete"]

        assert_raises_rpc_error(-3, "Missing amount", self.nodes[0].signrawtransactionwithwallet, rawtx, [{
            "txid": txid,
            "scriptPubKey": pubkey,
            "vout": 3,
        }])
        assert_raises_rpc_error(-3, "Missing vout", self.nodes[0].signrawtransactionwithwallet, rawtx, [{
            "txid": txid,
            "scriptPubKey": pubkey,
            "amount": 1,
        }])
        assert_raises_rpc_error(-3, "Missing txid", self.nodes[0].signrawtransactionwithwallet, rawtx, [{
            "scriptPubKey": pubkey,
            "vout": 3,
            "amount": 1,
        }])
        assert_raises_rpc_error(-3, "Missing scriptPubKey", self.nodes[0].signrawtransactionwithwallet, rawtx, [{
            "txid": txid,
            "vout": 3,
            "amount": 1,
        }])

    def run_test(self):
        self.raw_tx = self.nodes[0].createrawtransaction(
            [{"txid": "01" * 32, "vout": 0}],
            [{self.nodes[0].getnewaddress(): 0.1}],
        )
        self.script_verification_error_test()
        self.test_with_lock_outputs()
        self.test_with_invalid_sighashtype()
        self.test_fully_signed_tx()
        self.test_signing_with_csv()
        self.test_signing_with_cltv()
        self.test_signing_with_missing_prevtx_info()


if __name__ == '__main__':
    SignRawTransactionWithWalletTest(__file__).main()
