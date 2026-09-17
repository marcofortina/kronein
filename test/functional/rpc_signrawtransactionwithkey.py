#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Taproot transaction signing with signrawtransactionwithkey."""

from decimal import Decimal

from test_framework.address import (
    address_to_scriptpubkey,
    p2a,
    program_to_witness,
)
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import getnewdestination, MiniWallet
from test_framework.wallet_util import generate_keypair


class SignRawTransactionWithKeyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def send_to_address(self, address, amount):
        tx = self.wallet.send_to(
            from_node=self.nodes[0],
            scriptPubKey=address_to_scriptpubkey(address),
            amount=int(amount * COIN),
        )
        return tx["txid"], tx["sent_vout"]

    def assert_signing_completed_successfully(self, signed_tx):
        assert "errors" not in signed_tx
        assert_equal(signed_tx["complete"], True)

    def successful_signing_test(self):
        self.log.info("Sign and spend a Taproot key-path output")
        private_key, public_key = generate_keypair(wif=True)

        # Use the x-only public key directly as the output key. This exercises
        # stateless signing without requiring descriptor-derived tweak data.
        output_key = public_key[1:]
        address = program_to_witness(1, output_key)
        script_pub_key = "5120" + output_key.hex()
        txid, vout = self.send_to_address(address, 10)

        prevout = {
            "txid": txid,
            "vout": vout,
            "scriptPubKey": script_pub_key,
            "amount": 10,
        }
        spending_tx = self.nodes[0].createrawtransaction(
            [{"txid": txid, "vout": vout}],
            [{getnewdestination()[2]: Decimal("9.999")}],
        )
        signed_tx = self.nodes[0].signrawtransactionwithkey(spending_tx, [private_key], [prevout])
        self.assert_signing_completed_successfully(signed_tx)
        assert self.nodes[0].testmempoolaccept([signed_tx["hex"]])[0]["allowed"]

    def keyless_signing_test(self):
        self.log.info("Keyless signing of a pay-to-anchor input succeeds")
        txid, vout = self.send_to_address(p2a(), 49.999)
        spending_tx = self.nodes[0].createrawtransaction(
            [{"txid": txid, "vout": vout}],
            [{getnewdestination()[2]: Decimal("49.998")}],
        )
        signed_tx = self.nodes[0].signrawtransactionwithkey(spending_tx, [], [])
        self.assert_signing_completed_successfully(signed_tx)
        assert self.nodes[0].testmempoolaccept([signed_tx["hex"]])[0]["allowed"]
        assert_equal(spending_tx, signed_tx["hex"])

    def invalid_arguments_test(self):
        tx = self.nodes[0].createrawtransaction(
            [{"txid": "01" * 32, "vout": 0}],
            [{getnewdestination()[2]: Decimal("0.1")}],
        )
        private_key = self.nodes[0].get_deterministic_priv_key().key

        self.log.info("Reject an invalid sighash type")
        assert_raises_rpc_error(
            -8,
            "'all' is not a valid sighash parameter.",
            self.nodes[0].signrawtransactionwithkey,
            tx,
            [private_key],
            sighashtype="all",
        )

        self.log.info("Reject an invalid private key")
        assert_raises_rpc_error(-5, "Invalid private key", self.nodes[0].signrawtransactionwithkey, tx, ["123"])

        self.log.info("Reject invalid transaction hex")
        assert_raises_rpc_error(
            -22,
            "TX decode failed. Make sure the tx has at least one input.",
            self.nodes[0].signrawtransactionwithkey,
            tx + "00",
            [private_key],
        )

        self.log.info("Reject unsupported previous output scripts")
        for script_pub_key in ["6a00", f"0014{'00' * 20}"]:
            prevout = {
                "txid": "01" * 32,
                "vout": 0,
                "scriptPubKey": script_pub_key,
                "amount": 1,
            }
            assert_raises_rpc_error(
                -8,
                "Previous output must be Taproot or pay-to-anchor",
                self.nodes[0].signrawtransactionwithkey,
                tx,
                [private_key],
                [prevout],
            )

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])
        self.successful_signing_test()
        self.keyless_signing_test()
        self.invalid_arguments_test()


if __name__ == "__main__":
    SignRawTransactionWithKeyTest(__file__).main()
