#!/usr/bin/env python3
# Copyright (c) 2014-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the fundrawtransaction RPC."""


from decimal import Decimal
from itertools import product
from math import ceil
from test_framework.address import address_to_scriptpubkey

from test_framework.descriptors import descsum_create
from test_framework.messages import (
    COIN,
    CTransaction,
    CTxOut,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_not_equal,
    assert_approx,
    assert_equal,
    assert_fee_amount,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
    count_bytes,
)
from test_framework.wallet_util import generate_keypair, WalletUnlock

ERR_NOT_ENOUGH_PRESET_INPUTS = "The preselected coins total amount does not cover the transaction target. " \
                               "Please allow other inputs to be automatically selected or include more coins manually"

def get_unspent(listunspent, amount):
    for utx in listunspent:
        if utx['amount'] == amount:
            return utx
    raise AssertionError('Could not find unspent with amount={}'.format(amount))

class RawTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [[
            "-minrelaytxfee=0.00001000",
        ] for i in range(self.num_nodes)]

        self.setup_clean_chain = True
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True
        self.rpc_timeout = 90  # to prevent timeouts in `test_transaction_too_large`
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

        self.connect_nodes(0, 1)
        self.connect_nodes(1, 2)
        self.connect_nodes(0, 2)
        self.connect_nodes(0, 3)

    def unlock_utxos(self, wallet):
        """
        Unlock all UTXOs except the watchonly one
        """
        to_keep = []
        if self.watchonly_utxo is not None:
            to_keep.append(self.watchonly_utxo)
        wallet.lockunspent(True)
        wallet.lockunspent(False, to_keep)

    def run_test(self):
        self.watchonly_utxo = None
        self.log.info("Connect nodes, set fees, generate blocks, and sync")
        self.min_relay_tx_fee = self.nodes[0].getmempoolinfo()['minrelaytxfee']
        # This test is not meant to test fee estimation and we'd like
        # to be sure all txs are sent at a consistent desired feerate
        self.fee_rate_sats_per_vb = self.min_relay_tx_fee * Decimal(1e8) / 1000

        # if the fee's positive delta is higher than this value tests will fail,
        # neg. delta always fail the tests.
        # The size of the signature of every input may be at most 2 bytes larger
        # than a minimum sized signature.

        #            = 2 bytes * minRelayTxFeePerByte
        self.fee_tolerance = 2 * self.min_relay_tx_fee / 1000

        self.generate(self.nodes[2], 1)
        self.generate(self.nodes[0], 121)

        self.test_add_inputs_default_value()
        self.test_preset_inputs_selection()
        self.test_weight_limits()
        self.test_change_position()
        self.test_simple()
        self.test_simple_two_coins()
        self.test_simple_two_outputs()
        self.test_change()
        self.test_no_change()
        self.test_invalid_option()
        self.test_invalid_change_address()
        self.test_valid_change_address()
        self.test_coin_selection()
        self.test_two_vin()
        self.test_two_vin_two_vout()
        self.test_invalid_input()
        self.test_locked_wallet()
        self.test_many_inputs_fee()
        self.test_many_inputs_send()
        self.test_op_return()
        self.test_watchonly()
        self.test_all_watched_funds()
        self.test_option_feerate()
        self.test_address_reuse()
        self.test_option_subtract_fee_from_outputs()
        self.test_subtract_fee_with_presets()
        self.test_transaction_too_large()
        self.test_include_unsafe()
        self.test_external_inputs()
        self.test_input_confs_control()
        self.test_duplicate_outputs()
        self.test_cannot_cover_fees()

    def test_duplicate_outputs(self):
        self.log.info("Test deserializing and funding a transaction with duplicate outputs")
        self.nodes[1].createwallet("fundtx_duplicate_outputs")
        w = self.nodes[1].get_wallet_rpc("fundtx_duplicate_outputs")

        addr = w.getnewaddress()
        self.nodes[0].sendtoaddress(addr, 5, fee_rate=self.fee_rate_sats_per_vb)
        self.generate(self.nodes[0], 1)

        address = self.nodes[0].getnewaddress()
        tx = CTransaction()
        tx.vin = []
        tx.vout = [CTxOut(1 * COIN, bytearray(address_to_scriptpubkey(address)))] * 2
        tx.nLockTime = 0
        tx_hex = tx.serialize().hex()
        res = w.fundrawtransaction(tx_hex, add_inputs=True, fee_rate=self.fee_rate_sats_per_vb)
        signed_res = w.signrawtransactionwithwallet(res["hex"])
        txid = w.sendrawtransaction(signed_res["hex"])
        assert self.nodes[1].getrawtransaction(txid)

        self.log.info("Test SFFO with duplicate outputs")

        res_sffo = w.fundrawtransaction(tx_hex, add_inputs=True, subtractFeeFromOutputs=[0,1], fee_rate=self.fee_rate_sats_per_vb)
        signed_res_sffo = w.signrawtransactionwithwallet(res_sffo["hex"])
        txid_sffo = w.sendrawtransaction(signed_res_sffo["hex"])
        assert self.nodes[1].getrawtransaction(txid_sffo)

    def test_change_position(self):
        """Ensure setting changePosition in fundraw with an exact match is handled properly."""
        self.log.info("Test fundrawtxn changePosition option")
        rawmatch = self.nodes[2].createrawtransaction([], [{self.nodes[2].getnewaddress():50}])
        rawmatch = self.nodes[2].fundrawtransaction(rawmatch, changePosition=1, subtractFeeFromOutputs=[0], fee_rate=self.fee_rate_sats_per_vb)
        assert_equal(rawmatch["changepos"], -1)

        self.nodes[3].createwallet(wallet_name="wwatch", disable_private_keys=True)
        wwatch = self.nodes[3].get_wallet_rpc('wwatch')
        watchonly_address = self.nodes[0].getnewaddress()
        self.watchonly_amount = Decimal(200)
        import_res = wwatch.importdescriptors([{"desc": self.nodes[0].getaddressinfo(watchonly_address)["desc"], "timestamp": "now"}])
        assert_equal(import_res[0]["success"], True)
        self.watchonly_utxo = self.create_outpoints(self.nodes[0], outputs=[{watchonly_address: self.watchonly_amount}])[0]

        # Lock UTXO so nodes[0] doesn't accidentally spend it
        self.nodes[0].lockunspent(False, [self.watchonly_utxo])

        self.nodes[0].sendtoaddress(self.nodes[3].get_wallet_rpc(self.default_wallet_name).getnewaddress(), self.watchonly_amount / 10, fee_rate=self.fee_rate_sats_per_vb)

        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1.5, fee_rate=self.fee_rate_sats_per_vb)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1.0, fee_rate=self.fee_rate_sats_per_vb)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 5.0, fee_rate=self.fee_rate_sats_per_vb)

        self.generate(self.nodes[0], 1)

        wwatch.unloadwallet()

    def test_simple(self):
        self.log.info("Test fundrawtxn")
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 1.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        assert len(dec_tx['vin']) > 0  #test that we have enough inputs

    def test_simple_two_coins(self):
        self.log.info("Test fundrawtxn with 2 coins")
        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 2.2 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        assert len(dec_tx['vin']) > 0  #test if we have enough inputs
        assert_equal(dec_tx['vin'][0]['scriptSig']['hex'], '')

    def test_simple_two_outputs(self):
        self.log.info("Test fundrawtxn with 2 outputs")

        inputs  = [ ]
        outputs = { self.nodes[0].getnewaddress() : 2.6, self.nodes[1].getnewaddress() : 2.5 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])

        assert len(dec_tx['vin']) > 0
        assert_equal(dec_tx['vin'][0]['scriptSig']['hex'], '')

    def test_change(self):
        self.log.info("Test fundrawtxn with a vin > required amount")
        utx = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']}]
        outputs = { self.nodes[0].getnewaddress() : 1.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)
        fee = rawtxfund['fee']
        self.test_no_change_fee = fee  # Use the same fee for the next tx
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        for out in dec_tx['vout']:
            totalOut += out['value']

        assert_equal(fee + totalOut, utx['amount']) #compare vin total and totalout+fee

    def test_no_change(self):
        self.log.info("Test fundrawtxn not having a change output")
        utx = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']}]
        outputs = {self.nodes[0].getnewaddress(): Decimal(5.0) - self.test_no_change_fee - self.fee_tolerance}
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)
        fee = rawtxfund['fee']
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        totalOut = 0
        for out in dec_tx['vout']:
            totalOut += out['value']

        assert_equal(rawtxfund['changepos'], -1)
        assert_equal(fee + totalOut, utx['amount']) #compare vin total and totalout+fee

    def test_invalid_option(self):
        self.log.info("Test fundrawtxn with an invalid option")
        utx = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']} ]
        outputs = { self.nodes[0].getnewaddress() : Decimal(4.0) }
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        assert_raises_rpc_error(-8, "Unknown named parameter foo", self.nodes[2].fundrawtransaction, rawtx, foo='bar')

    def test_invalid_change_address(self):
        self.log.info("Test fundrawtxn with an invalid change address")
        utx = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']} ]
        outputs = { self.nodes[0].getnewaddress() : Decimal(4.0) }
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        assert_raises_rpc_error(-5, "Change address must be a valid bitcoin address", self.nodes[2].fundrawtransaction, rawtx, changeAddress='foobar')

    def test_valid_change_address(self):
        self.log.info("Test fundrawtxn with a provided change address")
        utx = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']} ]
        outputs = { self.nodes[0].getnewaddress() : Decimal(4.0) }
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        change = self.nodes[2].getnewaddress()
        assert_raises_rpc_error(-8, "changePosition out of bounds", self.nodes[2].fundrawtransaction, rawtx, changeAddress=change, changePosition=2)
        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, changeAddress=change, changePosition=0, fee_rate=self.fee_rate_sats_per_vb)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        out = dec_tx['vout'][0]
        assert_equal(change, out['scriptPubKey']['address'])

    def test_coin_selection(self):
        self.log.info("Test fundrawtxn with a vin < required amount")
        utx = get_unspent(self.nodes[2].listunspent(), 1)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']}]
        outputs = { self.nodes[0].getnewaddress() : 1.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])

        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        # Should fail without add_inputs:
        assert_raises_rpc_error(-4, ERR_NOT_ENOUGH_PRESET_INPUTS, self.nodes[2].fundrawtransaction, rawtx, add_inputs=False)
        # add_inputs is enabled by default
        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)

        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        matchingOuts = 0
        for i, out in enumerate(dec_tx['vout']):
            if out['scriptPubKey']['address'] in outputs:
                matchingOuts+=1
            else:
                assert_equal(i, rawtxfund['changepos'])

        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])
        assert_equal("", dec_tx['vin'][0]['scriptSig']['hex'])

        assert_equal(matchingOuts, 1)
        assert_equal(len(dec_tx['vout']), 2)

    def test_two_vin(self):
        self.log.info("Test fundrawtxn with 2 vins")
        utx = get_unspent(self.nodes[2].listunspent(), 1)
        utx2 = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']},{'txid' : utx2['txid'], 'vout' : utx2['vout']} ]
        outputs = { self.nodes[0].getnewaddress() : 6.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        # Should fail without add_inputs:
        assert_raises_rpc_error(-4, ERR_NOT_ENOUGH_PRESET_INPUTS, self.nodes[2].fundrawtransaction, rawtx, add_inputs=False)
        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, add_inputs=True, fee_rate=self.fee_rate_sats_per_vb)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        matchingOuts = 0
        for out in dec_tx['vout']:
            if out['scriptPubKey']['address'] in outputs:
                matchingOuts+=1

        assert_equal(matchingOuts, 1)
        assert_equal(len(dec_tx['vout']), 2)

        matchingIns = 0
        for vinOut in dec_tx['vin']:
            for vinIn in inputs:
                if vinIn['txid'] == vinOut['txid']:
                    matchingIns+=1

        assert_equal(matchingIns, 2) #we now must see two vins identical to vins given as params

    def test_two_vin_two_vout(self):
        self.log.info("Test fundrawtxn with 2 vins and 2 vouts")
        utx = get_unspent(self.nodes[2].listunspent(), 1)
        utx2 = get_unspent(self.nodes[2].listunspent(), 5)

        inputs  = [ {'txid' : utx['txid'], 'vout' : utx['vout']},{'txid' : utx2['txid'], 'vout' : utx2['vout']} ]
        outputs = { self.nodes[0].getnewaddress() : 6.0, self.nodes[0].getnewaddress() : 1.0 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)
        assert_equal(utx['txid'], dec_tx['vin'][0]['txid'])

        # Should fail without add_inputs:
        assert_raises_rpc_error(-4, ERR_NOT_ENOUGH_PRESET_INPUTS, self.nodes[2].fundrawtransaction, rawtx, add_inputs=False)
        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, add_inputs=True, fee_rate=self.fee_rate_sats_per_vb)

        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])
        matchingOuts = 0
        for out in dec_tx['vout']:
            if out['scriptPubKey']['address'] in outputs:
                matchingOuts+=1

        assert_equal(matchingOuts, 2)
        assert_equal(len(dec_tx['vout']), 3)

    def test_invalid_input(self):
        self.log.info("Test fundrawtxn with an invalid vin")
        txid = "1c7f966dab21119bac53213a2bc7532bff1fa844c124fd750a7d0b1332440bd1"
        vout = 0
        inputs  = [ {'txid' : txid, 'vout' : vout} ] #invalid vin!
        outputs = { self.nodes[0].getnewaddress() : 1.0}
        rawtx   = self.nodes[2].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        assert_raises_rpc_error(-4, "Unable to find UTXO for external input", self.nodes[2].fundrawtransaction, rawtx)

    def test_locked_wallet(self):
        self.log.info("Test fundrawtxn with locked wallet and hardened derivation")

        df_wallet = self.nodes[1].get_wallet_rpc(self.default_wallet_name)
        self.nodes[1].createwallet(wallet_name="locked_wallet")
        wallet = self.nodes[1].get_wallet_rpc("locked_wallet")

        # Add some balance to the wallet (this will be reverted at the end of the test)
        self.nodes[0].sendtoaddress(wallet.getnewaddress(), 5)
        self.generate(self.nodes[0], 1)

        # Encrypt wallet and import descriptors
        wallet.encryptwallet("test")

        with WalletUnlock(wallet, "test"):
            wallet.importdescriptors([{
                'desc': descsum_create('tr(tprv8ZgxMBicQKsPdYeeZbPSKd2KYLmeVKtcFA7kqCxDvDR13MQ6us8HopUR2wLcS2ZKPhLyKsqpDL2FtL73LMHcgoCL7DXsciA8eX8nbjCR2eG/0h/*h)'),
                'timestamp': 'now',
                'active': True
            },
            {
                'desc': descsum_create('tr(tprv8ZgxMBicQKsPdYeeZbPSKd2KYLmeVKtcFA7kqCxDvDR13MQ6us8HopUR2wLcS2ZKPhLyKsqpDL2FtL73LMHcgoCL7DXsciA8eX8nbjCR2eG/1h/*h)'),
                'timestamp': 'now',
                'active': True,
                'internal': True
            }])

        # Drain the keypool.
        wallet.getnewaddress()
        wallet.getrawchangeaddress()

        # Choose input
        inputs = wallet.listunspent()

        outputs = {self.nodes[0].getnewaddress(): inputs[0]["amount"]}
        rawtx = wallet.createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        # fund a transaction that does not require a new key for the change output
        funded_tx = wallet.fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb, subtractFeeFromOutputs=[0])
        assert_equal(funded_tx["changepos"], -1)

        # fund a transaction that requires a new key for the change output
        # creating the key must be impossible because the wallet is locked
        outputs = {self.nodes[0].getnewaddress(): inputs[0]["amount"] - Decimal("0.1")}
        rawtx = wallet.createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        assert_raises_rpc_error(-4, "Transaction needs a change address, but we can't generate it.", wallet.fundrawtransaction, rawtx)

        # Refill the keypool.
        with WalletUnlock(wallet, "test"):
            wallet.keypoolrefill(8) #need to refill the keypool to get an internal change address

        assert_raises_rpc_error(-13, "walletpassphrase", wallet.sendtoaddress, self.nodes[0].getnewaddress(), 1.2)

        oldBalance = self.nodes[0].getbalance()

        inputs = []
        outputs = {self.nodes[0].getnewaddress():1.1}
        rawtx = wallet.createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])

        fundedTx = wallet.fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)
        assert_not_equal(fundedTx["changepos"], -1)

        # Now we need to unlock.
        with WalletUnlock(wallet, "test"):
            signedTx = wallet.signrawtransactionwithwallet(fundedTx['hex'])
            wallet.sendrawtransaction(signedTx['hex'])
            self.generate(self.nodes[1], 1)

            # Make sure funds are received at node1.
            assert_equal(oldBalance+Decimal('51.10000000'), self.nodes[0].getbalance())

            # Restore pre-test wallet state
            wallet.sendall(recipients=[df_wallet.getnewaddress(), df_wallet.getnewaddress(), df_wallet.getnewaddress()], fee_rate=self.fee_rate_sats_per_vb)
        wallet.unloadwallet()
        self.generate(self.nodes[1], 1)

    def test_many_inputs_fee(self):
        """Multiple (~19) inputs tx test | Compare fee."""
        self.log.info("Test fundrawtxn fee with many inputs")

        # Empty node1, send some small coins from node0 to node1.
        self.nodes[1].sendall(recipients=[self.nodes[0].getnewaddress()], fee_rate=self.fee_rate_sats_per_vb)
        self.generate(self.nodes[1], 1)

        for _ in range(20):
            self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 0.01, fee_rate=self.fee_rate_sats_per_vb)
        self.generate(self.nodes[0], 1)

        # Fund a tx with ~20 small inputs.
        inputs = []
        outputs = {self.nodes[0].getnewaddress():0.15,self.nodes[0].getnewaddress():0.04}
        rawtx = self.nodes[1].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        fundedTx = self.nodes[1].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)

        # Create same transaction over sendtoaddress.
        txId = self.nodes[1].sendmany(outputs, fee_rate=self.fee_rate_sats_per_vb)
        signedFee = self.nodes[1].getmempoolentry(txId)['fees']['base']

        # Compare fee.
        feeDelta = Decimal(fundedTx['fee']) - Decimal(signedFee)
        assert feeDelta >= 0 and feeDelta <= self.fee_tolerance * 19  #~19 inputs

    def test_many_inputs_send(self):
        """Multiple (~19) inputs tx test | sign/send."""
        self.log.info("Test fundrawtxn sign+send with many inputs")

        # Again, empty node1, send some small coins from node0 to node1.
        self.nodes[1].sendall(recipients=[self.nodes[0].getnewaddress()], fee_rate=self.fee_rate_sats_per_vb)
        self.generate(self.nodes[1], 1)

        for _ in range(20):
            self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 0.01, fee_rate=self.fee_rate_sats_per_vb)
        self.generate(self.nodes[0], 1)

        # Fund a tx with ~20 small inputs.
        oldBalance = self.nodes[0].getbalance()

        inputs = []
        outputs = {self.nodes[0].getnewaddress():0.15,self.nodes[0].getnewaddress():0.04}
        rawtx = self.nodes[1].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])
        fundedTx = self.nodes[1].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)
        fundedAndSignedTx = self.nodes[1].signrawtransactionwithwallet(fundedTx['hex'])
        self.nodes[1].sendrawtransaction(fundedAndSignedTx['hex'])
        self.generate(self.nodes[1], 1)
        assert_equal(oldBalance+Decimal('50.19000000'), self.nodes[0].getbalance()) #0.19+block reward

    def test_op_return(self):
        self.log.info("Test fundrawtxn with OP_RETURN and no vin")

        rawtx   = "0100000000010000000000000000066a047465737400000000"
        dec_tx  = self.nodes[2].decoderawtransaction(rawtx)

        assert_equal(len(dec_tx['vin']), 0)
        assert_equal(len(dec_tx['vout']), 1)

        rawtxfund = self.nodes[2].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)
        dec_tx  = self.nodes[2].decoderawtransaction(rawtxfund['hex'])

        assert_greater_than(len(dec_tx['vin']), 0) # at least one vin
        assert_equal(len(dec_tx['vout']), 2) # one change output added

    def test_watchonly(self):
        self.log.info("Test fundrawtxn using only watchonly")

        inputs = []
        outputs = {self.nodes[2].getnewaddress(): self.watchonly_amount / 2}
        rawtx = self.nodes[3].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])

        self.nodes[3].loadwallet('wwatch')
        wwatch = self.nodes[3].get_wallet_rpc('wwatch')
        # Setup change addresses for the watchonly wallet
        desc_import = [{
            "desc": descsum_create("tr(tpubD6NzVbkrYhZ4YNXVQbNhMK1WqguFsUXceaVJKbmno2aZ3B6QfbMeraaYvnBSGpV3vxLyTTK9DYT1yoEck4XUScMzXoQ2U2oSmE2JyMedq3H/1/*)"),
            "timestamp": "now",
            "internal": True,
            "active": True,
            "keypool": True,
            "range": [0, 100],
            "watchonly": True,
        }]
        wwatch.importdescriptors(desc_import)

        result = wwatch.fundrawtransaction(rawtx)
        res_dec = self.nodes[0].decoderawtransaction(result["hex"])
        assert_equal(len(res_dec["vin"]), 1)
        assert_equal(res_dec["vin"][0]["txid"], self.watchonly_utxo['txid'])

        assert "fee" in result.keys()
        assert_greater_than(result["changepos"], -1)

        wwatch.unloadwallet()

    def test_all_watched_funds(self):
        self.log.info("Test fundrawtxn using entirety of watched funds")

        inputs = []
        outputs = {self.nodes[2].getnewaddress(): self.watchonly_amount}
        rawtx = self.nodes[3].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])

        self.nodes[3].loadwallet('wwatch')
        wwatch = self.nodes[3].get_wallet_rpc('wwatch')
        w3 = self.nodes[3].get_wallet_rpc(self.default_wallet_name)
        result = wwatch.fundrawtransaction(rawtx, changeAddress=w3.getrawchangeaddress(), subtractFeeFromOutputs=[0])
        res_dec = self.nodes[0].decoderawtransaction(result["hex"])
        assert_equal(len(res_dec["vin"]), 1)
        assert res_dec["vin"][0]["txid"] == self.watchonly_utxo['txid']

        assert_greater_than(result["fee"], 0)
        assert_equal(result["changepos"], -1)
        assert_equal(result["fee"] + res_dec["vout"][0]["value"], self.watchonly_amount)

        signedtx = wwatch.signrawtransactionwithwallet(result["hex"])
        assert not signedtx["complete"]
        signedtx = self.nodes[0].signrawtransactionwithwallet(signedtx["hex"])
        assert signedtx["complete"]
        self.nodes[0].sendrawtransaction(signedtx["hex"])
        self.generate(self.nodes[0], 1)

        wwatch.unloadwallet()

    def test_option_feerate(self):
        self.log.info("Test fundrawtxn with explicit fee rates (fee_rate sat/vB and feeRate BTC/kvB)")
        node = self.nodes[3]
        # Make sure there is exactly one input so coin selection can't skew the result.
        assert_equal(len(self.nodes[3].listunspent(1)), 1)
        inputs = []
        outputs = {node.getnewaddress() : 1}
        rawtx = node.createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])

        result = node.fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)  # uses self.min_relay_tx_fee (set by fee_rate in sat/vB)
        btc_kvb_to_sat_vb = 100000  # (1e5)
        result1 = node.fundrawtransaction(rawtx, fee_rate=str(2 * btc_kvb_to_sat_vb * self.min_relay_tx_fee))
        result2 = node.fundrawtransaction(rawtx, feeRate=2 * self.min_relay_tx_fee)
        result3 = node.fundrawtransaction(rawtx, fee_rate=10 * btc_kvb_to_sat_vb * self.min_relay_tx_fee)
        result4 = node.fundrawtransaction(rawtx, feeRate=str(10 * self.min_relay_tx_fee))

        result_fee_rate = result['fee'] * 1000 / count_bytes(result['hex'])
        assert_fee_amount(result1['fee'], count_bytes(result1['hex']), 2 * result_fee_rate)
        assert_fee_amount(result2['fee'], count_bytes(result2['hex']), 2 * result_fee_rate)
        assert_fee_amount(result3['fee'], count_bytes(result3['hex']), 10 * result_fee_rate)
        assert_fee_amount(result4['fee'], count_bytes(result4['hex']), 10 * result_fee_rate)

        # Test that funding non-standard "zero-fee" transactions is valid.
        for param, zero_value in product(["fee_rate", "feeRate"], [0, 0.000, 0.00000000, "0", "0.000", "0.00000000"]):
            assert_equal(self.nodes[3].fundrawtransaction(rawtx, {param: zero_value})["fee"], 0)

        # Reusing the same fee rate must produce the same fee.
        assert_equal(node.fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb)["fee"], result["fee"])
        # Expect fee to be 10,000x higher when an explicit fee rate 10,000x greater is specified.
        high_fee_result = node.fundrawtransaction(rawtx, fee_rate=10000)
        assert_approx(high_fee_result["fee"], vexp=result["fee"] * 10000, vspan=0.0001)

        self.log.info("Test fundrawtxn with invalid estimate_mode settings")
        for k, v in {"number": 42, "object": {"foo": "bar"}}.items():
            assert_raises_rpc_error(-3, f"JSON value of type {k} for field estimate_mode is not of expected type string",
                node.fundrawtransaction, rawtx, estimate_mode=v, conf_target=0.1, add_inputs=True)
        for mode in ["", "foo", Decimal("3.141592")]:
            assert_raises_rpc_error(-8, 'Invalid estimate_mode parameter, must be one of: "unset", "economical", "conservative"',
                node.fundrawtransaction, rawtx, estimate_mode=mode, conf_target=0.1, add_inputs=True)

        self.log.info("Test fundrawtxn with invalid conf_target settings")
        for mode in ["unset", "economical", "conservative"]:
            self.log.debug("{}".format(mode))
            for k, v in {"string": "", "object": {"foo": "bar"}}.items():
                assert_raises_rpc_error(-3, f"JSON value of type {k} for field conf_target is not of expected type number",
                    node.fundrawtransaction, rawtx, estimate_mode=mode, conf_target=v, add_inputs=True)
            for n in [-1, 0, 1009]:
                assert_raises_rpc_error(-8, "Invalid conf_target, must be between 1 and 1008",  # max value of 1008 per src/policy/fees/block_policy_estimator.h
                    node.fundrawtransaction, rawtx, estimate_mode=mode, conf_target=n, add_inputs=True)

        self.log.info("Test invalid fee rate settings")
        for param, value in {("fee_rate", 100000), ("feeRate", 1.000)}:
            assert_raises_rpc_error(-4, "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)",
                node.fundrawtransaction, rawtx, add_inputs=True, **{param: value})
            assert_raises_rpc_error(-3, "Amount out of range",
                node.fundrawtransaction, rawtx, add_inputs=True, **{param: -1})
            assert_raises_rpc_error(-3, "Amount is not a number or string",
                node.fundrawtransaction, rawtx, add_inputs=True, **{param: {"foo": "bar"}})
            # Test fee rate values that don't pass fixed-point parsing checks.
            for invalid_value in ["", 0.000000001, 1e-09, 1.111111111, 1111111111111111, "31.999999999999999999999"]:
                assert_raises_rpc_error(-3, "Invalid amount", node.fundrawtransaction, rawtx, add_inputs=True, **{param: invalid_value})
        # Test fee_rate values that cannot be represented in sat/vB.
        for invalid_value in [0.0001, 0.00000001, 0.00099999, 31.99999999]:
            assert_raises_rpc_error(-3, "Invalid amount",
                node.fundrawtransaction, rawtx, fee_rate=invalid_value, add_inputs=True)

        self.log.info("Test min fee rate checks are bypassed with fundrawtxn, e.g. a fee_rate under 1 sat/vB is allowed")
        node.fundrawtransaction(rawtx, fee_rate=0.999, add_inputs=True)
        node.fundrawtransaction(rawtx, feeRate=0.00000999, add_inputs=True)

        self.log.info("- raises RPC error if both feeRate and fee_rate are passed")
        assert_raises_rpc_error(-8, "Cannot specify both fee_rate (sat/vB) and feeRate (BTC/kvB)",
            node.fundrawtransaction, rawtx, fee_rate=0.1, feeRate=0.1, add_inputs=True)

        self.log.info("- raises RPC error if both feeRate and estimate_mode passed")
        assert_raises_rpc_error(-8, "Cannot specify both estimate_mode and feeRate",
            node.fundrawtransaction, rawtx, estimate_mode="economical", feeRate=0.1, add_inputs=True)

        for param in ["feeRate", "fee_rate"]:
            self.log.info("- raises RPC error if both {} and conf_target are passed".format(param))
            assert_raises_rpc_error(-8, "Cannot specify both conf_target and {}. Please provide either a confirmation "
                "target in blocks for automatic fee estimation, or an explicit fee rate.".format(param),
                node.fundrawtransaction, rawtx, {param: 1, "conf_target": 1, "add_inputs": True})

        self.log.info("- raises RPC error if both fee_rate and estimate_mode are passed")
        assert_raises_rpc_error(-8, "Cannot specify both estimate_mode and fee_rate",
            node.fundrawtransaction, rawtx, fee_rate=1, estimate_mode="economical", add_inputs=True)

    def test_address_reuse(self):
        """Test no address reuse occurs."""
        self.log.info("Test fundrawtxn does not reuse addresses")

        rawtx = self.nodes[3].createrawtransaction(inputs=[], outputs=[{self.nodes[3].getnewaddress(): 1}])
        result3 = self.nodes[3].fundrawtransaction(rawtx)
        res_dec = self.nodes[0].decoderawtransaction(result3["hex"])
        changeaddress = ""
        for out in res_dec['vout']:
            if out['value'] > 1.0:
                changeaddress += out['scriptPubKey']['address']
        assert_not_equal(changeaddress, "")
        nextaddr = self.nodes[3].getnewaddress()
        # Now the change address key should be removed from the keypool.
        assert_not_equal(changeaddress, nextaddr)

    def test_option_subtract_fee_from_outputs(self):
        self.log.info("Test fundrawtxn subtractFeeFromOutputs option")

        # Make sure there is exactly one input so coin selection can't skew the result.
        assert_equal(len(self.nodes[3].listunspent(1)), 1)

        inputs = []
        outputs = {self.nodes[2].getnewaddress(): 1}
        rawtx = self.nodes[3].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])

        # Test subtract fee from outputs with feeRate (BTC/kvB)
        result = [self.nodes[3].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb),
            self.nodes[3].fundrawtransaction(rawtx, subtractFeeFromOutputs=[], fee_rate=self.fee_rate_sats_per_vb),  # empty subtraction list
            self.nodes[3].fundrawtransaction(rawtx, subtractFeeFromOutputs=[0], fee_rate=self.fee_rate_sats_per_vb), # uses self.min_relay_tx_fee (set by fee_rate in sat/vB)
            self.nodes[3].fundrawtransaction(rawtx, feeRate=2 * self.min_relay_tx_fee),
            self.nodes[3].fundrawtransaction(rawtx, feeRate=2 * self.min_relay_tx_fee, subtractFeeFromOutputs=[0]),]
        dec_tx = [self.nodes[3].decoderawtransaction(tx_['hex']) for tx_ in result]
        output = [d['vout'][1 - r['changepos']]['value'] for d, r in zip(dec_tx, result)]
        change = [d['vout'][r['changepos']]['value'] for d, r in zip(dec_tx, result)]

        assert_equal(result[0]['fee'], result[1]['fee'], result[2]['fee'])
        assert_equal(result[3]['fee'], result[4]['fee'])
        assert_equal(change[0], change[1])
        assert_equal(output[0], output[1])
        assert_equal(output[0], output[2] + result[2]['fee'])
        assert_equal(change[0] + result[0]['fee'], change[2])
        assert_equal(output[3], output[4] + result[4]['fee'])
        assert_equal(change[3] + result[3]['fee'], change[4])

        # Test subtract fee from outputs with fee_rate (sat/vB)
        btc_kvb_to_sat_vb = 100000  # (1e5)
        result = [self.nodes[3].fundrawtransaction(rawtx, fee_rate=self.fee_rate_sats_per_vb),  # uses self.min_relay_tx_fee (set by fee_rate in sat/vB)
            self.nodes[3].fundrawtransaction(rawtx, subtractFeeFromOutputs=[], fee_rate=self.fee_rate_sats_per_vb),  # empty subtraction list
            self.nodes[3].fundrawtransaction(rawtx, subtractFeeFromOutputs=[0], fee_rate=self.fee_rate_sats_per_vb),  # uses self.min_relay_tx_fee (set by fee_rate in sat/vB)
            self.nodes[3].fundrawtransaction(rawtx, fee_rate=2 * btc_kvb_to_sat_vb * self.min_relay_tx_fee),
            self.nodes[3].fundrawtransaction(rawtx, fee_rate=2 * btc_kvb_to_sat_vb * self.min_relay_tx_fee, subtractFeeFromOutputs=[0]),]
        dec_tx = [self.nodes[3].decoderawtransaction(tx_['hex']) for tx_ in result]
        output = [d['vout'][1 - r['changepos']]['value'] for d, r in zip(dec_tx, result)]
        change = [d['vout'][r['changepos']]['value'] for d, r in zip(dec_tx, result)]

        assert_equal(result[0]['fee'], result[1]['fee'], result[2]['fee'])
        assert_equal(result[3]['fee'], result[4]['fee'])
        assert_equal(change[0], change[1])
        assert_equal(output[0], output[1])
        assert_equal(output[0], output[2] + result[2]['fee'])
        assert_equal(change[0] + result[0]['fee'], change[2])
        assert_equal(output[3], output[4] + result[4]['fee'])
        assert_equal(change[3] + result[3]['fee'], change[4])

        inputs = []
        outputs = {self.nodes[2].getnewaddress(): value for value in (1.0, 1.1, 1.2, 1.3)}
        rawtx = self.nodes[3].createrawtransaction(inputs, [{key: value} for key, value in outputs.items()])

        result = [self.nodes[3].fundrawtransaction(rawtx),
                  # Split the fee between outputs 0, 2, and 3, but not output 1.
                  self.nodes[3].fundrawtransaction(rawtx, subtractFeeFromOutputs=[0, 2, 3])]

        dec_tx = [self.nodes[3].decoderawtransaction(result[0]['hex']),
                  self.nodes[3].decoderawtransaction(result[1]['hex'])]

        # Nested list of non-change output amounts for each transaction.
        output = [[out['value'] for i, out in enumerate(d['vout']) if i != r['changepos']]
                  for d, r in zip(dec_tx, result)]

        # List of differences in output amounts between normal and subtractFee transactions.
        share = [o0 - o1 for o0, o1 in zip(output[0], output[1])]

        # Output 1 is the same in both transactions.
        assert_equal(share[1], 0)

        # The other 3 outputs are smaller as a result of subtractFeeFromOutputs.
        assert_greater_than(share[0], 0)
        assert_greater_than(share[2], 0)
        assert_greater_than(share[3], 0)

        # Outputs 2 and 3 take the same share of the fee.
        assert_equal(share[2], share[3])

        # Output 0 takes at least as much share of the fee, and no more than 2
        # satoshis more, than outputs 2 and 3.
        assert_greater_than_or_equal(share[0], share[2])
        assert_greater_than_or_equal(share[2] + Decimal(2e-8), share[0])

        # The fee is the same in both transactions.
        assert_equal(result[0]['fee'], result[1]['fee'])

        # The total subtracted from the outputs is equal to the fee.
        assert_equal(share[0] + share[2] + share[3], result[0]['fee'])

    def test_subtract_fee_with_presets(self):
        self.log.info("Test fundrawtxn subtract fee from outputs with preset inputs that are sufficient")

        addr = self.nodes[0].getnewaddress()
        utxo = self.create_outpoints(self.nodes[0], outputs=[{addr: 10}])[0]

        rawtx = self.nodes[0].createrawtransaction([utxo], [{self.nodes[0].getnewaddress(): 5}])
        fundedtx = self.nodes[0].fundrawtransaction(rawtx, subtractFeeFromOutputs=[0], fee_rate=self.fee_rate_sats_per_vb)
        signedtx = self.nodes[0].signrawtransactionwithwallet(fundedtx['hex'])
        self.nodes[0].sendrawtransaction(signedtx['hex'])

    def test_transaction_too_large(self):
        self.log.info("Test fundrawtx where BnB solution would result in a too large transaction, but Knapsack would not")
        self.nodes[0].createwallet("large")
        wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        recipient = self.nodes[0].get_wallet_rpc("large")
        outputs = {}
        rawtx = recipient.createrawtransaction([], [{wallet.getnewaddress(): 177.99899260}])

        # Make 1800 0.1 BTC outputs. The amount that we target for funding is in
        # the BnB range when these outputs are used.  However if these outputs
        # are selected, the transaction will end up being too large, so it
        # shouldn't use BnB and instead fall back to Knapsack but that behavior
        # is not implemented yet. For now we just check that we get an error.
        # First, force the wallet to bulk-generate the addresses we'll need.
        recipient.keypoolrefill(1800)
        for _ in range(1800):
            outputs[recipient.getnewaddress()] = 0.1
        wallet.sendmany(outputs, fee_rate=self.fee_rate_sats_per_vb)
        self.generate(self.nodes[0], 10)
        assert_raises_rpc_error(-4, "The inputs size exceeds the maximum weight. "
                                    "Please try sending a smaller amount or manually consolidating your wallet's UTXOs",
                                recipient.fundrawtransaction, rawtx)
        self.nodes[0].unloadwallet("large")

    def test_external_inputs(self):
        self.log.info("Test funding with external inputs")
        privkey, _ = generate_keypair(wif=True)
        self.nodes[2].createwallet("extfund")
        wallet = self.nodes[2].get_wallet_rpc("extfund")

        # Create an external but signable native Taproot output.
        desc = descsum_create("tr({})".format(privkey))
        res = self.nodes[0].importdescriptors([{"desc": desc, "timestamp": "now"}])
        assert res[0]["success"]
        addr = self.nodes[0].deriveaddresses(desc)[0]

        self.nodes[0].sendtoaddress(addr, 10, fee_rate=self.fee_rate_sats_per_vb)
        self.nodes[0].sendtoaddress(wallet.getnewaddress(), 10, fee_rate=self.fee_rate_sats_per_vb)
        self.generate(self.nodes[0], 6)
        ext_utxo = self.nodes[0].listunspent(addresses=[addr])[0]

        # Native Taproot key-path inputs have a predictable weight even without solving data.
        raw_tx = wallet.createrawtransaction([ext_utxo], [{self.nodes[0].getnewaddress(): ext_utxo["amount"] / 2}])
        wallet.fundrawtransaction(raw_tx, fee_rate=self.fee_rate_sats_per_vb)

        # Error conditions
        assert_raises_rpc_error(-5, 'Pubkey "not a pubkey" must be a hex string', wallet.fundrawtransaction, raw_tx, solving_data={"pubkeys":["not a pubkey"]})
        assert_raises_rpc_error(-5, 'Pubkey "01234567890a0b0c0d0e0f" must have a length of either 33 or 65 bytes', wallet.fundrawtransaction, raw_tx, solving_data={"pubkeys":["01234567890a0b0c0d0e0f"]})
        assert_raises_rpc_error(-5, "'not a script' is not hex", wallet.fundrawtransaction, raw_tx, solving_data={"scripts":["not a script"]})
        assert_raises_rpc_error(-8, "Unable to parse descriptor 'not a descriptor'", wallet.fundrawtransaction, raw_tx, solving_data={"descriptors":["not a descriptor"]})
        assert_raises_rpc_error(-8, "Invalid parameter, missing vout key", wallet.fundrawtransaction, raw_tx, input_weights=[{"txid": ext_utxo["txid"]}])
        assert_raises_rpc_error(-8, "Invalid parameter, vout cannot be negative", wallet.fundrawtransaction, raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": -1}])
        assert_raises_rpc_error(-8, "Invalid parameter, missing weight key", wallet.fundrawtransaction, raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"]}])
        assert_raises_rpc_error(-8, "Invalid parameter, weight cannot be less than 165", wallet.fundrawtransaction, raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"], "weight": 164}])
        assert_raises_rpc_error(-8, "Invalid parameter, weight cannot be less than 165", wallet.fundrawtransaction, raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"], "weight": -1}])
        assert_raises_rpc_error(-8, "Invalid parameter, weight cannot be greater than", wallet.fundrawtransaction, raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"], "weight": 400001}])

        # Funding should work when the native descriptor is provided.
        funded_tx = wallet.fundrawtransaction(raw_tx, solving_data={"descriptors": [desc]}, fee_rate=self.fee_rate_sats_per_vb)
        signed_tx1 = wallet.signrawtransactionwithwallet(funded_tx['hex'])
        assert not signed_tx1['complete']
        signed_tx2 = self.nodes[0].signrawtransactionwithwallet(signed_tx1['hex'])
        assert signed_tx2['complete']

        unsigned_weight = self.nodes[0].decoderawtransaction(signed_tx1["hex"])["weight"]
        signed_weight = self.nodes[0].decoderawtransaction(signed_tx2["hex"])["weight"]
        # Input's weight is difference between weight of signed and unsigned,
        # and the weight of stuff that didn't change (prevout, sequence, 1 byte of scriptSig)
        input_weight = signed_weight - unsigned_weight + (41 * 4)
        low_input_weight = max(165, input_weight // 2)
        high_input_weight = input_weight * 2

        # Funding should also work if the input weight is provided
        funded_tx = wallet.fundrawtransaction(raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"], "weight": input_weight}], fee_rate=2)
        signed_tx = wallet.signrawtransactionwithwallet(funded_tx["hex"])
        signed_tx = self.nodes[0].signrawtransactionwithwallet(signed_tx["hex"])
        assert_equal(self.nodes[0].testmempoolaccept([signed_tx["hex"]])[0]["allowed"], True)
        assert_equal(signed_tx["complete"], True)
        # Reducing the weight should have a lower fee
        funded_tx2 = wallet.fundrawtransaction(raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"], "weight": low_input_weight}], fee_rate=2)
        assert_greater_than(funded_tx["fee"], funded_tx2["fee"])
        # Increasing the weight should have a higher fee
        funded_tx2 = wallet.fundrawtransaction(raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"], "weight": high_input_weight}], fee_rate=2)
        assert_greater_than(funded_tx2["fee"], funded_tx["fee"])
        # The provided weight should override the calculated weight when solving data is provided
        funded_tx3 = wallet.fundrawtransaction(raw_tx, solving_data={"descriptors": [desc]}, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"], "weight": high_input_weight}], fee_rate=2)
        assert_equal(funded_tx2["fee"], funded_tx3["fee"])
        # The feerate should be met
        funded_tx4 = wallet.fundrawtransaction(raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"], "weight": high_input_weight}], fee_rate=10)
        # The unsigned transaction already contains the input skeleton and its empty witness stack.
        input_add_weight = high_input_weight - (41 * 4 + 1)
        tx4_weight = wallet.decoderawtransaction(funded_tx4["hex"])["weight"] + input_add_weight
        tx4_vsize = int(ceil(tx4_weight / 4))
        assert_fee_amount(funded_tx4["fee"], tx4_vsize, Decimal(0.0001))

        # Funding with weight at csuint boundaries should not cause problems
        funded_tx = wallet.fundrawtransaction(raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"], "weight": 255}], fee_rate=2)
        funded_tx = wallet.fundrawtransaction(raw_tx, input_weights=[{"txid": ext_utxo["txid"], "vout": ext_utxo["vout"], "weight": 65539}], fee_rate=2)

        self.nodes[2].unloadwallet("extfund")

    def test_add_inputs_default_value(self):
        self.log.info("Test 'add_inputs' default value")

        # Create and fund the wallet with 5 BTC
        self.nodes[2].createwallet("test_preset_inputs")
        wallet = self.nodes[2].get_wallet_rpc("test_preset_inputs")
        addr1 = wallet.getnewaddress()
        self.nodes[0].sendtoaddress(addr1, 5, fee_rate=self.fee_rate_sats_per_vb)
        self.generate(self.nodes[0], 1)

        # Covered cases:
        # 1. Default add_inputs value with no preset inputs (add_inputs=true):
        #       Expect: automatically add coins from the wallet to the tx.
        # 2. Default add_inputs value with preset inputs (add_inputs=false):
        #       Expect: disallow automatic coin selection.
        # 3. Explicit add_inputs=true and preset inputs (with preset inputs not-covering the target amount).
        #       Expect: include inputs from the wallet.
        # 4. Explicit add_inputs=true and preset inputs (with preset inputs covering the target amount).
        #       Expect: only preset inputs are used.
        # 5. Explicit add_inputs=true, no preset inputs (same as (1) but with an explicit set):
        #       Expect: include inputs from the wallet.
        # 6. Explicit add_inputs=false, no preset inputs:
        #       Expect: failure as we did not provide inputs and the process cannot automatically select coins.

        # Case (1), 'send' command
        # 'add_inputs' value is true unless "inputs" are specified, in such case, add_inputs=false.
        # So, the wallet will automatically select coins and create the transaction if only the outputs are provided.
        tx = wallet.send(outputs=[{addr1: 3}], fee_rate=self.fee_rate_sats_per_vb)
        assert tx["complete"]

        # Case (2), 'send' command
        # Select an input manually, which doesn't cover the entire output amount and
        # verify that the dynamically set 'add_inputs=false' value works.

        # Fund wallet with 2 outputs, 5 BTC each.
        addr2 = wallet.getnewaddress()
        source_tx = self.nodes[0].send(outputs=[{addr1: 5}, {addr2: 5}], change_position=0, fee_rate=self.fee_rate_sats_per_vb)
        self.generate(self.nodes[0], 1)

        # Select only one input.
        options = {
            "inputs": [
                {
                    "txid": source_tx["txid"],
                    "vout": 1  # change position was hardcoded to index 0
                }
            ]
        }
        assert_raises_rpc_error(-4, ERR_NOT_ENOUGH_PRESET_INPUTS, wallet.send, outputs=[{addr1: 8}], **options)

        # Case (3), Explicit add_inputs=true and preset inputs (with preset inputs not-covering the target amount)
        options["add_inputs"] = True
        options["add_to_wallet"] = False
        options["fee_rate"] = self.fee_rate_sats_per_vb
        tx = wallet.send(outputs=[{addr1: 8}], **options)
        assert tx["complete"]

        # Case (4), Explicit add_inputs=true and preset inputs (with preset inputs covering the target amount)
        options["inputs"].append({
            "txid": source_tx["txid"],
            "vout": 2  # change position was hardcoded to index 0
        })
        tx = wallet.send(outputs=[{addr1: 8}], **options)
        assert tx["complete"]
        # Check that only the preset inputs were added to the tx
        decoded_psbt_inputs = self.nodes[0].decodepsbt(tx["psbt"])['tx']['vin']
        assert_equal(len(decoded_psbt_inputs), 2)
        for input in decoded_psbt_inputs:
            assert_equal(input["txid"], source_tx["txid"])

        # Case (5), assert that inputs are added to the tx by explicitly setting add_inputs=true
        options = {"add_inputs": True, "add_to_wallet": True}
        tx = wallet.send(outputs=[{addr1: 8}], **options)
        assert tx["complete"]

        # 6. Explicit add_inputs=false, no preset inputs:
        options = {"add_inputs": False}
        assert_raises_rpc_error(-4, ERR_NOT_ENOUGH_PRESET_INPUTS, wallet.send, outputs=[{addr1: 3}], **options)

        ################################################

        # Case (1), 'walletcreatefundedpsbt' command
        # Default add_inputs value with no preset inputs (add_inputs=true)
        inputs = []
        outputs = {self.nodes[1].getnewaddress(): 8}
        assert "psbt" in wallet.walletcreatefundedpsbt(inputs=inputs, outputs=[{key: value} for key, value in outputs.items()], options={'fee_rate': self.fee_rate_sats_per_vb})

        # Case (2), 'walletcreatefundedpsbt' command
        # Default add_inputs value with preset inputs (add_inputs=false).
        inputs = [{
            "txid": source_tx["txid"],
            "vout": 1  # change position was hardcoded to index 0
        }]
        outputs = {self.nodes[1].getnewaddress(): 8}
        assert_raises_rpc_error(-4, ERR_NOT_ENOUGH_PRESET_INPUTS, wallet.walletcreatefundedpsbt, inputs=inputs, outputs=[{key: value} for key, value in outputs.items()], options={'fee_rate': self.fee_rate_sats_per_vb})

        # Case (3), Explicit add_inputs=true and preset inputs (with preset inputs not-covering the target amount)
        options["add_inputs"] = True
        assert "psbt" in wallet.walletcreatefundedpsbt(outputs=[{addr1: 8}], inputs=inputs, **options)

        # Case (4), Explicit add_inputs=true and preset inputs (with preset inputs covering the target amount)
        inputs.append({
            "txid": source_tx["txid"],
            "vout": 2  # change position was hardcoded to index 0
        })
        psbt_tx = wallet.walletcreatefundedpsbt(outputs=[{addr1: 8}], inputs=inputs, **options)
        # Check that only the preset inputs were added to the tx
        decoded_psbt_inputs = self.nodes[0].decodepsbt(psbt_tx["psbt"])['tx']['vin']
        assert_equal(len(decoded_psbt_inputs), 2)
        for input in decoded_psbt_inputs:
            assert_equal(input["txid"], source_tx["txid"])

        # Case (5), 'walletcreatefundedpsbt' command
        # Explicit add_inputs=true, no preset inputs
        options = {
            "add_inputs": True,
        }
        assert "psbt" in wallet.walletcreatefundedpsbt(inputs=[], outputs=[{key: value} for key, value in outputs.items()], **options)

        # Case (6). Explicit add_inputs=false, no preset inputs:
        options = {"add_inputs": False}
        assert_raises_rpc_error(-4, ERR_NOT_ENOUGH_PRESET_INPUTS, wallet.walletcreatefundedpsbt, inputs=[], outputs=[{key: value} for key, value in outputs.items()], **options)

        self.nodes[2].unloadwallet("test_preset_inputs")

    def test_preset_inputs_selection(self):
        self.log.info('Test wallet preset inputs are not double-counted or reused in coin selection')

        # Create and fund the wallet with 4 UTXO of 5 BTC each (20 BTC total)
        self.nodes[2].createwallet("test_preset_inputs_selection")
        wallet = self.nodes[2].get_wallet_rpc("test_preset_inputs_selection")
        outputs = {}
        for _ in range(4):
            outputs[wallet.getnewaddress()] = 5
        self.nodes[0].sendmany(outputs, fee_rate=self.fee_rate_sats_per_vb)
        self.generate(self.nodes[0], 1)

        # Select the preset inputs
        coins = wallet.listunspent()
        preset_inputs = [coins[0], coins[1], coins[2]]

        # Now let's create the tx creation options
        options = {
            "inputs": preset_inputs,
            "add_inputs": True,  # automatically add coins from the wallet to fulfill the target
            "subtract_fee_from_outputs": [0],  # deduct fee from first output
            "add_to_wallet": False,
            "fee_rate": self.fee_rate_sats_per_vb
        }

        # Attempt to send 29 BTC from a wallet that only has 20 BTC. The wallet should exclude
        # the preset inputs from the pool of available coins, realize that there is not enough
        # money to fund the 29 BTC payment, and fail with "Insufficient funds".
        #
        # Even with SFFO, the wallet can only afford to send 20 BTC.
        # If the wallet does not properly exclude preset inputs from the pool of available coins
        # prior to coin selection, it may create a transaction that does not fund the full payment
        # amount or, through SFFO, incorrectly reduce the recipient's amount by the difference
        # between the original target and the wrongly counted inputs (in this case 9 BTC)
        # so that the recipient's amount is no longer equal to the user's selected target of 29 BTC.

        # First case, use 'subtract_fee_from_outputs = true'
        assert_raises_rpc_error(-4, "Insufficient funds", wallet.send, outputs=[{wallet.getnewaddress(): 29}], options=options)

        # Second case, don't use 'subtract_fee_from_outputs'
        del options["subtract_fee_from_outputs"]
        assert_raises_rpc_error(-4, "Insufficient funds", wallet.send, outputs=[{wallet.getnewaddress(): 29}], options=options)

        self.nodes[2].unloadwallet("test_preset_inputs_selection")

    def test_weight_limits(self):
        self.log.info("Test weight limits")

        self.nodes[2].createwallet("test_weight_limits")
        wallet = self.nodes[2].get_wallet_rpc("test_weight_limits")

        outputs = []
        for _ in range(1800):
            outputs.append({wallet.getnewaddress(): 0.1})
        txid = self.nodes[0].send(outputs=outputs, change_position=0, fee_rate=self.fee_rate_sats_per_vb)["txid"]
        self.generate(self.nodes[0], 1)

        # 230 WU per Taproot key-path input (231 with an explicit sighash byte);
        # picking 1799 inputs exceeds the maximum standard transaction weight.
        rawtx = wallet.createrawtransaction([], [{wallet.getnewaddress(): 0.1 * 1799}])

        # 1) Try to fund transaction only using all preset inputs to cover the fee.
        input_weights = []
        for i in range(1, 1801):  # skip first output as it is the parent tx change output
            input_weights.append({"txid": txid, "vout": i, "weight": 231})
        assert_raises_rpc_error(-4, "Transaction too large", wallet.fundrawtransaction, hexstring=rawtx, input_weights=input_weights)

        # 2) Let the wallet fund the transaction
        assert_raises_rpc_error(-4, "The inputs size exceeds the maximum weight. Please try sending a smaller amount or manually consolidating your wallet's UTXOs",
                                wallet.fundrawtransaction, hexstring=rawtx)

        # 3) Pre-select some inputs and let the wallet fill-up the remaining amount
        inputs = input_weights[0:1000]
        assert_raises_rpc_error(-4, "The combination of the pre-selected inputs and the wallet automatic inputs selection exceeds the transaction maximum weight. Please try sending a smaller amount or manually consolidating your wallet's UTXOs",
                                wallet.fundrawtransaction, hexstring=rawtx, input_weights=inputs)

        self.nodes[2].unloadwallet("test_weight_limits")

    def test_include_unsafe(self):
        self.log.info("Test fundrawtxn with unsafe inputs")

        self.nodes[0].createwallet("unsafe")
        wallet = self.nodes[0].get_wallet_rpc("unsafe")

        # We receive unconfirmed funds from external keys (unsafe outputs).
        addr = wallet.getnewaddress()
        inputs = []
        for i in range(0, 2):
            utxo = self.create_outpoints(self.nodes[2], outputs=[{addr: 5}])[0]
            inputs.append((utxo['txid'], utxo['vout']))
        self.sync_mempools()

        # Unsafe inputs are ignored by default.
        rawtx = wallet.createrawtransaction([], [{self.nodes[2].getnewaddress(): 7.5}])
        assert_raises_rpc_error(-4, "Insufficient funds", wallet.fundrawtransaction, rawtx)

        # But we can opt-in to use them for funding.
        fundedtx = wallet.fundrawtransaction(rawtx, include_unsafe=True, fee_rate=self.fee_rate_sats_per_vb)
        tx_dec = wallet.decoderawtransaction(fundedtx['hex'])
        assert all((txin["txid"], txin["vout"]) in inputs for txin in tx_dec["vin"])
        signedtx = wallet.signrawtransactionwithwallet(fundedtx['hex'])
        assert wallet.testmempoolaccept([signedtx['hex']])[0]["allowed"]

        # And we can also use them once they're confirmed.
        self.generate(self.nodes[0], 1)
        fundedtx = wallet.fundrawtransaction(rawtx, include_unsafe=False, fee_rate=self.fee_rate_sats_per_vb)
        tx_dec = wallet.decoderawtransaction(fundedtx['hex'])
        assert all((txin["txid"], txin["vout"]) in inputs for txin in tx_dec["vin"])
        signedtx = wallet.signrawtransactionwithwallet(fundedtx['hex'])
        assert wallet.testmempoolaccept([signedtx['hex']])[0]["allowed"]
        self.nodes[0].unloadwallet("unsafe")

    def test_input_confs_control(self):
        self.nodes[0].createwallet("minconf")
        wallet = self.nodes[0].get_wallet_rpc("minconf")

        # Fund the wallet with different chain heights
        for _ in range(2):
            self.nodes[2].sendmany({wallet.getnewaddress():1, wallet.getnewaddress():1}, fee_rate=self.fee_rate_sats_per_vb)
            self.generate(self.nodes[2], 1)

        unconfirmed_txid = wallet.sendtoaddress(wallet.getnewaddress(), 0.5, fee_rate=self.fee_rate_sats_per_vb)

        self.log.info("Crafting TX using an unconfirmed input")
        target_address = self.nodes[2].getnewaddress()
        raw_tx1 = wallet.createrawtransaction([], [{target_address: 0.1}], 0, True)
        funded_tx1 = wallet.fundrawtransaction(raw_tx1, {'fee_rate': 1, 'maxconf': 0})['hex']

        # Make sure we only had the one input
        tx1_inputs = self.nodes[0].decoderawtransaction(funded_tx1)['vin']
        assert_equal(len(tx1_inputs), 1)

        utxo1 = tx1_inputs[0]
        assert unconfirmed_txid == utxo1['txid']

        final_tx1 = wallet.signrawtransactionwithwallet(funded_tx1)['hex']
        txid1 = self.nodes[0].sendrawtransaction(final_tx1)

        mempool = self.nodes[0].getrawmempool()
        assert txid1 in mempool

        self.log.info("Fail to craft a new TX with minconf above highest one")
        # Create a replacement tx to 'final_tx1' that has 1 BTC target instead of 0.1.
        raw_tx2 = wallet.createrawtransaction([{'txid': utxo1['txid'], 'vout': utxo1['vout']}], [{target_address: 1}])
        assert_raises_rpc_error(-4, "Insufficient funds", wallet.fundrawtransaction, raw_tx2, {'add_inputs': True, 'minconf': 3, 'fee_rate': 10})

        self.log.info("Fail to broadcast a new TX with maxconf 0 due to BIP125 rules to verify it actually chose unconfirmed outputs")
        # Now fund 'raw_tx2' to fulfill the total target (1 BTC) by using all the wallet unconfirmed outputs.
        # As it was created with the first unconfirmed output, 'raw_tx2' only has 0.1 BTC covered (need to fund 0.9 BTC more).
        # So, the selection process, to cover the amount, will pick up the 'final_tx1' output as well, which is an output of the tx that this
        # new tx is replacing!. So, once we send it to the mempool, it will return a "bad-txns-spends-conflicting-tx"
        # because the input will no longer exist once the first tx gets replaced by this new one).
        funded_invalid = wallet.fundrawtransaction(raw_tx2, {'add_inputs': True, 'maxconf': 0, 'fee_rate': 10})['hex']
        final_invalid = wallet.signrawtransactionwithwallet(funded_invalid)['hex']
        assert_raises_rpc_error(-26, "bad-txns-spends-conflicting-tx", self.nodes[0].sendrawtransaction, final_invalid)

        self.log.info("Craft a replacement adding inputs with highest depth possible")
        funded_tx2 = wallet.fundrawtransaction(raw_tx2, {'add_inputs': True, 'minconf': 2, 'fee_rate': 10})['hex']
        tx2_inputs = self.nodes[0].decoderawtransaction(funded_tx2)['vin']
        assert_greater_than_or_equal(len(tx2_inputs), 2)
        for vin in tx2_inputs:
            if vin['txid'] != unconfirmed_txid:
                assert_greater_than_or_equal(self.nodes[0].gettxout(vin['txid'], vin['vout'])['confirmations'], 2)

        final_tx2 = wallet.signrawtransactionwithwallet(funded_tx2)['hex']
        txid2 = self.nodes[0].sendrawtransaction(final_tx2)

        mempool = self.nodes[0].getrawmempool()
        assert txid1 not in mempool
        assert txid2 in mempool

        wallet.unloadwallet()

    def test_cannot_cover_fees(self):
        self.log.info("Test error message when transaction amount exceeds available balance when fees are included")
        default_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        self.nodes[1].createwallet("cannot_cover_fees")
        wallet = self.nodes[1].get_wallet_rpc("cannot_cover_fees")

        # Set up wallet with 2 utxos: 0.3 BTC and 0.15 BTC
        default_wallet.sendtoaddress(wallet.getnewaddress(), 0.3)
        txid2 = default_wallet.sendtoaddress(wallet.getnewaddress(), 0.15)
        self.generate(self.nodes[0], 1)
        vout2 = next(utxo["vout"] for utxo in wallet.listunspent() if utxo["txid"] == txid2)
        amount_with_fee_err_msg = "The total exceeds your balance when the {} transaction fee is included."

        self.log.info("Test without preselected inputs")
        self.log.info("Attempt to send 0.45 BTC without SFFO")
        rawtx = wallet.createrawtransaction(inputs=[], outputs=[{default_wallet.getnewaddress(): 0.45}])
        assert_raises_rpc_error(-4, amount_with_fee_err_msg.format("0.00000054"), wallet.fundrawtransaction, rawtx, options={"fee_rate":1})

        self.log.info("Send 0.45 BTC with SFFO")
        wallet.fundrawtransaction(rawtx, options={"subtractFeeFromOutputs":[0]})

        self.log.info("Attempt to send 0.45 BTC by restricting coin selection with minconf=6")
        assert_raises_rpc_error(-4, "Insufficient funds", wallet.fundrawtransaction, rawtx, options={"minconf":6})

        self.log.info("Test with preselected inputs")
        self.log.info("Attempt to send 0.45 BTC preselecting 0.15 BTC utxo")
        rawtx = wallet.createrawtransaction(inputs=[{"txid": txid2, "vout": vout2}], outputs=[{default_wallet.getnewaddress(): 0.45}])
        assert_raises_rpc_error(-4, amount_with_fee_err_msg.format("0.00000054"), wallet.fundrawtransaction, rawtx, options={"fee_rate":1})

        self.log.info("Send 0.45 BTC preselecting 0.15 BTC utxo with SFFO")
        wallet.fundrawtransaction(hexstring=rawtx, options={"subtractFeeFromOutputs":[0]})

        self.log.info("Attempt to send 0.15 BTC using only the 0.15 BTC preselected utxo")
        rawtx = wallet.createrawtransaction(inputs=[{"txid": txid2, "vout": vout2}], outputs=[{default_wallet.getnewaddress(): 0.15}])
        assert_raises_rpc_error(-4, ERR_NOT_ENOUGH_PRESET_INPUTS, wallet.fundrawtransaction, rawtx, options={"fee_rate":1, "add_inputs":False})
        self.log.info("Send 0.15 BTC using only the 0.15 BTC preselected utxo with SFFO")
        wallet.fundrawtransaction(hexstring=rawtx, options={"subtractFeeFromOutputs":[0], "add_inputs":False})


if __name__ == '__main__':
    RawTransactionsTest(__file__).main()
