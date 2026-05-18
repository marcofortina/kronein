#!/usr/bin/env python3
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Partially Signed Transaction RPCs.
"""
from random import randbytes
import struct

from test_framework.blocktools import (
    MAX_STANDARD_TX_WEIGHT,
)
from test_framework.descriptors import descsum_create
from test_framework.key import H_POINT
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    MAX_BIP125_RBF_SEQUENCE,
    WITNESS_SCALE_FACTOR,
    ser_compact_size,
)
from test_framework.psbt import (
    PSBT,
    PSBTMap,
    PSBT_GLOBAL_PROPRIETARY,
    PSBT_GLOBAL_TX_VERSION,
    PSBT_IN_RIPEMD160,
    PSBT_IN_SHA256,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_HASH160,
    PSBT_IN_HASH256,
    PSBT_IN_MUSIG2_PARTIAL_SIG,
    PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_IN_MUSIG2_PUB_NONCE,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_PROPRIETARY,
    PSBT_IN_SEQUENCE,
    PSBT_OUT_AMOUNT,
    PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS,
    PSBT_OUT_PROPRIETARY,
    PSBT_OUT_SCRIPT,
    PSBT_OUT_TAP_TREE,
)
from test_framework.script import SIGHASH_ALL, SIGHASH_ANYONECANPAY
from test_framework.script_util import MIN_STANDARD_TX_NONWITNESS_SIZE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_not_equal,
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
    find_vout_for_address,
)
from test_framework.wallet_util import (
    generate_keypair,
    get_generate_key,
)

class PSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [
            ["-walletrbf=1"],
            ["-walletrbf=0"],
            []
        ]
        # whitelist peers to speed up tx relay / mempool sync
        for args in self.extra_args:
            args.append("-whitelist=noban@127.0.0.1")

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def psbt_from_tx(tx):
        """Construct the native PSBTv2 representation of an unsigned transaction."""
        psbt = PSBT(g=PSBTMap({PSBT_GLOBAL_TX_VERSION: struct.pack("<i", tx.version)}))
        psbt.i = [PSBTMap({
            PSBT_IN_PREVIOUS_TXID: txin.prevout.hash.to_bytes(32, "little"),
            PSBT_IN_OUTPUT_INDEX: struct.pack("<I", txin.prevout.n),
            PSBT_IN_SEQUENCE: struct.pack("<I", txin.nSequence),
        }) for txin in tx.vin]
        psbt.o = [PSBTMap({
            PSBT_OUT_AMOUNT: struct.pack("<q", txout.nValue),
            PSBT_OUT_SCRIPT: bytes(txout.scriptPubKey),
        }) for txout in tx.vout]
        return psbt

    def test_psbt_incomplete_after_invalid_modification(self):
        self.log.info("Check that PSBT is correctly marked as incomplete after invalid modification")
        node = self.nodes[2]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        address = wallet.getnewaddress()
        wallet.sendtoaddress(address=address, amount=1.0)
        self.generate(node, nblocks=1)

        utxos = wallet.listunspent(addresses=[address])
        psbt = wallet.createpsbt([{"txid": utxos[0]["txid"], "vout": utxos[0]["vout"]}], [{wallet.getnewaddress(): 0.9999}])
        signed_psbt = wallet.walletprocesspsbt(psbt)["psbt"]

        # Modify the raw transaction by changing the output address, so the signature is no longer valid
        signed_psbt_obj = PSBT.from_base64(signed_psbt)
        substitute_addr = wallet.getnewaddress()
        signed_psbt_obj.o[0].map[PSBT_OUT_SCRIPT] = bytes.fromhex(wallet.getaddressinfo(substitute_addr)["scriptPubKey"])

        # Check that the walletprocesspsbt call succeeds but also recognizes that the transaction is not complete
        signed_psbt_incomplete = wallet.walletprocesspsbt(psbt=signed_psbt_obj.to_base64(), finalize=False)
        assert signed_psbt_incomplete["complete"] is False

    def test_native_utxo(self):
        self.log.info("Check that PSBT inputs use the spent native output")
        mining_node = self.nodes[2]
        offline_node = self.nodes[0]
        online_node = self.nodes[1]

        # Disconnect offline node from others
        # Topology of test network is linear, so this one call is enough
        self.disconnect_nodes(0, 1)

        # Create watchonly on online_node
        online_node.createwallet(wallet_name='wonline', disable_private_keys=True)
        wonline = online_node.get_wallet_rpc('wonline')
        w2 = online_node.get_wallet_rpc(self.default_wallet_name)

        # Mine a transaction that credits the offline address
        offline_addr = offline_node.getnewaddress()
        online_addr = w2.getnewaddress()
        import_res = wonline.importdescriptors([{"desc": offline_node.getaddressinfo(offline_addr)["desc"], "timestamp": "now"}])
        assert_equal(import_res[0]["success"], True)
        mining_wallet = mining_node.get_wallet_rpc(self.default_wallet_name)
        mining_wallet.sendtoaddress(address=offline_addr, amount=1.0)
        self.generate(mining_node, nblocks=1, sync_fun=lambda: self.sync_all([online_node, mining_node]))

        # Construct an unsigned PSBT on the online node
        utxos = wonline.listunspent(addresses=[offline_addr])
        raw = wonline.createrawtransaction([{"txid":utxos[0]["txid"], "vout":utxos[0]["vout"]}],[{online_addr:0.9999}])
        psbt = wonline.walletprocesspsbt(online_node.converttopsbt(raw))["psbt"]
        assert "witness_utxo" in mining_node.decodepsbt(psbt)["inputs"][0]

        # Have the offline node sign the PSBT using the spent output.
        signed_psbt = offline_node.walletprocesspsbt(psbt)

        # Make sure we can mine the resulting transaction
        txid = mining_node.sendrawtransaction(signed_psbt["hex"])
        self.generate(mining_node, nblocks=1, sync_fun=lambda: self.sync_all([online_node, mining_node]))
        assert_equal(online_node.gettxout(txid,0)["confirmations"], 1)

        wonline.unloadwallet()

        # Reconnect
        self.connect_nodes(1, 0)
        self.connect_nodes(0, 2)

    def test_input_confs_control(self):
        self.nodes[0].createwallet("minconf")
        wallet = self.nodes[0].get_wallet_rpc("minconf")

        # Fund the wallet with different chain heights
        for _ in range(2):
            self.nodes[1].sendmany({wallet.getnewaddress():1, wallet.getnewaddress():1})
            self.generate(self.nodes[1], 1)

        unconfirmed_txid = wallet.sendtoaddress(wallet.getnewaddress(), 0.5)

        self.log.info("Crafting PSBT using an unconfirmed input")
        target_address = self.nodes[1].getnewaddress()
        psbtx1 = wallet.walletcreatefundedpsbt([], [{target_address: 0.1}], 0, {'fee_rate': 1, 'maxconf': 0})['psbt']

        # Make sure we only had the one input
        tx1_inputs = self.nodes[0].decodepsbt(psbtx1)['inputs']
        assert_equal(len(tx1_inputs), 1)

        utxo1 = tx1_inputs[0]
        assert_equal(unconfirmed_txid, utxo1['previous_txid'])

        signed_tx1 = wallet.walletprocesspsbt(psbtx1)
        txid1 = self.nodes[0].sendrawtransaction(signed_tx1['hex'])

        mempool = self.nodes[0].getrawmempool()
        assert txid1 in mempool

        self.log.info("Fail to craft a new PSBT that sends more funds with add_inputs = False")
        assert_raises_rpc_error(-4, "The preselected coins total amount does not cover the transaction target. Please allow other inputs to be automatically selected or include more coins manually", wallet.walletcreatefundedpsbt, [{'txid': utxo1['previous_txid'], 'vout': utxo1['previous_vout']}], [{target_address: 1}], 0, {'add_inputs': False})

        self.log.info("Fail to craft a new PSBT with minconf above highest one")
        assert_raises_rpc_error(-4, "Insufficient funds", wallet.walletcreatefundedpsbt, [{'txid': utxo1['previous_txid'], 'vout': utxo1['previous_vout']}], [{target_address: 1}], 0, {'add_inputs': True, 'minconf': 3, 'fee_rate': 10})

        self.log.info("Fail to broadcast a new PSBT with maxconf 0 due to BIP125 rules to verify it actually chose unconfirmed outputs")
        psbt_invalid = wallet.walletcreatefundedpsbt([{'txid': utxo1['previous_txid'], 'vout': utxo1['previous_vout']}], [{target_address: 1}], 0, {'add_inputs': True, 'maxconf': 0, 'fee_rate': 10})['psbt']
        signed_invalid = wallet.walletprocesspsbt(psbt_invalid)
        assert_raises_rpc_error(-26, "bad-txns-spends-conflicting-tx", self.nodes[0].sendrawtransaction, signed_invalid['hex'])

        self.log.info("Craft a replacement adding inputs with highest confs possible")
        psbtx2 = wallet.walletcreatefundedpsbt([{'txid': utxo1['previous_txid'], 'vout': utxo1['previous_vout']}], [{target_address: 1}], 0, {'add_inputs': True, 'minconf': 2, 'fee_rate': 10})['psbt']
        tx2_inputs = self.nodes[0].decodepsbt(psbtx2)['inputs']
        assert_greater_than_or_equal(len(tx2_inputs), 2)
        for vin in tx2_inputs:
            if vin['previous_txid'] != unconfirmed_txid:
                assert_greater_than_or_equal(self.nodes[0].gettxout(vin['previous_txid'], vin['previous_vout'])['confirmations'], 2)

        signed_tx2 = wallet.walletprocesspsbt(psbtx2)
        txid2 = self.nodes[0].sendrawtransaction(signed_tx2['hex'])

        mempool = self.nodes[0].getrawmempool()
        assert txid1 not in mempool
        assert txid2 in mempool

        wallet.unloadwallet()

    def test_decodepsbt_musig2_input_output_types(self):
        self.log.info("Test decoding PSBT with MuSig2 per-input and per-output types")
        # create 2-of-2 musig2 using fake aggregate key, leaf hash, pubnonce, and partial sig
        # TODO: actually implement MuSig2 aggregation (for decoding only it doesn't matter though)
        _, in_pubkey1 = generate_keypair()
        _, in_pubkey2 = generate_keypair()
        _, in_fake_agg_pubkey = generate_keypair()
        fake_leaf_hash = randbytes(32)
        fake_pubnonce = randbytes(66)
        fake_partialsig = randbytes(32)
        tx = CTransaction()
        tx.vin = [CTxIn(outpoint=COutPoint(hash=int('ee' * 32, 16), n=0), scriptSig=b"")]
        tx.vout = [CTxOut(nValue=0, scriptPubKey=b"")]
        psbt = self.psbt_from_tx(tx)
        participant1_keydata = in_pubkey1 + in_fake_agg_pubkey + fake_leaf_hash
        psbt.i[0].map.update({
                    bytes([PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS]) + in_fake_agg_pubkey: [in_pubkey1, in_pubkey2],
                    bytes([PSBT_IN_MUSIG2_PUB_NONCE]) + participant1_keydata: fake_pubnonce,
                    bytes([PSBT_IN_MUSIG2_PARTIAL_SIG]) + participant1_keydata: fake_partialsig,
                 })
        _, out_pubkey1 = generate_keypair()
        _, out_pubkey2 = generate_keypair()
        _, out_fake_agg_pubkey = generate_keypair()
        psbt.o[0].map.update({
                    bytes([PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS]) + out_fake_agg_pubkey: [out_pubkey1, out_pubkey2],
                 })
        res = self.nodes[0].decodepsbt(psbt.to_base64())
        assert_equal(len(res["inputs"]), 1)
        res_input = res["inputs"][0]
        assert_equal(len(res["outputs"]), 1)
        res_output = res["outputs"][0]

        assert "musig2_participant_pubkeys" in res_input
        in_participant_pks = res_input["musig2_participant_pubkeys"][0]
        assert "aggregate_pubkey" in in_participant_pks
        assert_equal(in_participant_pks["aggregate_pubkey"], in_fake_agg_pubkey.hex())
        assert "participant_pubkeys" in in_participant_pks
        assert_equal(in_participant_pks["participant_pubkeys"], [in_pubkey1.hex(), in_pubkey2.hex()])

        assert "musig2_pubnonces" in res_input
        in_pubnonce = res_input["musig2_pubnonces"][0]
        assert "participant_pubkey" in in_pubnonce
        assert_equal(in_pubnonce["participant_pubkey"], in_pubkey1.hex())
        assert "aggregate_pubkey" in in_pubnonce
        assert_equal(in_pubnonce["aggregate_pubkey"], in_fake_agg_pubkey.hex())
        assert "leaf_hash" in in_pubnonce
        assert_equal(in_pubnonce["leaf_hash"], fake_leaf_hash.hex())
        assert "pubnonce" in in_pubnonce
        assert_equal(in_pubnonce["pubnonce"], fake_pubnonce.hex())

        assert "musig2_partial_sigs" in res_input
        in_partialsig = res_input["musig2_partial_sigs"][0]
        assert "participant_pubkey" in in_partialsig
        assert_equal(in_partialsig["participant_pubkey"], in_pubkey1.hex())
        assert "aggregate_pubkey" in in_partialsig
        assert_equal(in_partialsig["aggregate_pubkey"], in_fake_agg_pubkey.hex())
        assert "leaf_hash" in in_partialsig
        assert_equal(in_partialsig["leaf_hash"], fake_leaf_hash.hex())
        assert "partial_sig" in in_partialsig
        assert_equal(in_partialsig["partial_sig"], fake_partialsig.hex())

        assert "musig2_participant_pubkeys" in res_output
        out_participant_pks = res_output["musig2_participant_pubkeys"][0]
        assert "aggregate_pubkey" in out_participant_pks
        assert_equal(out_participant_pks["aggregate_pubkey"], out_fake_agg_pubkey.hex())
        assert "participant_pubkeys" in out_participant_pks
        assert_equal(out_participant_pks["participant_pubkeys"], [out_pubkey1.hex(), out_pubkey2.hex()])

    def test_combinepsbt_preserves_proprietary_fields(self):
        self.log.info("Test that combining PSBTs preserves proprietary fields")

        def proprietary_key(type_byte, identifier, subtype, key_data=b""):
            return bytes([type_byte]) + ser_compact_size(len(identifier)) + identifier + ser_compact_size(subtype) + key_data

        def proprietary_entry(key, value, identifier, subtype):
            return {"identifier": identifier.hex(), "subtype": subtype, "key": key.hex(), "value": value.hex()}

        tx = CTransaction()
        tx.vin = [CTxIn(outpoint=COutPoint(hash=int('aa' * 32, 16), n=0), scriptSig=b"")]
        tx.vout = [CTxOut(nValue=0, scriptPubKey=b"")]

        global_key_a = proprietary_key(type_byte=PSBT_GLOBAL_PROPRIETARY, identifier=b"gc", subtype=1, key_data=b"\x01")
        global_key_b = proprietary_key(type_byte=PSBT_GLOBAL_PROPRIETARY, identifier=b"gc", subtype=2, key_data=b"\x02")
        input_key_a = proprietary_key(type_byte=PSBT_IN_PROPRIETARY, identifier=b"in", subtype=3, key_data=b"\x03")
        input_key_b = proprietary_key(type_byte=PSBT_IN_PROPRIETARY, identifier=b"in", subtype=4, key_data=b"\x04")
        output_key_a = proprietary_key(type_byte=PSBT_OUT_PROPRIETARY, identifier=b"out", subtype=5, key_data=b"\x05")
        output_key_b = proprietary_key(type_byte=PSBT_OUT_PROPRIETARY, identifier=b"out", subtype=6, key_data=b"\x06")

        psbt1 = self.psbt_from_tx(tx)
        psbt1.g.map[global_key_a] = b"\xaa"
        psbt1.i[0].map[input_key_a] = b"\xbb"
        psbt1.o[0].map[output_key_a] = b"\xcc"

        psbt2 = self.psbt_from_tx(tx)
        psbt2.g.map[global_key_b] = b"\xdd"
        psbt2.i[0].map[input_key_b] = b"\xee"
        psbt2.o[0].map[output_key_b] = b"\xff"

        decoded = self.nodes[0].decodepsbt(self.nodes[0].combinepsbt([psbt1.to_base64(), psbt2.to_base64()]))
        assert_equal(decoded["proprietary"], [
            proprietary_entry(key=global_key_a, value=b"\xaa", identifier=b"gc", subtype=1),
            proprietary_entry(key=global_key_b, value=b"\xdd", identifier=b"gc", subtype=2),
        ])
        assert_equal(decoded["inputs"][0]["proprietary"], [
            proprietary_entry(key=input_key_a, value=b"\xbb", identifier=b"in", subtype=3),
            proprietary_entry(key=input_key_b, value=b"\xee", identifier=b"in", subtype=4),
        ])
        assert_equal(decoded["outputs"][0]["proprietary"], [
            proprietary_entry(key=output_key_a, value=b"\xcc", identifier=b"out", subtype=5),
            proprietary_entry(key=output_key_b, value=b"\xff", identifier=b"out", subtype=6),
        ])

    def test_sighash_mismatch(self):
        self.log.info("Test sighash type mismatches")
        self.nodes[0].createwallet("sighash_mismatch")
        wallet = self.nodes[0].get_wallet_rpc("sighash_mismatch")
        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        addr = wallet.getnewaddress()
        def_wallet.sendtoaddress(addr, 5)
        self.generate(self.nodes[0], 6)

        # Retrieve the descriptors so we can do all of the tests with descriptorprocesspsbt as well
        descs = wallet.listdescriptors(True)["descriptors"]

        # Make a PSBT
        psbt = wallet.walletcreatefundedpsbt([], [{def_wallet.getnewaddress(): 1}])["psbt"]

        # Modify the PSBT and insert a sighash field for ALL|ANYONECANPAY on input 0
        mod_psbt = PSBT.from_base64(psbt)
        mod_psbt.i[0].map[PSBT_IN_SIGHASH_TYPE] = (SIGHASH_ALL | SIGHASH_ANYONECANPAY).to_bytes(4, byteorder="little")
        psbt = mod_psbt.to_base64()

        # Mismatching sighash type fails, including when no type is specified
        for sighash in ["DEFAULT", "ALL", "NONE", "SINGLE", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY", None]:
            assert_raises_rpc_error(-22, "Specified sighash value does not match value stored in PSBT", wallet.walletprocesspsbt, psbt, True, sighash)

        # Matching sighash type succeeds
        proc = wallet.walletprocesspsbt(psbt, True, "ALL|ANYONECANPAY")
        assert_equal(proc["complete"], True)

        # Repeat with descriptorprocesspsbt
        # Mismatching sighash type fails, including when no type is specified
        for sighash in ["DEFAULT", "ALL", "NONE", "SINGLE", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY", None]:
            assert_raises_rpc_error(-22, "Specified sighash value does not match value stored in PSBT", self.nodes[0].descriptorprocesspsbt, psbt, descs, sighash)

        # Matching sighash type succeeds
        proc = self.nodes[0].descriptorprocesspsbt(psbt, descs, "ALL|ANYONECANPAY")
        assert_equal(proc["complete"], True)

        wallet.unloadwallet()

    def test_sighash_adding(self):
        self.log.info("Test adding of sighash type field")
        self.nodes[0].createwallet("sighash_adding")
        wallet = self.nodes[0].get_wallet_rpc("sighash_adding")
        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)

        outputs = [{wallet.getnewaddress(): 1}]
        outputs.append({wallet.getnewaddress(): 1})
        descs = wallet.listdescriptors(True)["descriptors"]
        def_wallet.send(outputs)
        self.generate(self.nodes[0], 6)
        utxos = wallet.listunspent()

        # Make a PSBT
        psbt = wallet.walletcreatefundedpsbt(utxos, [{def_wallet.getnewaddress(): 0.5}])["psbt"]

        # Process the PSBT with the wallet
        wallet_psbt = wallet.walletprocesspsbt(psbt=psbt, sighashtype="ALL|ANYONECANPAY", finalize=False)["psbt"]

        # Separately process the PSBT with descriptors
        desc_psbt = self.nodes[0].descriptorprocesspsbt(psbt=psbt, descriptors=descs, sighashtype="ALL|ANYONECANPAY", finalize=False)["psbt"]

        for psbt in [wallet_psbt, desc_psbt]:
            # Check that the PSBT has a sighash field on all inputs
            dec_psbt = self.nodes[0].decodepsbt(psbt)
            for input in dec_psbt["inputs"]:
                assert_equal(input["sighash"], "ALL|ANYONECANPAY")

            # Make sure we can still finalize the transaction
            fin_res = self.nodes[0].finalizepsbt(psbt)
            assert_equal(fin_res["complete"], True)
            fin_hex = fin_res["hex"]
            assert_equal(self.nodes[0].testmempoolaccept([fin_hex])[0]["allowed"], True)

            # Change the sighash field to a different value and make sure we can no longer finalize
            mod_psbt = PSBT.from_base64(psbt)
            mod_psbt.i[0].map[PSBT_IN_SIGHASH_TYPE] = (SIGHASH_ALL).to_bytes(4, byteorder="little")
            mod_psbt.i[1].map[PSBT_IN_SIGHASH_TYPE] = (SIGHASH_ALL).to_bytes(4, byteorder="little")
            psbt = mod_psbt.to_base64()
            fin_res = self.nodes[0].finalizepsbt(psbt)
            assert_equal(fin_res["complete"], False)

        self.nodes[0].sendrawtransaction(fin_hex)
        self.generate(self.nodes[0], 1)

        wallet.unloadwallet()

    def test_psbt_named_parameter_handling(self):
        """Test that PSBT Base64 parameters with '=' padding are handled correctly in -named mode"""
        self.log.info("Testing PSBT Base64 parameter handling with '=' padding characters")
        node = self.nodes[0]
        psbt = PSBT.from_base64(node.createpsbt([], [{node.getnewaddress(): 1}]))
        padding = b""
        while not (psbt_with_padding := psbt.to_base64()).endswith("="):
            padding += b"\x00"
            psbt.g.map[0x50] = padding

        # Test decodepsbt with explicit named parameter containing '=' padding
        result = node.cli("-named", "decodepsbt", f"psbt={psbt_with_padding}").send_cli()
        assert 'tx' in result

        # Test decodepsbt with positional argument containing '=' padding
        result = node.cli("-named", "decodepsbt", psbt_with_padding).send_cli()
        assert 'tx' in result

        # Test analyzepsbt with positional argument containing '=' padding
        result = node.cli("-named", "analyzepsbt", psbt_with_padding).send_cli()
        assert isinstance(result, dict)

        # Test finalizepsbt with positional argument containing '=' padding
        result = node.cli("-named", "finalizepsbt", psbt_with_padding, "extract=true").send_cli()
        assert 'complete' in result

        # Test walletprocesspsbt with positional argument containing '=' padding
        result = node.cli("-named", "walletprocesspsbt", psbt_with_padding).send_cli()
        assert 'complete' in result

        # Test utxoupdatepsbt with positional argument containing '=' padding
        result = node.cli("-named", "utxoupdatepsbt", psbt_with_padding).send_cli()
        assert isinstance(result, str) and len(result) > 0

        # Test that unknown parameter with '=' gets treated as positional and return error
        unknown_psbt_param = "unknown_param_data=more_data="
        # This should be treated as positional and fail with decode error, not parameter error
        assert_raises_rpc_error(-22, "TX decode failed invalid base64", node.cli("-named", "finalizepsbt", unknown_psbt_param).send_cli)

        self.log.info("PSBT parameter handling test completed successfully")

    def run_test(self):
        # Create and fund a raw tx for sending 10 BTC
        psbtx1 = self.nodes[0].walletcreatefundedpsbt([], [{self.nodes[2].getnewaddress():10}])['psbt']

        self.log.info("Test for invalid maximum transaction weights")
        dest_arg = [{self.nodes[0].getnewaddress(): 1}]
        min_tx_weight = MIN_STANDARD_TX_NONWITNESS_SIZE * WITNESS_SCALE_FACTOR
        assert_raises_rpc_error(-4, f"Maximum transaction weight must be between {min_tx_weight} and {MAX_STANDARD_TX_WEIGHT}", self.nodes[0].walletcreatefundedpsbt, [], dest_arg, 0, {"max_tx_weight": -1})
        assert_raises_rpc_error(-4, f"Maximum transaction weight must be between {min_tx_weight} and {MAX_STANDARD_TX_WEIGHT}", self.nodes[0].walletcreatefundedpsbt, [], dest_arg, 0, {"max_tx_weight": 0})
        assert_raises_rpc_error(-4, f"Maximum transaction weight must be between {min_tx_weight} and {MAX_STANDARD_TX_WEIGHT}", self.nodes[0].walletcreatefundedpsbt, [], dest_arg, 0, {"max_tx_weight": MAX_STANDARD_TX_WEIGHT + 1})

        # Base transaction vsize before the output count: version (4) + locktime (4) + input count (1) = 9 vbytes
        base_tx_vsize = 9
        # One P2TR output: amount, script length, and 34-byte script (43 vbytes)
        p2tr_output_vsize = 43
        # 1 vbyte for output count
        output_count = 1
        tx_weight_without_inputs = (base_tx_vsize + output_count + p2tr_output_vsize) * WITNESS_SCALE_FACTOR
        # min_tx_weight is greater than transaction weight without inputs
        assert_greater_than(min_tx_weight, tx_weight_without_inputs)

        # In order to test for when the passed max weight is less than the transaction weight without inputs
        # Define destination with two outputs.
        dest_arg_large = [{self.nodes[0].getnewaddress(): 1}, {self.nodes[0].getnewaddress(): 1}]
        large_tx_vsize_without_inputs = base_tx_vsize + output_count + (p2tr_output_vsize * 2)
        large_tx_weight_without_inputs = large_tx_vsize_without_inputs * WITNESS_SCALE_FACTOR
        assert_greater_than(large_tx_weight_without_inputs, min_tx_weight)
        # Test for max_tx_weight less than Transaction weight without inputs
        assert_raises_rpc_error(-4, "Maximum transaction weight is less than transaction weight without inputs", self.nodes[0].walletcreatefundedpsbt, [], dest_arg_large, 0, {"max_tx_weight": min_tx_weight})
        assert_raises_rpc_error(-4, "Maximum transaction weight is less than transaction weight without inputs", self.nodes[0].walletcreatefundedpsbt, [], dest_arg_large, 0, {"max_tx_weight": large_tx_weight_without_inputs})

        # Test for max_tx_weight just enough to include inputs but not change output
        assert_raises_rpc_error(-4, "Maximum transaction weight is too low, can not accommodate change output", self.nodes[0].walletcreatefundedpsbt, [], dest_arg_large, 0, {"max_tx_weight": (large_tx_vsize_without_inputs + 1) * WITNESS_SCALE_FACTOR})
        self.log.info("Test that a funded PSBT is always faithful to max_tx_weight option")
        large_tx_vsize_with_change = large_tx_vsize_without_inputs + p2tr_output_vsize
        # It's enough but won't accommodate selected input size
        assert_raises_rpc_error(-4, "The inputs size exceeds the maximum weight", self.nodes[0].walletcreatefundedpsbt, [], dest_arg_large, 0, {"max_tx_weight": (large_tx_vsize_with_change) * WITNESS_SCALE_FACTOR})

        max_tx_weight_sufficient = 1000 # 1k vbytes is enough
        psbt = self.nodes[0].walletcreatefundedpsbt(outputs=dest_arg,locktime=0, options={"max_tx_weight": max_tx_weight_sufficient})["psbt"]
        weight = self.nodes[0].decodepsbt(psbt)["tx"]["weight"]
        # ensure the transaction's weight is below the specified max_tx_weight.
        assert_greater_than_or_equal(max_tx_weight_sufficient, weight)

        # If inputs are specified, do not automatically add more:
        utxo1 = self.nodes[0].listunspent()[0]
        assert_raises_rpc_error(-4, "The preselected coins total amount does not cover the transaction target. "
                                    "Please allow other inputs to be automatically selected or include more coins manually",
                                self.nodes[0].walletcreatefundedpsbt, [{"txid": utxo1['txid'], "vout": utxo1['vout']}], [{self.nodes[2].getnewaddress():90}])

        psbtx1 = self.nodes[0].walletcreatefundedpsbt([{"txid": utxo1['txid'], "vout": utxo1['vout']}], [{self.nodes[2].getnewaddress():90}], 0, {"add_inputs": True})['psbt']
        assert_equal(len(self.nodes[0].decodepsbt(psbtx1)['tx']['vin']), 2)

        # Inputs argument can be null
        self.nodes[0].walletcreatefundedpsbt(None, [{self.nodes[2].getnewaddress():10}])

        # Node 1 should not be able to add anything to it but still return the psbtx same as before
        psbtx = self.nodes[1].walletprocesspsbt(psbtx1)['psbt']
        assert_equal(psbtx1, psbtx)

        # Node 0 should not be able to sign the transaction with the wallet is locked
        self.nodes[0].encryptwallet("password")
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first", self.nodes[0].walletprocesspsbt, psbtx)

        # Node 0 should be able to process without signing though
        unsigned_tx = self.nodes[0].walletprocesspsbt(psbtx, False)
        assert_equal(unsigned_tx['complete'], False)

        self.nodes[0].walletpassphrase(passphrase="password", timeout=1000000)

        # Sign the transaction but don't finalize
        processed_psbt = self.nodes[0].walletprocesspsbt(psbt=psbtx, finalize=False)
        assert "hex" not in processed_psbt
        signed_psbt = processed_psbt['psbt']

        # Finalize and send
        finalized_hex = self.nodes[0].finalizepsbt(signed_psbt)['hex']
        self.nodes[0].sendrawtransaction(finalized_hex)

        # Alternative method: sign AND finalize in one command
        processed_finalized_psbt = self.nodes[0].walletprocesspsbt(psbt=psbtx, finalize=True)
        finalized_psbt = processed_finalized_psbt['psbt']
        finalized_psbt_hex = processed_finalized_psbt['hex']
        assert_not_equal(signed_psbt, finalized_psbt)
        assert finalized_psbt_hex == finalized_hex

        # Manually selected inputs can be locked:
        assert_equal(len(self.nodes[0].listlockunspent()), 0)
        utxo1 = self.nodes[0].listunspent()[0]
        psbtx1 = self.nodes[0].walletcreatefundedpsbt([{"txid": utxo1['txid'], "vout": utxo1['vout']}], [{self.nodes[2].getnewaddress():1}], 0,{"lock_unspents": True})["psbt"]
        assert_equal(len(self.nodes[0].listlockunspent()), 1)

        # Locks are ignored for manually selected inputs
        self.nodes[0].walletcreatefundedpsbt([{"txid": utxo1['txid'], "vout": utxo1['vout']}], [{self.nodes[2].getnewaddress():1}], 0)

        # Native Taproot PSBT behavior is covered by the remaining tests below.

        # check that walletprocesspsbt fails to decode a non-psbt
        rawtx = self.nodes[1].createrawtransaction([], [{self.nodes[1].getnewaddress(): 1}])
        assert_raises_rpc_error(-22, "TX decode failed", self.nodes[1].walletprocesspsbt, rawtx)

        # Convert a non-psbt to psbt and make sure we can decode it
        rawtx = self.nodes[0].createrawtransaction([], [{self.nodes[1].getnewaddress():10}])
        rawtx = self.nodes[0].fundrawtransaction(rawtx)
        new_psbt = self.nodes[0].converttopsbt(rawtx['hex'])
        self.nodes[0].decodepsbt(new_psbt)

        # Make sure that a non-psbt with signatures cannot be converted
        signedtx = self.nodes[0].signrawtransactionwithwallet(rawtx['hex'])
        assert_raises_rpc_error(-22, "Inputs must not contain signature data",
                                self.nodes[0].converttopsbt, hexstring=signedtx['hex'])  # permitsigdata=False by default
        assert_raises_rpc_error(-22, "Inputs must not contain signature data",
                                self.nodes[0].converttopsbt, hexstring=signedtx['hex'], permitsigdata=False)
        # Unless we allow it to convert and strip signatures
        self.nodes[0].converttopsbt(hexstring=signedtx['hex'], permitsigdata=True)

        # Create outputs to nodes 1 and 2
        # (note that we intentionally create two different txs here, as we want
        #  to check that each node is missing prevout data for one of the two
        #  utxos, see "should only have data for one input" test below)
        node1_addr = self.nodes[1].getnewaddress()
        node2_addr = self.nodes[2].getnewaddress()
        utxo1 = self.create_outpoints(self.nodes[0], outputs=[{node1_addr: 13}])[0]
        utxo2 = self.create_outpoints(self.nodes[0], outputs=[{node2_addr: 13}])[0]
        self.generate(self.nodes[0], 6)[0]

        # Create a psbt spending outputs from nodes 1 and 2
        psbt_orig = self.nodes[0].createpsbt([utxo1, utxo2], [{self.nodes[0].getnewaddress():25.999}])

        # Update psbts, should only have data for one input and not the other
        psbt1 = self.nodes[1].walletprocesspsbt(psbt_orig, sign=False)['psbt']
        psbt1_decoded = self.nodes[0].decodepsbt(psbt1)
        assert "witness_utxo" in psbt1_decoded['inputs'][0]
        assert "witness_utxo" not in psbt1_decoded['inputs'][1]
        # Check that BIP32 path was added
        assert "taproot_bip32_derivs" in psbt1_decoded['inputs'][0]
        psbt2 = self.nodes[2].walletprocesspsbt(psbt_orig, sign=False, bip32derivs=False)['psbt']
        psbt2_decoded = self.nodes[0].decodepsbt(psbt2)
        assert "witness_utxo" not in psbt2_decoded['inputs'][0]
        assert "witness_utxo" in psbt2_decoded['inputs'][1]
        # Check that BIP32 paths were not added
        assert "taproot_bip32_derivs" not in psbt2_decoded['inputs'][1]

        # Test additional args in walletcreatepsbt
        # Make sure both pre-included and funded inputs
        # have the correct sequence numbers based on
        # replaceable arg
        block_height = self.nodes[0].getblockcount()
        unspent = self.nodes[0].listunspent()[0]
        psbtx_info = self.nodes[0].walletcreatefundedpsbt([{"txid":unspent["txid"], "vout":unspent["vout"]}], [{self.nodes[2].getnewaddress():unspent["amount"]+1}], block_height+2, {"replaceable": False, "add_inputs": True}, False)
        decoded_psbt = self.nodes[0].decodepsbt(psbtx_info["psbt"])
        for tx_in in decoded_psbt["tx"]["vin"]:
            assert_greater_than(tx_in["sequence"], MAX_BIP125_RBF_SEQUENCE)
        assert_equal(decoded_psbt["tx"]["locktime"], block_height+2)

        # Same construction with only locktime set and RBF explicitly enabled
        psbtx_info = self.nodes[0].walletcreatefundedpsbt([{"txid":unspent["txid"], "vout":unspent["vout"]}], [{self.nodes[2].getnewaddress():unspent["amount"]+1}], block_height, {"replaceable": True, "add_inputs": True}, True)
        decoded_psbt = self.nodes[0].decodepsbt(psbtx_info["psbt"])
        for tx_in in decoded_psbt["tx"]["vin"]:
            assert_equal(tx_in["sequence"], MAX_BIP125_RBF_SEQUENCE)
        assert_equal(decoded_psbt["tx"]["locktime"], block_height)

        # Same construction without optional arguments
        psbtx_info = self.nodes[0].walletcreatefundedpsbt([], [{self.nodes[2].getnewaddress():unspent["amount"]+1}])
        decoded_psbt = self.nodes[0].decodepsbt(psbtx_info["psbt"])
        for tx_in in decoded_psbt["tx"]["vin"]:
            assert_equal(tx_in["sequence"], MAX_BIP125_RBF_SEQUENCE)
        assert_equal(decoded_psbt["tx"]["locktime"], 0)

        # Same construction without optional arguments, for a node with -walletrbf=0
        unspent1 = self.nodes[1].listunspent()[0]
        psbtx_info = self.nodes[1].walletcreatefundedpsbt([{"txid":unspent1["txid"], "vout":unspent1["vout"]}], [{self.nodes[2].getnewaddress():unspent1["amount"]+1}], block_height, {"add_inputs": True})
        decoded_psbt = self.nodes[1].decodepsbt(psbtx_info["psbt"])
        for tx_in in decoded_psbt["tx"]["vin"]:
            assert_greater_than(tx_in["sequence"], MAX_BIP125_RBF_SEQUENCE)

        # Make sure change address wallet does not have P2SH innerscript access to results in success
        # when attempting BnB coin selection
        self.nodes[0].walletcreatefundedpsbt([], [{self.nodes[2].getnewaddress():unspent["amount"]+1}], block_height+2, {"change_address":self.nodes[1].getnewaddress()}, False)

        # Wallet change is always native Taproot.

        # Regression test for 14473 (mishandling of already-signed witness transaction):
        psbtx_info = self.nodes[0].walletcreatefundedpsbt([{"txid":unspent["txid"], "vout":unspent["vout"]}], [{self.nodes[2].getnewaddress():unspent["amount"]+1}], 0, {"add_inputs": True})
        complete_psbt = self.nodes[0].walletprocesspsbt(psbtx_info["psbt"])
        double_processed_psbt = self.nodes[0].walletprocesspsbt(complete_psbt["psbt"])
        assert_equal(complete_psbt, double_processed_psbt)
        # We don't care about the decode result, but decoding must succeed.
        self.nodes[0].decodepsbt(double_processed_psbt["psbt"])

        # Make sure unsafe inputs are included if specified
        self.nodes[2].createwallet(wallet_name="unsafe")
        wunsafe = self.nodes[2].get_wallet_rpc("unsafe")
        self.nodes[0].sendtoaddress(wunsafe.getnewaddress(), 2)
        self.sync_mempools()
        assert_raises_rpc_error(-4, "Insufficient funds", wunsafe.walletcreatefundedpsbt, [], [{self.nodes[0].getnewaddress(): 1}])
        wunsafe.walletcreatefundedpsbt([], [{self.nodes[0].getnewaddress(): 1}], 0, {"include_unsafe": True})

        # Empty combiner test
        assert_raises_rpc_error(-8, "Parameter 'txs' cannot be empty", self.nodes[0].combinepsbt, [])

        self.test_native_utxo()
        self.test_psbt_incomplete_after_invalid_modification()

        self.test_input_confs_control()

        # Test that PSBTs with native outputs are created properly.
        destination = self.nodes[0].getnewaddress()
        psbt = self.nodes[1].walletcreatefundedpsbt(inputs=[], outputs=[{destination: 1}], bip32derivs=True)
        self.nodes[0].decodepsbt(psbt['psbt'])

        # Test decoding error: invalid base64
        assert_raises_rpc_error(-22, "TX decode failed invalid base64", self.nodes[0].decodepsbt, ";definitely not base64;")

        self.log.info("Test signing a Taproot input whose script is watched by another wallet")
        self.nodes[1].createwallet(wallet_name="scriptwatchonly", disable_private_keys=True)
        watchonly = self.nodes[1].get_wallet_rpc("scriptwatchonly")

        privkey, pubkey = generate_keypair(wif=True)

        desc = descsum_create("tr({},pk({}))".format(H_POINT, pubkey.hex()))
        res = watchonly.importdescriptors([{"desc": desc, "timestamp": "now"}])
        assert res[0]["success"]
        addr = self.nodes[0].deriveaddresses(desc)[0]
        self.nodes[0].sendtoaddress(addr, 10)
        self.generate(self.nodes[0], 1)
        self.nodes[0].importdescriptors([{"desc": descsum_create("tr({})".format(privkey)), "timestamp":"now"}])

        node1_wallet = self.nodes[1].get_wallet_rpc(self.default_wallet_name)
        psbt = watchonly.sendall([node1_wallet.getnewaddress(), addr])["psbt"]
        processed_psbt = self.nodes[0].walletprocesspsbt(psbt)
        txid = self.nodes[0].sendrawtransaction(processed_psbt["hex"])
        vout = find_vout_for_address(self.nodes[0], txid, addr)

        # Make sure tap tree is in psbt
        parsed_psbt = PSBT.from_base64(psbt)
        assert_greater_than(len(parsed_psbt.o[vout].map[PSBT_OUT_TAP_TREE]), 0)
        assert "taproot_tree" in self.nodes[0].decodepsbt(psbt)["outputs"][vout]
        parsed_psbt.make_blank()
        comb_psbt = self.nodes[0].combinepsbt([psbt, parsed_psbt.to_base64()])
        assert_equal(comb_psbt, psbt)

        self.log.info("Test that walletprocesspsbt both updates and signs a non-updated psbt containing Taproot inputs")
        addr = self.nodes[0].getnewaddress()
        utxo = self.create_outpoints(self.nodes[0], outputs=[{addr: 1}])[0]
        psbt = self.nodes[0].createpsbt([utxo], [{self.nodes[0].getnewaddress(): 0.9999}])
        signed = self.nodes[0].walletprocesspsbt(psbt)
        rawtx = signed["hex"]
        self.nodes[0].sendrawtransaction(rawtx)
        self.generate(self.nodes[0], 1)

        # Make sure tap tree is not in psbt
        parsed_psbt = PSBT.from_base64(psbt)
        assert PSBT_OUT_TAP_TREE not in parsed_psbt.o[0].map
        assert "taproot_tree" not in self.nodes[0].decodepsbt(psbt)["outputs"][0]
        parsed_psbt.make_blank()
        comb_psbt = self.nodes[0].combinepsbt([psbt, parsed_psbt.to_base64()])
        assert_equal(comb_psbt, psbt)

        self.log.info("Test walletprocesspsbt raises if an invalid sighashtype is passed")
        assert_raises_rpc_error(-8, "'all' is not a valid sighash parameter.", self.nodes[0].walletprocesspsbt, psbt, sighashtype="all")

        self.log.info("Test decoding PSBT with per-input preimage types")
        # note that the decodepsbt RPC doesn't check whether preimages and hashes match
        hash_ripemd160, preimage_ripemd160 = randbytes(20), randbytes(50)
        hash_sha256, preimage_sha256 = randbytes(32), randbytes(50)
        hash_hash160, preimage_hash160 = randbytes(20), randbytes(50)
        hash_hash256, preimage_hash256 = randbytes(32), randbytes(50)

        tx = CTransaction()
        tx.vin = [CTxIn(outpoint=COutPoint(hash=int('aa' * 32, 16), n=0), scriptSig=b""),
                  CTxIn(outpoint=COutPoint(hash=int('bb' * 32, 16), n=0), scriptSig=b""),
                  CTxIn(outpoint=COutPoint(hash=int('cc' * 32, 16), n=0), scriptSig=b""),
                  CTxIn(outpoint=COutPoint(hash=int('dd' * 32, 16), n=0), scriptSig=b"")]
        tx.vout = [CTxOut(nValue=0, scriptPubKey=b"")]
        psbt = self.psbt_from_tx(tx)
        psbt.i[0].map[bytes([PSBT_IN_RIPEMD160]) + hash_ripemd160] = preimage_ripemd160
        psbt.i[1].map[bytes([PSBT_IN_SHA256]) + hash_sha256] = preimage_sha256
        psbt.i[2].map[bytes([PSBT_IN_HASH160]) + hash_hash160] = preimage_hash160
        psbt.i[3].map[bytes([PSBT_IN_HASH256]) + hash_hash256] = preimage_hash256
        res_inputs = self.nodes[0].decodepsbt(psbt.to_base64())["inputs"]
        assert_equal(len(res_inputs), 4)
        preimage_keys = ["ripemd160_preimages", "sha256_preimages", "hash160_preimages", "hash256_preimages"]
        expected_hashes = [hash_ripemd160, hash_sha256, hash_hash160, hash_hash256]
        expected_preimages = [preimage_ripemd160, preimage_sha256, preimage_hash160, preimage_hash256]
        for res_input, preimage_key, hash, preimage in zip(res_inputs, preimage_keys, expected_hashes, expected_preimages):
            assert preimage_key in res_input
            assert_equal(len(res_input[preimage_key]), 1)
            assert hash.hex() in res_input[preimage_key]
            assert_equal(res_input[preimage_key][hash.hex()], preimage.hex())

        self.test_decodepsbt_musig2_input_output_types()

        self.test_combinepsbt_preserves_proprietary_fields()

        self.log.info("Test that combining PSBTs with different transactions fails")
        tx = CTransaction()
        tx.vin = [CTxIn(outpoint=COutPoint(hash=int('aa' * 32, 16), n=0), scriptSig=b"")]
        tx.vout = [CTxOut(nValue=0, scriptPubKey=b"")]
        psbt1 = self.psbt_from_tx(tx).to_base64()
        tx.vout[0].nValue += 1  # slightly modify tx
        psbt2 = self.psbt_from_tx(tx).to_base64()
        assert_raises_rpc_error(-8, "PSBTs not compatible (different transactions)", self.nodes[0].combinepsbt, [psbt1, psbt2])
        combined = self.nodes[0].combinepsbt([psbt1, psbt1])
        assert_equal(self.nodes[0].combinepsbt([combined, combined]), combined)

        self.log.info("Test we don't crash when making a 0-value funded transaction at 0 fee without forcing an input selection")
        assert_raises_rpc_error(-4, "Transaction requires one destination of non-zero value, a non-zero feerate, or a pre-selected input", self.nodes[0].walletcreatefundedpsbt, [], [{"data": "deadbeef"}], 0, {"fee_rate": "0"})

        self.log.info("Test descriptorprocesspsbt updates and signs a psbt with descriptors")

        def test_psbt_input_keys(psbt_input, keys):
            expected = set(keys) | {"previous_txid", "previous_vout", "sequence"}
            assert_equal(expected, set(psbt_input.keys()))

        self.generate(self.nodes[2], 1)

        # Disable the wallet for node 2 since `descriptorprocesspsbt` does not use the wallet
        self.restart_node(2, extra_args=["-disablewallet"])
        self.connect_nodes(0, 2)
        self.connect_nodes(1, 2)

        key_info = get_generate_key()
        key = key_info.privkey

        descriptor = descsum_create(f"tr({key})")
        address = self.nodes[2].deriveaddresses(descriptor)[0]

        utxo = self.create_outpoints(self.nodes[0], outputs=[{address: 1}])[0]
        self.sync_all()

        psbt = self.nodes[2].createpsbt([utxo], [{self.nodes[0].getnewaddress(): 0.99999}])
        decoded = self.nodes[2].decodepsbt(psbt)
        test_psbt_input_keys(decoded['inputs'][0], [])

        # Test that even if the wrong descriptor is given, the Taproot UTXO
        # and requested sighash type are still added to the PSBT.
        alt_descriptor = descsum_create(f"tr({get_generate_key().privkey})")
        alt_psbt = self.nodes[2].descriptorprocesspsbt(psbt=psbt, descriptors=[alt_descriptor], sighashtype="ALL")["psbt"]
        decoded = self.nodes[2].decodepsbt(alt_psbt)
        test_psbt_input_keys(decoded['inputs'][0], ['witness_utxo', 'sighash'])

        # Test that the psbt is not finalized and does not have bip32_derivs unless specified
        processed_psbt = self.nodes[2].descriptorprocesspsbt(psbt=psbt, descriptors=[descriptor], sighashtype="ALL", bip32derivs=True, finalize=False)
        decoded = self.nodes[2].decodepsbt(processed_psbt['psbt'])
        test_psbt_input_keys(decoded['inputs'][0], ['witness_utxo', 'sighash', 'taproot_key_path_sig', 'taproot_bip32_derivs', 'taproot_internal_key'])

        # If psbt not finalized, test that result does not have hex
        assert "hex" not in processed_psbt

        processed_psbt = self.nodes[2].descriptorprocesspsbt(psbt=psbt, descriptors=[descriptor], sighashtype="ALL", bip32derivs=False, finalize=True)
        decoded = self.nodes[2].decodepsbt(processed_psbt['psbt'])
        test_psbt_input_keys(decoded['inputs'][0], ['witness_utxo', 'final_scriptwitness'])

        # Test psbt is complete
        assert_equal(processed_psbt['complete'], True)

        # Broadcast transaction
        self.nodes[2].sendrawtransaction(processed_psbt['hex'])

        self.log.info("Test descriptorprocesspsbt raises if an invalid sighashtype is passed")
        assert_raises_rpc_error(-8, "'all' is not a valid sighash parameter.", self.nodes[2].descriptorprocesspsbt, psbt, [descriptor], sighashtype="all")

        if not self.options.usecli:
            self.test_sighash_mismatch()
        self.test_sighash_adding()
        self.test_psbt_named_parameter_handling()

if __name__ == '__main__':
    PSBTTest(__file__).main()
