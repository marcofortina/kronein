#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test the verified child-chain registry read RPCs."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    child_port,
    p2p_port,
)


class ChainRegistryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        registry_args = [
            "-chainregistryactivationheight=1",
            "-chainregistryminregistrationburn=1",
            "-chainregistrymaxoperations=4",
            "-chaindepositactivationheight=1",
            "-chaindepositminimumamount=0.01",
            "-chaindepositmaxperblock=8",
        ]
        self.extra_args = [registry_args.copy(), registry_args.copy()]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Derive identities and round-trip canonical KREG operations")
        anchor = {"txid": "01" * 32, "vout": 7}
        spec = {
            "template_id": 1,
            "template_version": 1,
            "consensus_parameters": "aabbcc",
        }
        derived = node.derivechildchainid(anchor, spec)
        assert_equal(derived["main_genesis_hash"], node.getblockhash(0))
        assert_equal(derived["registration_anchor"], anchor)
        assert_equal(derived["spec"]["protocol_version"], 1)
        assert_equal(derived["spec"]["anchoring_policy"], "bmm_v1")
        assert_equal(len(derived["chain_spec_hash"]), 64)
        assert_equal(len(derived["chain_id"]), 64)

        fund = node.createfundchainoutput(derived["chain_id"], 1, "00" * 32)
        assert_equal(fund["version"], 1)
        assert_equal(fund["chain_id"], derived["chain_id"])
        assert_equal(fund["recipient_type"], 1)
        assert_equal(fund["recipient"], "00" * 32)
        assert_equal(node.decodefundchainoutput(fund["script"]), fund)
        assert_equal(fund["script"], node.decoderawtransaction(
            node.createrawtransaction([], [{"data": fund["data"]}]))["vout"][0]["scriptPubKey"]["hex"])
        assert_raises_rpc_error(-8, "chain_id must not be null",
                                node.createfundchainoutput, "00" * 32, 1, "00")
        assert_raises_rpc_error(-8, "recipient_type must be between 1 and 65535",
                                node.createfundchainoutput, derived["chain_id"], 0, "00")
        assert_raises_rpc_error(-8, "recipient must contain at least 1 byte",
                                node.createfundchainoutput, derived["chain_id"], 1, "")
        assert_raises_rpc_error(-8, "recipient must not exceed 64 bytes",
                                node.createfundchainoutput, derived["chain_id"], 1, "00" * 65)
        assert_raises_rpc_error(-22, "invalid FUND_CHAIN output",
                                node.decodefundchainoutput, "6a")

        registration = node.createchainregistryoperation("register", {
            "anchor_input": 0,
            "control_output": 1,
            "registration_anchor": anchor,
            "spec": spec,
            "child_genesis_hash": "02" * 32,
            "metadata_hash": "03" * 32,
        })
        assert_equal(registration["operation"], "register")
        assert_equal(registration["chain_id"], derived["chain_id"])
        assert_equal(registration["chain_spec_hash"], derived["chain_spec_hash"])
        assert_equal(len(registration["manifest_hash"]), 64)
        assert_equal(registration["script"], node.decoderawtransaction(
            node.createrawtransaction([], [{"data": registration["data"]}]))["vout"][0]["scriptPubKey"]["hex"])

        decoded_registration = node.decodechainregistryoperation(registration["script"], anchor)
        assert_equal(decoded_registration["operation"], "register")
        assert_equal(decoded_registration["chain_id"], registration["chain_id"])
        assert_equal(decoded_registration["chain_spec_hash"], registration["chain_spec_hash"])
        assert_equal(decoded_registration["manifest_hash"], registration["manifest_hash"])
        assert_equal(decoded_registration["manifest"]["spec"]["consensus_parameters"], "aabbcc")

        update = node.createchainregistryoperation("update", {
            "chain_id": registration["chain_id"],
            "control_output": 2,
            "metadata_hash": "04" * 32,
        })
        decoded_update = node.decodechainregistryoperation(update["script"])
        assert_equal(decoded_update["operation"], "update")
        assert_equal(decoded_update["chain_id"], registration["chain_id"])
        assert_equal(decoded_update["control_output"], 2)
        assert_equal(decoded_update["metadata_hash"], "04" * 32)

        retirement = node.createchainregistryoperation("retire", {
            "chain_id": registration["chain_id"],
        })
        assert_equal(node.decodechainregistryoperation(retirement["script"])["operation"], "retire")

        assert_raises_rpc_error(-8, "template_id must be greater than zero",
                                node.derivechildchainid, anchor, spec | {"template_id": 0})
        assert_raises_rpc_error(-8, "unexpected parameter metadata_hash",
                                node.createchainregistryoperation, "retire", {
                                    "chain_id": registration["chain_id"],
                                    "metadata_hash": "04" * 32,
                                })
        assert_raises_rpc_error(-8, "exceeds 1024 bytes",
                                node.derivechildchainid, anchor,
                                spec | {"consensus_parameters": "00" * 1025})
        assert_raises_rpc_error(-22, "invalid chain registry operation",
                                node.decodechainregistryoperation, "6a")

        self.log.info("Check configured registry state before activation")
        info = node.getchainregistryinfo()
        assert_equal(info["enabled"], True)
        assert_equal(info["active"], False)
        assert_equal(info["active_for_next_block"], True)
        assert_equal(info["activation_height"], 1)
        assert_equal(info["minimum_registration_burn"], Decimal("1.00000000"))
        assert_equal(info["maximum_operations"], 4)
        assert_equal(info["deposits_enabled"], True)
        assert_equal(info["deposits_active"], False)
        assert_equal(info["deposits_active_for_next_block"], True)
        assert_equal(info["deposit_activation_height"], 1)
        assert_equal(info["minimum_deposit_amount"], Decimal("0.01000000"))
        assert_equal(info["maximum_deposits"], 8)
        assert_equal(info["height"], 0)
        assert_equal(info["bestblockhash"], node.getbestblockhash())
        assert_equal(info["size"], 0)
        assert_equal(info["deposit_history_start_height"], 0)
        assert_equal(info["deposit_history_complete"], True)
        assert_equal(info["deposit_count"], 0)

        self.log.info("Activate registry consensus and verify the empty committed view")
        self.generate(node, 1)
        info = node.getchainregistryinfo()
        assert_equal(info["active"], True)
        assert_equal(info["active_for_next_block"], True)
        assert_equal(info["height"], 1)
        assert_equal(info["bestblockhash"], node.getbestblockhash())
        assert_equal(info["size"], 0)
        assert_equal(len(info["root"]), 64)

        missing_deposit = node.getdepositstatus("01" * 32, 0)
        assert_equal(missing_deposit["found"], False)
        assert_equal(missing_deposit["history_start_height"], 0)
        assert_equal(missing_deposit["history_complete"], True)
        assert_raises_rpc_error(-5, "deposit not found", node.getdepositproof, "01" * 32, 0)
        assert_raises_rpc_error(-8, "txid must not be null", node.getdepositstatus, "00" * 32, 0)
        assert_raises_rpc_error(-8, "vout must be less than", node.getdepositstatus, "01" * 32, -1)

        page = node.listchildchains()
        assert_equal(page["bestblockhash"], info["bestblockhash"])
        assert_equal(page["height"], info["height"])
        assert_equal(page["root"], info["root"])
        assert_equal(page["size"], 0)
        assert_equal(page["returned"], 0)
        assert_equal(page["has_more"], False)
        assert_equal(page["chains"], [])

        missing_id = "01" + "00" * 31
        missing = node.getchildchain(missing_id, True)
        assert_equal(missing["bestblockhash"], info["bestblockhash"])
        assert_equal(missing["height"], info["height"])
        assert_equal(missing["root"], info["root"])
        assert_equal(missing["found"], False)
        assert "chain" not in missing
        assert "inclusion_proof" not in missing
        assert_equal(missing["non_inclusion_proof"], {"leaf_count": 0})

        self.log.info("Reject malformed identifiers and invalid pagination bounds")
        assert_raises_rpc_error(-8, "chain_id must be exactly 32 non-null bytes", node.getchildchain, "01")
        assert_raises_rpc_error(-8, "chain_id must be exactly 32 non-null bytes", node.listchildchains, "zz" * 32)
        assert_raises_rpc_error(-8, "chain_id must be exactly 32 non-null bytes", node.getchildchain, "00" * 32)
        assert_raises_rpc_error(-8, "chain_id must be exactly 32 non-null bytes", node.listchildchains, "00" * 32)
        assert_raises_rpc_error(-8, "limit must be between 1 and 1000", node.listchildchains, None, 0)
        assert_raises_rpc_error(-8, "limit must be between 1 and 1000", node.listchildchains, None, 1001)

        self.log.info("Register, update, and retire a child chain through funded wallet PSBTs")
        node.createwallet("registry")
        wallet = node.get_wallet_rpc("registry")
        self.generatetoaddress(node, 101, wallet.getnewaddress())
        pre_registration = node.getchainregistryinfo()

        anchor_utxo = wallet.listunspent(1)[0]
        registration_anchor = {"txid": anchor_utxo["txid"], "vout": anchor_utxo["vout"]}
        control_address = wallet.getnewaddress()
        reference_child = node.createreferencechildmanifest(
            registration_anchor, "22" * 32)
        wallet_spec = {
            "template_id": reference_child["manifest"]["spec"]["template_id"],
            "template_version": reference_child["manifest"]["spec"]["template_version"],
            "consensus_parameters": reference_child["manifest"]["spec"]["consensus_parameters"],
            "anchoring_policy": reference_child["manifest"]["spec"]["anchoring_policy"],
        }
        registration_psbt = wallet.walletcreatechainregistrypsbt("register", {
            "registration_anchor": registration_anchor,
            "spec": wallet_spec,
            "child_genesis_hash": reference_child["genesis_hash"],
            "metadata_hash": "22" * 32,
            "control_address": control_address,
        }, {"fee_rate": 1})
        assert_equal(registration_psbt["operation"], "register")
        assert_equal(registration_psbt["authority_outpoint"], registration_anchor)
        assert_equal(registration_psbt["operation_vout"], 0)
        assert_equal(registration_psbt["control_vout"], 1)
        assert_equal(registration_psbt["registry_bestblockhash"], node.getbestblockhash())

        assert_raises_rpc_error(-8, "exceeds authorized maximum",
                                wallet.walletsubmitchainregistrypsbt,
                                registration_psbt["psbt"], Decimal("0.50000000"))
        submitted_registration = wallet.walletsubmitchainregistrypsbt(registration_psbt["psbt"])
        assert_equal(submitted_registration["operation"], "register")
        assert_equal(submitted_registration["chain_id"], registration_psbt["chain_id"])
        assert_equal(submitted_registration["registration_burn"], Decimal("1.00000000"))
        decoded_registration_tx = node.decoderawtransaction(submitted_registration["hex"])
        assert_equal(decoded_registration_tx["vin"][0]["txid"], registration_anchor["txid"])
        assert_equal(decoded_registration_tx["vin"][0]["vout"], registration_anchor["vout"])
        assert_equal(decoded_registration_tx["vout"][0]["value"], Decimal("1.00000000"))
        assert_equal(decoded_registration_tx["vout"][0]["scriptPubKey"]["type"], "nulldata")
        assert_equal(decoded_registration_tx["vout"][1]["scriptPubKey"]["address"], control_address)
        registration_txid = submitted_registration["txid"]
        assert_equal(registration_txid, decoded_registration_tx["txid"])
        registration_block = self.generatetoaddress(node, 1, wallet.getnewaddress())[0]
        self.sync_blocks()

        chain_id = registration_psbt["chain_id"]
        registered = node.getchildchain(chain_id, True)
        assert_equal(registered["found"], True)
        assert_equal(registered["chain"]["status"], "active")
        assert_equal(registered["chain"]["metadata_hash"], "22" * 32)
        assert_equal(registered["chain"]["control_outpoint"], {
            "txid": registration_txid,
            "vout": 1,
        })
        assert "inclusion_proof" in registered
        registered_info = node.getchainregistryinfo()

        self.log.info("Reserve registry control outputs from ordinary wallet spending")
        control_outpoint = {"txid": registration_txid, "vout": 1}
        assert_raises_rpc_error(
            -4, "reserved as a child-chain registry control output",
            wallet.walletcreatefundedpsbt,
            [control_outpoint],
            [{wallet.getnewaddress(): Decimal("0.00001000")}],
            0,
            {"add_inputs": False, "fee_rate": 1})
        funding_probe = wallet.walletcreatefundchainpsbt(
            chain_id, 1, "41" * 32, Decimal("0.01000000"), {"fee_rate": 1})
        decoded_probe = node.decodepsbt(funding_probe["psbt"])["tx"]
        assert control_outpoint not in [
            {"txid": txin["txid"], "vout": txin["vout"]}
            for txin in decoded_probe["vin"]
        ]

        self.log.info("Configure and exercise the opt-in child runtime lifecycle")
        runtimes = node.listchildchainruntimes()
        assert_equal(runtimes["loaded"], 0)
        assert_equal(runtimes["max_loaded"], 8)
        assert_equal(runtimes["aggregate_upload_target"], 8 << 30)
        assert_equal(runtimes["aggregate_upload_bytes_sent"], 0)
        assert_equal(runtimes["aggregate_upload_bytes_left"], 8 << 30)
        assert_equal(runtimes["aggregate_upload_timeframe"], 24 * 60 * 60)
        assert_equal(runtimes["aggregate_upload_time_left"], 24 * 60 * 60)
        assert_equal(runtimes["aggregate_upload_target_reached"], False)
        assert_equal(len(runtimes["chains"]), 1)
        assert_equal(runtimes["chains"][0]["chain_id"], chain_id)
        assert_equal(runtimes["chains"][0]["state"], "available")
        assert_equal(runtimes["chains"][0]["configured"], False)
        configured = node.addchildchain(
            registration_anchor, reference_child["manifest"])
        assert_equal(configured["chain_id"], chain_id)
        assert_equal(configured["already_configured"], False)
        assert_equal(configured["loaded"], False)
        assert_equal(node.addchildchain(
            registration_anchor,
            reference_child["manifest"])["already_configured"], True)
        assert_raises_rpc_error(
            -8, "explicit non-zero port",
            node.loadchildchain, chain_id, {"connect": ["127.0.0.1"]})
        failed_runtime = node.listchildchainruntimes()["chains"][0]
        assert_equal(failed_runtime["loaded"], False)
        assert_equal(failed_runtime["network_running"], False)
        child_endpoint = f"127.0.0.1:{child_port(0)}"
        loaded = node.loadchildchain(
            chain_id, {"bind": [child_endpoint]})
        assert_equal(loaded["loaded"], True)
        assert_equal(loaded["already_loaded"], False)
        assert_equal(loaded["height"], 0)
        assert_equal(loaded["bestblockhash"], reference_child["genesis_hash"])
        assert_equal(loaded["main_height"], node.getblockcount())
        assert_equal(loaded["main_bestblockhash"], node.getbestblockhash())
        assert_equal(loaded["network_running"], True)
        assert_equal(loaded["network_already_running"], False)
        assert_equal(loaded["network_active"], True)
        assert_equal(loaded["connections"], 0)
        assert_equal(loaded["handshaken_peers"], 0)
        assert_equal(loaded["rate_limited_block_requests"], 0)
        assert_equal(loaded["discovery_enabled"], False)
        assert_equal(loaded["bootstrap_nodes"], [])
        assert_equal(loaded["added_nodes"], [])
        assert_equal(loaded["binds"], [child_endpoint])
        network_info = node.getchildnetworkinfo(chain_id)
        assert_equal(network_info["chain_id"], chain_id)
        assert_equal(network_info["network_running"], True)
        assert_equal(network_info["max_added_nodes"], 8)
        assert_equal(network_info["max_bind_endpoints"], 4)
        assert_equal(network_info["max_bootstrap_nodes"], 8)
        assert_equal(network_info["max_automatic_connections"], 4)
        assert_equal(network_info["rate_limited_block_requests"], 0)
        assert_equal(network_info["aggregate_upload_target"], 8 << 30)
        assert_equal(network_info["aggregate_upload_target_reached"], False)
        assert_equal(network_info["binds"], [child_endpoint])
        paused = node.setchildnetworkactive(chain_id, False)
        assert_equal(paused["network_active"], False)
        assert_raises_rpc_error(
            -8, "numeric address",
            node.setchildnetworkdiscovery,
            chain_id, True, ["seed.example:29843"])
        discovery = node.setchildnetworkdiscovery(
            chain_id, True, ["192.0.2.1:29843"])
        assert_equal(discovery["discovery_enabled"], True)
        assert_equal(discovery["bootstrap_nodes"], ["192.0.2.1:29843"])
        discovery_disabled = node.setchildnetworkdiscovery(
            chain_id, False, [])
        assert_equal(discovery_disabled["discovery_enabled"], False)
        assert_equal(discovery_disabled["bootstrap_nodes"], [])
        endpoint = "127.0.0.1:29999"
        added_node = node.addchildnode(chain_id, endpoint)
        assert_equal(added_node["added_nodes"], [endpoint])
        assert_raises_rpc_error(
            -8, "already configured",
            node.addchildnode, chain_id, endpoint)
        removed_node = node.removechildnode(chain_id, endpoint)
        assert_equal(removed_node["added_nodes"], [])
        assert_raises_rpc_error(
            -8, "not configured",
            node.removechildnode, chain_id, endpoint)
        resumed = node.setchildnetworkactive(chain_id, True)
        assert_equal(resumed["network_active"], True)

        self.log.info("Accept and authenticate an isolated child-network peer")
        peer_node = self.nodes[1]
        configured_peer = peer_node.addchildchain(
            registration_anchor, reference_child["manifest"])
        assert_equal(configured_peer["chain_id"], chain_id)
        peer_loaded = peer_node.loadchildchain(
            chain_id, {"connect": [child_endpoint]})
        assert_equal(peer_loaded["binds"], [])
        assert_equal(peer_loaded["added_nodes"], [child_endpoint])
        self.wait_until(
            lambda: node.getchildnetworkinfo(chain_id)["handshaken_peers"] == 1)
        self.wait_until(
            lambda: peer_node.getchildnetworkinfo(chain_id)["handshaken_peers"] == 1)
        assert_equal(node.getchildnetworkinfo(chain_id)["connections"], 1)
        assert_equal(peer_node.getchildnetworkinfo(chain_id)["connections"], 1)

        self.log.info("Restart only the child listener and roll back failed binds")
        occupied_endpoint = f"127.0.0.1:{p2p_port(0)}"
        assert_raises_rpc_error(
            -1, "failed to start isolated child network",
            node.setchildnetworkbinds, chain_id, [occupied_endpoint])
        assert_equal(
            node.getchildnetworkinfo(chain_id)["binds"], [child_endpoint])
        assert_equal(
            peer_node.unloadchildchain(chain_id)["network_running"], False)
        peer_node.loadchildchain(
            chain_id, {"connect": [child_endpoint]})
        self.wait_until(
            lambda: node.getchildnetworkinfo(chain_id)["handshaken_peers"] == 1)
        self.wait_until(
            lambda: peer_node.getchildnetworkinfo(chain_id)["handshaken_peers"] == 1)
        disabled_listener = node.setchildnetworkbinds(chain_id, [])
        assert_equal(disabled_listener["network_running"], True)
        assert_equal(disabled_listener["binds"], [])
        self.wait_until(
            lambda: node.getchildnetworkinfo(chain_id)["connections"] == 0)
        restored_listener = node.setchildnetworkbinds(
            chain_id, [child_endpoint])
        assert_equal(restored_listener["binds"], [child_endpoint])
        assert_equal(
            peer_node.unloadchildchain(chain_id)["network_running"], False)
        peer_node.loadchildchain(
            chain_id, {"connect": [child_endpoint]})
        self.wait_until(
            lambda: node.getchildnetworkinfo(chain_id)["handshaken_peers"] == 1)
        self.wait_until(
            lambda: peer_node.getchildnetworkinfo(chain_id)["handshaken_peers"] == 1)
        assert_equal(peer_node.unloadchildchain(chain_id)["network_running"], False)
        main_height = node.getblockcount()
        main_tip = node.getbestblockhash()
        assert_equal(node.getblockcount(chain_id), 0)
        assert_equal(node.getbestblockhash(chain_id=chain_id), reference_child["genesis_hash"])
        assert_equal(node.getblockhash(0, chain_id), reference_child["genesis_hash"])
        assert_equal(node.getblockcount(), main_height)
        assert_equal(node.getbestblockhash(), main_tip)
        assert_raises_rpc_error(-8, "Block height out of range",
                                node.getblockhash, 1, chain_id)
        loaded_again = node.loadchildchain(chain_id)
        assert_equal(loaded_again["already_loaded"], True)
        assert_equal(loaded_again["network_already_running"], True)
        loaded_runtime = node.listchildchainruntimes()["chains"][0]
        assert_equal(loaded_runtime["state"], "loaded")
        assert_equal(loaded_runtime["network_running"], True)
        unloaded = node.unloadchildchain(chain_id)
        assert_equal(unloaded["loaded"], False)
        assert_equal(unloaded["network_running"], False)
        stopped_network = node.getchildnetworkinfo(chain_id)
        assert_equal(stopped_network["network_running"], False)
        assert_equal(stopped_network["network_active"], True)
        assert_equal(stopped_network["added_nodes"], [])
        assert_equal(stopped_network["binds"], [child_endpoint])
        assert_raises_rpc_error(-1, "child chain is not loaded",
                                node.getblockcount, chain_id)
        forgotten = node.forgetchildchain(chain_id)
        assert_equal(forgotten["configured"], False)
        assert_equal(forgotten["data_preserved"], True)
        assert_equal(node.listchildchainruntimes()["chains"][0]["state"], "available")
        assert_equal(node.addchildchain(
            registration_anchor,
            reference_child["manifest"])["already_configured"], False)
        reloaded = node.loadchildchain(chain_id)
        assert_equal(reloaded["loaded"], True)
        assert_equal(reloaded["bestblockhash"], reference_child["genesis_hash"])
        assert_equal(reloaded["main_height"], node.getblockcount())
        assert_equal(reloaded["main_bestblockhash"], node.getbestblockhash())
        assert_equal(reloaded["binds"], [child_endpoint])
        assert_raises_rpc_error(-8, "chain_id must not be null",
                                node.loadchildchain, "00" * 32)

        self.log.info("Index and export a canonical proof for an irreversible child deposit")
        deposit_amount = Decimal("0.25000000")
        deposit_psbt = wallet.walletcreatefundchainpsbt(
            chain_id, 1, "42" * 32, deposit_amount, {"fee_rate": 1})
        assert_equal(deposit_psbt["deposit_vout"], 0)
        assert_equal(deposit_psbt["amount"], deposit_amount)
        assert_equal(deposit_psbt["chain_id"], chain_id)
        assert_equal(deposit_psbt["recipient_type"], 1)
        assert_equal(deposit_psbt["recipient"], "42" * 32)
        assert_equal(deposit_psbt["irreversible"], True)
        assert "cannot be reversed" in deposit_psbt["warning"]
        assert_raises_rpc_error(
            -8, "confirm_irreversible must be true",
            wallet.walletsubmitfundchainpsbt,
            deposit_psbt["psbt"], False, deposit_amount)
        assert_raises_rpc_error(
            -8, "exceeds authorized maximum",
            wallet.walletsubmitfundchainpsbt,
            deposit_psbt["psbt"], True, Decimal("0.24999999"))
        submitted_deposit = wallet.walletsubmitfundchainpsbt(
            deposit_psbt["psbt"], True, deposit_amount)
        assert_equal(submitted_deposit["vout"], 0)
        assert_equal(submitted_deposit["chain_id"], chain_id)
        assert_equal(submitted_deposit["recipient"], "42" * 32)
        assert_equal(submitted_deposit["amount"], deposit_amount)
        assert_equal(submitted_deposit["irreversible"], True)
        deposit_txid = submitted_deposit["txid"]
        deposit_block = self.generatetoaddress(node, 1, wallet.getnewaddress())[0]

        deposit_status = node.getdepositstatus(deposit_txid, 0)
        assert_equal(deposit_status["found"], True)
        assert_equal(deposit_status["history_complete"], True)
        assert_equal(deposit_status["deposit"]["deposit_id"], deposit_status["deposit_id"])
        assert_equal(deposit_status["deposit_id"], submitted_deposit["deposit_id"])
        assert_equal(deposit_status["deposit"]["outpoint"], {"txid": deposit_txid, "vout": 0})
        assert_equal(deposit_status["deposit"]["amount"], deposit_amount)
        assert_equal(deposit_status["deposit"]["destination"], {
            "chain_id": chain_id,
            "recipient_type": 1,
            "recipient": "42" * 32,
        })
        assert_equal(deposit_status["deposit"]["blockhash"], deposit_block)
        assert_equal(deposit_status["deposit"]["confirmations"], 1)
        assert_equal(deposit_status["deposit"]["proof_available"], True)
        assert_equal(deposit_status["deposit"]["registry_root"], registered_info["root"])
        assert_equal(deposit_status["deposit"]["chain_record"], registered["chain"])

        deposit_proof = node.getdepositproof(deposit_txid, 0)
        assert_equal(deposit_proof["proof_version"], 1)
        assert_equal(deposit_proof["main_genesis_hash"], node.getblockhash(0))
        assert_equal(deposit_proof["deposit"], deposit_status["deposit"])
        assert len(deposit_proof["funding_transaction"]) > 20
        assert_equal(len(deposit_proof["block_header"]), 160)
        assert deposit_proof["proof"].startswith("4b44505201")
        assert_equal(node.getchainregistryinfo()["deposit_count"], 1)

        successor_address = wallet.getnewaddress()
        update_psbt = wallet.walletcreatechainregistrypsbt("update", {
            "chain_id": chain_id,
            "metadata_hash": "33" * 32,
            "control_address": successor_address,
        }, {"fee_rate": 1})
        assert_equal(update_psbt["authority_outpoint"], {
            "txid": registration_txid,
            "vout": 1,
        })
        submitted_update = wallet.walletsubmitchainregistrypsbt(update_psbt["psbt"])
        assert_equal(submitted_update["operation"], "update")
        assert_equal(submitted_update["registration_burn"], Decimal("0.00000000"))
        decoded_update_tx = node.decoderawtransaction(submitted_update["hex"])
        assert_equal(decoded_update_tx["vin"][0]["txid"], registration_txid)
        assert_equal(decoded_update_tx["vin"][0]["vout"], 1)
        assert_equal(decoded_update_tx["vout"][0]["value"], Decimal("0.00000000"))
        assert_equal(decoded_update_tx["vout"][0]["scriptPubKey"]["type"], "nulldata")
        assert_equal(decoded_update_tx["vout"][1]["scriptPubKey"]["address"], successor_address)
        update_txid = submitted_update["txid"]
        update_block = self.generatetoaddress(node, 1, wallet.getnewaddress())[0]

        updated = node.getchildchain(chain_id)
        assert_equal(updated["chain"]["metadata_hash"], "33" * 32)
        assert_equal(updated["chain"]["control_outpoint"], {"txid": update_txid, "vout": 1})
        updated_runtime = node.listchildchainruntimes()["chains"][0]
        assert_equal(updated_runtime["loaded"], True)
        assert_equal(updated_runtime["main_height"], node.getblockcount())
        assert_equal(updated_runtime["main_bestblockhash"], node.getbestblockhash())
        updated_info = node.getchainregistryinfo()

        self.log.info("Follow an active-main disconnect and reconnect while loaded")
        node.invalidateblock(update_block)
        node.syncwithvalidationinterfacequeue()
        disconnected_runtime = node.listchildchainruntimes()["chains"][0]
        assert_equal(disconnected_runtime["loaded"], True)
        assert_equal(disconnected_runtime["main_height"], node.getblockcount())
        assert_equal(disconnected_runtime["main_bestblockhash"], deposit_block)
        node.reconsiderblock(update_block)
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getbestblockhash(), update_block)
        reconnected_runtime = node.listchildchainruntimes()["chains"][0]
        assert_equal(reconnected_runtime["loaded"], True)
        assert_equal(reconnected_runtime["main_height"], node.getblockcount())
        assert_equal(reconnected_runtime["main_bestblockhash"], update_block)

        retirement_psbt = wallet.walletcreatechainregistrypsbt("retire", {
            "chain_id": chain_id,
        }, {"fee_rate": 1})
        assert "control_vout" not in retirement_psbt
        assert_equal(retirement_psbt["authority_outpoint"], {"txid": update_txid, "vout": 1})
        submitted_retirement = wallet.walletsubmitchainregistrypsbt(retirement_psbt["psbt"])
        assert_equal(submitted_retirement["operation"], "retire")
        decoded_retirement_tx = node.decoderawtransaction(submitted_retirement["hex"])
        assert_equal(decoded_retirement_tx["vin"][0]["txid"], update_txid)
        assert_equal(decoded_retirement_tx["vin"][0]["vout"], 1)
        assert_equal(decoded_retirement_tx["vout"][0]["value"], Decimal("0.00000000"))
        retirement_txid = submitted_retirement["txid"]
        assert_equal(retirement_txid, decoded_retirement_tx["txid"])
        retirement_block = self.generatetoaddress(node, 1, wallet.getnewaddress())[0]

        retired = node.getchildchain(chain_id)
        assert_equal(retired["chain"]["status"], "retired")
        assert retired["chain"]["retired_height"] > 0
        assert_equal(node.listchildchains()["chains"], [])
        assert_equal(node.listchildchains(None, 100, True)["chains"][0]["chain_id"], chain_id)
        retired_runtime = node.listchildchainruntimes()["chains"][0]
        assert_equal(retired_runtime["state"], "retired")
        assert_equal(retired_runtime["configured"], True)
        assert_equal(retired_runtime["loaded"], False)
        assert_equal(retired_runtime["network_running"], False)
        assert_raises_rpc_error(-8, "retired on the active main chain",
                                node.loadchildchain, chain_id)
        retired_info = node.getchainregistryinfo()

        assert_raises_rpc_error(-8, "chain_id must be exactly 32 non-null bytes",
                                wallet.walletcreatechainregistrypsbt, "retire", {"chain_id": "00" * 32})

        self.log.info("Roll registry state backward across RETIRE, UPDATE, and REGISTER")
        node.invalidateblock(retirement_block)
        assert_equal(node.getbestblockhash(), update_block)
        assert_equal(node.getchainregistryinfo()["root"], updated_info["root"])
        rolled_back_update = node.getchildchain(chain_id)
        assert_equal(rolled_back_update["chain"]["status"], "active")
        assert_equal(rolled_back_update["chain"]["metadata_hash"], "33" * 32)
        assert_equal(rolled_back_update["chain"]["control_outpoint"], {"txid": update_txid, "vout": 1})

        node.invalidateblock(update_block)
        assert_equal(node.getbestblockhash(), deposit_block)
        assert_equal(node.getchainregistryinfo()["root"], registered_info["root"])
        rolled_back_registration = node.getchildchain(chain_id)
        assert_equal(rolled_back_registration["chain"]["status"], "active")
        assert_equal(rolled_back_registration["chain"]["metadata_hash"], "22" * 32)
        assert_equal(rolled_back_registration["chain"]["control_outpoint"], {
            "txid": registration_txid,
            "vout": 1,
        })

        assert_equal(node.getdepositstatus(deposit_txid, 0)["found"], True)
        node.invalidateblock(deposit_block)
        assert_equal(node.getbestblockhash(), registration_block)
        assert_equal(node.getdepositstatus(deposit_txid, 0)["found"], False)
        assert_equal(node.getchainregistryinfo()["deposit_count"], 0)

        node.invalidateblock(registration_block)
        assert_equal(node.getbestblockhash(), pre_registration["bestblockhash"])
        assert_equal(node.getchainregistryinfo()["root"], pre_registration["root"])
        assert_equal(node.getchildchain(chain_id)["found"], False)

        self.log.info("Reload rolled-back state, reconnect the branch, and reload it again")
        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getbestblockhash(), pre_registration["bestblockhash"])
        assert_equal(node.getchainregistryinfo()["root"], pre_registration["root"])
        assert_equal(node.getchildchain(chain_id)["found"], False)

        node.reconsiderblock(registration_block)
        assert_equal(node.getbestblockhash(), retirement_block)
        reconnected_info = node.getchainregistryinfo()
        assert_equal(reconnected_info["root"], retired_info["root"])
        assert_equal(reconnected_info["size"], retired_info["size"])
        assert_equal(reconnected_info["deposit_count"], 1)
        assert_equal(node.getchildchain(chain_id)["chain"]["status"], "retired")
        persisted_runtime = node.listchildchainruntimes()["chains"][0]
        assert_equal(persisted_runtime["state"], "retired")
        assert_equal(persisted_runtime["configured"], True)
        assert_equal(persisted_runtime["loaded"], False)
        assert_equal(node.getdepositstatus(deposit_txid, 0)["found"], True)

        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getbestblockhash(), retirement_block)
        assert_equal(node.getchainregistryinfo()["root"], retired_info["root"])
        assert_equal(node.getchildchain(chain_id)["chain"]["status"], "retired")

        self.log.info("Rebuild the registry through chainstate and full reindex")
        registry_args = [
            "-chainregistryactivationheight=1",
            "-chainregistryminregistrationburn=1",
            "-chainregistrymaxoperations=4",
            "-chaindepositactivationheight=1",
            "-chaindepositminimumamount=0.01",
            "-chaindepositmaxperblock=8",
        ]
        for reindex_arg in ["-reindex-chainstate", "-reindex"]:
            self.restart_node(0, registry_args + [reindex_arg])
            node = self.nodes[0]
            assert_equal(node.getbestblockhash(), retirement_block)
            rebuilt_info = node.getchainregistryinfo()
            assert_equal(rebuilt_info["root"], retired_info["root"])
            assert_equal(rebuilt_info["size"], retired_info["size"])
            assert_equal(rebuilt_info["deposit_count"], 1)
            rebuilt_chain = node.getchildchain(chain_id, True)
            assert_equal(rebuilt_chain["found"], True)
            assert_equal(rebuilt_chain["chain"]["status"], "retired")
            assert "inclusion_proof" in rebuilt_chain

        self.log.info("Preserve the current registry while pruning block and registry undo data")
        prune_args = registry_args + ["-prune=1", "-fastprune"]
        self.restart_node(0, prune_args)
        node = self.nodes[0]
        node.loadwallet("registry")
        wallet = node.get_wallet_rpc("registry")
        self.generatetoaddress(
            node, 500, wallet.getnewaddress(), sync_fun=lambda: None)
        prune_target = node.getblockcount() - 288
        assert node.pruneblockchain(prune_target) > 0
        blockchain_info = node.getblockchaininfo()
        assert_equal(blockchain_info["pruned"], True)
        assert blockchain_info["pruneheight"] > 0

        pruned_registry_info = node.getchainregistryinfo()
        assert_equal(pruned_registry_info["root"], retired_info["root"])
        assert_equal(pruned_registry_info["size"], retired_info["size"])
        pruned_chain = node.getchildchain(chain_id, True)
        assert_equal(pruned_chain["chain"]["status"], "retired")
        assert "inclusion_proof" in pruned_chain
        pruned_deposit = node.getdepositstatus(deposit_txid, 0)
        assert_equal(pruned_deposit["found"], True)
        assert_equal(pruned_deposit["deposit"]["proof_available"], False)
        assert_raises_rpc_error(-1, "Block not available (pruned data)",
                                node.getdepositproof, deposit_txid, 0)

        self.restart_node(0, prune_args)
        node = self.nodes[0]
        assert_equal(node.getchainregistryinfo()["root"], retired_info["root"])
        assert_equal(node.getchildchain(chain_id, True)["chain"]["status"], "retired")
        assert_equal(node.getdepositstatus(deposit_txid, 0)["found"], True)

        self.log.info("Reject an invalid aggregate child upload target")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=prune_args + ["-maxchilduploadtarget=invalid"],
            expected_msg="Error: Unable to parse -maxchilduploadtarget: 'invalid'",
        )


if __name__ == "__main__":
    ChainRegistryTest(__file__).main()
