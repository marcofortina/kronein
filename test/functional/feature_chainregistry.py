#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test the verified child-chain registry read RPCs."""

from decimal import Decimal
from io import BytesIO
import json
import os
import sys

from test_framework.address import address_to_scriptpubkey
from test_framework.messages import CBlock
from test_framework.psbt import (
    PSBT,
    PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_OUT_SCRIPT,
    PSBT_OUT_TAP_BIP32_DERIVATION,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    child_port,
    p2p_port,
)


class ChainRegistryTest(BitcoinTestFramework):
    def mock_signer_path(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            "mocks", "signer.py")
        return sys.executable + " " + path

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
            "-chainbmmactivationheight=1",
            "-chainbmmmaxanchorsperblock=4",
        ]
        node_args = registry_args.copy()
        if self.is_external_signer_compiled():
            node_args.append(f"-signer={self.mock_signer_path()}")
        self.extra_args = [node_args, registry_args.copy()]

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
        node.createwallet("registry_attacker")
        attacker = node.get_wallet_rpc("registry_attacker")
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
        assert_equal(registration_psbt["registration_burn"], Decimal("1.00000000"))
        assert_equal(registration_psbt["authority_outpoint"], registration_anchor)
        assert_equal(registration_psbt["operation_vout"], 0)
        assert_equal(registration_psbt["control_vout"], 1)
        assert_equal(registration_psbt["registry_bestblockhash"], node.getbestblockhash())

        attacker_control_address = attacker.getnewaddress()
        attacker_control_script = bytes.fromhex(
            attacker.getaddressinfo(attacker_control_address)["scriptPubKey"])
        redirected_registration = PSBT.from_base64(registration_psbt["psbt"])
        redirected_registration.o[1].map[PSBT_OUT_SCRIPT] = attacker_control_script
        assert_raises_rpc_error(
            -8, "successor control output is not owned by this wallet",
            wallet.walletsubmitchainregistrypsbt,
            redirected_registration.to_base64())

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

        self.log.info("Derive and persist a wallet-owned child receiving identity")
        assert "chain_id" not in wallet.getbalances()
        assert all("chain_id" not in coin for coin in wallet.listunspent())
        assert_raises_rpc_error(
            -8, "chain_id must be exactly 32 non-null bytes",
            wallet.getnewchildrecipient, "00" * 32)
        assert_raises_rpc_error(
            -8, "chain_id is not registered",
            wallet.getnewchildrecipient, "01" * 32)
        child_identity = wallet.getnewchildrecipient(chain_id, "child-receive")
        child_recipient = child_identity["recipient"]
        assert_equal(child_identity["chain_id"], chain_id)
        assert_equal(child_identity["recipient_type"], 1)
        assert_equal(len(child_recipient), 64)
        assert_equal(child_identity["scriptPubKey"], "5120" + child_recipient)
        assert_equal(child_identity["label"], "child-receive")
        listed_identities = wallet.listchildrecipients(chain_id)
        assert_equal(listed_identities["chain_id"], chain_id)
        assert_equal(listed_identities["recipient_count"], 1)
        assert_equal(listed_identities["recipients"], [child_identity])
        assert_raises_rpc_error(
            -8, "chain_id must be exactly 32 non-null bytes",
            wallet.getbalances, "00" * 32)
        assert_raises_rpc_error(
            -8, "chain_id must be exactly 32 non-null bytes",
            wallet.listunspent, 1, 9999999, [], True, {}, "00" * 32)
        assert_raises_rpc_error(
            -8, "child chain is not configured locally",
            wallet.getbalances, chain_id)

        self.log.info("Reserve registry control outputs from ordinary wallet spending")
        control_outpoint = {"txid": registration_txid, "vout": 1}
        assert_raises_rpc_error(
            -4, "reserved as a child-chain registry control output",
            wallet.walletcreatefundedpsbt,
            [control_outpoint],
            [{wallet.getnewaddress(): Decimal("0.00001000")}],
            0,
            {"add_inputs": False, "fee_rate": 1})
        control_reference = node.createreferencechildmanifest(
            control_outpoint, "23" * 32)
        assert_raises_rpc_error(
            -8, "registration_anchor is reserved as a child-chain registry control output",
            wallet.walletcreatechainregistrypsbt,
            "register",
            {
                "registration_anchor": control_outpoint,
                "spec": {
                    "template_id": control_reference["manifest"]["spec"]["template_id"],
                    "template_version": control_reference["manifest"]["spec"]["template_version"],
                    "consensus_parameters": control_reference["manifest"]["spec"]["consensus_parameters"],
                    "anchoring_policy": control_reference["manifest"]["spec"]["anchoring_policy"],
                },
                "child_genesis_hash": control_reference["genesis_hash"],
                "metadata_hash": "23" * 32,
                "control_address": wallet.getnewaddress(),
            },
            {"fee_rate": 1})
        funding_probe = wallet.walletcreatefundchainpsbt(
            chain_id, 1, child_recipient, Decimal("0.01000000"), {"fee_rate": 1})
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
        assert_equal(loaded["historical_anchor_index_complete"], True)
        assert_equal(loaded["historical_anchor_lookups"], 0)
        assert_equal(loaded["local_proposals_checked"], 0)
        assert_equal(loaded["historical_anchors_found"], 0)
        assert_equal(loaded["historical_anchor_block_data_unavailable"], 0)
        assert_equal(loaded["historical_anchor_proofs_built"], 0)
        assert_equal(loaded["historical_anchors_staged"], 0)
        assert_equal(loaded["historical_proposals_activated"], 0)
        assert_equal(loaded["historical_proposal_activation_failures"], 0)
        assert_equal(loaded["historical_anchor_stage_failures"], 0)
        assert_equal(loaded["network_running"], True)
        assert_equal(loaded["network_already_running"], False)
        assert_equal(loaded["network_active"], True)
        assert_equal(loaded["connections"], 0)
        assert_equal(loaded["handshaken_peers"], 0)
        assert_equal(loaded["known_addresses"], 0)
        assert_equal(loaded["rate_limited_block_requests"], 0)
        assert_equal(loaded["discovery_enabled"], False)
        assert_equal(loaded["bootstrap_nodes"], [])
        assert_equal(loaded["added_nodes"], [])
        assert_equal(loaded["binds"], [child_endpoint])
        initial_child_balance = wallet.getbalances(chain_id)
        assert_equal(initial_child_balance["chain_id"], chain_id)
        assert_equal(initial_child_balance["mine"], {
            "trusted": Decimal("0.00000000"),
            "untrusted_pending": Decimal("0.00000000"),
            "immature": Decimal("0.00000000"),
        })
        assert_equal(initial_child_balance["lastprocessedblock"], {
            "hash": reference_child["genesis_hash"],
            "height": 0,
        })
        assert_equal(wallet.listunspent(
            1, 9999999, [], True, {}, chain_id), [])
        assert_raises_rpc_error(
            -8, "addresses must be empty when chain_id selects a child chain",
            wallet.listunspent, 1, 9999999,
            [wallet.getnewaddress()], True, {}, chain_id)
        initial_bmm_status = node.getchildbmmstatus(chain_id)
        assert_equal(initial_bmm_status["health"], "idle")
        assert_equal(initial_bmm_status["child_height"], 0)
        assert_equal(initial_bmm_status["bestblockhash"], reference_child["genesis_hash"])
        assert_equal(initial_bmm_status["main_height"], node.getblockcount())
        assert_equal(initial_bmm_status["main_bestblockhash"], node.getbestblockhash())
        assert_equal(initial_bmm_status["canonical_anchor_count"], 0)
        assert_equal(initial_bmm_status["has_tip_anchor"], False)
        assert_equal(initial_bmm_status["pending_blocks"], [])
        assert_equal(initial_bmm_status["proposals"], [])
        network_info = node.getchildnetworkinfo(chain_id)
        assert_equal(network_info["chain_id"], chain_id)
        assert_equal(network_info["network_running"], True)
        assert_equal(network_info["max_added_nodes"], 8)
        assert_equal(network_info["max_bind_endpoints"], 4)
        assert_equal(network_info["max_bootstrap_nodes"], 8)
        assert_equal(network_info["max_automatic_connections"], 4)
        assert_equal(network_info["rate_limited_block_requests"], 0)
        assert_equal(network_info["known_addresses"], 0)
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
            chain_id, True, ["8.8.8.8:29843"])
        assert_equal(discovery["discovery_enabled"], True)
        assert_equal(discovery["bootstrap_nodes"], ["8.8.8.8:29843"])
        assert_equal(discovery["known_addresses"], 1)
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
        assert_equal(node.getdifficulty(chain_id), Decimal(0))
        assert_equal(node.getbestblockhash(chain_id=chain_id), reference_child["genesis_hash"])
        assert_equal(node.getblockhash(0, chain_id), reference_child["genesis_hash"])
        child_tx_stats = node.getchaintxstats(
            0, reference_child["genesis_hash"], chain_id)
        assert_equal(child_tx_stats["chain_id"], chain_id)
        assert_equal(child_tx_stats["window_final_block_hash"], reference_child["genesis_hash"])
        assert_equal(child_tx_stats["window_final_block_height"], 0)
        assert_equal(child_tx_stats["window_block_count"], 0)
        assert_equal(child_tx_stats["txcount"], 0)
        for waited in [
            node.waitfornewblock(1, reference_child["genesis_hash"], chain_id),
            node.waitforblock("33" * 32, 1, chain_id),
            node.waitforblockheight(1, 1, chain_id),
        ]:
            assert_equal(waited["chain_id"], chain_id)
            assert_equal(waited["hash"], reference_child["genesis_hash"])
            assert_equal(waited["height"], 0)
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
        assert_raises_rpc_error(
            -1, "child chain is not loaded",
            wallet.getbalances, chain_id)
        assert_raises_rpc_error(
            -1, "child chain is not loaded",
            wallet.listunspent, 1, 9999999, [], True, {}, chain_id)
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
        assert_raises_rpc_error(
            -8, "requires recipient_type 1",
            wallet.walletcreatefundchainpsbt,
            chain_id, 2, child_recipient, deposit_amount, {"fee_rate": 1})
        assert_raises_rpc_error(
            -8, "valid 32-byte P2TR output key",
            wallet.walletcreatefundchainpsbt,
            chain_id, 1, "42" * 31, deposit_amount, {"fee_rate": 1})
        deposit_psbt = wallet.walletcreatefundchainpsbt(
            chain_id, 1, child_recipient, deposit_amount, {"fee_rate": 1})
        assert_equal(deposit_psbt["deposit_vout"], 0)
        assert_equal(deposit_psbt["amount"], deposit_amount)
        assert_equal(deposit_psbt["chain_id"], chain_id)
        assert_equal(deposit_psbt["recipient_type"], 1)
        assert_equal(deposit_psbt["recipient"], child_recipient)
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
        invalid_submit_psbt = PSBT.from_base64(deposit_psbt["psbt"])
        invalid_submit_psbt.o[0].map[PSBT_OUT_SCRIPT] = bytes.fromhex(
            node.createfundchainoutput(chain_id, 2, child_recipient)["script"])
        assert_raises_rpc_error(
            -8, "requires recipient_type 1",
            wallet.walletsubmitfundchainpsbt,
            invalid_submit_psbt.to_base64(), True, deposit_amount)
        submitted_deposit = wallet.walletsubmitfundchainpsbt(
            deposit_psbt["psbt"], True, deposit_amount)
        assert_equal(submitted_deposit["vout"], 0)
        assert_equal(submitted_deposit["chain_id"], chain_id)
        assert_equal(submitted_deposit["recipient"], child_recipient)
        assert_equal(submitted_deposit["amount"], deposit_amount)
        assert_equal(submitted_deposit["irreversible"], True)
        wallet_deposits = wallet.listwalletchaindeposits(chain_id)
        assert_equal(wallet_deposits["total"], 1)
        assert_equal(wallet_deposits["returned"], 1)
        assert_equal(wallet_deposits["deposits"][0]["deposit_id"], submitted_deposit["deposit_id"])
        assert_equal(wallet_deposits["deposits"][0]["txid"], submitted_deposit["txid"])
        assert_equal(wallet_deposits["deposits"][0]["vout"], submitted_deposit["vout"])
        assert_equal(wallet_deposits["deposits"][0]["chain_id"], chain_id)
        assert_equal(wallet_deposits["deposits"][0]["status"], "mempool")
        assert_equal(wallet_deposits["deposits"][0]["confirmations"], 0)
        assert_equal(wallet_deposits["deposits"][0]["in_mempool"], True)
        assert_equal(wallet_deposits["deposits"][0]["amount"], deposit_amount)
        deposit_txid = submitted_deposit["txid"]
        deposit_block = self.generatetoaddress(node, 1, wallet.getnewaddress())[0]
        confirmed_wallet_deposit = wallet.listwalletchaindeposits(
            chain_id)["deposits"][0]
        assert_equal(confirmed_wallet_deposit["status"], "confirmed")
        assert_equal(confirmed_wallet_deposit["confirmations"], 1)
        assert_equal(confirmed_wallet_deposit["in_mempool"], False)
        assert_equal(confirmed_wallet_deposit["blockhash"], deposit_block)
        all_wallet_deposits = wallet.listwalletchaindeposits()
        assert_equal(all_wallet_deposits["total"], 1)
        assert_equal(all_wallet_deposits["returned"], 1)
        assert_equal(wallet.listwalletchaindeposits(chain_id, 1, 1)["returned"], 0)
        assert_raises_rpc_error(
            -8, "chain_id must be exactly 32 non-null bytes",
            wallet.listwalletchaindeposits, "00" * 32)
        assert_raises_rpc_error(
            -8, "count must be between 1 and 1000",
            wallet.listwalletchaindeposits, None, 0)
        assert_raises_rpc_error(
            -8, "skip must be non-negative",
            wallet.listwalletchaindeposits, None, 100, -1)

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
            "recipient": child_recipient,
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

        self.log.info("Authenticate a mature deposit and build its canonical child IMPORT")
        assert_raises_rpc_error(
            -26, "immature (1/144 confirmations)",
            node.createchildimporttransaction, chain_id, deposit_proof["proof"])
        assert_raises_rpc_error(
            -22, "deposit proof decode failed",
            node.createchildimporttransaction, chain_id, deposit_proof["proof"][:-2])
        mature_deposit_tip = self.generatetoaddress(
            node, 143, wallet.getnewaddress())[-1]
        node.syncwithvalidationinterfacequeue()
        child_import = node.createchildimporttransaction(
            chain_id, deposit_proof["proof"])
        assert_equal(child_import["chain_id"], chain_id)
        assert_equal(child_import["deposit_id"], submitted_deposit["deposit_id"])
        assert_equal(child_import["amount"], deposit_amount)
        assert_equal(child_import["recipient_type"], 1)
        assert_equal(child_import["recipient"], child_recipient)
        assert_equal(child_import["main_block_hash"], deposit_block)
        assert_equal(child_import["main_block_height"], deposit_proof["deposit"]["blockheight"])
        assert_equal(child_import["confirmations"], 144)
        assert_equal(child_import["required_confirmations"], 144)
        assert_equal(child_import["authenticated"], True)
        decoded_import = node.decoderawtransaction(child_import["transaction"])
        assert_equal(decoded_import["txid"], child_import["txid"])
        assert_equal(decoded_import["hash"], child_import["wtxid"])
        assert_equal(len(decoded_import["vin"]), 1)
        assert_equal(decoded_import["vin"][0]["vout"], 0xfffffffe)
        assert_equal(len(decoded_import["vin"][0]["txinwitness"]), 1)
        assert_equal(len(decoded_import["vout"]), 1)
        assert_equal(decoded_import["vout"][0]["value"], deposit_amount)

        self.log.info("Automatically propose mature indexed child deposits")
        automatic_proposals = node.listchildproposals(chain_id)
        assert_equal(automatic_proposals["proposal_count"], 1)
        automatic_hash = automatic_proposals["proposals"][0]["blockhash"]
        automatic_block = node.getchildproposal(chain_id, automatic_hash)
        decoded_automatic_block = CBlock()
        decoded_automatic_block.deserialize(
            BytesIO(bytes.fromhex(automatic_block["block"])))
        assert_equal(decoded_automatic_block.hash_hex, automatic_hash)
        assert_equal(len(decoded_automatic_block.vtx), 2)
        assert_equal(decoded_automatic_block.vtx[1].txid_hex,
                     child_import["txid"])
        assert_equal(node.getchildbmmstatus(chain_id)["health"],
                     "awaiting_anchor")
        assert_equal(node.removechildproposal(
            chain_id, automatic_hash)["removed"], True)
        assert_equal(node.listchildproposals(chain_id)["proposal_count"], 0)

        assert_raises_rpc_error(
            -8, "deposit_proofs must contain at least one proof",
            node.createchildimportblock, chain_id, [])
        assert_raises_rpc_error(
            -8, "deposit proof 1 duplicates an earlier deposit",
            node.createchildimportblock,
            chain_id,
            [deposit_proof["proof"], deposit_proof["proof"]])
        child_block = node.createchildimportblock(
            chain_id, [deposit_proof["proof"]])
        assert_equal(child_block["chain_id"], chain_id)
        assert_equal(child_block["previousblockhash"], reference_child["genesis_hash"])
        assert_equal(child_block["height"], 1)
        assert_equal(child_block["requires_bmm_anchor"], True)
        assert_equal(child_block["proposal_stored"], True)
        assert_equal(child_block["contextually_valid"], True)
        assert_equal(child_block["pruned_proposals"], [])
        assert_equal(child_block["transactions"], [child_import["txid"]])
        assert_equal(child_block["deposits"], [{
            "deposit_id": submitted_deposit["deposit_id"],
            "amount": deposit_amount,
            "recipient_type": 1,
            "recipient": child_recipient,
            "confirmations": 144,
        }])
        assert child_block["bmm_anchor_script"].startswith("6a454b424d4d01")
        assert_equal(len(child_block["bmm_anchor_script"]), 142)
        assert_equal(child_block["size"], len(child_block["block"]) // 2)
        decoded_child_block = CBlock()
        decoded_child_block.deserialize(
            BytesIO(bytes.fromhex(child_block["block"])))
        assert_equal(decoded_child_block.serialize().hex(), child_block["block"])
        assert_equal(decoded_child_block.hash_hex, child_block["blockhash"])
        assert_equal(decoded_child_block.nBits, 0)
        assert_equal(decoded_child_block.nNonce, 0)
        assert_equal(len(decoded_child_block.vtx), 2)
        assert_equal(decoded_child_block.vtx[1].txid_hex, child_import["txid"])
        assert_equal(decoded_child_block.calc_merkle_root(),
                     decoded_child_block.hashMerkleRoot)
        proposals = node.listchildproposals(chain_id)
        assert_equal(proposals["proposal_count"], 1)
        assert_equal(proposals["proposal_bytes"], child_block["size"])
        assert_equal(proposals["proposals"], [{
            "blockhash": child_block["blockhash"],
            "previousblockhash": reference_child["genesis_hash"],
            "created_time": proposals["proposals"][0]["created_time"],
            "size": child_block["size"],
            "anchor_available": False,
            "anchor_count": 0,
        }])
        proposed_bmm_status = node.getchildbmmstatus(chain_id)
        assert_equal(proposed_bmm_status["health"], "awaiting_anchor")
        assert_equal(proposed_bmm_status["proposal_count"], 1)
        assert_equal(proposed_bmm_status["proposal_bytes"], child_block["size"])
        assert_equal(proposed_bmm_status["proposals_with_anchor"], 0)
        assert_equal(proposed_bmm_status["proposals_without_anchor"], 1)
        assert_equal(proposed_bmm_status["pending_block_count"], 0)
        assert_equal(proposed_bmm_status["proposals"], proposals["proposals"])
        stored_proposal = node.getchildproposal(
            chain_id, child_block["blockhash"])
        assert_equal(stored_proposal["block"], child_block["block"])
        assert_equal(stored_proposal["size"], child_block["size"])
        removed_proposal = node.removechildproposal(
            chain_id, child_block["blockhash"])
        assert_equal(removed_proposal["removed"], True)
        assert_equal(node.listchildproposals(chain_id)["proposal_count"], 0)
        assert_raises_rpc_error(
            -5, "local child proposal was not found",
            node.getchildproposal, chain_id, child_block["blockhash"])
        stored_again = node.storechildproposal(chain_id, child_block["block"])
        assert_equal(stored_again["stored"], True)
        assert_equal(stored_again["blockhash"], child_block["blockhash"])
        assert_equal(stored_again["pruned_proposals"], [])
        assert_equal(node.storechildproposal(
            chain_id, child_block["block"])["stored"], True)
        assert_raises_rpc_error(
            -26, "no authenticated pending BMM anchor commits to this child block",
            node.submitchildproposal, chain_id, child_block["blockhash"])

        self.log.info("Fund and publish the recurring main-chain BMM security bid")
        anchor_psbt = wallet.walletcreatechildanchorpsbt(
            chain_id, child_block["blockhash"], {"fee_rate": 1})
        assert_equal(anchor_psbt["chain_id"], chain_id)
        assert_equal(anchor_psbt["child_block_hash"], child_block["blockhash"])
        assert_equal(anchor_psbt["anchor_vout"], 0)
        assert_equal(anchor_psbt["anchor_script"], child_block["bmm_anchor_script"])
        assert anchor_psbt["security_bid"] > 0
        decoded_anchor_psbt = node.decodepsbt(anchor_psbt["psbt"])["tx"]
        assert_equal(decoded_anchor_psbt["vout"][0]["value"], Decimal("0.00000000"))
        assert_equal(decoded_anchor_psbt["vout"][0]["scriptPubKey"]["hex"],
                     child_block["bmm_anchor_script"])
        assert_raises_rpc_error(
            -8, "does not match the authorized chain_id and child_block_hash",
            wallet.walletsubmitchildanchorpsbt,
            anchor_psbt["psbt"], chain_id, "01" * 32, Decimal("1.00000000"))
        assert_raises_rpc_error(
            -8, "exceeds authorized maximum",
            wallet.walletsubmitchildanchorpsbt,
            anchor_psbt["psbt"], chain_id, child_block["blockhash"], 0)
        submitted_anchor = wallet.walletsubmitchildanchorpsbt(
            anchor_psbt["psbt"],
            chain_id,
            child_block["blockhash"],
            Decimal("1.00000000"))
        assert_equal(submitted_anchor["chain_id"], chain_id)
        assert_equal(submitted_anchor["child_block_hash"], child_block["blockhash"])
        assert_equal(submitted_anchor["vout"], 0)
        assert_equal(submitted_anchor["security_bid"], anchor_psbt["security_bid"])
        assert_equal(node.decoderawtransaction(submitted_anchor["hex"])["txid"],
                     submitted_anchor["txid"])
        assert_equal(node.getmempoolentry(submitted_anchor["txid"])["fees"]["base"],
                     submitted_anchor["security_bid"])

        self.log.info("Persist the same proposal on an unloaded peer for historical anchor catch-up")
        self.sync_blocks()
        peer_preparation = peer_node.loadchildchain(chain_id)
        assert_equal(peer_preparation["height"], 0)
        assert_equal(peer_preparation["deposit_index_complete"], True)
        assert_equal(peer_preparation["deposit_index_lookups"], 1)
        assert_equal(peer_preparation["deposit_proofs_built"], 1)
        assert_equal(peer_preparation["deposit_proposal_stored"], True)
        peer_node.removechildproposal(
            chain_id, peer_preparation["deposit_proposal_hash"])
        peer_proposal = peer_node.storechildproposal(chain_id, child_block["block"])
        assert_equal(peer_proposal["stored"], True)
        assert_equal(peer_proposal["blockhash"], child_block["blockhash"])
        assert_equal(peer_node.unloadchildchain(chain_id)["loaded"], False)
        assert_raises_rpc_error(
            -8, "child chain is not loaded",
            peer_node.getchildbmmstatus, chain_id)

        anchor_block = self.generatetoaddress(node, 1, wallet.getnewaddress())[0]
        node.syncwithvalidationinterfacequeue()
        self.sync_blocks()
        peer_node.syncwithvalidationinterfacequeue()
        mature_deposit_tip = anchor_block

        self.log.info("Automatically ingest the confirmed BMM anchor and activate the child block")
        automatic_child_info = node.getblockchaininfo(chain_id)
        assert_equal(automatic_child_info["blocks"], 1)
        assert_equal(automatic_child_info["bestblockhash"], child_block["blockhash"])
        child_balance = wallet.getbalances(chain_id)
        assert_equal(child_balance["chain_id"], chain_id)
        assert_equal(child_balance["mine"], {
            "trusted": deposit_amount,
            "untrusted_pending": Decimal("0.00000000"),
            "immature": Decimal("0.00000000"),
        })
        assert_equal(child_balance["lastprocessedblock"], {
            "hash": child_block["blockhash"],
            "height": 1,
        })
        child_unspent = wallet.listunspent(
            1, 9999999, [], True, {}, chain_id)
        assert_equal(len(child_unspent), 1)
        assert_equal(child_unspent[0]["txid"], child_import["txid"])
        assert_equal(child_unspent[0]["vout"], 0)
        assert_equal(child_unspent[0]["chain_id"], chain_id)
        assert_equal(child_unspent[0]["recipient_type"], 1)
        assert_equal(child_unspent[0]["recipient"], child_recipient)
        assert_equal(child_unspent[0]["label"], "child-receive")
        assert_equal(child_unspent[0]["scriptPubKey"], "5120" + child_recipient)
        assert_equal(child_unspent[0]["amount"], deposit_amount)
        assert_equal(child_unspent[0]["confirmations"], 1)
        assert_equal(child_unspent[0]["coinbase"], False)
        assert_equal(child_unspent[0]["solvable"], True)
        assert_equal(child_unspent[0]["safe"], True)
        assert_equal(wallet.listunspent(
            2, 9999999, [], True, {}, chain_id), [])
        assert_equal(wallet.listunspent(
            1, 9999999, [], True,
            {"maximumAmount": Decimal("0.24999999")}, chain_id), [])

        self.log.info("Create and sign a wallet PSBT in the child signature domain")
        child_destination = attacker.getnewchildrecipient(
            chain_id, "child-destination")
        child_spend_amount = Decimal("0.10000000")
        child_fee = Decimal("0.00001000")
        assert_raises_rpc_error(
            -8, "chain_id must be exactly 32 non-null bytes",
            wallet.walletcreatechildpsbt,
            "00" * 32,
            [{"recipient": child_destination["recipient"],
              "amount": child_spend_amount}],
            child_fee)
        child_psbt = wallet.walletcreatechildpsbt(
            chain_id,
            [{"recipient": child_destination["recipient"],
              "amount": child_spend_amount}],
            child_fee)
        assert_equal(child_psbt["chain_id"], chain_id)
        assert_equal(child_psbt["genesis_hash"],
                     reference_child["genesis_hash"])
        assert_equal(child_psbt["fee"], child_fee)
        assert_equal(child_psbt["inputs"], 1)
        assert child_psbt["changepos"] in [0, 1]
        assert_equal(child_psbt["change"],
                     deposit_amount - child_spend_amount - child_fee)
        assert_equal(child_psbt["child_tip"], child_block["blockhash"])
        assert_equal(child_psbt["child_height"], 1)
        child_descriptors = [
            descriptor
            for descriptor in wallet.listdescriptors()["descriptors"]
            if descriptor.get("chain_id") == chain_id
        ]
        assert_equal(len(child_descriptors), 2)
        assert_equal({descriptor["internal"] for descriptor in child_descriptors},
                     {False, True})
        assert all(not descriptor["active"] for descriptor in child_descriptors)
        child_wallet_identities = wallet.listchildrecipients(chain_id)
        assert_equal(child_wallet_identities["recipient_count"], 2)
        assert child_identity in child_wallet_identities["recipients"]
        child_change_identity = next(
            identity for identity in child_wallet_identities["recipients"]
            if identity != child_identity)
        assert_equal(child_change_identity["chain_id"], chain_id)
        assert_equal(child_change_identity["recipient_type"], 1)
        assert_equal(child_change_identity["label"], "")
        assert_equal(child_change_identity["scriptPubKey"],
                     "5120" + child_change_identity["recipient"])

        self.log.info("Restore child descriptor contexts in another wallet")
        exported_child_descriptors = [
            descriptor
            for descriptor in wallet.listdescriptors(True)["descriptors"]
            if descriptor.get("chain_id") == chain_id
        ]
        node.createwallet("child_restore")
        restored_wallet = node.get_wallet_rpc("child_restore")
        missing_role = dict(exported_child_descriptors[0])
        missing_role.pop("internal")
        rejected_import = restored_wallet.importdescriptors([missing_role])
        assert_equal(rejected_import[0]["success"], False)
        assert "explicit internal role" in rejected_import[0]["error"]["message"]
        restored_import = restored_wallet.importdescriptors(
            exported_child_descriptors)
        assert all(result["success"] for result in restored_import), restored_import
        restored_child_descriptors = [
            descriptor
            for descriptor in restored_wallet.listdescriptors()["descriptors"]
            if descriptor.get("chain_id") == chain_id
        ]
        assert_equal(len(restored_child_descriptors), 2)
        for restored_descriptor in restored_child_descriptors:
            source_descriptor = next(
                descriptor for descriptor in child_descriptors
                if descriptor["internal"] == restored_descriptor["internal"]
            )
            for field in ("desc", "timestamp", "active", "internal",
                          "chain_id", "next_index"):
                assert_equal(restored_descriptor[field],
                             source_descriptor[field])
        assert_raises_rpc_error(
            -8, "key_count must be between 1 and 10000",
            restored_wallet.recoverchildwallet, chain_id, 0, 0)
        recovery = restored_wallet.recoverchildwallet(chain_id, 0, 5)
        assert_equal(recovery["chain_id"], chain_id)
        assert_equal(recovery["best_block"], child_block["blockhash"])
        assert_equal(recovery["height"], 1)
        assert_equal(recovery["scanned_from_height"], 1)
        assert_equal(recovery["scanned_to_height"], 1)
        assert_equal(recovery["key_start"], 0)
        assert_equal(recovery["key_count"], 5)
        assert_equal(recovery["next_key_start"], 5)
        assert_equal(recovery["candidate_scripts"], 10)
        assert_equal(recovery["matched_transactions"], 1)
        assert_equal(recovery["receive_used"], 1)
        assert_equal(recovery["change_used"], 0)
        assert_equal(recovery["complete"], True)
        assert "next_height" not in recovery
        recovered_recipients = restored_wallet.listchildrecipients(chain_id)
        assert_equal(recovered_recipients["recipient_count"], 1)
        assert_equal(recovered_recipients["recipients"][0]["recipient"],
                     child_identity["recipient"])
        assert_equal(recovered_recipients["recipients"][0]["label"], "")
        repeated_recovery = restored_wallet.recoverchildwallet(chain_id, 0, 5)
        assert_equal(repeated_recovery["receive_used"], 1)
        assert_equal(repeated_recovery["change_used"], 0)
        assert_equal(restored_wallet.listchildrecipients(chain_id),
                     recovered_recipients)
        restored_receive = next(
            descriptor for descriptor in restored_child_descriptors
            if not descriptor["internal"])
        expected_address = node.deriveaddresses(
            restored_receive["desc"],
            [restored_receive["next_index"], restored_receive["next_index"]],
        )[0]
        restored_identity = restored_wallet.getnewchildrecipient(
            chain_id, "restored-child")
        assert_equal(
            restored_identity["scriptPubKey"],
            address_to_scriptpubkey(expected_address).hex(),
        )
        restored_state = restored_wallet.listchildrecipients(chain_id)
        assert_equal(restored_state["recipient_count"], 2)
        node.unloadwallet("child_restore")
        node.loadwallet("child_restore")
        restored_wallet = node.get_wallet_rpc("child_restore")
        assert_equal(restored_wallet.listchildrecipients(chain_id),
                     restored_state)

        unsigned_child = wallet.walletprocesschildpsbt(
            child_psbt["psbt"], child_fee, False)
        assert_equal(unsigned_child["chain_id"], chain_id)
        assert_equal(unsigned_child["fee"], child_fee)
        assert_equal(unsigned_child["complete"], False)
        assert "hex" not in unsigned_child
        assert_raises_rpc_error(
            -8, "exceeds authorized maximum",
            wallet.walletprocesschildpsbt,
            child_psbt["psbt"], Decimal("0.00000999"))

        main_domain_psbt = wallet.walletprocesspsbt(child_psbt["psbt"])
        assert_equal(main_domain_psbt["complete"], True)
        assert_raises_rpc_error(
            -8, "invalid child PSBT signature",
            wallet.walletprocesschildpsbt,
            main_domain_psbt["psbt"], child_fee)

        signed_child = wallet.walletprocesschildpsbt(
            child_psbt["psbt"], child_fee)
        assert_equal(signed_child["chain_id"], chain_id)
        assert_equal(signed_child["genesis_hash"],
                     reference_child["genesis_hash"])
        assert_equal(signed_child["fee"], child_fee)
        assert_equal(signed_child["complete"], True)
        decoded_child_spend = node.decoderawtransaction(signed_child["hex"])
        assert_equal(decoded_child_spend["txid"], signed_child["txid"])
        assert_equal(decoded_child_spend["vin"][0]["txid"],
                     child_import["txid"])
        assert_equal(decoded_child_spend["vin"][0]["vout"], 0)
        assert_equal(len(decoded_child_spend["vin"][0]["txinwitness"]), 1)
        destination_outputs = [
            output for output in decoded_child_spend["vout"]
            if output["scriptPubKey"]["hex"] ==
            child_destination["scriptPubKey"]]
        assert_equal(len(destination_outputs), 1)
        assert_equal(destination_outputs[0]["value"], child_spend_amount)

        if self.is_external_signer_compiled():
            self.log.info("Sign the same child PSBT with an external signer")
            all_private_descriptors = wallet.listdescriptors(True)["descriptors"]
            all_public_descriptors = wallet.listdescriptors()["descriptors"]
            main_descriptors = [
                descriptor for descriptor in all_public_descriptors
                if "chain_id" not in descriptor and descriptor["active"]
            ]
            child_private_descriptors = [
                descriptor for descriptor in all_private_descriptors
                if descriptor.get("chain_id") == chain_id
            ]
            origin = child_private_descriptors[0]["desc"].split("[", 1)[1].split("]", 1)[0]
            fingerprint, origin_path = origin.split("/", 1)
            account_path = "m/" + origin_path
            account_path = account_path.replace("'", "h")

            signer_identity = {
                "fingerprint": fingerprint,
                "receive": [next(
                    descriptor for descriptor in main_descriptors
                    if not descriptor["internal"])["desc"]],
                "internal": [next(
                    descriptor for descriptor in main_descriptors
                    if descriptor["internal"])["desc"]],
            }
            signer_child_descriptors = {
                "chain_id": chain_id,
                "account_path": account_path,
                "receive": [next(
                    descriptor for descriptor in child_descriptors
                    if not descriptor["internal"])["desc"]],
                "internal": [next(
                    descriptor for descriptor in child_descriptors
                    if descriptor["internal"])["desc"]],
            }
            with open(os.path.join(node.cwd, "mock_signer_identity"), "w") as f:
                json.dump(signer_identity, f)
            with open(os.path.join(node.cwd, "mock_child_descriptors"), "w") as f:
                json.dump(signer_child_descriptors, f)
            with open(os.path.join(node.cwd, "mock_child_signing_context"), "w") as f:
                json.dump({
                    "chain_id": chain_id,
                    "genesis_hash": reference_child["genesis_hash"],
                    "template_id": 1,
                    "template_version": 1,
                }, f)
            with open(os.path.join(node.cwd, "mock_psbt"), "w") as f:
                f.write(signed_child["psbt"])

            node.createwallet(wallet_name="child_external",
                              disable_private_keys=True,
                              external_signer=True)
            external_wallet = node.get_wallet_rpc("child_external")
            invalid_child_descriptors = dict(signer_child_descriptors)
            invalid_child_descriptors["receive"] = signer_child_descriptors["internal"]
            with open(os.path.join(node.cwd, "mock_child_descriptors"), "w") as f:
                json.dump(invalid_child_descriptors, f)
            assert_raises_rpc_error(
                -12, "does not match the requested fingerprint and D-039 path",
                external_wallet.getnewchildrecipient, chain_id)
            with open(os.path.join(node.cwd, "mock_child_descriptors"), "w") as f:
                json.dump(signer_child_descriptors, f)
            external_recipient = external_wallet.getnewchildrecipient(chain_id)
            assert_equal(external_recipient["recipient"], child_identity["recipient"])
            external_wallet.recoverchildwallet(chain_id, 0, 1)
            with open(os.path.join(node.cwd, "mock_psbt"), "w") as f:
                f.write(main_domain_psbt["psbt"])
            assert_raises_rpc_error(
                -4, "external signer returned invalid child input 0",
                external_wallet.walletprocesschildpsbt,
                child_psbt["psbt"], child_fee)
            with open(os.path.join(node.cwd, "mock_psbt"), "w") as f:
                f.write(signed_child["psbt"])
            external_signed = external_wallet.walletprocesschildpsbt(
                child_psbt["psbt"], child_fee)
            assert_equal(external_signed["complete"], True)
            assert_equal(external_signed["hex"], signed_child["hex"])
            assert_equal(external_signed["txid"], signed_child["txid"])
            external_without_paths = external_wallet.walletprocesschildpsbt(
                child_psbt["psbt"], child_fee, True, "DEFAULT", False)
            assert_equal(external_without_paths["complete"], True)
            stripped_psbt = PSBT.from_base64(external_without_paths["psbt"])
            assert all(not any(
                isinstance(key, bytes) and
                key[0] == PSBT_IN_TAP_BIP32_DERIVATION
                for key in psbt_map.map
            ) for psbt_map in stripped_psbt.i)
            assert all(not any(
                isinstance(key, bytes) and
                key[0] == PSBT_OUT_TAP_BIP32_DERIVATION
                for key in psbt_map.map
            ) for psbt_map in stripped_psbt.o)

        assert_equal(node.getchildpendingblocks(chain_id)["block_count"], 0)
        assert_equal(node.listchildproposals(chain_id)["proposal_count"], 0)
        anchored_bmm_status = node.getchildbmmstatus(chain_id)
        assert_equal(anchored_bmm_status["health"], "anchored")
        assert_equal(anchored_bmm_status["child_height"], 1)
        assert_equal(anchored_bmm_status["bestblockhash"], child_block["blockhash"])
        assert_equal(anchored_bmm_status["canonical_anchor_count"], 1)
        assert_equal(anchored_bmm_status["has_tip_anchor"], True)
        assert_equal(anchored_bmm_status["tip_anchor_main_block_hash"], anchor_block)
        assert_equal(anchored_bmm_status["tip_anchor_main_height"], node.getblockheader(anchor_block)["height"])
        assert_equal(anchored_bmm_status["tip_anchor_confirmations"], 1)
        assert_equal(anchored_bmm_status["tip_anchor_gap"], 0)
        assert_equal(anchored_bmm_status["proposal_count"], 0)
        assert_equal(anchored_bmm_status["pending_block_count"], 0)

        self.log.info("Catch up the anchor missed while the peer child runtime was unloaded")
        peer_catch_up = peer_node.loadchildchain(chain_id)
        assert_equal(peer_catch_up["height"], 1)
        assert_equal(peer_catch_up["bestblockhash"], child_block["blockhash"])
        assert_equal(peer_catch_up["historical_anchor_index_complete"], True)
        assert_equal(peer_catch_up["historical_anchor_lookups"], 1)
        assert_equal(peer_catch_up["local_proposals_checked"], 1)
        assert_equal(peer_catch_up["historical_anchors_found"], 1)
        assert_equal(peer_catch_up["historical_anchor_block_data_unavailable"], 0)
        assert_equal(peer_catch_up["historical_anchor_proofs_built"], 1)
        assert_equal(peer_catch_up["historical_anchors_staged"], 1)
        assert_equal(peer_catch_up["historical_proposals_activated"], 1)
        assert_equal(peer_catch_up["historical_proposal_activation_failures"], 0)
        assert_equal(peer_catch_up["historical_anchor_stage_failures"], 0)
        assert_equal(peer_node.listchildproposals(chain_id)["proposal_count"], 0)
        self.wait_until(
            lambda: node.getchildnetworkinfo(chain_id)["handshaken_peers"] == 1)
        self.wait_until(
            lambda: peer_node.getchildnetworkinfo(chain_id)["handshaken_peers"] == 1)
        peer_bmm_status = peer_node.getchildbmmstatus(chain_id)
        assert_equal(peer_bmm_status["health"], "anchored")
        assert_equal(peer_bmm_status["bestblockhash"], child_block["blockhash"])
        assert_equal(peer_bmm_status["tip_anchor_main_block_hash"], anchor_block)
        assert_equal(peer_bmm_status["proposal_count"], 0)

        self.log.info("Export the authenticated BMM proof and verify idempotent manual submission")
        registry_with_anchor = node.getchainregistryinfo()
        assert_equal(registry_with_anchor["bmm_enabled"], True)
        assert_equal(registry_with_anchor["bmm_active"], True)
        assert_equal(registry_with_anchor["bmm_anchor_count"], 1)
        anchor_proof = node.getbmmanchorproof(chain_id, anchor_block)
        assert anchor_proof["proof"].startswith("4b42505201")
        assert_equal(anchor_proof["proof_version"], 1)
        assert_equal(anchor_proof["main_genesis_hash"], node.getblockhash(0))
        assert_equal(anchor_proof["main_block_hash"], anchor_block)
        assert_equal(anchor_proof["confirmations"], 1)
        assert_equal(anchor_proof["chain_id"], chain_id)
        assert_equal(anchor_proof["child_block_hash"], child_block["blockhash"])
        assert_equal(anchor_proof["transaction_id"], submitted_anchor["txid"])
        assert_equal(anchor_proof["output_index"], 0)
        assert_equal(anchor_proof["registry_root"], registered_info["root"])
        assert_equal(anchor_proof["chain_record"], registered["chain"])
        assert_equal(len(anchor_proof["block_header"]), 160)

        staged_anchor = node.submitchildanchor(chain_id, anchor_proof["proof"])
        assert_equal(staged_anchor["chain_id"], chain_id)
        assert_equal(staged_anchor["child_block_hash"], child_block["blockhash"])
        assert_equal(staged_anchor["already_known"], True)
        assert_equal(staged_anchor["local_proposal_found"], False)
        assert_equal(staged_anchor["local_proposal_activated"], False)
        assert_equal(staged_anchor["selected_head"], child_block["blockhash"])
        assert_equal(staged_anchor["bestblockhash"], child_block["blockhash"])
        assert_equal(staged_anchor["pruned_proposals"], [])
        pending_blocks = node.getchildpendingblocks(chain_id)
        assert_equal(pending_blocks["block_count"], 0)
        assert_equal(pending_blocks["anchor_count"], 0)
        anchored_proposals = node.listchildproposals(chain_id)
        assert_equal(anchored_proposals["proposal_count"], 0)
        assert_raises_rpc_error(
            -5, "local child proposal was not found",
            node.submitchildproposal, chain_id, child_block["blockhash"])
        active_child_info = node.getblockchaininfo(chain_id)
        assert_equal(active_child_info["blocks"], 1)
        assert_equal(active_child_info["bestblockhash"], child_block["blockhash"])
        assert_equal(active_child_info["bmm_anchor_count"], 1)
        assert_raises_rpc_error(
            -25, "deposit is already imported",
            node.createchildimporttransaction, chain_id, deposit_proof["proof"])

        self.log.info("Build, anchor, and activate the finalized child spend")
        assert_raises_rpc_error(
            -8, "transactions must contain at least one transaction",
            node.createchildblock, chain_id, [])
        assert "hex" in main_domain_psbt
        assert_raises_rpc_error(
            -26, "contextual validation",
            node.createchildblock, chain_id, [main_domain_psbt["hex"]])
        assert_raises_rpc_error(
            -8, "valid 32-byte reference-child P2TR output key",
            node.createchildblock, chain_id, [signed_child["hex"]], "01")

        assert_equal(
            node.sendrawtransaction(
                signed_child["hex"], 0, 0, chain_id),
            signed_child["txid"])
        self.wait_until(
            lambda: peer_node.getrawmempool(False, False, chain_id) ==
                    [signed_child["txid"]])
        assert_equal(peer_node.unloadchildchain(chain_id)["loaded"], False)
        assert_equal(
            node.sendrawtransaction(
                signed_child["hex"], 0, 0, chain_id),
            signed_child["txid"])
        assert_equal(
            node.getrawmempool(False, False, chain_id),
            [signed_child["txid"]])
        child_mempool_sequence = node.getrawmempool(
            False, True, chain_id)
        assert_equal(child_mempool_sequence["txids"],
                     [signed_child["txid"]])
        assert child_mempool_sequence["mempool_sequence"] > 0
        child_mempool_entry = node.getmempoolentry(
            signed_child["txid"], chain_id)
        assert_equal(child_mempool_entry["fees"]["base"], child_fee)
        assert_equal(child_mempool_entry["ancestorcount"], 1)
        assert_equal(child_mempool_entry["descendantcount"], 1)
        assert_equal(
            node.getrawmempool(True, False, chain_id)
                [signed_child["txid"]]["wtxid"],
            decoded_child_spend["hash"])
        mempool_raw = node.getrawtransaction(
            signed_child["txid"], 1, None, chain_id)
        assert_equal(mempool_raw["chain_id"], chain_id)
        assert_equal(mempool_raw["txid"], signed_child["txid"])
        assert "blockhash" not in mempool_raw

        assert_equal(
            node.gettxout(child_import["txid"], 0, True, chain_id), None)
        assert_equal(
            node.gettxout(child_import["txid"], 0, False, chain_id)
                ["confirmations"],
            1)
        destination_outpoint = destination_outputs[0]["n"]
        mempool_destination = node.gettxout(
            signed_child["txid"], destination_outpoint, True, chain_id)
        assert_equal(mempool_destination["chain_id"], chain_id)
        assert_equal(mempool_destination["confirmations"], 0)
        assert_equal(mempool_destination["value"], child_spend_amount)
        assert_equal(mempool_destination["coinbase"], False)
        assert_equal(
            node.gettxout(
                signed_child["txid"], destination_outpoint, False,
                chain_id),
            None)

        child_mempool_activity = node.getdescriptoractivity(
            [],
            ["raw(" + child_unspent[0]["scriptPubKey"] + ")",
             "raw(" + child_destination["scriptPubKey"] + ")"],
            True,
            chain_id)
        assert_equal(child_mempool_activity["chain_id"], chain_id)
        assert_equal(
            [event["type"] for event in child_mempool_activity["activity"]],
            ["spend", "receive"])
        assert_equal(
            child_mempool_activity["activity"][0]["spend_txid"],
            signed_child["txid"])
        assert_equal(
            child_mempool_activity["activity"][1]["txid"],
            signed_child["txid"])
        assert_equal(
            node.getdescriptoractivity(
                [],
                ["raw(" + child_unspent[0]["scriptPubKey"] + ")"],
                False,
                chain_id)["activity"],
            [])

        child_change = deposit_amount - child_spend_amount - child_fee
        assert_equal(wallet.getbalances(chain_id)["mine"], {
            "trusted": child_change,
            "untrusted_pending": Decimal("0.00000000"),
            "immature": Decimal("0.00000000"),
        })
        assert_equal(attacker.getbalances(chain_id)["mine"], {
            "trusted": Decimal("0.00000000"),
            "untrusted_pending": child_spend_amount,
            "immature": Decimal("0.00000000"),
        })
        pending_change = wallet.listunspent(
            0, 9999999, [], True, {}, chain_id)
        assert_equal(len(pending_change), 1)
        assert_equal(pending_change[0]["txid"], signed_child["txid"])
        assert_equal(pending_change[0]["amount"], child_change)
        assert_equal(pending_change[0]["confirmations"], 0)
        assert_equal(pending_change[0]["safe"], True)
        assert_equal(
            wallet.listunspent(1, 9999999, [], True, {}, chain_id), [])
        pending_destination = attacker.listunspent(
            0, 9999999, [], True, {}, chain_id)
        assert_equal(len(pending_destination), 1)
        assert_equal(pending_destination[0]["amount"], child_spend_amount)
        assert_equal(pending_destination[0]["confirmations"], 0)
        assert_equal(pending_destination[0]["safe"], False)
        assert_equal(
            attacker.listunspent(0, 9999999, [], False, {}, chain_id), [])

        child_history = wallet.listtransactions("*", 10, 0, chain_id)
        pending_send = [
            entry for entry in child_history
            if entry["txid"] == signed_child["txid"]]
        assert_equal(len(pending_send), 1)
        assert_equal(pending_send[0]["chain_id"], chain_id)
        assert_equal(pending_send[0]["category"], "send")
        assert_equal(pending_send[0]["recipient"],
                     child_destination["recipient"])
        assert_equal(pending_send[0]["amount"], -child_spend_amount)
        assert_equal(pending_send[0]["fee"], -child_fee)
        assert_equal(pending_send[0]["confirmations"], 0)
        assert_equal(pending_send[0]["trusted"], True)
        import_history = [
            entry for entry in child_history
            if entry["txid"] == child_import["txid"]]
        assert_equal(len(import_history), 1)
        assert_equal(import_history[0]["category"], "receive")
        assert_equal(import_history[0]["amount"], deposit_amount)
        assert_equal(import_history[0]["label"], "child-receive")
        assert_equal(import_history[0]["confirmations"], 1)
        assert_equal(
            wallet.listtransactions(
                "child-receive", 10, 0, chain_id),
            import_history)

        pending_wallet_tx = wallet.gettransaction(
            signed_child["txid"], False, chain_id)
        assert_equal(pending_wallet_tx["chain_id"], chain_id)
        assert_equal(pending_wallet_tx["amount"], -child_spend_amount)
        assert_equal(pending_wallet_tx["fee"], -child_fee)
        assert_equal(pending_wallet_tx["confirmations"], 0)
        assert_equal(pending_wallet_tx["trusted"], True)
        assert_equal(pending_wallet_tx["lastprocessedblock"], {
            "hash": child_block["blockhash"],
            "height": 1,
        })
        assert_equal(len(pending_wallet_tx["details"]), 1)
        assert_equal(pending_wallet_tx["details"][0]["category"], "send")

        pending_attacker_tx = attacker.gettransaction(
            signed_child["txid"], True, chain_id)
        assert_equal(pending_attacker_tx["amount"], child_spend_amount)
        assert "fee" not in pending_attacker_tx
        assert_equal(pending_attacker_tx["confirmations"], 0)
        assert_equal(pending_attacker_tx["trusted"], False)
        assert_equal(len(pending_attacker_tx["details"]), 1)
        assert_equal(pending_attacker_tx["details"][0]["category"],
                     "receive")
        assert_equal(pending_attacker_tx["decoded"]["txid"],
                     signed_child["txid"])

        child_fee_recipient = wallet.getnewchildrecipient(
            chain_id, "child-fees")
        child_wallet_identities = wallet.listchildrecipients(chain_id)
        assert_equal(child_wallet_identities["recipient_count"], 3)
        assert child_fee_recipient in child_wallet_identities["recipients"]
        spend_block = node.createchildblock(
            chain_id,
            None,
            child_fee_recipient["recipient"])
        assert_equal(spend_block["chain_id"], chain_id)
        assert_equal(spend_block["previousblockhash"], child_block["blockhash"])
        assert_equal(spend_block["height"], 2)
        assert_equal(spend_block["transactions"], [signed_child["txid"]])
        assert_equal(spend_block["fees"], child_fee)
        assert_equal(spend_block["claimed_fees"], child_fee)
        assert_equal(spend_block["fee_recipient"],
                     child_fee_recipient["recipient"])
        assert_equal(spend_block["proposal_stored"], True)
        assert_equal(spend_block["contextually_valid"], True)
        assert_equal(node.listchildproposals(chain_id)["proposal_count"], 1)

        spend_anchor_psbt = wallet.walletcreatechildanchorpsbt(
            chain_id, spend_block["blockhash"], {"fee_rate": 1})
        submitted_spend_anchor = wallet.walletsubmitchildanchorpsbt(
            spend_anchor_psbt["psbt"],
            chain_id,
            spend_block["blockhash"],
            Decimal("1.00000000"))
        assert_equal(submitted_spend_anchor["child_block_hash"],
                     spend_block["blockhash"])
        spend_anchor_block = self.generatetoaddress(
            node, 1, wallet.getnewaddress())[0]
        node.syncwithvalidationinterfacequeue()
        mature_deposit_tip = spend_anchor_block

        spend_chain_info = node.getblockchaininfo(chain_id)
        assert_equal(spend_chain_info["blocks"], 2)
        assert_equal(spend_chain_info["bestblockhash"],
                     spend_block["blockhash"])
        assert_equal(node.listchildproposals(chain_id)["proposal_count"], 0)
        assert_equal(node.getrawmempool(False, False, chain_id), [])
        assert_raises_rpc_error(
            -5, "Transaction not in child mempool",
            node.getmempoolentry, signed_child["txid"], chain_id)
        spend_bmm_status = node.getchildbmmstatus(chain_id)
        assert_equal(spend_bmm_status["health"], "anchored")
        assert_equal(spend_bmm_status["child_height"], 2)
        assert_equal(spend_bmm_status["canonical_anchor_count"], 2)
        assert_equal(spend_bmm_status["tip_anchor_main_block_hash"],
                     spend_anchor_block)

        child_balance_after_spend = wallet.getbalances(chain_id)
        assert_equal(child_balance_after_spend["mine"], {
            "trusted": deposit_amount - child_spend_amount - child_fee,
            "untrusted_pending": Decimal("0.00000000"),
            "immature": child_fee,
        })
        child_destination_balance = attacker.getbalances(chain_id)
        assert_equal(child_destination_balance["mine"], {
            "trusted": child_spend_amount,
            "untrusted_pending": Decimal("0.00000000"),
            "immature": Decimal("0.00000000"),
        })
        confirmed_wallet_tx = wallet.gettransaction(
            signed_child["txid"], False, chain_id)
        assert_equal(confirmed_wallet_tx["amount"], -child_spend_amount)
        assert_equal(confirmed_wallet_tx["fee"], -child_fee)
        assert_equal(confirmed_wallet_tx["confirmations"], 1)
        assert_equal(confirmed_wallet_tx["blockhash"],
                     spend_block["blockhash"])
        assert_equal(confirmed_wallet_tx["blockheight"], 2)
        assert_equal(confirmed_wallet_tx["lastprocessedblock"], {
            "hash": spend_block["blockhash"],
            "height": 2,
        })
        confirmed_attacker_tx = attacker.gettransaction(
            signed_child["txid"], False, chain_id)
        assert_equal(confirmed_attacker_tx["amount"], child_spend_amount)
        assert_equal(confirmed_attacker_tx["confirmations"], 1)
        assert_equal(confirmed_attacker_tx["blockhash"],
                     spend_block["blockhash"])

        confirmed_history = wallet.listtransactions("*", 10, 0, chain_id)
        assert_equal(
            next(entry for entry in confirmed_history
                 if entry["txid"] == signed_child["txid"])["confirmations"],
            1)
        assert_equal(node.unloadchildchain(chain_id)["loaded"], False)
        assert_raises_rpc_error(
            -1, "child chain is not loaded",
            wallet.listtransactions, "*", 10, 0, chain_id)
        assert_equal(node.loadchildchain(chain_id)["height"], 2)
        assert_equal(wallet.listtransactions("*", 10, 0, chain_id),
                     confirmed_history)

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
        assert_equal(update_psbt["registration_burn"], Decimal("0.00000000"))
        redirected_update = PSBT.from_base64(update_psbt["psbt"])
        redirected_update.o[1].map[PSBT_OUT_SCRIPT] = attacker_control_script
        assert_raises_rpc_error(
            -8, "successor control output is not owned by this wallet",
            wallet.walletsubmitchainregistrypsbt,
            redirected_update.to_base64())
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
        assert_equal(disconnected_runtime["main_bestblockhash"], mature_deposit_tip)
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
        assert_equal(retirement_psbt["registration_burn"], Decimal("0.00000000"))
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
        assert_equal(node.getbestblockhash(), mature_deposit_tip)
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
        orphaned_identities = wallet.listchildrecipients(chain_id)
        assert_equal(orphaned_identities, child_wallet_identities)

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
        node.loadwallet("registry")
        wallet = node.get_wallet_rpc("registry")
        assert_equal(node.getbestblockhash(), retirement_block)
        assert_equal(node.getchainregistryinfo()["root"], retired_info["root"])
        assert_equal(node.getchildchain(chain_id)["chain"]["status"], "retired")
        persisted_identities = wallet.listchildrecipients(chain_id)
        assert_equal(persisted_identities, child_wallet_identities)
        assert_raises_rpc_error(
            -8, "child chain is retired",
            wallet.getnewchildrecipient, chain_id)

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
