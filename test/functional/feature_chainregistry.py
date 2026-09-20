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
)


class ChainRegistryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-chainregistryactivationheight=1",
            "-chainregistryminregistrationburn=1",
            "-chainregistrymaxoperations=4",
        ]]

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
        assert_equal(info["height"], 0)
        assert_equal(info["bestblockhash"], node.getbestblockhash())
        assert_equal(info["size"], 0)

        self.log.info("Activate registry consensus and verify the empty committed view")
        self.generate(node, 1)
        info = node.getchainregistryinfo()
        assert_equal(info["active"], True)
        assert_equal(info["active_for_next_block"], True)
        assert_equal(info["height"], 1)
        assert_equal(info["bestblockhash"], node.getbestblockhash())
        assert_equal(info["size"], 0)
        assert_equal(len(info["root"]), 64)

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
        assert_raises_rpc_error(-8, "chain_id must be exactly 32 bytes", node.getchildchain, "01")
        assert_raises_rpc_error(-8, "chain_id must be exactly 32 bytes", node.listchildchains, "zz" * 32)
        assert_raises_rpc_error(-8, "limit must be between 1 and 1000", node.listchildchains, None, 0)
        assert_raises_rpc_error(-8, "limit must be between 1 and 1000", node.listchildchains, None, 1001)

        self.log.info("Register, update, and retire a child chain through funded wallet PSBTs")
        node.createwallet("registry")
        wallet = node.get_wallet_rpc("registry")
        self.generatetoaddress(node, 101, wallet.getnewaddress())

        anchor_utxo = wallet.listunspent(1)[0]
        registration_anchor = {"txid": anchor_utxo["txid"], "vout": anchor_utxo["vout"]}
        control_address = wallet.getnewaddress()
        wallet_spec = {
            "template_id": 1,
            "template_version": 1,
            "consensus_parameters": "01020304",
        }
        registration_psbt = wallet.walletcreatechainregistrypsbt("register", {
            "registration_anchor": registration_anchor,
            "spec": wallet_spec,
            "child_genesis_hash": "11" * 32,
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
        self.generatetoaddress(node, 1, wallet.getnewaddress())

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
        self.generatetoaddress(node, 1, wallet.getnewaddress())

        updated = node.getchildchain(chain_id)
        assert_equal(updated["chain"]["metadata_hash"], "33" * 32)
        assert_equal(updated["chain"]["control_outpoint"], {"txid": update_txid, "vout": 1})

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
        self.generatetoaddress(node, 1, wallet.getnewaddress())

        retired = node.getchildchain(chain_id)
        assert_equal(retired["chain"]["status"], "retired")
        assert retired["chain"]["retired_height"] > 0
        assert_equal(node.listchildchains()["chains"], [])
        assert_equal(node.listchildchains(None, 100, True)["chains"][0]["chain_id"], chain_id)

        assert_raises_rpc_error(-8, "chain_id must be exactly 32 non-null bytes",
                                wallet.walletcreatechainregistrypsbt, "retire", {"chain_id": "00" * 32})


if __name__ == "__main__":
    ChainRegistryTest(__file__).main()
