#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise one main chain with two independently loaded reference children."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, child_port


class MultichainDevnetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        node_args = [
            "-chainregistryactivationheight=1",
            "-chainregistryminregistrationburn=1",
            "-chainregistrymaxoperations=4",
            "-chaindepositactivationheight=1",
            "-chaindepositminimumamount=0.01",
            "-chaindepositmaxperblock=8",
            "-chainbmmactivationheight=1",
            "-chainbmmmaxanchorsperblock=4",
        ]
        self.extra_args = [node_args, node_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def register_child(self, wallet, metadata_byte):
        node = self.nodes[0]
        anchor_coin = wallet.listunspent(1)[0]
        anchor = {"txid": anchor_coin["txid"], "vout": anchor_coin["vout"]}
        metadata_hash = metadata_byte * 32
        reference = node.createreferencechildmanifest(anchor, metadata_hash)
        spec = reference["manifest"]["spec"]
        registration = wallet.walletcreatechainregistrypsbt("register", {
            "registration_anchor": anchor,
            "spec": {
                "template_id": spec["template_id"],
                "template_version": spec["template_version"],
                "consensus_parameters": spec["consensus_parameters"],
                "anchoring_policy": spec["anchoring_policy"],
            },
            "child_genesis_hash": reference["genesis_hash"],
            "metadata_hash": metadata_hash,
            "control_address": wallet.getnewaddress(),
        }, {"fee_rate": 1})
        submitted = wallet.walletsubmitchainregistrypsbt(registration["psbt"])
        self.generatetoaddress(
            node, 1, wallet.getnewaddress(), sync_fun=lambda: None)
        assert_equal(submitted["chain_id"], registration["chain_id"])
        return {
            "anchor": anchor,
            "chain_id": registration["chain_id"],
            "reference": reference,
        }

    def fund_child(self, wallet, child, amount, label):
        node = self.nodes[0]
        identity = wallet.getnewchildrecipient(child["chain_id"], label)
        funded = wallet.walletcreatefundchainpsbt(
            child["chain_id"], 1, identity["recipient"], amount,
            {"fee_rate": 1})
        submitted = wallet.walletsubmitfundchainpsbt(
            funded["psbt"], True, amount)
        return {
            "deposit_id": submitted["deposit_id"],
            "recipient": identity["recipient"],
            "txid": submitted["txid"],
            "vout": submitted["vout"],
        }

    def anchor_proposal(self, wallet, chain_id, block_hash):
        node = self.nodes[0]
        anchor = wallet.walletcreatechildanchorpsbt(
            chain_id, block_hash, {"fee_rate": 1})
        submitted = wallet.walletsubmitchildanchorpsbt(
            anchor["psbt"], chain_id, block_hash, Decimal("1.00000000"))
        assert_equal(submitted["chain_id"], chain_id)
        assert_equal(submitted["child_block_hash"], block_hash)
        self.generatetoaddress(
            node, 1, wallet.getnewaddress(), sync_fun=lambda: None)
        node.syncwithvalidationinterfacequeue()

    def run_test(self):
        node = self.nodes[0]
        fork_node = self.nodes[1]
        self.generate(node, 1)
        self.sync_blocks()
        node.createwallet("devnet")
        wallet = node.get_wallet_rpc("devnet")
        fork_node.createwallet("devnet_fork")
        fork_wallet = fork_node.get_wallet_rpc("devnet_fork")
        self.generatetoaddress(node, 101, wallet.getnewaddress())
        self.sync_blocks()
        self.generatetoaddress(fork_node, 101, fork_wallet.getnewaddress())
        self.sync_blocks()

        self.log.info("Register two distinct reference child chains")
        children = [
            self.register_child(wallet, "11"),
            self.register_child(wallet, "22"),
        ]
        self.sync_blocks()
        assert children[0]["chain_id"] != children[1]["chain_id"]
        assert (children[0]["reference"]["genesis_hash"] !=
                children[1]["reference"]["genesis_hash"])
        assert_equal(node.getchainregistryinfo()["size"], 2)

        self.log.info("Configure and load both child runtimes with isolated listeners")
        for index, child in enumerate(children):
            configured = node.addchildchain(
                child["anchor"], child["reference"]["manifest"])
            assert_equal(configured["chain_id"], child["chain_id"])
            endpoint = f"127.0.0.1:{child_port(index)}"
            loaded = node.loadchildchain(
                child["chain_id"], {"bind": [endpoint]})
            assert_equal(loaded["bestblockhash"],
                         child["reference"]["genesis_hash"])
            assert_equal(loaded["binds"], [endpoint])

        runtimes = node.listchildchainruntimes()
        assert_equal(runtimes["loaded"], 2)
        loaded_by_id = {entry["chain_id"]: entry for entry in runtimes["chains"]}
        for child in children:
            assert_equal(loaded_by_id[child["chain_id"]]["loaded"], True)
            assert_equal(loaded_by_id[child["chain_id"]]["child_height"], 0)

        self.log.info("Migrate independent balances to both children")
        amount = Decimal("0.05000000")
        deposits = []
        deposits.append(self.fund_child(
            wallet, children[0], amount, "devnet-child-a"))
        self.generatetoaddress(node, 1, wallet.getnewaddress())
        self.sync_blocks()
        self.disconnect_nodes(0, 1)
        deposits.append(self.fund_child(
            wallet, children[1], amount, "devnet-child-b"))
        self.generatetoaddress(
            node, 1, wallet.getnewaddress(), sync_fun=lambda: None)
        assert deposits[0]["recipient"] != deposits[1]["recipient"]
        proofs = [
            node.getdepositproof(deposit["txid"], deposit["vout"])["proof"]
            for deposit in deposits
        ]
        self.generatetoaddress(
            node, 143, wallet.getnewaddress(), sync_fun=lambda: None)
        node.syncwithvalidationinterfacequeue()

        proposals = []
        for child, proof, deposit in zip(children, proofs, deposits):
            child_import = node.createchildimporttransaction(
                child["chain_id"], proof)
            assert_equal(child_import["deposit_id"], deposit["deposit_id"])
            listed = node.listchildproposals(child["chain_id"])
            assert_equal(listed["proposal_count"], 1)
            proposals.append(listed["proposals"][0]["blockhash"])
            assert_equal(node.getchildbmmstatus(child["chain_id"])["health"],
                         "awaiting_anchor")

        fork_anchor = fork_wallet.walletcreatechildanchorpsbt(
            children[1]["chain_id"], proposals[1], {"fee_rate": 1})
        fork_submitted = fork_wallet.walletsubmitchildanchorpsbt(
            fork_anchor["psbt"], children[1]["chain_id"], proposals[1],
            Decimal("1.00000000"))
        assert_equal(fork_submitted["child_block_hash"], proposals[1])

        self.log.info("Anchor one child without advancing the other")
        self.anchor_proposal(wallet, children[0]["chain_id"], proposals[0])
        assert_equal(node.getblockcount(children[0]["chain_id"]), 1)
        assert_equal(node.getblockcount(children[1]["chain_id"]), 0)
        assert_equal(
            wallet.getbalances(children[0]["chain_id"])["mine"]["trusted"],
            amount)
        assert_equal(
            wallet.getbalances(children[1]["chain_id"])["mine"]["trusted"],
            Decimal("0.00000000"))

        self.log.info("Anchor the second child and verify independent balances")
        self.anchor_proposal(wallet, children[1]["chain_id"], proposals[1])
        for child in children:
            assert_equal(node.getblockcount(child["chain_id"]), 1)
            assert_equal(
                wallet.getbalances(child["chain_id"])["mine"]["trusted"],
                amount)

        self.log.info("Pause and unload one child without affecting its peer")
        assert_equal(node.setchildnetworkactive(
            children[0]["chain_id"], False)["network_active"], False)
        assert_equal(node.getchildnetworkinfo(
            children[1]["chain_id"])["network_active"], True)
        assert_equal(node.setchildnetworkactive(
            children[0]["chain_id"], True)["network_active"], True)

        self.log.info("Build a longer competing main branch without the second deposit")
        competing_blocks = node.getblockcount() - fork_node.getblockcount() + 1
        assert competing_blocks > 0
        self.generatetoaddress(
            fork_node, competing_blocks, fork_wallet.getnewaddress(),
            sync_fun=lambda: None)
        competing_tip = fork_node.getbestblockhash()
        self.connect_nodes(0, 1)
        self.sync_blocks()
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getbestblockhash(), competing_tip)

        self.log.info("Verify selective SAFE_HALT evidence after the deep reorg")
        normal_status = node.getchildbmmstatus(children[0]["chain_id"])
        halted_status = node.getchildbmmstatus(children[1]["chain_id"])
        assert_equal(normal_status["safe_halt"], False)
        assert "safe_halt_reason" not in normal_status
        assert_equal(halted_status["health"], "safe_halt")
        assert_equal(halted_status["safe_halt"], True)
        assert_equal(halted_status["safe_halt_reason"],
                     "imported_deposit_left_main_chain")
        assert_equal(halted_status["safe_halt_observed_main_tip"],
                     competing_tip)
        assert_equal(halted_status["safe_halt_affected_deposits"],
                     [deposits[1]["deposit_id"]])
        assert_equal(node.getblockcount(children[0]["chain_id"]), 0)
        assert_equal(node.getblockcount(children[1]["chain_id"]), 1)
        assert_raises_rpc_error(
            -26, "child chain is in SAFE_HALT",
            node.createchildimporttransaction,
            children[1]["chain_id"], proofs[1])

        assert_equal(node.unloadchildchain(
            children[0]["chain_id"])["loaded"], False)
        assert_equal(node.getchildnetworkinfo(
            children[1]["chain_id"])["network_running"], True)
        assert_equal(node.getblockcount(children[1]["chain_id"]), 1)

        self.log.info("Persist SAFE_HALT evidence across restart and explicit reload")
        self.restart_node(0)
        node = self.nodes[0]
        node.loadwallet("devnet")
        assert_equal(node.getbestblockhash(), competing_tip)
        runtime_by_id = {
            entry["chain_id"]: entry
            for entry in node.listchildchainruntimes()["chains"]
        }
        assert_equal(runtime_by_id[children[1]["chain_id"]]["loaded"], False)
        node.loadchildchain(children[1]["chain_id"])
        restored_status = node.getchildbmmstatus(children[1]["chain_id"])
        assert_equal(restored_status["health"], "safe_halt")
        assert_equal(restored_status["safe_halt_reason"],
                     halted_status["safe_halt_reason"])
        assert_equal(restored_status["safe_halt_observed_main_tip"],
                     halted_status["safe_halt_observed_main_tip"])
        assert_equal(restored_status["safe_halt_affected_deposits"],
                     halted_status["safe_halt_affected_deposits"])
        assert_equal(node.getblockcount(children[1]["chain_id"]), 1)


if __name__ == "__main__":
    MultichainDevnetTest(__file__).main()
