#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Exercise the mainnet-sized dealer quorum on an isolated regtest network."""

from itertools import combinations

from test_framework.key import compute_xonly_pubkey, sign_schnorr
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error


class DealerAuthorityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Public, deterministic test fixtures only; sorted indices are wire identities.
        self.secrets = sorted(
            (i.to_bytes(32, "big") for i in range(1, 6)),
            key=lambda secret: compute_xonly_pubkey(secret)[0],
        )
        self.keys = [compute_xonly_pubkey(secret)[0].hex() for secret in self.secrets]
        args = [
            "-chainregistryactivationheight=1",
            "-chainregistrymaxoperations=4",
            "-chaindealerauthoritythreshold=4",
            *[f"-chaindealerauthoritykey={key}" for key in self.keys],
        ]
        self.extra_args = [args.copy(), args.copy()]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def signed_parameters(self, operation, parameters, signers):
        draft = self.nodes[0].createchainregistryoperation(operation, parameters)
        return {
            **parameters,
            "authority_signatures": [
                {"key_index": i, "signature": sign_schnorr(
                    self.secrets[i], bytes.fromhex(draft["authority_hash"])).hex()}
                for i in signers
            ],
        }

    def funded_transaction(self, data, outputs=()):
        raw_outputs = [{"data": data}, *outputs]
        raw = self.nodes[0].createrawtransaction([], raw_outputs)
        funded = self.wallet.fundrawtransaction(raw, change_position=len(raw_outputs), fee_rate=1)
        signed = self.wallet.signrawtransactionwithwallet(funded["hex"])
        assert signed["complete"]
        return signed["hex"]

    def run_test(self):
        node, peer = self.nodes
        node.createwallet("authority")
        self.wallet = node.get_wallet_rpc("authority")
        self.address = self.wallet.getnewaddress()
        self.generatetoaddress(node, 101, self.address)
        control = self.wallet.getnewaddress()
        script = self.wallet.getaddressinfo(control)["scriptPubKey"]
        parameters = {
            "authority_sequence": 1,
            "authorization_nonce": "35" * 32,
            "dealer_control_key": script[4:],
            "control_output": 1,
            "payout_script": script,
            "initial_licenses": 10,
        }
        self.log.info("Expose the real quorum and verify all five four-of-five combinations")
        info = node.getchainregistryinfo()
        assert_equal(info["dealer_authority_keys"], self.keys)
        assert_equal(info["dealer_authority_threshold"], 4)
        draft = node.createchainregistryoperation("authorize_dealer", parameters)
        assert_equal(draft["authority_keys"], self.keys)
        assert_equal(draft["authority_signatures_needed"], 4)
        assert not draft["authority_complete"]
        for signers in combinations(range(5), 4):
            signed = self.signed_parameters("authorize_dealer", parameters, signers)
            complete = node.createchainregistryoperation("authorize_dealer", signed)
            assert complete["authority_complete"]
            assert_equal(complete["authority_hash"], draft["authority_hash"])
            assert_equal(complete["authority_signatures_needed"], 0)
            decoded = node.decodechainregistryoperation(complete["script"])
            assert_equal(decoded["authority_signatures"], signed["authority_signatures"])

        self.log.info("Reject partial quorum at mempool admission, not merely in the builder")
        partial = self.signed_parameters("authorize_dealer", parameters, range(3))
        result = node.createchainregistryoperation("authorize_dealer", partial)
        assert not result["authority_complete"]
        assert_equal(result["authority_signatures_needed"], 1)
        raw = self.funded_transaction(result["data"], [{control: 1}])
        assert not node.testmempoolaccept([raw])[0]["allowed"]
        assert_equal(node.listchaindealers()["authority_sequence"], 0)

        self.log.info("Reject duplicate indices, wrong signatures, order and allocation violations")
        signed = self.signed_parameters("authorize_dealer", parameters, range(4))
        signatures = signed["authority_signatures"]
        for invalid in ([signatures[0]] * 4, list(reversed(signatures)), [{"key_index": 5, "signature": signatures[0]["signature"]}]):
            assert_raises_rpc_error(-8, "Authority signer indices", node.createchainregistryoperation,
                                    "authorize_dealer", {**parameters, "authority_signatures": invalid})
        copied = [{"key_index": i, "signature": signatures[0]["signature"]} for i in range(4)]
        assert_raises_rpc_error(-8, "authority_signatures do not verify", node.createchainregistryoperation,
                                "authorize_dealer", {**parameters, "authority_signatures": copied})
        all_signed = self.signed_parameters("authorize_dealer", parameters, range(5))
        all_signed["authority_signatures"][-1]["signature"] = "00" * 64
        assert_raises_rpc_error(-8, "authority_signatures do not verify", node.createchainregistryoperation,
                                "authorize_dealer", all_signed)
        for licenses in (0, 1, 9, 11, 4294967295):
            assert_raises_rpc_error(-8, "initial_licenses must be exactly 10", node.createchainregistryoperation,
                                    "authorize_dealer", {**parameters, "initial_licenses": licenses})

        self.log.info("Confirm, disconnect, reconnect and reload a multi-signature authorization")
        complete = node.createchainregistryoperation("authorize_dealer", signed)
        dealer_id = complete["dealer_id"]
        raw = self.funded_transaction(complete["data"], [{control: 1}])
        assert node.testmempoolaccept([raw])[0]["allowed"]
        txid = node.sendrawtransaction(raw)
        self.sync_mempools()
        tip = self.generatetoaddress(node, 1, self.address)[0]
        for n in self.nodes:
            assert_equal(n.getchaindealer(dealer_id)["remaining_licenses"], 10)
        assert_raises_rpc_error(-8, "authority_sequence must be exactly 2", node.createchainregistryoperation,
                                "authorize_dealer", signed)
        for n in self.nodes:
            n.invalidateblock(tip)
            assert_equal(n.listchaindealers()["authority_sequence"], 0)
            assert txid in n.getrawmempool()
        for n in self.nodes:
            n.reconsiderblock(tip)
        self.sync_blocks()
        self.restart_node(1, extra_args=[*self.extra_args[1], "-reindex-chainstate"])
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(peer.getchaindealer(dealer_id)["remaining_licenses"], 10)

        self.log.info("Enforce bounded replenishment while allowing payout-only updates")
        update = {"authority_sequence": 2, "dealer_id": dealer_id, "added_licenses": 11}
        assert_raises_rpc_error(-8, "added_licenses must not exceed 10", node.createchainregistryoperation,
                                "update_dealer", update)
        update["added_licenses"] = 10
        signed_update = self.signed_parameters("update_dealer", update, (1, 2, 3, 4))
        complete = node.createchainregistryoperation("update_dealer", signed_update)
        node.sendrawtransaction(self.funded_transaction(complete["data"]))
        self.generatetoaddress(node, 1, self.address)
        assert_equal(peer.getchaindealer(dealer_id)["remaining_licenses"], 20)

        self.log.info("Reject ambiguous or invalid authority configuration before opening chainstate")
        self.stop_node(1)
        base = ["-chainregistryactivationheight=1", "-chainregistrymaxoperations=4"]
        policies = [
            (self.keys, None, "required for multiple keys"),
            (self.keys, 0, "must be between 1"),
            (self.keys, 6, "must be between 1"),
            (self.keys + [self.keys[0]], 4, "At most five"),
            ([self.keys[0]] * 3, 2, "must be distinct"),
            (list(reversed(self.keys)), 4, "in increasing hexadecimal order"),
            (["ff" * 32], 1, "must be a valid 32-byte"),
        ]
        for keys, threshold, message in policies:
            args = [*base, *[f"-chaindealerauthoritykey={key}" for key in keys]]
            if threshold is not None:
                args.append(f"-chaindealerauthoritythreshold={threshold}")
            peer.assert_start_raises_init_error(args, message, match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(1)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(peer.getchaindealer(dealer_id)["remaining_licenses"], 20)
        payout_update = {"authority_sequence": 3, "dealer_id": dealer_id, "added_licenses": 0, "payout_script": script}
        complete = node.createchainregistryoperation("update_dealer", self.signed_parameters("update_dealer", payout_update, range(4)))
        node.sendrawtransaction(self.funded_transaction(complete["data"]))
        self.generatetoaddress(node, 1, self.address)
        assert_equal(peer.getchaindealer(dealer_id)["remaining_licenses"], 20)


if __name__ == "__main__":
    DealerAuthorityTest(__file__).main()
