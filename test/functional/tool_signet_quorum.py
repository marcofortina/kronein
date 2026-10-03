#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Mine the development Signet through separate 2-of-3 custodian wallets."""

from itertools import combinations
from pathlib import Path
import json
import logging
import runpy
import shlex
import subprocess
import sys
import time

from test_framework.descriptors import descsum_create
from test_framework.key import compute_xonly_pubkey, H_POINT
from test_framework.psbt import PSBT, PSBT_IN_FINAL_SCRIPTWITNESS, PSBT_OUT_AMOUNT
from test_framework.script import CScript, OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL, taproot_construct
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises
from test_framework.wallet_util import WIF_PREFIX_SIGNET, bytes_to_wif


class SignetQuorumTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()
        self.skip_if_no_wallet()
        self.skip_if_no_bitcoin_util()

    def run_test(self):
        node = self.nodes[0]
        # These widely known test secrets simulate custodians, not independent
        # production custody. Authority dealer keys use a different fixture set.
        secrets = sorted((i.to_bytes(32, "big") for i in (42, 43, 44)),
                         key=lambda secret: compute_xonly_pubkey(secret)[0])
        keys = [compute_xonly_pubkey(secret)[0] for secret in secrets]
        leaf = CScript([keys[0], OP_CHECKSIG, keys[1], OP_CHECKSIGADD, keys[2], OP_CHECKSIGADD, 2, OP_NUMEQUAL])
        challenge = taproot_construct(bytes.fromhex(H_POINT), [("quorum", leaf)]).scriptPubKey.hex()
        assert_equal(node.getblockchaininfo()["signet_challenge"], challenge)
        wallets = []
        for i in range(3):
            name = f"custodian{i}"
            node.createwallet(name, blank=True)
            wallet = node.get_wallet_rpc(name)
            key_expressions = [bytes_to_wif(secret, version=WIF_PREFIX_SIGNET) if j == i else keys[j].hex()
                               for j, secret in enumerate(secrets)]
            descriptor = descsum_create(f'tr({H_POINT},multi_a(2,{",".join(key_expressions)}))')
            assert wallet.importdescriptors([{"desc": descriptor, "timestamp": "now"}])[0]["success"]
            wallets.append(wallet)
        coordinator = node.get_wallet_rpc(self.default_wallet_name)
        reward_address = coordinator.getnewaddress()
        script = bytes.fromhex(coordinator.getaddressinfo(reward_address)["scriptPubKey"])
        tool = Path(self.config["environment"]["SRCDIR"]) / "contrib" / "signet" / "miner"
        handlers = logging.getLogger().handlers.copy()
        module = runpy.run_path(str(tool))
        # Retain a handler while invoking tool helpers too: module-level
        # logging would otherwise call basicConfig again after restoration.
        logging.getLogger().handlers = handlers or [logging.NullHandler()]
        template = node.getblocktemplate({"rules": ["signet", "segwit", "chainregistry"]})
        block = module["new_block"](template, script)
        draft = module["generate_psbt"](block, challenge, bytes.fromhex(template["randomx"]["seed"]))

        self.log.info("No wallet alone can satisfy the challenge, including by key path")
        for wallet in wallets:
            partial = wallet.walletprocesspsbt(draft, True, "DEFAULT")
            assert not partial["complete"]
            assert not node.finalizepsbt(partial["psbt"])["complete"]
        for first, second in combinations(wallets, 2):
            partial = first.walletprocesspsbt(draft, True, "DEFAULT")
            complete = second.walletprocesspsbt(partial["psbt"], True, "DEFAULT")
            assert complete["complete"]
            assert node.finalizepsbt(complete["psbt"])["complete"]
            module["check_signer_response"](PSBT.from_base64(draft), complete["psbt"])

        self.log.info("Reject mutated coordinator data before forwarding it to another custodian")
        for mutate in (
            lambda p: p.g.map.__setitem__(module["PSBT_SIGNET_BLOCK"], b"wrong block"),
            lambda p: p.g.map.__setitem__(module["PSBT_RANDOMX_SEED"], bytes(32)),
            lambda p: p.o[0].map.__setitem__(PSBT_OUT_AMOUNT, (1).to_bytes(8, "little")),
        ):
            modified = PSBT.from_base64(draft)
            mutate(modified)
            assert_raises(ValueError, module["check_signer_response"], PSBT.from_base64(draft), modified.to_base64())

        rpc_argv = node.binaries.rpc_argv() + [f"-datadir={node.cli.datadir}"]
        coordinator_cli = shlex.join(rpc_argv + [f"-rpcwallet={self.default_wallet_name}"])
        signer_commands = [shlex.join(rpc_argv + [f"-rpcwallet=custodian{i}"]) for i in range(3)]
        unavailable = shlex.join(rpc_argv + ["-rpcwallet=missing-custodian"])
        grind = shlex.join(node.binaries.util_argv() + ["-signet", "-randomxlight", "grind"])

        def mine(signers, expected_success):
            height = node.getblockcount()
            timestamp = max(int(time.time()), node.getblockheader(node.getbestblockhash())["time"] + 1)
            command = [sys.executable, str(tool), f"--cli={coordinator_cli}", "generate",
                       f"--address={reward_address}", f"--grind-cmd={grind}",
                       f"--set-block-time={timestamp}", "--signer-timeout=5",
                       *[f"--signer-cli={signer}" for signer in signers]]
            result = subprocess.run(command, text=True, capture_output=True, timeout=90)
            assert result.returncode == (0 if expected_success else 1), result.stderr
            if not expected_success:
                assert "Signet signing quorum not reached" in result.stderr, result.stderr
            assert_equal(node.getblockcount(), height + int(expected_success))

        self.log.info("Refuse one custodian and repeated copies of the same custodian")
        mine([signer_commands[0]], False)
        mine([signer_commands[0], signer_commands[0]], False)
        self.log.info("Mine with every pair, even if the first configured custodian is unavailable")
        for pair in combinations(signer_commands, 2):
            mine([unavailable, *pair], True)

        self.log.info("Do not accept a remote complete flag for a forged witness")
        forged = PSBT.from_base64(draft)
        forged.i[0].map[PSBT_IN_FINAL_SCRIPTWITNESS] = b"\x01\x40" + bytes(64)
        def bad_signer(*args, **kwargs):
            return json.dumps({"psbt": forged.to_base64(), "complete": True})
        def verifier(*args, **kwargs):
            return json.dumps(node.finalizepsbt(forged.to_base64(), False))
        assert_raises(ValueError, module["sign_challenge"], draft, [bad_signer], verifier, 5)


if __name__ == "__main__":
    SignetQuorumTest(__file__).main()
