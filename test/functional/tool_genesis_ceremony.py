#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Reproduce and independently decode an offline development genesis."""

from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import runpy
import subprocess
import sys

from test_framework.messages import CBlock, hash256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises


class GenesisCeremonyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0

    def setup_network(self):
        pass

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_util()

    def run_test(self):
        tool = Path(self.config["environment"]["SRCDIR"]) / "contrib/devtools/genesis_ceremony.py"
        module = runpy.run_path(str(tool))
        util_argv = self.get_binaries().util_argv()
        assert_equal(len(util_argv), 1)
        util = module["Utility"](util_argv[0], timeout=90)
        canonical = module["canonical"]
        not_before, genesis_time = 1_800_000_000, 1_800_000_600
        manifest = module["make_manifest"](util, not_before, genesis_time)
        manifest_hash = module["validate_manifest"](manifest)
        assert_equal(manifest_hash, hashlib.sha256(canonical(manifest)).hexdigest())
        # Canonicalization does not depend on input dictionary order.
        assert_equal(canonical(manifest), canonical(dict(reversed(list(manifest.items())))))
        for invalid in (1.5, float("nan"), 1 << 64, -(1 << 63) - 1, {1: "key"}):
            assert_raises(ValueError, canonical, invalid)
        for network, threshold, count, hrp in (
            ("main", 4, 5, "kne"), ("testnet4", 2, 3, "tkne"),
            ("signet", 2, 3, "skne"), ("regtest", 1, 1, "rkne"),
        ):
            params = manifest["networks"][network]["parameters"]
            assert params["development_only"]
            assert_equal(params["authority_threshold"], threshold)
            assert_equal(len(params["authority_keys"]), count)
            assert_equal(params["hrp"], hrp)
            assert_equal(params["minimum_deposit"], 100_000)
            assert_equal(params["registry_activation"], 1)
            assert_equal(params["maximum_deposits"], 64)

        entropy = b"Public test vector only\x00\xff; not a real entropy ceremony."
        source = "test-vector:kronein-genesis-v1"
        artifact = module["create_artifact"](util, manifest, "regtest", entropy, source, not_before)
        genesis = artifact["genesis"]
        # The native miner scans nonces in ascending order. A second run must
        # reproduce the complete artifact, not merely find another valid PoW.
        assert_equal(artifact, module["create_artifact"](
            util, manifest, "regtest", entropy, source, not_before))
        assert module["verify_artifact"](util, manifest, artifact, entropy)["valid"]

        self.log.info("Check header, merkle root and full binary commitments independently in Python")
        encoded = bytes.fromhex(genesis["block"])
        stream = BytesIO(encoded)
        block = CBlock()
        block.deserialize(stream)
        assert_equal(stream.read(), b"")
        assert_equal(block.serialize(), encoded)
        assert_equal(encoded[:80].hex(), genesis["header"])
        assert_equal(hash256(encoded[:80])[::-1].hex(), genesis["hash"])
        assert_equal(len(block.vtx), 1)
        assert_equal(f"{block.calc_merkle_root():064x}", genesis["merkle_root"])
        timestamp = b"KNE:regtest:" + bytes.fromhex(manifest_hash) + hashlib.sha256(entropy).digest()
        assert_equal(genesis["timestamp_hex"], timestamp.hex())
        assert timestamp in block.vtx[0].vin[0].scriptSig
        assert len(block.vtx[0].vin[0].scriptSig) <= 100
        assert block.vtx[0].vout[0].scriptPubKey.startswith(b"\x6a")
        assert_equal(block.nTime, genesis_time)
        assert_equal(block.nNonce, genesis["nonce"])

        self.log.info("Reject changed commitments, network, parameters and chronology")
        assert_raises(ValueError, module["verify_artifact"], util, manifest, artifact, entropy + b"x")
        for field, value in (("manifest_sha256", "00" * 32), ("network", "signet"),
                             ("development_only", False), ("entropy_observed_at_utc", not_before - 1)):
            changed = deepcopy(artifact)
            changed[field] = value
            assert_raises(ValueError, module["verify_artifact"], util, manifest, changed, entropy)
        for field in ("header", "block", "hash", "merkle_root", "timestamp_hex", "randomx_seed"):
            changed = deepcopy(artifact)
            changed["genesis"][field] = "00"
            assert_raises(ValueError, module["verify_artifact"], util, manifest, changed, entropy)
        changed = deepcopy(manifest)
        changed["networks"]["regtest"]["parameters"]["minimum_deposit"] += 1
        assert_raises(ValueError, module["create_artifact"], util, changed, "regtest", entropy, source, not_before)
        changed = deepcopy(manifest)
        changed["networks"]["regtest"]["parameters"]["registry_activation"] = True
        assert_raises(ValueError, module["create_artifact"], util, changed, "regtest", entropy, source, not_before)
        for observed_at in (not_before - 1, genesis_time + 1, True):
            assert_raises(ValueError, module["create_artifact"], util, manifest, "regtest", entropy, source, observed_at)
        # Target zero is unconditionally invalid, independently of the nonce.
        invalid_header = bytearray.fromhex(genesis["header"])
        invalid_header[72:76] = bytes(4)
        assert_raises(ValueError, util.call, "regtest", "verify", invalid_header.hex(), genesis["randomx_seed"])
        assert_raises(ValueError, util.call, "regtest", "verify", genesis["header"] + "00", genesis["randomx_seed"])
        for timestamp_hex, time, bits, nonce in (("00" * 91, genesis_time, "207fffff", 0),
                                                ("00", -1, "207fffff", 0),
                                                ("00", genesis_time, "2100ffff", 0),
                                                ("00", genesis_time, "207fffff", -1)):
            assert_raises(ValueError, util.call, "regtest", "genesis", timestamp_hex, time, bits, nonce)

        self.log.info("Exercise the CLI and reject ambiguous or oversized input files")
        directory = Path(self.options.tmpdir)
        manifest_path, entropy_path, artifact_path = [directory / name for name in ("manifest.json", "entropy.bin", "artifact.json")]
        manifest_path.write_bytes(canonical(manifest))
        entropy_path.write_bytes(entropy)
        artifact_path.write_bytes(canonical(artifact))
        command = [sys.executable, str(tool), "--util", util_argv[0], "verify",
                   "--manifest", str(manifest_path), "--entropy-file", str(entropy_path), "--artifact", str(artifact_path)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        assert_equal(result.returncode, 0)
        assert json.loads(result.stdout)["valid"]
        for invalid in (b'{"duplicate":1,"duplicate":2}', b'{"x":NaN}', b" " * (module["MAX_INPUT"] + 1)):
            manifest_path.write_bytes(invalid)
            result = subprocess.run(command, capture_output=True, text=True, timeout=90)
            assert_equal(result.returncode, 1)
            assert "Error:" in result.stderr
            assert "Traceback" not in result.stderr


if __name__ == "__main__":
    GenesisCeremonyTest(__file__).main()
