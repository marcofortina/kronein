#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Offline, reproducible development-genesis ceremony. No network or file writes.

All results go to stdout. This tool does not select public entropy, certify its
publication time, change chainparams, or authorize a public launch. The current
network keys and parameters remain explicitly development-only.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

NETWORKS = ("main", "testnet4", "signet", "regtest")
MANIFEST_FORMAT = "kronein-genesis-manifest-v1"
ARTIFACT_FORMAT = "kronein-genesis-artifact-v1"
MAX_INPUT = 1_048_576


def canonical(value):
    """UTF-8 JSON, sorted keys, no whitespace, floats or non-finite numbers."""
    def check(item):
        if item is None or type(item) is bool:
            return
        if type(item) is int and -(1 << 63) <= item < (1 << 64):
            return
        if type(item) is str:
            item.encode("utf-8", errors="strict")
            return
        if type(item) is list:
            for child in item:
                check(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for key, child in item.items():
                check(key)
                check(child)
            return
        raise ValueError("Manifest values must be bounded integers, strings, booleans, nulls, lists or objects")
    check(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def read_bounded(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError("Input exceeds one MiB")
    return data


def read_json(path):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    result = json.loads(read_bounded(path), object_pairs_hook=object_pairs)
    canonical(result)
    return result


def require_fields(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError(f"Expected exactly these fields: {', '.join(fields)}")


def uint32(value):
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise ValueError("Expected an unsigned 32-bit integer")
    return value


class Utility:
    def __init__(self, executable, *, timeout=3600, full_memory=False):
        self.executable = str(Path(executable).resolve())
        self.timeout = timeout
        self.full_memory = full_memory

    def call(self, network, command, *arguments):
        if network not in NETWORKS:
            raise ValueError("Unknown network")
        argv = [self.executable, f"-chain={network}"]
        if not self.full_memory:
            argv.append("-randomxlight")
        result = subprocess.run([*argv, command, *map(str, arguments)], capture_output=True,
                                text=True, check=False, timeout=self.timeout)
        if result.returncode:
            raise ValueError(f"kronein-util {command} failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def info(self, network):
        return json.loads(self.call(network, "genesisinfo"))

    def genesis(self, network, timestamp, time, bits, nonce):
        return json.loads(self.call(network, "genesis", timestamp.hex(), time, bits, nonce))


def make_manifest(util, not_before, genesis_time):
    uint32(not_before)
    uint32(genesis_time)
    if genesis_time < not_before:
        raise ValueError("Genesis time precedes the precommitted earliest entropy time")
    return {
        "format": MANIFEST_FORMAT,
        "not_before_utc": not_before,
        "networks": {network: {"parameters": util.info(network), "time": genesis_time}
                     for network in NETWORKS},
    }


def validate_manifest(manifest):
    require_fields(manifest, ("format", "not_before_utc", "networks"))
    if manifest["format"] != MANIFEST_FORMAT:
        raise ValueError("Unsupported manifest version")
    not_before = uint32(manifest["not_before_utc"])
    require_fields(manifest["networks"], NETWORKS)
    for network, entry in manifest["networks"].items():
        require_fields(entry, ("parameters", "time"))
        if uint32(entry["time"]) < not_before:
            raise ValueError("Genesis time precedes the precommitted earliest entropy time")
        params = entry["parameters"]
        if type(params) is not dict or params.get("network") != network or params.get("development_only") is not True:
            raise ValueError("A network-bound, explicitly development-only parameter set is required")
    return hashlib.sha256(canonical(manifest)).hexdigest()


def ceremony_inputs(util, manifest, network, entropy, source, observed_at):
    manifest_hash = validate_manifest(manifest)
    if network not in NETWORKS or not entropy or len(entropy) > MAX_INPUT:
        raise ValueError("A supported network and nonempty bounded entropy bytes are required")
    if type(source) is not str or not source.strip() or len(source) > 2048:
        raise ValueError("Record the public entropy source (1..2048 characters)")
    if uint32(observed_at) < manifest["not_before_utc"]:
        raise ValueError("Entropy was observed before the precommitted earliest time")
    entry = manifest["networks"][network]
    # Python considers True == 1. Compare canonical bytes so the approved
    # parameter schema cannot silently change booleans into integers.
    if canonical(entry["parameters"]) != canonical(util.info(network)):
        raise ValueError("Approved manifest parameters differ from this binary")
    if observed_at > entry["time"]:
        raise ValueError("Genesis time precedes the entropy observation")
    entropy_hash = hashlib.sha256(entropy).hexdigest()
    # Full hashes, not abbreviations. Binary commitments fit the normal
    # 100-byte coinbase scriptSig limit while retaining a readable network tag.
    timestamp = b"KNE:" + network.encode("ascii") + b":" + bytes.fromhex(manifest_hash + entropy_hash)
    return manifest_hash, entropy_hash, timestamp, entry


def create_artifact(util, manifest, network, entropy, source, observed_at):
    manifest_hash, entropy_hash, timestamp, entry = ceremony_inputs(
        util, manifest, network, entropy, source, observed_at)
    candidate = util.genesis(network, timestamp, entry["time"], entry["parameters"]["initial_bits"], 0)
    solved = util.call(network, "grind", candidate["header"], candidate["randomx_seed"])
    header = bytes.fromhex(solved)
    if len(header) != 80 or header[:76] != bytes.fromhex(candidate["header"])[:76]:
        raise ValueError("Mining changed fields other than the nonce")
    candidate = util.genesis(network, timestamp, entry["time"], entry["parameters"]["initial_bits"],
                             int.from_bytes(header[76:], "little"))
    if candidate["header"] != solved:
        raise ValueError("Reconstructed genesis header differs from mining result")
    util.call(network, "verify", solved, candidate["randomx_seed"])
    return {
        "format": ARTIFACT_FORMAT,
        "development_only": True,
        "network": network,
        "manifest_sha256": manifest_hash,
        "entropy_sha256": entropy_hash,
        "entropy_source": source,
        "entropy_observed_at_utc": observed_at,
        "genesis": candidate,
    }


def verify_artifact(util, manifest, artifact, entropy):
    require_fields(artifact, ("format", "development_only", "network", "manifest_sha256", "entropy_sha256",
                             "entropy_source", "entropy_observed_at_utc", "genesis"))
    if artifact["format"] != ARTIFACT_FORMAT or artifact["development_only"] is not True:
        raise ValueError("Unsupported or non-development artifact")
    network = artifact["network"]
    mh, eh, timestamp, entry = ceremony_inputs(
        util, manifest, network, entropy, artifact["entropy_source"], artifact["entropy_observed_at_utc"])
    if (mh, eh) != (artifact["manifest_sha256"], artifact["entropy_sha256"]):
        raise ValueError("Manifest or entropy commitment mismatch")
    nonce = uint32(artifact["genesis"]["nonce"])
    expected = util.genesis(network, timestamp, entry["time"], entry["parameters"]["initial_bits"], nonce)
    if canonical(expected) != canonical(artifact["genesis"]):
        raise ValueError("Genesis artifact fields or serialization were modified")
    util.call(network, "verify", expected["header"], expected["randomx_seed"])
    return {"valid": True, "network": network, "hash": expected["hash"], "development_only": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--util", required=True, help="Path to this checkout's kronein-util")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--full-memory", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)
    template = commands.add_parser("manifest", help="Export a parameter manifest for separate review")
    template.add_argument("--not-before", required=True, type=int, help="Earliest public entropy time, Unix UTC seconds")
    template.add_argument("--genesis-time", required=True, type=int, help="Candidate genesis time, Unix UTC seconds")
    mine = commands.add_parser("mine")
    mine.add_argument("--network", choices=NETWORKS, required=True)
    mine.add_argument("--source", required=True)
    mine.add_argument("--observed-at", required=True, type=int)
    verify = commands.add_parser("verify")
    verify.add_argument("--artifact", required=True, type=Path)
    for command in (mine, verify):
        command.add_argument("--manifest", required=True, type=Path)
        command.add_argument("--entropy-file", required=True, type=Path)
    args = parser.parse_args()
    try:
        if not 1 <= args.timeout <= 14400:
            raise ValueError("Timeout must be between 1 and 14400 seconds")
        util = Utility(args.util, timeout=args.timeout, full_memory=args.full_memory)
        if args.command == "manifest":
            result = make_manifest(util, args.not_before, args.genesis_time)
        elif args.command == "mine":
            result = create_artifact(util, read_json(args.manifest), args.network, read_bounded(args.entropy_file),
                                     args.source, args.observed_at)
        else:
            result = verify_artifact(util, read_json(args.manifest), read_json(args.artifact), read_bounded(args.entropy_file))
        print(canonical(result).decode("utf-8"))
    except (ValueError, KeyError, TypeError, OSError, RecursionError, subprocess.SubprocessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
