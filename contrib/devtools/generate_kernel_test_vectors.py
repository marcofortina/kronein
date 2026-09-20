#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Generate the native regtest chain used by the kernel API tests.

The fixture contains 206 blocks after genesis. The final two blocks contain a
Taproot transaction and a transaction spending its 1 KNE output, respectively,
so the kernel tests exercise block undo data and script verification as well as
header and block processing.
"""

import argparse
import json
import pathlib
import subprocess
import tempfile
import time


WALLET_NAME = "kernel_fixture"
BLOCK_COUNT = 206
EXTERNAL_DESCRIPTOR = "tr([00000001/86h/1h/0']KrprvXJ7sdXeAaebXiey7yvDXgmhNCdCzN1Y36DXgM2RACzavCQ9XHZMve7dsUoSCAVrvH2cnVH5b2oCtgDsATtXKyhvUSurRftNtHnke6h3P4VP/0/*)#4wmwql9e"
INTERNAL_DESCRIPTOR = "tr([00000001/86h/1h/0']KrprvXJ7sdXeAaebXiey7yvDXgmhNCdCzN1Y36DXgM2RACzavCQ9XHZMve7dsUoSCAVrvH2cnVH5b2oCtgDsATtXKyhvUSurRftNtHnke6h3P4VP/1/*)#y670a24p"


def run(command: list[str], *, parse_json: bool = True):
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr.strip()}")
    output = result.stdout.strip()
    if not parse_json or not output:
        return output
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=pathlib.Path, default=pathlib.Path("build/bin/kroneind"))
    parser.add_argument("--cli", type=pathlib.Path, default=pathlib.Path("build/bin/kronein-cli"))
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("src/test/kernel/block_data.h"))
    args = parser.parse_args()

    daemon = args.daemon.resolve()
    cli = args.cli.resolve()
    output = args.output.resolve()

    with tempfile.TemporaryDirectory(prefix="kronein-kernel-vectors-") as datadir:
        common = ["-regtest", f"-datadir={datadir}"]
        run([
            str(daemon),
            *common,
            "-daemonwait",
            "-server=1",
            "-listen=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-fallbackfee=0.0002",
            "-txindex=1",
        ], parse_json=False)

        def rpc(method: str, *params: str, wallet: bool = False):
            command = [str(cli), *common, "-rpcwait"]
            if wallet:
                command.append(f"-rpcwallet={WALLET_NAME}")
            command.extend([method, *params])
            return run(command)

        try:
            genesis_hash = rpc("getblockhash", "0")
            genesis_time = rpc("getblockheader", genesis_hash)["time"]
            # Create the wallet after setting deterministic mock time, otherwise
            # its key birthday would be newer than all generated fixture blocks.
            rpc("setmocktime", str(genesis_time + 1))
            rpc("createwallet", WALLET_NAME, "false", "true")
            descriptors = [
                {"desc": EXTERNAL_DESCRIPTOR, "active": True, "timestamp": genesis_time, "range": [0, 10], "next_index": 0},
                {"desc": INTERNAL_DESCRIPTOR, "active": True, "internal": True, "timestamp": genesis_time, "range": [0, 10], "next_index": 0},
            ]
            imported = rpc("importdescriptors", json.dumps(descriptors, separators=(",", ":")), wallet=True)
            if not all(result.get("success") for result in imported):
                raise RuntimeError(f"could not import deterministic fixture descriptors: {imported}")
            mining_address = rpc("getnewaddress", wallet=True)

            for height in range(1, 205):
                rpc("setmocktime", str(genesis_time + height))
                rpc("generatetoaddress", "1", mining_address, "1000000")

            first_block_hash = rpc("getblockhash", "1")
            first_coinbase = rpc("getblock", first_block_hash, "2")["tx"][0]
            change_destination = rpc("getnewaddress", wallet=True)
            first_destination = rpc("getnewaddress", wallet=True)
            first_unsigned = rpc(
                "createrawtransaction",
                json.dumps([{"txid": first_coinbase["txid"], "vout": 0}], separators=(",", ":")),
                json.dumps([{change_destination: 48.9999846}, {first_destination: 1.0}], separators=(",", ":")),
            )
            first_signed = rpc("signrawtransactionwithwallet", first_unsigned, wallet=True)
            if not first_signed["complete"]:
                raise RuntimeError("wallet did not completely sign the first fixture transaction")
            first_txid = rpc("sendrawtransaction", first_signed["hex"], "0")
            rpc("setmocktime", str(genesis_time + 205))
            block_205 = rpc("generatetoaddress", "1", mining_address, "1000000")[0]
            first_tx = rpc("getrawtransaction", first_txid, "1", block_205)
            first_output = next(
                output
                for output in first_tx["vout"]
                if output["value"] == 1.0 and output["scriptPubKey"].get("address") == first_destination
            )

            second_destination = rpc("getnewaddress", wallet=True)
            unsigned = rpc(
                "createrawtransaction",
                json.dumps([{"txid": first_txid, "vout": first_output["n"]}], separators=(",", ":")),
                json.dumps([{second_destination: 0.999}], separators=(",", ":")),
            )
            signed = rpc("signrawtransactionwithwallet", unsigned, wallet=True)
            if not signed["complete"]:
                raise RuntimeError("wallet did not completely sign the second fixture transaction")
            second_txid = rpc("sendrawtransaction", signed["hex"])
            rpc("setmocktime", str(genesis_time + 206))
            block_206 = rpc("generatetoaddress", "1", mining_address, "1000000")[0]
            second_tx = rpc("getrawtransaction", second_txid, "1", block_206)

            blocks = []
            headers = []
            for height in range(1, BLOCK_COUNT + 1):
                block_hash = rpc("getblockhash", str(height))
                blocks.append(rpc("getblock", block_hash, "0"))
                headers.append(rpc("getblockheader", block_hash))

            first_block = rpc("getblock", headers[0]["hash"], "2")
            header = [
                "// Copyright (c) 2024-present The Bitcoin Core developers",
                "// Copyright (c) 2026 The Kronein Core developers",
                "// Distributed under the MIT software license, see the accompanying",
                "// file COPYING or https://opensource.org/license/mit.",
                "",
                "// Generated by contrib/devtools/generate_kernel_test_vectors.py.",
                "#ifndef BITCOIN_TEST_KERNEL_BLOCK_DATA_H",
                "#define BITCOIN_TEST_KERNEL_BLOCK_DATA_H",
                "",
                "#include <array>",
                "#include <cstdint>",
                "#include <string_view>",
                "",
                f'inline constexpr std::string_view REGTEST_FIRST_BLOCK_HASH{{"{headers[0]["hash"]}"}};',
                f'inline constexpr std::string_view REGTEST_SECOND_BLOCK_HASH{{"{headers[1]["hash"]}"}};',
                f'inline constexpr std::string_view REGTEST_FIRST_COINBASE_TXID{{"{first_block["tx"][0]["txid"]}"}};',
                f"inline constexpr uint32_t REGTEST_FIRST_BLOCK_TIME{{{headers[0]['time']}}};",
                f"inline constexpr uint32_t REGTEST_SECOND_BLOCK_TIME{{{headers[1]['time']}}};",
                f"inline constexpr uint32_t REGTEST_FIRST_BLOCK_BITS{{0x{headers[0]['bits']}U}};",
                f"inline constexpr uint32_t REGTEST_FIRST_BLOCK_NONCE{{{headers[0]['nonce']}}};",
                f"inline constexpr uint32_t REGTEST_SECOND_BLOCK_NONCE{{{headers[1]['nonce']}}};",
                f'inline constexpr std::string_view REGTEST_TRANSACTION_DATA{{"{first_tx["hex"]}"}};',
                f'inline constexpr std::string_view REGTEST_TRANSACTION_DATA_2{{"{second_tx["hex"]}"}};',
                f'inline constexpr std::string_view REGTEST_SPENT_SCRIPT_DATA{{"{first_output["scriptPubKey"]["hex"]}"}};',
                "",
                f"inline constexpr std::array<std::string_view, {BLOCK_COUNT}> REGTEST_BLOCK_DATA {{{{",
            ]
            header.extend(f'    "{block}",' for block in blocks)
            header.extend(["}};", "", "#endif // BITCOIN_TEST_KERNEL_BLOCK_DATA_H", ""])

            temporary = output.with_suffix(output.suffix + ".new")
            temporary.write_text("\n".join(header), encoding="utf-8")
            temporary.replace(output)
        finally:
            try:
                rpc("stop")
            except (RuntimeError, json.JSONDecodeError):
                pass
            for _ in range(50):
                if not pathlib.Path(datadir, "regtest", "kroneind.pid").exists():
                    break
                time.sleep(0.1)


if __name__ == "__main__":
    main()
