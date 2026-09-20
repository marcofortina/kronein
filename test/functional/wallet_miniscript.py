#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Miniscript descriptors integration in the wallet."""

from test_framework.descriptors import descsum_create
from test_framework.psbt import PSBT, PSBT_IN_SHA256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


TPRVS = [
    "KrprvXJ7sdXeAaebXkPuBzXjHU2om1faVxAzvPFx7u5hpvmXNLjQocuDmQ4He6CUW3GeS1C7eGDTFaAQuWpwx4XcDTUFhnQU3V4qPsDKku7Cx3XB",
    "KrprvXJ7sdXeAaebXib74k6RRkW4yjE8RGAyHGXhYVp1P3CnncZgUVnWG1HfcywPjy8t9PLGPevKDBCHi95NK1RM7wmdJQaA4jSqUZBFWue6rBs9",
    "KrprvXSg2nP2nU7DNymLc82MAvy9xgE1dCosMJG3L9EX75BSuVhtRK7DCRDxeowxSc9Labftma7jKV1rfDnpZJ74e7Lhgs1RUajyemqEnRwf9p4J",
]
TPUBS = [
    "KrpubTX7E33B4R29pxwhk5ofXVvt8CfXytpCKUuYq3MGBXjDXQHNUGpopwqB71pzBy1nqqgkqRV3nVEdNDGwpuDj3bkGzK79yF7aY34Y88QZD128",
    "KrpubTX7E33B4R29pxuwL7Ds3kNf9H5DQ4X543mXFTYFejkUKk43jCHGRYzJUWmvGuZRXFYsY3e8NaNmvLLdMgrx4supQYC5EPndUwu5foKwoWJv",
    "KrpubTX7E33B4R29py2h4TARggSjVWyii6FhHCEwayjXkG297WE9CjhQcPYaf46QuH4qa4GedrPgVsifWYHfCRFwBbEhKkrNQtgKWDt8mGt2Qe1p",
    "KrpubTX7E33B4R29pwytkTPuxtu2nHzyJzqh4dhnhvXRtAv5rQZzwAarpm9sCvRNJMAM4WRqWFBhorrWq3RgrREXWqMYFGhbBTBcT4HvWo8ynyfZ",
    "KrpubTX7E33B4R29pwSNa6NLMy64ivX8noynozL6bUUmeuWv8AqiFN7bbDq8E397ngaURaJKHUoRdtT2XA5dZAmKihPUhPFv9TqyCcbSnbipApgM",
    "KrpubTeyaBdAXL5jM97J7Z8hKA8ZfugdBTdA3BGYJJLMuWmarBvLFbHTVYrCcij8Ln8jJazPKgEKM5ZxCtWM64Djfpjp21JnWDcLqjJK6RrXBsEc",
    "KrpubTX7E33B4R29pvygJ5qPKwtRdaCxgNNXfkHZYEGQZjKQZuvuVJkGiowFVcG88PRtusekkdbvL55TuuKAA1sE6gHYGokGsXewwYBEowpZouSS",
]
PUBKEYS = [
    "02aebf2d10b040eb936a6f02f44ee82f8b34f5c1ccb20ff3949c2b28206b7c1068",
    "030f64b922aee2fd597f104bc6cb3b670f1ca2c6c49b1071a1a6c010575d94fe5a",
    "02abe475b199ec3d62fa576faee16a334fdb86ffb26dce75becebaaedf328ac3fe",
    "0314f3dc33595b0d016bb522f6fe3a67680723d842c1b9b8ae6b59fdd8ab5cccb4",
    "025eba3305bd3c829e4e1551aac7358e4178832c739e4fc4729effe428de0398ab",
    "029ffbe722b147f3035c87cb1c60b9a5947dd49c774cc31e94773478711a929ac0",
    "0211c7b2e18b6fd330f322de087da62da92ae2ae3d0b7cec7e616479cce175f183",
]

TAP_MINISCRIPTS = [
    # One of two keys
    f"or_b(pk({TPUBS[0]}/*),s:pk({TPUBS[1]}/*))",
    # A script similar (same spending policy) to BOLT3's offered HTLC (with anchor outputs)
    f"or_d(pk({TPUBS[0]}/*),and_v(and_v(v:pk({TPUBS[1]}/*),or_c(pk({TPUBS[2]}/*),v:hash160(7f999c905d5e35cefd0a37673f746eb13fba3640))),older(1)))",
    # A Revault Unvault policy with the older() replaced by an after()
    f"andor(multi_a(2,{TPUBS[0]}/*,{TPUBS[1]}/*),and_v(v:multi_a(4,{PUBKEYS[0]},{PUBKEYS[1]},{PUBKEYS[2]},{PUBKEYS[3]}),after(424242)),thresh(4,pkh({TPUBS[2]}/*),a:pkh({TPUBS[3]}/*),a:pkh({TPUBS[4]}/*),a:pkh({TPUBS[5]}/*)))",
    # Liquid-like federated pegin with emergency recovery keys
    f"or_i(and_b(pk({PUBKEYS[0]}),a:and_b(pk({PUBKEYS[1]}),a:and_b(pk({PUBKEYS[2]}),a:and_b(pk({PUBKEYS[3]}),s:pk({PUBKEYS[4]}))))),and_v(v:thresh(2,pkh({TPUBS[0]}/*),a:pkh({PUBKEYS[5]}),a:pkh({PUBKEYS[6]})),older(4209713)))",
]

DESCS = [
    # A Taproot with one of the above scripts as the single script path.
    f"tr(4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768,{TAP_MINISCRIPTS[0]})",
    # A Taproot with two script paths among the above scripts.
    f"tr(4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768,{{{TAP_MINISCRIPTS[0]},{TAP_MINISCRIPTS[1]}}})",
    # A Taproot with three script paths among the above scripts.
    f"tr(4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768,{{{{{TAP_MINISCRIPTS[0]},{TAP_MINISCRIPTS[1]}}},{TAP_MINISCRIPTS[2]}}})",
    # A Taproot with all above scripts in its tree.
    f"tr(4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768,{{{{{TAP_MINISCRIPTS[0]},{TAP_MINISCRIPTS[1]}}},{{{TAP_MINISCRIPTS[2]},{TAP_MINISCRIPTS[3]}}}}})",
]

DESCS_PRIV = [
    # Each leaf needs two sigs. We've got one key on each. Will sign both but can't finalize.
    {
        "desc": f"tr({TPUBS[0]}/*,{{and_v(v:pk({TPRVS[0]}/*),pk({TPUBS[1]})),and_v(v:pk({TPRVS[1]}/*),pk({TPUBS[2]}))}})",
        "sequence": None,
        "locktime": None,
        "sigs_count": 2,
        "stack_size": None,
    },
    # The same but now the two leaves are identical. Will add a single sig that is valid for both. Can't finalize.
    {
        "desc": f"tr({TPUBS[0]}/*,{{and_v(v:pk({TPRVS[0]}/*),pk({TPUBS[1]})),and_v(v:pk({TPRVS[0]}/*),pk({TPUBS[1]}))}})",
        "sequence": None,
        "locktime": None,
        "sigs_count": 1,
        "stack_size": None,
    },
    # The same but we have the two necessary privkeys on one of the leaves. Also it uses a pubkey hash.
    {
        "desc": f"tr({TPUBS[0]}/*,{{and_v(v:pk({TPRVS[0]}/*),pk({TPUBS[1]})),and_v(v:pkh({TPRVS[1]}/*),pk({TPRVS[2]}))}})",
        "sequence": None,
        "locktime": None,
        "sigs_count": 3,
        "stack_size": 5,
    },
    # A key immediately or one of two keys after a timelock. If both paths are available it'll use the
    # non-timelocked path because it's a smaller witness.
    {
        "desc": f"tr({TPUBS[0]}/*,{{pk({TPRVS[0]}/*),and_v(v:older(42),multi_a(1,{TPRVS[1]},{TPRVS[2]}))}})",
        "sequence": 42,
        "locktime": None,
        "sigs_count": 3,
        "stack_size": 3,
    },
    # A key immediately or one of two keys after a timelock. If the "primary" key isn't available though it'll
    # use the timelocked path. Same remark for multi_a.
    {
        "desc": f"tr({TPUBS[0]}/*,{{pk({TPUBS[1]}/*),and_v(v:older(42),multi_a(1,{TPRVS[0]},{TPRVS[1]}))}})",
        "sequence": 42,
        "locktime": None,
        "sigs_count": 2,
        "stack_size": 4,
    },
    # Liquid-like federated pegin with emergency recovery privkeys, but in a Taproot.
    {
        "desc": f"tr({TPUBS[1]}/*,{{and_b(pk({TPUBS[2]}/*),a:and_b(pk({TPUBS[3]}),a:and_b(pk({TPUBS[4]}),a:and_b(pk({TPUBS[5]}),s:pk({PUBKEYS[0]}))))),and_v(v:thresh(2,pkh({TPRVS[0]}),a:pkh({TPRVS[1]}),a:pkh({TPUBS[6]})),older(42))}})",
        "sequence": 42,
        "locktime": None,
        "sigs_count": 2,
        "stack_size": 8,
    },
]


class WalletMiniscriptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def watchonly_test(self, desc):
        self.log.info(f"Importing descriptor '{desc}'")
        desc = descsum_create(f"{desc}")
        assert self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": desc,
                    "active": True,
                    "range": 2,
                    "next_index": 0,
                    "timestamp": "now",
                }
            ]
        )[0]["success"]

        self.log.info("Testing we derive new addresses for it")
        assert_equal(
            self.ms_wo_wallet.getnewaddress(),
            self.funder.deriveaddresses(desc, 0)[0],
        )
        assert_equal(
            self.ms_wo_wallet.getnewaddress(),
            self.funder.deriveaddresses(desc, 1)[1],
        )

        self.log.info("Testing we detect funds sent to one of them")
        addr = self.ms_wo_wallet.getnewaddress()
        txid = self.funder.sendtoaddress(addr, 0.01)
        self.wait_until(
            lambda: len(self.ms_wo_wallet.listunspent(minconf=0, addresses=[addr])) == 1
        )
        utxo = self.ms_wo_wallet.listunspent(minconf=0, addresses=[addr])[0]
        assert utxo["txid"] == txid and utxo["solvable"]

    def signing_test(
        self, desc, sequence, locktime, sigs_count, stack_size, sha256_preimages
    ):
        self.log.info(f"Importing private Miniscript descriptor '{desc}'")
        desc = descsum_create(desc)
        res = self.ms_sig_wallet.importdescriptors(
            [
                {
                    "desc": desc,
                    "active": True,
                    "range": 0,
                    "next_index": 0,
                    "timestamp": "now",
                }
            ]
        )
        assert res[0]["success"], res

        self.log.info("Generating an address for it and testing it detects funds")
        addr = self.ms_sig_wallet.getnewaddress()
        txid = self.funder.sendtoaddress(addr, 0.01)
        self.wait_until(lambda: txid in self.funder.getrawmempool())
        self.funder.generatetoaddress(1, self.funder.getnewaddress())
        utxo = self.ms_sig_wallet.listunspent(addresses=[addr])[0]
        assert txid == utxo["txid"] and utxo["solvable"]

        self.log.info("Creating a transaction spending these funds")
        dest_addr = self.funder.getnewaddress()
        seq = sequence if sequence is not None else 0xFFFFFFFF - 2
        lt = locktime if locktime is not None else 0
        psbt = self.ms_sig_wallet.createpsbt(
            [
                {
                    "txid": txid,
                    "vout": utxo["vout"],
                    "sequence": seq,
                }
            ],
            [{dest_addr: 0.009}],
            lt,
        )

        self.log.info("Signing it and checking the satisfaction.")
        if sha256_preimages is not None:
            psbt = PSBT.from_base64(psbt)
            for (h, preimage) in sha256_preimages.items():
                k = PSBT_IN_SHA256.to_bytes(1, "big") + bytes.fromhex(h)
                psbt.i[0].map[k] = bytes.fromhex(preimage)
            psbt = psbt.to_base64()
        res = self.ms_sig_wallet.walletprocesspsbt(psbt=psbt, finalize=False)
        psbtin = self.nodes[0].decodepsbt(res["psbt"])["inputs"][0]
        assert len(psbtin["taproot_script_path_sigs"]) == sigs_count
        res = self.ms_sig_wallet.finalizepsbt(res["psbt"])
        assert res["complete"] == (stack_size is not None)

        if stack_size is not None:
            txin = self.nodes[0].decoderawtransaction(res["hex"])["vin"][0]
            assert len(txin["txinwitness"]) == stack_size, txin["txinwitness"]
            self.log.info("Broadcasting the transaction.")
            # If necessary, satisfy a relative timelock
            if sequence is not None:
                self.funder.generatetoaddress(sequence, self.funder.getnewaddress())
            # If necessary, satisfy an absolute timelock
            height = self.funder.getblockcount()
            if locktime is not None and height < locktime:
                self.funder.generatetoaddress(
                    locktime - height, self.funder.getnewaddress()
                )
            self.ms_sig_wallet.sendrawtransaction(res["hex"])

    def run_test(self):
        self.log.info("Making a descriptor wallet")
        self.funder = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.nodes[0].createwallet(
            wallet_name="ms_wo", disable_private_keys=True
        )
        self.ms_wo_wallet = self.nodes[0].get_wallet_rpc("ms_wo")
        self.nodes[0].createwallet(wallet_name="ms_sig")
        self.ms_sig_wallet = self.nodes[0].get_wallet_rpc("ms_sig")

        # Sanity check we wouldn't let an insane Miniscript descriptor in
        res = self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": descsum_create(
                        f"tr({PUBKEYS[0]},and_b(ripemd160(1fd9b55a054a2b3f658d97e6b84cf3ee00be429a),a:1))"
                    ),
                    "active": False,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert not res["success"]
        assert "is not sane: witnesses without signature exist" in res["error"]["message"]

        # Sanity check we wouldn't let an unspendable Miniscript descriptor in
        res = self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": descsum_create(f"tr({PUBKEYS[0]},0)"),
                    "active": False,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert not res["success"] and "is not satisfiable" in res["error"]["message"]

        # Native wallets track Miniscript through Taproot script paths.
        for desc in DESCS:
            self.watchonly_test(desc)

        # Test signing Taproot Miniscript policies.
        for desc in DESCS_PRIV:
            self.signing_test(
                desc["desc"],
                desc["sequence"],
                desc["locktime"],
                desc["sigs_count"],
                desc["stack_size"],
                desc.get("sha256_preimages"),
            )

        # Test we can sign for a max-size TapMiniscript. Recompute the maximum accepted size
        # for a TapMiniscript (see cpp file for details). Then pad a simple pubkey check up
        # to the maximum size. Make sure we can import and spend this script.
        leeway_weight = (4 + 4 + 1 + 36 + 4 + 1 + 1 + 8 + 1 + 1 + 33) * 4 + 2
        max_tapmini_size = 400_000 - 3 - (1 + 65) * 1_000 - 3 - (33 + 32 * 128) - leeway_weight - 5
        padding = max_tapmini_size - 33 - 1
        ms = f"pk({TPRVS[0]}/*)"
        ms = "n" * padding + ":" + ms
        desc = f"tr({PUBKEYS[0]},{ms})"
        self.signing_test(desc, None, None, 1, 3, None)
        # This was really the maximum size, one more byte and we can't import it.
        ms = "n" + ms
        desc = f"tr({PUBKEYS[0]},{ms})"
        res = self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": descsum_create(desc),
                    "active": False,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert not res["success"]


if __name__ == "__main__":
    WalletMiniscriptTest(__file__).main()
