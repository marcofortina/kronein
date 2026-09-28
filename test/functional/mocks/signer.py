#!/usr/bin/env python3
# Copyright (c) 2018-present The Bitcoin Core developers
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import argparse
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from test_framework.descriptors import descsum_create


def signer_identity():
    identity_path = os.path.join(os.getcwd(), "mock_signer_identity")
    if os.path.isfile(identity_path):
        with open(identity_path, "r") as f:
            return json.load(f)
    return {"fingerprint": "00000001"}

def perform_pre_checks():
    mock_result_path = os.path.join(os.getcwd(), "mock_result")
    if os.path.isfile(mock_result_path):
        with open(mock_result_path, "r") as f:
            mock_result = f.read()
        if mock_result[0]:
            sys.stdout.write(mock_result[2:])
            sys.exit(int(mock_result[0]))

def enumerate(args):
    sys.stdout.write(json.dumps([{"fingerprint": signer_identity()["fingerprint"], "type": "trezor", "model": "trezor_t"}]))

def getdescriptors(args):
    if args.chain_id is not None:
        with open(os.path.join(os.getcwd(), "mock_child_descriptors"), "r") as f:
            child = json.load(f)
        if args.chain_id != child["chain_id"]:
            return sys.stdout.write(json.dumps({"error": "Unexpected child chain id"}))
        if args.account_path != child["account_path"]:
            return sys.stdout.write(json.dumps({"error": "Unexpected child account path"}))
        return sys.stdout.write(json.dumps({
            "receive": child["receive"],
            "internal": child["internal"],
        }))

    identity = signer_identity()
    if "receive" in identity and "internal" in identity:
        return sys.stdout.write(json.dumps({
            "receive": identity["receive"],
            "internal": identity["internal"],
        }))

    xpub = "KrpubTX7E33B4R29pw93b5wkY3ue6kf3UmUFtTSTH9QpmmL7u5CUfq6gBBuxML4Eov9RNfbmZLFHSXrWCyApiZif8p1AiwyGxrXuBi6M3jbkjJdo"
    receive = "tr([00000001/86h/1h/" + args.account + "']" + xpub + "/0/*)"
    internal = "tr([00000001/86h/1h/" + args.account + "']" + xpub + "/1/*)"

    sys.stdout.write(json.dumps({
        "receive": [descsum_create(receive)],
        "internal": [descsum_create(internal)],
    }))


def displayaddress(args):
    if args.fingerprint != signer_identity()["fingerprint"]:
        return sys.stdout.write(json.dumps({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint}))

    expected_desc = {
        "tr([00000001/86h/1h/0h/0/0]c97dc3f4420402e01a113984311bf4a1b8de376cac0bdcfaf1b3ac81f13433c7)#puqqa90m": "rkne1phw4cgpt6cd30kz9k4wkpwm872cdvhss29jga2xpmftelhqll62ms3u0cc2",
    }
    if args.desc not in expected_desc:
        return sys.stdout.write(json.dumps({"error": "Unexpected descriptor", "desc": args.desc}))

    return sys.stdout.write(json.dumps({"address": expected_desc[args.desc]}))

def signtx(args):
    if args.fingerprint != signer_identity()["fingerprint"]:
        return sys.stdout.write(json.dumps({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint}))

    with open(os.path.join(os.getcwd(), "mock_psbt"), "r") as f:
        mock_psbt = f.read()

    if args.child_chain_id is not None:
        with open(os.path.join(os.getcwd(), "mock_child_signing_context"), "r") as f:
            expected = json.load(f)
        actual = {
            "chain_id": args.child_chain_id,
            "genesis_hash": args.child_genesis_hash,
            "template_id": args.child_template_id,
            "template_version": args.child_template_version,
        }
        if actual != expected:
            return sys.stdout.write(json.dumps({"error": "Unexpected child signing context"}))

    if args.fingerprint == signer_identity()["fingerprint"]:
        sys.stdout.write(json.dumps({
            "psbt": mock_psbt,
            "complete": True
        }))
    else:
        sys.stdout.write(json.dumps({"psbt": args.psbt}))

parser = argparse.ArgumentParser(prog='./signer.py', description='External signer mock')
parser.add_argument('--fingerprint')
parser.add_argument('--chain', default='main')
parser.add_argument('--stdin', action='store_true')
parser.add_argument('--child-chain-id')
parser.add_argument('--child-genesis-hash')
parser.add_argument('--child-template-id', type=int)
parser.add_argument('--child-template-version', type=int)

subparsers = parser.add_subparsers(description='Commands', dest='command')
subparsers.required = True

parser_enumerate = subparsers.add_parser('enumerate', help='list available signers')
parser_enumerate.set_defaults(func=enumerate)

parser_getdescriptors = subparsers.add_parser('getdescriptors')
parser_getdescriptors.set_defaults(func=getdescriptors)
parser_getdescriptors.add_argument('--account', metavar='account')
parser_getdescriptors.add_argument('--chain-id')
parser_getdescriptors.add_argument('--account-path')

parser_displayaddress = subparsers.add_parser('displayaddress', help='display address on signer')
parser_displayaddress.add_argument('--desc', metavar='desc')
parser_displayaddress.set_defaults(func=displayaddress)

parser_signtx = subparsers.add_parser('signtx')
parser_signtx.add_argument('psbt', metavar='psbt')

parser_signtx.set_defaults(func=signtx)

if not sys.stdin.isatty():
    buffer = sys.stdin.read()
    if buffer and buffer.rstrip() != "":
        sys.argv.extend(buffer.rstrip().split(" "))

args = parser.parse_args()

perform_pre_checks()

args.func(args)
