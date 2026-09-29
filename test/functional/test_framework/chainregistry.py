#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Helpers for regtest child-chain dealer authorization."""

from decimal import Decimal

from test_framework.key import sign_schnorr


DEALER_AUTHORITY_SECRET = (1).to_bytes(32, "big")
DEALER_AUTHORITY_KEY = (
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)


def submit_dealer_admin_operation(node, funding_wallet, operation, parameters,
                                  outputs=()):
    """Sign, fund, and broadcast one sequenced dealer-authority operation."""
    parameters = dict(parameters)
    parameters["authority_sequence"] = (
        node.listchaindealers()["authority_sequence"] + 1
    )
    draft = node.createchainregistryoperation(operation, parameters)
    parameters["authority_signature"] = sign_schnorr(
        DEALER_AUTHORITY_SECRET,
        bytes.fromhex(draft["authority_hash"]),
    ).hex()
    signed_operation = node.createchainregistryoperation(operation, parameters)
    assert signed_operation["authority_signature_present"]

    raw_outputs = [{"data": signed_operation["data"]}, *outputs]
    raw = node.createrawtransaction([], raw_outputs)
    funded = funding_wallet.fundrawtransaction(
        raw,
        change_position=len(raw_outputs),
        fee_rate=1,
    )
    signed = funding_wallet.signrawtransactionwithwallet(funded["hex"])
    assert signed["complete"]
    signed_operation["txid"] = node.sendrawtransaction(signed["hex"])
    return signed_operation


def authorize_dealer(node, funding_wallet, dealer_wallet, *, nonce, licenses,
                     control_amount=Decimal("0.00100000")):
    """Authorize ``dealer_wallet`` and broadcast the authority transaction.

    The caller mines the returned transaction. ``funding_wallet`` only pays
    its normal transaction outputs and fee; the resulting control and payout
    scripts belong exclusively to ``dealer_wallet``.
    """
    control_address = dealer_wallet.getnewaddress("dealer-control")
    payout_address = dealer_wallet.getnewaddress("dealer-payout")
    control_script = dealer_wallet.getaddressinfo(control_address)["scriptPubKey"]
    payout_script = dealer_wallet.getaddressinfo(payout_address)["scriptPubKey"]
    assert control_script.startswith("5120") and len(control_script) == 68
    assert payout_script.startswith("5120") and len(payout_script) == 68

    parameters = {
        "authorization_nonce": nonce,
        "dealer_control_key": control_script[4:],
        "control_output": 1,
        "payout_script": payout_script,
        "initial_licenses": licenses,
    }
    operation = submit_dealer_admin_operation(
        node,
        funding_wallet,
        "authorize_dealer",
        parameters,
        outputs=({control_address: control_amount},),
    )
    return {
        "dealer_id": operation["dealer_id"],
        "control_address": control_address,
        "payout_address": payout_address,
        "payout_script": payout_script,
        "txid": operation["txid"],
    }
