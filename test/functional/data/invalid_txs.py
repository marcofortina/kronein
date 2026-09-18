#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Templates for constructing various sorts of invalid transactions.

These templates (or an iterator over all of them) can be reused in different
contexts to test using a number of invalid transaction types.

Hopefully this makes it easier to get coverage of a full variety of tx
validation checks through different interfaces (AcceptBlock, AcceptToMemPool,
etc.) without repeating ourselves.

Invalid tx cases not covered here can be found by running:

    $ diff \
      <(grep -IREho "bad-txns[a-zA-Z-]+" src | sort -u) \
      <(grep -IEho "bad-txns[a-zA-Z-]+" test/functional/data/invalid_txs.py | sort -u)

"""
import abc

from typing import Optional
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    MAX_MONEY,
    SEQUENCE_FINAL,
)
from test_framework.blocktools import create_tx_with_script
from test_framework.script import CScript, OP_0, OP_RETURN
from test_framework.script_util import (
    MIN_PADDING,
    MIN_STANDARD_TX_NONWITNESS_SIZE,
    output_key_to_p2tr_script,
)
basic_output = output_key_to_p2tr_script(bytes.fromhex("11" * 32))

class BadTxTemplate:
    """Allows simple construction of a certain kind of invalid tx. Base class to be subclassed."""
    __metaclass__ = abc.ABCMeta

    # The expected error code given by kroneind upon submission of the tx.
    reject_reason: Optional[str] = ""

    def __init__(self, *, spend_tx=None, spend_block=None):
        self.spend_tx = spend_block.vtx[0] if spend_block else spend_tx
        self.spend_avail = sum(o.nValue for o in self.spend_tx.vout)
        self.valid_txin = CTxIn(COutPoint(self.spend_tx.txid_int, 0), b"", SEQUENCE_FINAL)

    @abc.abstractmethod
    def get_tx(self, *args, **kwargs):
        """Return a CTransaction that is invalid per the subclass."""
        pass


class OutputMissing(BadTxTemplate):
    reject_reason = "bad-txns-vout-empty"

    def get_tx(self):
        tx = CTransaction()
        tx.vin.append(self.valid_txin)
        return tx


class InputMissing(BadTxTemplate):
    reject_reason = "bad-txns-vin-empty"

    def get_tx(self):
        tx = CTransaction()
        return tx


# The following check prevents exploit of lack of merkle
# tree depth commitment (CVE-2017-12842)
class SizeTooSmall(BadTxTemplate):
    reject_reason = "tx-size-small"

    def get_tx(self):
        tx = CTransaction()
        tx.vin.append(self.valid_txin)
        tx.vout.append(CTxOut(0, CScript([OP_RETURN] + ([OP_0] * (MIN_PADDING - 2)))))
        assert len(tx.serialize_without_witness()) == 64
        assert MIN_STANDARD_TX_NONWITNESS_SIZE - 1 == 64
        return tx

class BadInputOutpointIndex(BadTxTemplate):
    # Won't be rejected - nonexistent outpoint index is treated as an orphan since the coins
    # database can't distinguish between spent outpoints and outpoints which never existed.
    reject_reason = None
    def get_tx(self):
        num_indices = len(self.spend_tx.vin)
        bad_idx = num_indices + 100

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.spend_tx.txid_int, bad_idx), b"", SEQUENCE_FINAL))
        tx.vout.append(CTxOut(0, basic_output))
        return tx


class DuplicateInput(BadTxTemplate):
    reject_reason = 'bad-txns-inputs-duplicate'

    def get_tx(self):
        tx = CTransaction()
        tx.vin.append(self.valid_txin)
        tx.vin.append(self.valid_txin)
        tx.vout.append(CTxOut(1, basic_output))
        return tx


class PrevoutNullInput(BadTxTemplate):
    reject_reason = 'bad-txns-prevout-null'

    def get_tx(self):
        tx = CTransaction()
        tx.vin.append(self.valid_txin)
        tx.vin.append(CTxIn(COutPoint(hash=0, n=0xffffffff)))
        tx.vout.append(CTxOut(1, basic_output))
        return tx


class NonexistentInput(BadTxTemplate):
    reject_reason = None  # Added as an orphan tx.

    def get_tx(self):
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.spend_tx.txid_int + 1, 0), b"", SEQUENCE_FINAL))
        tx.vin.append(self.valid_txin)
        tx.vout.append(CTxOut(1, basic_output))
        return tx


class SpendTooMuch(BadTxTemplate):
    reject_reason = 'bad-txns-in-belowout'

    def get_tx(self):
        return create_tx_with_script(
            self.spend_tx, 0, output_script=basic_output, amount=(self.spend_avail + 1))


class CreateNegative(BadTxTemplate):
    reject_reason = 'bad-txns-vout-negative'

    def get_tx(self):
        return create_tx_with_script(self.spend_tx, 0, output_script=basic_output, amount=-1)


class CreateTooLarge(BadTxTemplate):
    reject_reason = 'bad-txns-vout-toolarge'

    def get_tx(self):
        return create_tx_with_script(self.spend_tx, 0, output_script=basic_output, amount=MAX_MONEY + 1)


class CreateSumTooLarge(BadTxTemplate):
    reject_reason = 'bad-txns-txouttotal-toolarge'

    def get_tx(self):
        tx = create_tx_with_script(self.spend_tx, 0, output_script=basic_output, amount=MAX_MONEY)
        tx.vout = [tx.vout[0]] * 2
        return tx


class NonEmptyScriptSig(BadTxTemplate):
    reject_reason = "bad-txns-scriptsig-not-empty"

    def get_tx(self):
        return create_tx_with_script(
            self.spend_tx,
            0,
            script_sig=b'\x01',
            output_script=basic_output,
            amount=(self.spend_avail // 2),
        )


class NonNativeOutput(BadTxTemplate):
    reject_reason = "bad-txns-non-native-output"

    def get_tx(self):
        return create_tx_with_script(
            self.spend_tx,
            0,
            output_script=CScript([OP_0]),
            amount=(self.spend_avail // 2),
        )


def iter_all_templates():
    """Iterate through all bad transaction template types."""
    return BadTxTemplate.__subclasses__()
