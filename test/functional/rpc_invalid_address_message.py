#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test native Bech32m address validation error messages."""

from test_framework.address import (
    ADDRESS_BCRT1_UNSPENDABLE,
    output_key_to_p2tr,
    p2a,
)
from test_framework.segwit_addr import bech32_encode, convertbits
from test_framework.test_framework import BitcoinTestFramework

from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

BECH32M_VALID_TAPROOT = ADDRESS_BCRT1_UNSPENDABLE
BECH32M_VALID_CAPITALS = BECH32M_VALID_TAPROOT.upper()
BECH32M_VALID_ANCHOR = p2a()

BECH32M_INVALID_SIZE = bech32_encode("bcrt", [1] + convertbits(bytes(41), 8, 5))
BECH32M_INVALID_PREFIX = output_key_to_p2tr(bytes(32), main=True)
BECH32M_TOO_LONG = bech32_encode("bcrt", [1] + convertbits(bytes(50), 8, 5))
BECH32M_ONE_ERROR = BECH32M_VALID_TAPROOT[:9] + 'p' + BECH32M_VALID_TAPROOT[10:]
BECH32M_TWO_ERRORS = BECH32M_VALID_TAPROOT[:9] + 'p' + BECH32M_VALID_TAPROOT[10:20] + 'p' + BECH32M_VALID_TAPROOT[21:]
BECH32M_NO_SEPARATOR = BECH32M_VALID_TAPROOT.replace('1', 'q', 1)
BECH32M_INVALID_CHAR = BECH32M_VALID_TAPROOT[:8] + 'o' + BECH32M_VALID_TAPROOT[9:]

INVALID_ADDRESS = 'asfah14i8fajz0123f'
INVALID_ADDRESS_2 = '1q049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv'
UNSUPPORTED_P2PKH = 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn'
UNSUPPORTED_P2SH = '2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br'
UNSUPPORTED_P2WPKH = 'bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202'

class InvalidAddressErrorMessageTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.uses_wallet = None

    def check_valid(self, addr):
        info = self.nodes[0].validateaddress(addr)
        assert info['isvalid']
        assert 'error' not in info
        assert 'error_locations' not in info

    def check_invalid(self, addr, error_str, error_locations=None):
        res = self.nodes[0].validateaddress(addr)
        assert not res['isvalid']
        assert_equal(res['error'], error_str)
        if error_locations:
            assert_equal(res['error_locations'], error_locations)
        else:
            assert_equal(res['error_locations'], [])

    def test_validateaddress(self):
        self.check_invalid(BECH32M_INVALID_SIZE, "Only Taproot and pay-to-anchor Bech32m addresses are supported")
        self.check_invalid(BECH32M_INVALID_PREFIX, 'Invalid prefix for Bech32m address (expected bcrt, got bc).')
        self.check_invalid(BECH32M_TOO_LONG, 'Bech32 string too long', list(range(90, len(BECH32M_TOO_LONG))))
        self.check_invalid(BECH32M_ONE_ERROR, 'Invalid Bech32m checksum', [9])
        self.check_invalid(BECH32M_TWO_ERRORS, 'Invalid Bech32m checksum', [9, 20])
        self.check_invalid(BECH32M_NO_SEPARATOR, 'Missing separator')
        self.check_invalid(BECH32M_INVALID_CHAR, 'Invalid Base 32 character', [8])

        self.check_valid(BECH32M_VALID_TAPROOT)
        self.check_valid(BECH32M_VALID_CAPITALS)
        self.check_valid(BECH32M_VALID_ANCHOR)

        # Invalid address format
        self.check_invalid(INVALID_ADDRESS, 'Invalid separator position', [14])
        self.check_invalid(INVALID_ADDRESS_2, 'Invalid separator position', [0])
        for unsupported_address in [UNSUPPORTED_P2PKH, UNSUPPORTED_P2SH, UNSUPPORTED_P2WPKH]:
            result = self.nodes[0].validateaddress(unsupported_address)
            assert not result['isvalid']

        node = self.nodes[0]


        if not self.options.usecli:
            # Missing arg returns the help text
            assert_raises_rpc_error(-1, "Return information about the given bitcoin address.", node.validateaddress)
            # Explicit None is not allowed for required parameters
            assert_raises_rpc_error(-3, "JSON value of type null is not of expected type string", node.validateaddress, None)

    def test_getaddressinfo(self):
        node = self.nodes[0]

        assert_raises_rpc_error(-5, "Only Taproot and pay-to-anchor Bech32m addresses are supported", node.getaddressinfo, BECH32M_INVALID_SIZE)
        assert_raises_rpc_error(-5, "Invalid prefix for Bech32m address (expected bcrt, got bc).", node.getaddressinfo, BECH32M_INVALID_PREFIX)
        assert_raises_rpc_error(-5, "Invalid separator position", node.getaddressinfo, INVALID_ADDRESS)
        for unsupported_address in [UNSUPPORTED_P2PKH, UNSUPPORTED_P2SH, UNSUPPORTED_P2WPKH]:
            assert_raises_rpc_error(-5, "Invalid", node.getaddressinfo, unsupported_address)

    def run_test(self):
        self.test_validateaddress()

        if self.is_wallet_compiled():
            self.init_wallet(node=0)
            self.test_getaddressinfo()


if __name__ == '__main__':
    InvalidAddressErrorMessageTest(__file__).main()
