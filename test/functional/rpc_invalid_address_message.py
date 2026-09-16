#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test native Bech32m address validation error messages."""

from test_framework.address import (
    ADDRESS_BCRT1_UNSPENDABLE,
    output_key_to_p2tr,
    p2a,
    program_to_witness,
)
from test_framework.test_framework import BitcoinTestFramework

from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

BECH32M_VALID_TAPROOT = ADDRESS_BCRT1_UNSPENDABLE
BECH32M_VALID_UNKNOWN_WITNESS = program_to_witness(2, bytes.fromhex("0123456789abcdef"))
BECH32M_VALID_CAPITALS = BECH32M_VALID_TAPROOT.upper()
BECH32M_VALID_ANCHOR = p2a()

BECH32_INVALID_BECH32 = 'bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqdmchcc'
BECH32_INVALID_BECH32M = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7k35mrzd'
BECH32_INVALID_VERSION = 'bcrt130xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqynjegk'
BECH32_INVALID_SIZE = 'bcrt1s0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav25430mtr'
BECH32_INVALID_V0_SIZE = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kqqq5k3my'
BECH32_INVALID_PREFIX = output_key_to_p2tr(bytes(32), main=True)
BECH32_TOO_LONG = 'bcrt1q049edschfnwystcqnsvyfpj23mpsg3jcedq9xv049edschfnwystcqnsvyfpj23mpsg3jcedq9xv049edschfnwystcqnsvyfpj23m'
BECH32_ONE_ERROR = 'bcrt1q049edschfnwystcqnsvyfpj23mpsg3jcedq9xv'
BECH32_ONE_ERROR_CAPITALS = 'BCRT1QPLMTZKC2XHARPPZDLNPAQL78RSHJ68U32RAH7R'
BECH32_TWO_ERRORS = 'bcrt1qax9suht3qv95sw33xavx8crpxduefdrsvgsklu' # should be bcrt1qax9suht3qv95sw33wavx8crpxduefdrsvgsklx
BECH32_NO_SEPARATOR = 'bcrtq049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv'
BECH32_INVALID_CHAR = 'bcrt1q04oldschfnwystcqnsvyfpj23mpsg3jcedq9xv'
BECH32_MULTISIG_TWO_ERRORS = 'bcrt1qdg3myrgvzw7ml8q0ejxhlkyxn7vl9r56yzkfgvzclrf4hkpx9yfqhpsuks'
BECH32_WRONG_VERSION = 'bcrt1ptmp74ayg7p24uslctssvjm06q5phz4yrxucgnv'

INVALID_ADDRESS = 'asfah14i8fajz0123f'
INVALID_ADDRESS_2 = '1q049ldschfnwystcqnsvyfpj23mpsg3jcedq9xv'

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
        self.check_invalid(BECH32_INVALID_SIZE, "Invalid Bech32m address program size (41 bytes)")
        self.check_invalid(BECH32_INVALID_PREFIX, 'Invalid prefix for Bech32m address (expected bcrt, got bc).')
        self.check_invalid(BECH32_INVALID_BECH32, 'Only native Bech32m addresses are supported')
        self.check_invalid(BECH32_INVALID_BECH32M, 'Invalid Bech32m address witness version')
        self.check_invalid(BECH32_INVALID_VERSION, 'Invalid Bech32m address witness version')
        self.check_invalid(BECH32_INVALID_V0_SIZE, 'Only native Bech32m addresses are supported')
        self.check_invalid(BECH32_TOO_LONG, 'Bech32 string too long', list(range(90, 108)))
        self.check_invalid(BECH32_ONE_ERROR, 'Invalid Bech32 checksum', [9])
        self.check_invalid(BECH32_TWO_ERRORS, 'Invalid Bech32 checksum', [22, 43])
        self.check_invalid(BECH32_ONE_ERROR_CAPITALS, 'Invalid Bech32 checksum', [38])
        self.check_invalid(BECH32_NO_SEPARATOR, 'Missing separator')
        self.check_invalid(BECH32_INVALID_CHAR, 'Invalid Base 32 character', [8])
        self.check_invalid(BECH32_MULTISIG_TWO_ERRORS, 'Invalid Bech32 checksum', [19, 30])
        self.check_invalid(BECH32_WRONG_VERSION, 'Invalid Bech32 checksum', [5])

        self.check_valid(BECH32M_VALID_TAPROOT)
        self.check_valid(BECH32M_VALID_UNKNOWN_WITNESS)
        self.check_valid(BECH32M_VALID_CAPITALS)
        self.check_valid(BECH32M_VALID_ANCHOR)

        # Invalid address format
        self.check_invalid(INVALID_ADDRESS, 'Invalid separator position', [14])
        self.check_invalid(INVALID_ADDRESS_2, 'Invalid separator position', [0])

        node = self.nodes[0]


        if not self.options.usecli:
            # Missing arg returns the help text
            assert_raises_rpc_error(-1, "Return information about the given bitcoin address.", node.validateaddress)
            # Explicit None is not allowed for required parameters
            assert_raises_rpc_error(-3, "JSON value of type null is not of expected type string", node.validateaddress, None)

    def test_getaddressinfo(self):
        node = self.nodes[0]

        assert_raises_rpc_error(-5, "Invalid Bech32m address program size (41 bytes)", node.getaddressinfo, BECH32_INVALID_SIZE)
        assert_raises_rpc_error(-5, "Invalid prefix for Bech32m address (expected bcrt, got bc).", node.getaddressinfo, BECH32_INVALID_PREFIX)
        assert_raises_rpc_error(-5, "Invalid separator position", node.getaddressinfo, INVALID_ADDRESS)
        assert "isscript" not in node.getaddressinfo(BECH32M_VALID_UNKNOWN_WITNESS)

    def run_test(self):
        self.test_validateaddress()

        if self.is_wallet_compiled():
            self.init_wallet(node=0)
            self.test_getaddressinfo()


if __name__ == '__main__':
    InvalidAddressErrorMessageTest(__file__).main()
