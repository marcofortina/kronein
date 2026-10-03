#!/usr/bin/env python3
# Copyright (c) 2026 The Kronein Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bound Tor control replies without requiring a real Tor process."""

import socket

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class TorControlTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        # Include complete and incomplete overlong lines, and a reply spread
        # across many lines that never supplies the final status line.
        cases = [
            (b"250-" + b"x" * 100001 + b"\r\n", "Tor control reply limits exceeded"),
            (b"250-" + b"x" * 100001, "MAX_LINE_LENGTH exceeded"),
            (b"250-x\r\n" * 1001, "Tor control reply limits exceeded"),
        ]
        for response, expected in cases:
            self.stop_node(0)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.bind(("127.0.0.1", 0))
                server.listen()
                server.settimeout(60 * self.options.timeout_factor)
                port = server.getsockname()[1]
                self.start_node(0, ["-listenonion=1", f"-torcontrol=127.0.0.1:{port}"])
                connection, _ = server.accept()
                with connection, connection.makefile("rb") as stream:
                    connection.settimeout(60 * self.options.timeout_factor)
                    assert_equal(stream.readline(), b"PROTOCOLINFO 1\r\n")
                    with node.assert_debug_log([expected]):
                        connection.sendall(response)
                        assert_equal(stream.read(1), b"")
                # The next connection must start with fresh reply state.
                connection, _ = server.accept()
                with connection, connection.makefile("rb") as stream:
                    connection.settimeout(60 * self.options.timeout_factor)
                    assert_equal(stream.readline(), b"PROTOCOLINFO 1\r\n")
                    connection.sendall(b'250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250 OK\r\n')
                    assert_equal(stream.readline(), b"AUTHENTICATE\r\n")
                self.stop_node(0)
                self.start_node(0)


if __name__ == "__main__":
    TorControlTest(__file__).main()
