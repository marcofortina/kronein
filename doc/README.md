Kronein Core
=============

Setup
---------------------
Kronein Core is the reference client for the Kronein network. It downloads and,
by default, stores the complete history of Kronein transactions. Storage and
synchronization requirements will be documented once the production network
parameters are frozen.

Kronein Core is currently pre-release software and must be built from this
repository. Published releases will appear on the
[Kronein releases page](https://github.com/marcofortina/kronein/releases).

Running
---------------------
The following are some helpful notes on how to run Kronein Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/bitcoin-qt` (GUI) or
- `bin/bitcoind` (headless)
- `bin/bitcoin` (wrapper command)

The `bitcoin` command supports subcommands like `bitcoin gui`, `bitcoin node`, and `bitcoin rpc` exposing different functionality. Subcommands can be listed with `bitcoin help`.

### Windows

Unpack the files into a directory, and then run bitcoin-qt.exe.

### macOS

Drag Kronein Core to your applications folder, and then run Kronein Core.

### Need Help?

* Search the documentation in this repository.
* Report Kronein-specific problems in the
  [Kronein issue tracker](https://github.com/marcofortina/kronein/issues).
* Bitcoin documentation can provide background for inherited code, but its
  network parameters and user guidance must not be assumed to apply to Kronein.

Building
---------------------
The following are developer notes on how to build Kronein Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows-msvc.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)

Development
---------------------
The Kronein repository's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Process](release-process.md)
- Source documentation can be generated locally with the Doxygen build target.
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Resources
* Discuss project-specific development in Kronein GitHub issues and pull requests.
* Use Kronein Core development resources only for inherited upstream code and
  coordination of fixes that also affect Kronein Core.

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [bitcoin.conf Configuration File](bitcoin-conf.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/OpenRC/launchd)](init.md)
- [Managing Wallets](managing-wallets.md)
- [Multisig Tutorial](multisig-tutorial.md)
- [Offline Signing Tutorial](offline-signing-tutorial.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [PSBT support](psbt.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
