# Kronein Core

https://github.com/marcofortina/kronein

Kronein Core is the reference node, wallet, and graphical application for the
Kronein (KNE) blockchain. It downloads and fully validates blocks and
transactions and participates in the Kronein peer-to-peer network.

Kronein is a new blockchain derived from Bitcoin Core source code. It has no
upgrade path from Bitcoin and is not intended to accept Bitcoin blocks,
transactions, wallets, or addresses. The inherited executable names remain in
place during the current development phase.

The network is under active development and is not ready for production use.
The genesis blocks, proof-of-work and monetary parameters, network identifiers,
ports, seeds, and address prefixes will be replaced before launch. See the
[development release notes](doc/release-notes.md) for the current baseline.

## Documentation

Build and developer documentation is available in the [doc folder](doc/). The
main platform-specific build guides are linked from [doc/README.md](doc/README.md).

## License

Kronein Core is released under the terms of the MIT license. See
[COPYING](COPYING) for details. The project retains the copyright notices and
attributions of the Bitcoin Core code from which it is derived.

## Development process

The `working` branch is the active integration branch during initial chain
development. Changes must be kept focused, reviewable, and covered by tests
appropriate to their consensus, wallet, networking, or user-interface impact.

The contribution workflow is described in
[CONTRIBUTING.md](CONTRIBUTING.md), with additional engineering guidance in
[doc/developer-notes.md](doc/developer-notes.md).

## Testing

Unit tests can be built and run with:

```sh
cmake --build build -j8
ctest --test-dir build -j8
```

Functional and integration tests are written in Python and can be run with:

```sh
build/test/functional/test_runner.py -j8
```

See [src/test/README.md](src/test/README.md) and
[test/README.md](test/README.md) for more information.

## Translations

Qt translation catalogs are stored in [src/qt/locale](src/qt/locale). Until a
dedicated Kronein translation service is established, translation changes are
reviewed in this repository together with the source strings they update.

## Upstream

Kronein Core is based on Bitcoin Core. Upstream source history, security fixes,
and technical references remain available at
[bitcoin/bitcoin](https://github.com/bitcoin/bitcoin). Upstream references are
retained where they provide attribution or document inherited behavior.
