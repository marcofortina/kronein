# Development release notes

This repository defines a new blockchain with no upgrade path from Bitcoin or
from earlier on-disk, wallet, transaction, block, address, or network formats.

The current development baseline uses:

- version 1 blocks and transactions with native witness serialization;
- SegWit, CSV, and Taproot consensus rules from block 1;
- BIP324 encrypted peer transport;
- descriptor wallets backed only by SQLite;
- Bech32m/Taproot wallet addresses;
- MuHash UTXO commitments.
- RandomX v2.0.1 proof of work over the unchanged 80-byte block header, with
  epoch-derived cache keys documented in [randomx.md](randomx.md).

Before a production release, freeze and independently review the development
genesis blocks, proof-of-work and difficulty parameters, network magic values,
ports, seeds, checkpoints, and chain-work assumptions.
