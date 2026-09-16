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

Before a production release, replace the inherited development genesis blocks,
proof-of-work parameters, network magic values, ports, seeds, checkpoints, and
chain-work assumptions with values generated for the new chain.
