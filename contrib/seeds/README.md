# Seeds

Utilities to generate the fixed-seed list compiled into the client.

Kronein does not currently ship DNS seeds or fixed seeds. The inherited Bitcoin
seed lists were removed to prevent accidental cross-network discovery. Populate
the input files only with verified Kronein nodes after the public networks and
their ports have been finalized.

Be sure to update `PATTERN_AGENT` in `makeseeds.py` to include the current version,
and remove old versions as necessary (at a minimum when SeedsServiceFlags()
changes its default return value, as those are the services which seeds are added
to addrman with).

Update `MIN_BLOCKS` in  `makeseeds.py` and the `-m`/`--minblocks` arguments below, as needed.

When Kronein seed crawlers are available, collect their output and run the
following commands from the `/contrib/seeds` directory:

```
python3 makeseeds.py -a asmap-filled.dat -s seeds_main.txt > nodes_main.txt
python3 makeseeds.py -a asmap-filled.dat -s seeds_testnet4.txt -m 100000 > nodes_testnet4.txt
python3 generate-seeds.py . > ../../src/chainparamsseeds.h
```
