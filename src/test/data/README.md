Description
------------

This directory contains data-driven tests for various aspects of Kronein.

Premined common test chain
-------------------------

`regtest_chain100.json` is checked-in, static test data, not a CI cache. It contains
two deterministic sequences of 100 genuine, serialized regtest blocks: one with
the registry active from height 1 and one without registry commitments (used by
tests activating the registry at height 101). Both use the existing fixed coinbase
key, timestamps and mining recipe from `TestChain100Setup`.

Each `TestChain100Setup` loads fresh blocks into an independent chainstate through
normal block processing, including RandomX proof-of-work and transaction
validation. Only nonce searching during common setup is removed. No chainstate,
UTXO database or cached block-validation flags are shared. Further blocks and
mining tests continue to use real mining. The Python functional-test cache uses
a separate 199-block fixture documented in `test/functional/data/README.md`.

The JSON records its format version, network, genesis hash, RandomX seed, coinbase
script and expected tips. Incompatible metadata, unsupported registry activation
within the first 100 blocks, malformed data or consensus failures are errors;
there is no automatic fallback to mining.

To regenerate explicitly after an intentional change to these test parameters:

```sh
cmake --build build --target generate_chain100
build/bin/kronein-generate-chain100 > build/regtest_chain100.json
```

Review the generated file, replace `src/test/data/regtest_chain100.json` with it,
then rebuild and run `setup_common_tests` and the affected unit/Qt tests. The
generator mines using the existing fixture implementation, independently of the
old JSON. It is excluded from the default build and is never run automatically by
CI. Generate with a normal (non-fuzz) test build so the proofs are genuine RandomX
proofs. Consensus or snapshot expectations must not be changed merely to accept
a regenerated fixture.

License
--------

The data files in this directory are distributed under the MIT software
license, see the accompanying file COPYING or
https://www.opensource.org/licenses/mit-license.php.
