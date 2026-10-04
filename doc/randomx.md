# RandomX proof of work

Kronein uses the upstream RandomX **v2.0.1** algorithm as its proof-of-work
function. The vendored upstream revision and the local integration patches are
recorded in [`src/crypto/randomx/README.md`](../src/crypto/randomx/README.md).

## Header and identifiers

The serialized block header remains exactly 80 bytes:

| Field | Size |
| --- | ---: |
| version | 4 bytes |
| previous block identifier | 32 bytes |
| Merkle root | 32 bytes |
| timestamp | 4 bytes |
| compact target (`nBits`) | 4 bytes |
| nonce | 4 bytes |

No RandomX dataset, cache, program, scratchpad, or auxiliary solution is stored
in a block. A verifier reconstructs the RandomX state deterministically from
the epoch key and hashes the ordinary 80-byte header.

Kronein deliberately separates two hashes:

- the block identifier is the inherited double-SHA256 hash of the serialized
  header, so database keys, P2P inventory identifiers, Merkle-linked headers,
  and existing block-index code retain their fixed 32-byte identifiers;
- the proof-of-work hash is the 32-byte RandomX v2.0.1 output. Interpreted as
  the little-endian integer used by `uint256`, it must be no greater than the
  target encoded by `nBits`.

Changing either interpretation is a consensus change.

## Epoch keys

Mainnet, testnet4, and signet use 2,048-block epochs with a 64-block lag. For a
block at height `H`:

```text
H < 64:       SHA256("Kronein/RandomX/v2/<network>/bootstrap")
H >= 64:      block_id(floor((H - 64) / 2048) * 2048)
```

The lag guarantees that the seed block is already known before miners need to
construct the next dataset. Reorganizations derive the key from the candidate
chain's own ancestor, never from the currently active chain.

Regtest uses the fixed key
`SHA256("Kronein/RandomX/v2/regtest/fixed-seed")`. This avoids rebuilding a
multi-gigabyte dataset while tests create short private chains.

## Verification and mining modes

Consensus verification uses RandomX light mode. It needs the RandomX cache
(approximately 256 MiB), but not the full dataset. The process retains two
light contexts so an epoch transition or a shallow reorganization does not
immediately discard the previous key.

The built-in nonce grinder uses full mode on public networks and light mode on
regtest. Full mode builds the approximately 2 GiB RandomX dataset and is meant
for repeated mining hashes. Dataset construction cannot block the independent
light-verification cache. If full-mode allocation fails, the built-in miner
falls back to the slower but bit-identical light mode. Failure to allocate even
the light cache or VM is a local resource error and never makes an invalid
block valid.

The full dataset is 2,181,038,016 bytes, exceeding `PTRDIFF_MAX` on a 32-bit
host. The adapter rejects full mode before cache initialization on those hosts.
On 32-bit builds, the built-in mining RPCs (`generatetoaddress`,
`generatetodescriptor`, and `generateblock`) are available only on regtest.
Node and wallet operation, light-mode validation, `getblocktemplate`, and
`submitblock` remain available on every network. Regtest generation remains
enabled for wallet, network, and RPC tests; no consensus checks are skipped.
The lower-level nonce grinder also retains its light-mode fallback for tests
and tools. Validation and hashing produce identical consensus results.
Tests verify full-mode rejection and fallback on 32-bit builds, and retain
mandatory light/full hash equivalence on 64-bit builds.

MemorySanitizer builds use the portable interpreter instead of the JIT:
generated machine code cannot update the sanitizer's shadow memory. The
interpreter remains instrumented, uses the same RandomX v2 algorithm, and is
checked against the same reference vector and light/full equivalence tests.
Normal builds retain the optimized JIT where supported.

Functional tests hash through the persistent `kronein-randomx-test-bridge`
worker. It links the same native adapter and retains its cache across requests.
Keeping it in a separate process lets the sanitizer runtime initialize normally;
an instrumented C++ library cannot safely be loaded into an ordinary Python
interpreter. Worker errors and sanitizer diagnostics fail the test, and no
sanitizers are disabled. `KRONEIN_RANDOMX_HELPER` can override its executable path.

## Mining interface

`getblocktemplate` exposes the consensus inputs needed by an external miner:

- `powalgorithm`: `randomx-v2.0.1`;
- `randomx.version`: `2.0.1`;
- `randomx.seed`: the raw 32-byte epoch key in hexadecimal;
- `randomx.seedheight`: the key block height, or `-1` for the bootstrap key;
- `randomx.epochblocks` and `randomx.epochlag`.

The miner hashes the exact serialized header supplied by the template, updates
only its normal header fields, and submits an ordinary block. Nodes recompute
the epoch key, RandomX work hash, target, difficulty transition, timestamps,
and all other consensus rules independently.

## Difficulty and timestamp rules

Mainnet, testnet4, and signet adjust difficulty after every block with the
integer ASERTI3-2d algorithm. The fixed anchor is the genesis target and a
virtual parent timestamp one 600-second interval before genesis. Consequently,
an exactly on-schedule chain keeps the genesis target, while getting one
two-day half-life ahead of schedule doubles difficulty. ASERT is absolute and
memoryless: returning to the original height/time schedule restores the same
target without retaining accumulated rounding or adjustment state.

The implementation follows the published cubic fixed-point approximation and
its official test vectors. It uses an explicit 288-bit intermediate so it also
works safely with Kronein's wide signet target; floating-point arithmetic is
never used in consensus code.

Testnet4 retains the public-testnet rule that a block more than 1,200 seconds
after its parent may use the minimum difficulty. Regtest deliberately keeps a
fixed target. Public networks additionally require nondecreasing header
timestamps, on top of median-time-past and the two-hour future-time limit. This
removes backwards-timestamp sequences used by known time-warp strategies.

ASERT makes sustained rapid mining exponentially harder and reacts per block,
instead of waiting for a 2,016-block boundary. It cannot make a proof-of-work
chain immune to a majority attacker, compromised local clocks, or an
instantaneous hashrate change before any new block exposes that change. Those
are fundamental limits rather than properties RandomX or a DAA can eliminate.

References: [ASERT specification](https://spec.nexa.org/forks/2020-11-15-asert/)
and [DA-ASERT paper](https://toom.im/files/da-asert.pdf).

## Test coverage

The C++ tests include the upstream RandomX v2.0.1 reference vector, frozen
genesis proofs for every network, epoch-boundary key derivation, contextual
header validation, official ASERT vectors, spike/recovery difficulty cases,
and mining/verification round trips. The Python functional
framework calls the same vendored implementation through a test-only bridge;
it does not substitute another hash function or bypass proof of work.

As in upstream Bitcoin Core, the separate fuzz harness uses a cheap,
deterministic work predicate. Its miner and verifier use the same predicate;
the fixed genesis proofs are still checked with real RandomX through
`CheckProofOfWorkImpl`. This substitution is unavailable in production builds
and is not used by the functional tests. The height-200 regtest assumeutxo
fixture consequently has separately frozen block hashes for real and fuzz
mining, with the same transaction count and UTXO hash. The snapshot fuzz
targets check all of these values before replaying any inputs.

## Reproducible launch measurements

Build the existing benchmark target and run:

```sh
cmake --build build --target bench_bitcoin
build/bin/bench_kronein '-filter=RandomX(Full|Light)' -min-time=5000
build/bin/test_kronein --run_test=pow_tests/asert_launch_hashrate_scenarios --log_level=message
```

`RandomXFull` and `RandomXLight` hash changing 80-byte headers through the same
wrapper as mining and verification. Results are hashes per second for one VM;
parallel dataset construction is not parallel mining. Cache/dataset setup is
excluded. Record CPU, build mode, background load, power governor, and repeated
runs before using a measurement. Do not extrapolate a shared development
machine into a claimed network hashrate.

On 32-bit hosts only `RandomXLight` is registered: the full dataset exceeds
`PTRDIFF_MAX` and cannot be allocated. Full-mode allocation and hashing remain
mandatory checks on 64-bit hosts; the benchmark does not silently fall back.

The ASERT test uses the production integer difficulty calculation with a
hypothetical anchor 1024 times harder than powLimit. It measures deterministic
expected arrivals after 10x/100x increases and decreases, then a return to the
baseline rate. It is not a stochastic forecast, adversarial simulation, or a
promise of rapid recovery. At the two-day half-life, recovery can take days.
At powLimit no DAA can make a block easier: if the remaining hashrate is too
low, the target interval cannot be restored. Launch hashrate, powLimit, initial
target and half-life must therefore be evaluated together.
