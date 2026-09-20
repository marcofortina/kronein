# RandomX proof of work

Kronein uses the upstream RandomX **v2.0.1** algorithm as its proof-of-work
function. The vendored upstream revision and the local build-only patch are
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
