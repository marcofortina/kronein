# Native output descriptors

The node and wallet use output descriptors to describe scripts and the keys
needed to spend them. This chain only accepts native outputs, so a top-level
descriptor must produce one of the following:

- a Taproot output (`tr` or `rawtr`);
- a Taproot or pay-to-anchor address (`addr`);
- a raw Taproot, pay-to-anchor, or unspendable `OP_RETURN` script (`raw`).

P2PK, P2PKH, P2SH, witness-v0, and bare multisig are not part of the descriptor
grammar. Script expressions inside a Taproot script tree are Tapscript, not
alternative top-level output types.

## Examples

Key-path Taproot:

```
tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)
```

Taproot with two script paths:

```
tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),pk(e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)})
```

Two-of-two Tapscript multisig:

```
tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,sortedmulti_a(2,2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc))
```

Ranged key-path descriptor with receiving and change branches:

```
tr([d34db33f/86h/0h/0h]xpub.../<0;1>/*)
```

MuSig2 key aggregation:

```
tr(musig(xpub1...,xpub2...)/0/*)
```

## Top-level expressions

- `tr(KEY)` creates a key-path P2TR output.
- `tr(KEY,TREE)` creates a P2TR output with optional Tapscript paths.
- `rawtr(KEY)` treats `KEY` as the final Taproot output key. Prefer `tr`
  unless the inability to prove the absence of hidden script paths is intended.
- `addr(ADDR)` expands a supported native address.
- `raw(HEX)` describes an exact native or unspendable script.

Descriptor checksums are optional for analysis RPCs and required by
`deriveaddresses` and `importdescriptors`.

## Tapscript trees

A `TREE` is either one script expression or two trees enclosed in braces:

```
{TREE,TREE}
```

Taproot leaves support `pk`, `pkh`, `multi_a`, `sortedmulti_a`, timelocks,
hashlocks, and the Tapscript Miniscript combinators. `multi_a` and
`sortedmulti_a` implement k-of-n policies using `OP_CHECKSIGADD`.

For the complete Miniscript expression grammar, see BIP 379. For Taproot
descriptors and Tapscript multisig, see BIP 386 and BIP 387.

## Keys and derivation

A `KEY` may be:

- an x-only or compressed hexadecimal public key;
- a WIF private key;
- a BIP32 extended public or private key followed by derivation steps;
- `musig(KEY,KEY,...)` inside `tr`, optionally followed by unhardened
  derivation steps.

Key origin information may prefix a key as `[FINGERPRINT/PATH]`. The
fingerprint is eight hexadecimal characters. Path elements may be unhardened
(`/0`) or hardened (`/0'` or `/0h`). Hardened derivation after an extended
public key requires the corresponding private key.

A final `/*` or `/*'` makes a descriptor ranged. One multipath element such as
`/<0;1>/*` may select parallel derivation branches. Wallets use the first
branch for receiving and the second for change.

## Basic multisig example

Each participant should provide a Taproot account xpub with complete origin
information. A watch-only coordinator can import a descriptor of this form:

```
tr(INTERNAL_KEY,sortedmulti_a(M,XPUB1/<0;1>/*,XPUB2/<0;1>/*,...,XPUBN/<0;1>/*))
```

All participants independently import the same descriptor and verify that it
derives the same receive and change addresses. A coordinator creates a PSBT,
each signer verifies and signs it, and the final signer or coordinator
finalizes and broadcasts it. The executable example is
[`wallet_multisig_descriptor_psbt.py`](/test/functional/wallet_multisig_descriptor_psbt.py).

A timelocked Taproot Miniscript example is available in
[`wallet_miniscript_decaying_multisig_descriptor_psbt.py`](/test/functional/wallet_miniscript_decaying_multisig_descriptor_psbt.py).

## Private descriptors

Private keys and xprvs can replace their public forms when hardened
derivation or signing is required. Treat private descriptors as wallet backup
material. `getdescriptorinfo` returns the canonical public descriptor and
reports whether private keys were present.

## Checksums

A descriptor may end in `#CHECKSUM`, where the checksum has eight
alphanumeric characters. RPC results include checksums. Use
`getdescriptorinfo` to canonicalize a descriptor and calculate its checksum.
