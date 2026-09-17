# Taproot multisig tutorial

This chain supports multisig exclusively as a Taproot script path.

For an M-of-N wallet, every participant first creates a signer wallet and
shares the public Taproot account key, including its origin fingerprint and
derivation path. The shared watch-only wallet imports one multipath descriptor:

```
tr(INTERNAL_KEY,sortedmulti_a(M,XPUB1/<0;1>/*,XPUB2/<0;1>/*,...,XPUBN/<0;1>/*))
```

The `/0` branch derives receiving addresses and `/1` derives change. Every
participant should independently import the same descriptor and verify several
derived addresses before funds are sent.

To spend:

1. Create a PSBT from the shared watch-only wallet.
2. Have every signer inspect the inputs, outputs, amount, and fee.
3. Pass the PSBT through at least M signer wallets with `walletprocesspsbt`.
4. Finalize it with `finalizepsbt` and broadcast the resulting transaction.

The complete executable flow is in
[`wallet_multisig_descriptor_psbt.py`](/test/functional/wallet_multisig_descriptor_psbt.py).
For timelocked policies, see
[`wallet_miniscript_decaying_multisig_descriptor_psbt.py`](/test/functional/wallet_miniscript_decaying_multisig_descriptor_psbt.py).

See [Native output descriptors](descriptors.md) for key origins, ranged
descriptors, checksums, and Taproot script trees.
