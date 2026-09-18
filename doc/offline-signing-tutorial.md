# Offline signing with native PSBTv2

This workflow keeps private keys on an offline host and uses an online,
watch-only wallet to select coins and broadcast transactions. The two wallets
share the same Taproot descriptors. Only the offline wallet can sign.

The interchange format is the chain's native PSBT version 2 format. Addresses
and change outputs are Taproot/Bech32m; there are no address-type choices in
the commands below.

The examples use Signet. Omit `-signet` when working on mainnet. Replace paths,
amounts, wallet names, and addresses as appropriate.

## Requirements

- Identical node software on both hosts.
- `jq` for extracting JSON fields in the shell examples.
- A one-way or carefully controlled method for transferring files between the
  online and offline hosts.

The offline host does not need blockchain data and must remain disconnected
from all networks.

## 1. Create the offline wallet

Create and encrypt a wallet on the offline host:

```sh
[offline]$ ./build/bin/kronein-cli -signet -named createwallet \
    wallet_name="offline_wallet" \
    passphrase="use-a-strong-passphrase"
```

Export its public descriptors. The default `listdescriptors` result does not
include private keys:

```sh
[offline]$ ./build/bin/kronein-cli -signet \
    -rpcwallet=offline_wallet listdescriptors \
    | jq '.descriptors' > descriptors.json
```

Verify that `descriptors.json` contains the active external and internal
`tr(...)` descriptors, then transfer it to the online host. Do not transfer an
export made with `listdescriptors true`; that form contains private keys.

## 2. Create the online watch-only wallet

Create a blank wallet with private keys disabled:

```sh
[online]$ ./build/bin/kronein-cli -signet -named createwallet \
    wallet_name="watch_only_wallet" \
    disable_private_keys=true \
    blank=true
```

Import the public descriptors:

```sh
[online]$ ./build/bin/kronein-cli -signet \
    -rpcwallet=watch_only_wallet importdescriptors \
    "$(cat descriptors.json)"
```

Every returned entry must report `"success": true`. Confirm that newly derived
addresses are native Bech32m addresses:

```sh
[online]$ ./build/bin/kronein-cli -signet \
    -rpcwallet=watch_only_wallet getnewaddress
```

Fund that address from a source on the same network and wait for the desired
number of confirmations. The online wallet can track the funds but cannot sign
for them.

## 3. Create a PSBTv2 online

Set the destination to a Taproot address and create a funded PSBT. The wallet
selects inputs and creates Taproot change automatically:

```sh
[online]$ DESTINATION='tb1p...'
[online]$ ./build/bin/kronein-cli -signet \
    -rpcwallet=watch_only_wallet \
    -named walletcreatefundedpsbt \
    outputs="[{\"$DESTINATION\":0.009}]" \
    | jq -r '.psbt' > unsigned.psbt
```

Inspect the transaction before moving it offline:

```sh
[online]$ ./build/bin/kronein-cli -signet decodepsbt \
    "$(cat unsigned.psbt)"
[online]$ ./build/bin/kronein-cli -signet analyzepsbt \
    "$(cat unsigned.psbt)"
```

Check every destination, amount, input, change output, and the resulting fee.
Transfer `unsigned.psbt` to the offline host.

## 4. Verify and sign offline

Decode the PSBT again on the offline host and compare it with the information
verified online:

```sh
[offline]$ ./build/bin/kronein-cli -signet decodepsbt \
    "$(cat unsigned.psbt)"
```

Unlock the wallet only for the time needed to sign:

```sh
[offline]$ ./build/bin/kronein-cli -signet \
    -rpcwallet=offline_wallet walletpassphrase \
    "use-a-strong-passphrase" 60
```

Update, sign, and finalize the PSBT:

```sh
[offline]$ ./build/bin/kronein-cli -signet \
    -rpcwallet=offline_wallet walletprocesspsbt \
    "$(cat unsigned.psbt)" > signed.json
```

For a single-signer wallet, `signed.json` should contain `"complete": true` and
a `hex` field. Multisig workflows pass the returned `psbt` through the other
signers and use `combinepsbt` or `finalizepsbt` when required.

Transfer `signed.json` to the online host. A finalized transaction contains no
private key material, but the file can reveal wallet metadata and should still
be handled carefully.

## 5. Broadcast online

Optionally inspect the finalized transaction:

```sh
[online]$ ./build/bin/kronein-cli -signet decoderawtransaction \
    "$(jq -r '.hex' signed.json)"
```

Broadcast it:

```sh
[online]$ ./build/bin/kronein-cli -signet sendrawtransaction \
    "$(jq -r '.hex' signed.json)"
```

Use `gettransaction`, `listtransactions`, or `getbalances` on the watch-only
wallet to follow confirmation. Keep an encrypted backup of the offline SQLite
wallet and test its restoration before relying on it.
