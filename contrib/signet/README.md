Contents
========
This directory contains tools related to Signet, both for running a Signet yourself and for using one.

getcoins.py
===========

A script to call a faucet to get Signet coins.

Syntax: `getcoins.py [-h|--help] [-c|--cmd=<kronein-cli path>] -f|--faucet=<faucet URL> [-a|--addr=<signet Bech32m address>] [-p|--password=<faucet password>] [--] [<kronein-cli args>]`

* `--cmd` lets you customize the kronein-cli path. By default it will look for it in the PATH
* `--faucet` specifies the project Signet faucet to use; the faucet is assumed to be compatible with https://github.com/kallewoof/bitcoin-faucet
* `--addr` lets you specify a Signet Taproot address. This and `--cmd` above complement each other (i.e. you do not need `kronein-cli` if you use `--addr`)
* `--password` lets you specify a faucet password; this is handy if you are in a classroom and set up your own faucet for your students; (above faucet does not limit by IP when password is enabled)

The faucet URL is intentionally explicit because this project Signet is independent from Bitcoin's
public Signet.

miner
=====

Development challenge and cooperative signing
--------------------------------------------

The default development Signet uses a Taproot **2-of-3 script-path** challenge.
Its NUMS internal key has no known private key; none of the three custodians
has a single-key spending bypass. The reproducible descriptor (add its checksum
with `getdescriptorinfo`) is:

```text
tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,multi_a(2,5d045857332d5b9e541514731622af8d60c180165d971a61e06b70a9b3834765,d528ecd9b696b54c907a9ed045447a79bb408ec39b68df504bb51f459bc3ffc9,fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af))
```

The challenge is `512043ff4e5478ee4c2664707b4d80358225b1205a391afcddf789a8ade04c3a5bfe`
and its derived message magic is `b409be08`. These keys are public fixtures
(private scalars 42, 43 and 44, sorted by public key). **Do not use them for a
public or valuable network.** This is a custody simulation, not three
independent real custodians. Replacing the old development challenge changes
the network magic and requires a fresh Signet data directory, not migration of
old blocks under the new challenge.

Each custodian imports the same descriptor, replacing only their own public
key with its WIF; the other two remain public. The coordinator only needs a
reward wallet and access to the signing services. Configure separate signer
CLI commands, using protected configuration files instead of passwords on the
command line:

```sh
contrib/signet/miner --cli="kronein-cli -conf=coordinator.conf" generate \
  --address="$REWARD_ADDRESS" --nbits=207fffff \
  --grind-cmd="kronein-util -signet -randomxlight grind" \
  --signer-cli="kronein-cli -conf=custodian-a.conf -rpcwallet=signet-a" \
  --signer-cli="kronein-cli -conf=custodian-b.conf -rpcwallet=signet-b" \
  --signer-cli="kronein-cli -conf=custodian-c.conf -rpcwallet=signet-c"
```

The miner passes the partial PSBT between custodians, checks that the block,
seed and virtual transaction were not replaced, and has the local node verify
the final witness before doing proof of work. A missing custodian is skipped
after `--signer-timeout` seconds (default 30, range 1..300). Failure to reach
quorum exits unsuccessfully without submitting a block. `--ongoing` automates
subsequent blocks too. The services must apply their own signing policy;
automatic RPC access is not an offline custody solution. Dealer authority keys
must never be reused here. Without `--signer-cli`, the original single-wallet
workflow remains available for explicit custom challenges.

Calibration and pacing
----------------------

You will first need to pick a difficulty target. Since signet chains are primarily protected by a signature rather than proof of work, there is no need to spend as much energy as possible mining, however you may wish to choose to spend more time than the absolute minimum. The calibrate subcommand can be used to pick a target appropriate for your hardware, eg:

    MINER="./contrib/signet/miner"
    GRIND="./build/bin/kronein-util -signet -randomxlight grind"
    CALIBRATION=$($MINER calibrate --grind-cmd="$GRIND")
    echo "$CALIBRATION"
    NBITS=$(printf '%s\n' "$CALIBRATION" | sed -n 's/^nbits=\([0-9a-f]\{8\}\).*/\1/p')

It defaults to estimating an nbits value resulting in 25s average time to find a block, but the --seconds parameter can be used to pick a different target, or the --nbits parameter can be used to estimate how long it will take for a given difficulty.

Calibration sends `header [randomx-seed]` requests to `$GRIND -` over standard
input. The bundled utility keeps one RandomX cache or dataset alive for the
whole sample instead of rebuilding it for every trial. Custom grinders used
with `calibrate` must implement the same line-oriented interface.

To mine the first block in your custom chain, you can run:

    CLI="./build/bin/kronein-cli -conf=mysignet.conf"
    ADDR=$($CLI -signet getnewaddress)
    $MINER --cli="$CLI" generate --grind-cmd="$GRIND" --address="$ADDR" --nbits=$NBITS

This will mine a single block with a backdated timestamp designed to allow 100 blocks to be mined as quickly as possible, so that it is possible to do transactions.

Adding the --ongoing parameter will then cause the signet miner to create blocks indefinitely. It will pick the time between blocks so that difficulty is adjusted to match the provided --nbits value.

    $MINER --cli="$CLI" generate --grind-cmd="$GRIND" --address="$ADDR" --nbits=$NBITS --ongoing

Other options
-------------

The --debug and --quiet options are available to control how noisy the signet miner's output is. Note that the --debug, --quiet and --cli parameters must all appear before the subcommand (generate, calibrate, etc) if used.

Instead of specifying --ongoing, you can specify --max-blocks=N to mine N blocks and stop.

The --set-block-time option sets a single block's timestamp. Kronein also requires
it to be no earlier than the previous block, exceed median time past, and remain
within the future-time limit. It cannot be combined with multi-block generation. If no pacing nBits is
provided, the current chain target is used; the block itself always uses GBT's
consensus target.

Instead of using a single address, a ranged descriptor may be provided via the --descriptor parameter, with the reward for the block at height H being sent to the H'th address generated from the descriptor.

Instead of calculating a specific nbits value, --min-nbits can be specified instead,
in which case Kronein Signet's minimum difficulty (`--nbits=207fffff`) is targeted.

By default, the signet miner mines blocks at fixed intervals with minimal variation. If you want blocks to appear more randomly, as they do in mainnet, specify the --poisson option.

Using the --multiminer parameter allows mining to be distributed amongst multiple miners. For example, if you have 3 miners and want to share blocks between them, specify --multiminer=1/3 on one, --multiminer=2/3 on another, and --multiminer=3/3 on the last one. If you want one to do 10% of blocks and two others to do 45% each, --multiminer=1-10/100 on the first, and --multiminer=11-55 and --multiminer=56-100 on the others. Note that which miner mines which block is determined by the previous block hash, so occasional runs of one miner doing many blocks in a row is to be expected.

When --multiminer is used, if a miner is down and does not mine a block within five minutes of when it is due, the other miners will automatically act as redundant backups ensuring the chain does not halt. The --backup-delay parameter can be used to change how long a given miner waits, allowing one to be the primary backup (after five minutes) and another to be the secondary backup (after six minutes, eg).

The --standby-delay parameter can be used to make a backup miner that only mines if a block doesn't arrive on time. This can be combined with --multiminer if desired. Setting --standby-delay also prevents the first block from being mined immediately.

Advanced usage
--------------

The Signet challenge must be a P2TR scriptPubKey. The generate process gets a block template, converts
the virtual challenge spend into a PSBT, signs its Taproot input, moves the final witness into the block
template's coinbase, grinds proof of work, and submits the block.

These steps can instead be done explicitly:

    $CLI -signet getblocktemplate '{"rules": ["signet","segwit"]}' |
      $MINER --cli="$CLI" genpsbt --address="$ADDR" |
      $CLI -signet -stdin walletprocesspsbt |
      jq -r .psbt |
      $MINER --cli="$CLI" solvepsbt --grind-cmd="$GRIND" |
      $CLI -signet -stdin submitblock

This is intended to allow you to replace part of the pipeline for further experimentation (eg, to sign the block with a hardware wallet).
