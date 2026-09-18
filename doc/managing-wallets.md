# Managing the Wallet

## 1. Backing Up and Restoring The Wallet

### 1.1 Creating the Wallet

The node has no default wallet. Wallets are SQLite descriptor wallets and can
be created with the `createwallet` RPC or with the `Create wallet` GUI menu
item.

In the GUI, the `Create a new wallet` button is displayed on the main screen when there is no wallet loaded. Alternatively, there is the option `File` ->`Create wallet`.

The following command, for example, creates a descriptor wallet. More information about this command may be found by running `kronein-cli help createwallet`.

```
$ kronein-cli createwallet "wallet-01"
```

`kronein rpc` can also be substituted for `kronein-cli`.

By default, wallets are created in the `wallets` folder of the data directory, which varies by operating system, as shown below. The user can change the default by using the `-datadir` or `-walletdir` initialization parameters.

| Operating System | Default wallet directory                                    |
| -----------------|:------------------------------------------------------------|
| Linux            | `/home/<user>/.kronein/wallets`                             |
| Windows          | `C:\Users\<user>\AppData\Local\Kronein\wallets`             |
| macOS            | `/Users/<user>/Library/Application Support/Kronein/wallets` |

### 1.2 Encrypting the Wallet

The `wallet.dat` file is not encrypted by default and is, therefore, vulnerable if an attacker gains access to the device where the wallet or the backups are stored.

Wallet encryption may prevent unauthorized access. However, this significantly increases the risk of losing coins due to forgotten passphrases. There is no way to recover a passphrase. This tradeoff should be well thought out by the user.

Wallet encryption may also not protect against more sophisticated attacks. An attacker can, for example, obtain the password by installing a keylogger on the user's machine.

After encrypting the wallet or changing the passphrase, a new backup needs to be created immediately. The reason is that the keypool is flushed and a new HD seed is generated after encryption. Any bitcoins received by the new seed cannot be recovered from the previous backups.

The wallet's private key may be encrypted with the following command:

```
$ kronein-cli -rpcwallet="wallet-01" encryptwallet "passphrase"
```

Once encrypted, the passphrase can be changed with the `walletpassphrasechange` command.

```
$ kronein-cli -rpcwallet="wallet-01" walletpassphrasechange "oldpassphrase" "newpassphrase"
```

The argument passed to `-rpcwallet` is the name of the wallet to be encrypted.

Only the wallet's private key is encrypted. All other wallet information, such as transactions, is still visible.

The wallet's private key can also be encrypted in the `createwallet` command via the `passphrase` argument:

```
$ kronein-cli -named createwallet wallet_name="wallet-01" passphrase="passphrase"
```

Note that if the passphrase is lost, all the coins in the wallet will also be lost forever.

### 1.3 Unlocking the Wallet

If the wallet is encrypted and the user tries any operation related to private keys, such as sending bitcoins, an error message will be displayed.

```
$ kronein-cli -rpcwallet="wallet-01" sendtoaddress "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkgkkf5" 0.01
error code: -13
error message:
Error: Please enter the wallet passphrase with walletpassphrase first.
```

To unlock the wallet and allow it to run these operations, the `walletpassphrase` RPC is required.

This command takes the passphrase and an argument called `timeout`, which specifies the time in seconds that the wallet decryption key is stored in memory. After this period expires, the user needs to execute this RPC again.

```
$ kronein-cli -rpcwallet="wallet-01" walletpassphrase "passphrase" 120
```

In the GUI, there is no specific menu item to unlock the wallet. When the user sends bitcoins, the passphrase will be prompted automatically.

### 1.4 Backing Up the Wallet

To backup the wallet, the `backupwallet` RPC or the `Backup Wallet` GUI menu item must be used to ensure the file is in a safe state when the copy is made.

In the RPC, the destination parameter must include the name of the file. Otherwise, the command will return an error message like "Error: Wallet backup failed!".

```
$ kronein-cli -rpcwallet="wallet-01" backupwallet /home/node01/Backups/backup-01.dat
```

In the GUI, the wallet is selected in the `Wallet` drop-down list in the upper right corner. If this list is not present, the wallet can be loaded in `File` ->`Open Wallet` if necessary. Then, the backup can be done in `File` -> `Backup Wallet…`.

This backup file can be stored on one or multiple offline devices, which must be reliable enough to work in an emergency and be malware free. Backup files can be regularly tested to avoid problems in the future.

If the computer has malware, it can compromise the wallet when recovering the backup file. One way to minimize this is to not connect the backup to an online device.

If both the wallet and all backups are lost for any reason, the bitcoins related to this wallet will become permanently inaccessible.

### 1.5 Backup Frequency

Wallet keys use deterministic derivation, so one backup contains the material
needed to derive later addresses. Regular backups are still recommended to
preserve metadata such as labels, which cannot be recovered by rescanning the
blockchain.

### 1.6 Restoring the Wallet From a Backup

To restore a wallet, the `restorewallet` RPC or the `Restore Wallet` GUI menu item (`File` -> `Restore Wallet…`) must be used.

```
$ kronein-cli restorewallet "restored-wallet" /home/node01/Backups/backup-01.dat
```

After that, `getwalletinfo` can be used to check if the wallet has been fully restored.

```
$ kronein-cli -rpcwallet="restored-wallet" getwalletinfo
```

The restored wallet can also be loaded in the GUI via `File` ->`Open wallet`.

## Wallet Passphrase

Understanding wallet security is crucial for safely storing your KNE. A key aspect is the wallet passphrase, used for encryption. Let's explore its nuances, role, encryption process, and limitations.

- **Not the Seed:**
The wallet passphrase and the seed are two separate components in wallet security. The seed, or HD seed, functions as a master key for deriving private and public keys in a hierarchical deterministic (HD) wallet. In contrast, the passphrase serves as an additional layer of security specifically designed to secure the private keys within the wallet. The passphrase serves as a safeguard, demanding an additional layer of authentication to access funds in the wallet.

- **Protection Against Unauthorized Access:**
The passphrase serves as a protective measure, securing your funds in situations where an unauthorized user gains access to your unlocked computer or device while your wallet application is active. Without the passphrase, they would be unable to access your wallet's funds or execute transactions. However, it's essential to be aware that someone with access can potentially compromise the security of your passphrase by installing a keylogger.

- **Doesn't Encrypt Metadata or Public Keys:**
It's important to note that the passphrase primarily secures the private keys and access to funds within the wallet. It does not encrypt metadata associated with transactions or public keys. Information about your transaction history and the public keys involved may still be visible.

- **Risk of Fund Loss if Forgotten or Lost:**
If the wallet passphrase is too complex and is subsequently forgotten or lost, there is a risk of losing access to the funds permanently. A forgotten passphrase will result in the inability to unlock the wallet and access the funds.
