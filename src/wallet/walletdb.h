// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLETDB_H
#define BITCOIN_WALLET_WALLETDB_H

#include <key.h>
#include <primitives/transaction_identifier.h>
#include <script/sign.h>
#include <wallet/db.h>
#include <wallet/walletutil.h>

#include <cstdint>
#include <string>
#include <vector>

class CScript;
class uint160;
class uint256;
struct CBlockLocator;

namespace wallet {
class CMasterKey;
class CWallet;
class CWalletTx;
struct WalletContext;

// Logs information about the database, including available engines, features, and other capabilities
void LogDBInfo();

/**
 * Overview of wallet database classes:
 *
 * - WalletBatch is an abstract modifier object for the wallet database, and encapsulates a database
 *   batch update as well as methods to act on the database. It should be agnostic to the database implementation.
 */

/** Error statuses for the wallet database.
 * Values are in order of severity. When multiple errors occur, the most severe (highest value) will be returned.
 */
enum class DBErrors : int
{
    LOAD_OK = 0,
    NEED_RESCAN = 1,
    NEED_REWRITE = 2,
    EXTERNAL_SIGNER_SUPPORT_REQUIRED = 3,
    NONCRITICAL_ERROR = 4,
    TOO_NEW = 5,
    UNKNOWN_DESCRIPTOR = 6,
    LOAD_FAIL = 7,
    CORRUPT = 8,
};

namespace DBKeys {
extern const std::string ACENTRY;
extern const std::string ACTIVEEXTERNALSPK;
extern const std::string ACTIVEINTERNALSPK;
extern const std::string BESTBLOCK;
extern const std::string DESTDATA;
extern const std::string FLAGS;
extern const std::string LOCKED_UTXO;
extern const std::string MASTER_KEY;
extern const std::string NAME;
extern const std::string ORDERPOSNEXT;
extern const std::string PURPOSE;
extern const std::string SETTINGS;
extern const std::string TX;
extern const std::string VERSION;
extern const std::string WALLETDESCRIPTOR;
extern const std::string WALLETDESCRIPTORCKEY;
extern const std::string WALLETDESCRIPTORKEY;
} // namespace DBKeys

struct DbTxnListener
{
    std::function<void()> on_commit, on_abort;
};

/** Access to the wallet database.
 * Opens the database and provides read and write access to it. Each read and write is its own transaction.
 * Multiple operation transactions can be started using TxnBegin() and committed using TxnCommit()
 * Otherwise the transaction will be committed when the object goes out of scope.
 * Optionally (on by default) it will flush to disk on close.
 * Every 1000 writes will automatically trigger a flush to disk.
 */
class WalletBatch
{
private:
    template <typename K, typename T>
    bool WriteIC(const K& key, const T& value, bool fOverwrite = true)
    {
        if (!m_batch->Write(key, value, fOverwrite)) {
            return false;
        }
        return true;
    }

    template <typename K>
    bool EraseIC(const K& key)
    {
        if (!m_batch->Erase(key)) {
            return false;
        }
        return true;
    }

public:
    explicit WalletBatch(WalletDatabase &database) :
        m_batch(database.MakeBatch())
    {
    }
    WalletBatch(const WalletBatch&) = delete;
    WalletBatch& operator=(const WalletBatch&) = delete;

    bool WriteName(const std::string& strAddress, const std::string& strName);
    bool EraseName(const std::string& strAddress);

    bool WritePurpose(const std::string& strAddress, const std::string& purpose);
    bool ErasePurpose(const std::string& strAddress);

    bool WriteTx(const CWalletTx& wtx);
    bool EraseTx(Txid hash);

    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey);
    bool EraseMasterKey(unsigned int id);

    bool WriteBestBlock(const CBlockLocator& locator);
    bool ReadBestBlock(CBlockLocator& locator);

    // Returns true if wallet stores encryption keys
    bool IsEncrypted();

    bool WriteOrderPosNext(int64_t nOrderPosNext);

    bool WriteDescriptorKey(const uint256& desc_id, const CPubKey& pubkey, const CPrivKey& privkey);
    bool WriteCryptedDescriptorKey(const uint256& desc_id, const CPubKey& pubkey, const std::vector<unsigned char>& secret);
    bool WriteDescriptor(const uint256& desc_id, const WalletDescriptor& descriptor);
    bool WriteDescriptorDerivedCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index, uint32_t der_index);
    bool WriteDescriptorParentCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index);
    bool WriteDescriptorLastHardenedCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index);
    bool WriteDescriptorCacheItems(const uint256& desc_id, const DescriptorCache& cache);

    bool WriteLockedUTXO(const COutPoint& output);
    bool EraseLockedUTXO(const COutPoint& output);

    bool WriteAddressPreviouslySpent(const CTxDestination& dest, bool previously_spent);
    bool WriteAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& receive_request);
    bool EraseAddressReceiveRequest(const CTxDestination& dest, const std::string& id);
    bool EraseAddressData(const CTxDestination& dest);

    bool WriteActiveScriptPubKeyMan(uint8_t type, const uint256& id, bool internal);
    bool EraseActiveScriptPubKeyMan(uint8_t type, bool internal);

    DBErrors LoadWallet(CWallet* pwallet);

    //! Write the given client_version.
    bool WriteVersion(int client_version) { return m_batch->Write(DBKeys::VERSION, CLIENT_VERSION); }

    //! Delete records of the given types

    bool WriteWalletFlags(uint64_t flags);
    //! Begin a new transaction
    bool TxnBegin();
    //! Commit current transaction
    bool TxnCommit();
    //! Abort current transaction
    bool TxnAbort();
    bool HasActiveTxn() { return m_batch->HasActiveTxn(); }

    //! Registers db txn callback functions
    void RegisterTxnListener(const DbTxnListener& l);

private:
    std::unique_ptr<DatabaseBatch> m_batch;

    // External functions listening to the current db txn outcome.
    // Listeners are cleared at the end of the transaction.
    std::vector<DbTxnListener> m_txn_listeners;
};

/**
 * Executes the provided function 'func' within a database transaction context.
 *
 * This function ensures that all db modifications performed within 'func()' are
 * atomically committed to the db at the end of the process. And, in case of a
 * failure during execution, all performed changes are rolled back.
 *
 * @param database The db connection instance to perform the transaction on.
 * @param process_desc A description of the process being executed, used for logging purposes in the event of a failure.
 * @param func The function to be executed within the db txn context. It returns a boolean indicating whether to commit or roll back the txn.
 * @return true if the db txn executed successfully, false otherwise.
 */
bool RunWithinTxn(WalletDatabase& database, std::string_view process_desc, const std::function<bool(WalletBatch&)>& func);

bool LoadEncryptionKey(CWallet* pwallet, DataStream& ssKey, DataStream& ssValue, std::string& strErr);
} // namespace wallet

#endif // BITCOIN_WALLET_WALLETDB_H
