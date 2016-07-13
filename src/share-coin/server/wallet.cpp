
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcoind.h"
#include "wallet.h"
#include "walletdb.h"
#include "crypter.h"
#include "ui_interface.h"
#include "base58.h"
#include "chain.h"

using namespace std;

CWallet* pwalletMaster[MAX_COIN_IFACE];



CWallet *GetWallet(int iface_idx)
{
#ifndef TEST_SHCOIND
  if (iface_idx == 0)
    return (NULL);
#endif

  if (iface_idx < 0 || iface_idx >= MAX_COIN_IFACE)
    return (NULL);

  return (pwalletMaster[iface_idx]); 
}

CWallet *GetWallet(CIface *iface)
{
  return (GetWallet(GetCoinIndex(iface)));
}

void SetWallet(int iface_idx, CWallet *wallet)
{
#ifndef TEST_SHCOIND
  if (iface_idx == 0)
    return;
#endif

  if (iface_idx < 0 || iface_idx >= MAX_COIN_IFACE)
    return;

  pwalletMaster[iface_idx] = wallet;
}

void SetWallet(CIface *iface, CWallet *wallet)
{
  return (SetWallet(GetCoinIndex(iface), wallet));
}





struct CompareValueOnly
{
    bool operator()(const pair<int64, pair<const CWalletTx*, unsigned int> >& t1,
                    const pair<int64, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

CPubKey CWallet::GenerateNewKey()
{
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    RandAddSeedPerfmon();
    CKey key;
    key.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    if (!AddKey(key))
        throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");
    return key.GetPubKey();
}

bool CWallet::AddKey(const CKey& key)
{
    if (!CCryptoKeyStore::AddKey(key))
        return false;
    if (!fFileBacked)
        return true;
    if (!IsCrypted())
        return CWalletDB(strWalletFile).WriteKey(key.GetPubKey(), key.GetPrivKey());
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret);
    }
    return false;
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    if (!IsLocked())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64 nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                Debug("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

// This class implements an addrIncoming entry that causes pre-0.4
// clients to crash on startup if reading a private-key-encrypted wallet.
class CCorruptAddress
{
public:
    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
            READWRITE(nVersion);
    )
};

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion >= 40000)
        {
            // Versions prior to 0.4.0 did not support the "minversion" record.
            // Use a CCorruptAddress to make them crash instead.
            CCorruptAddress corruptAddress;
            pwalletdb->WriteSetting("addrIncoming", corruptAddress);
        }
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    RandAddSeedPerfmon();
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64 nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    Debug("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin())
                return false;
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbEncryption->TxnAbort();
            exit(1); //We now probably have half of our keys encrypted in memory, and half not...die and let the user reload their unencrypted wallet.
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
                exit(1); //We now have keys encrypted in memory, but no on disk...die to avoid confusion and let the user reload their unencrypted wallet.

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

void CWallet::WalletUpdateSpent(const CTransaction &tx)
{
    // Anytime a signature is successfully verified, it's proof the outpoint is spent.
    // Update the wallet spent flag if it doesn't know due to wallet.dat being
    // restored from backup or the user making copies of wallet.dat.
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end())
            {
                CWalletTx& wtx = (*mi).second;
                if (!wtx.IsSpent(txin.prevout.n) && IsMine(wtx.vout[txin.prevout.n]))
                {
                    Debug("WalletUpdateSpent found spent coin %sbc %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkSpent(txin.prevout.n);
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, txin.prevout.hash, CT_UPDATED);
                }
            }
        }
    }
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
            wtx.nTimeReceived = GetAdjustedTime();

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
        }

        Debug("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString().substr(0,10).c_str(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated) {
            if (!wtx.WriteToDisk())
                return false;
        }
#ifndef QT_GUI
        // If default receiving address gets used, replace it with a new one
        CScript scriptDefaultKey;
        scriptDefaultKey.SetDestination(vchDefaultKey.GetID());
        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            if (txout.scriptPubKey == scriptDefaultKey)
            {
                CPubKey newDefaultKey;
                if (GetKeyFromPool(newDefaultKey, false))
                {
                    SetDefaultKey(newDefaultKey);
                    SetAddressBookName(vchDefaultKey.GetID(), "");
                }
            }
        }
#endif
        // since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
        WalletUpdateSpent(wtx);

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);
    }
    return true;
}

// Add a transaction to the wallet, or update it.
// pblock is optional, but should be provided if the transaction is known to be in a block.
// If fUpdate is true, existing transactions will be updated.
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fFindBlock)
{
  uint256 hash = tx.GetHash();
  {
    LOCK(cs_wallet);
    bool fExisted = mapWallet.count(hash);
    if (fExisted && !fUpdate) return false;
    if (fExisted || IsFromMe(tx) || IsMine(tx)) {
      CWalletTx wtx(this,tx);
      // Get merkle branch if transaction was found in a block
      if (pblock) {
        wtx.SetMerkleBranch(pblock);
      }
      return AddToWallet(wtx);
    }
    else
      WalletUpdateSpent(tx);
  }
  return false;
}

bool CWallet::EraseFromWallet(uint256 hash)
{
    if (!fFileBacked)
        return false;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return true;
}


bool CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return true;
        }
    }
    return false;
}

int64 CWallet::GetDebit(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    CTxDestination address;

    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a TX_PUBKEYHASH that is mine but isn't in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (ExtractDestination(txout.scriptPubKey, address) && ::IsMine(*this, address))
    {
        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

int64 CWalletTx::GetTxTime() const
{
    return nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase())
        {
            // Generated block
            if (hashBlock != 0)
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && hashBlock != 0)
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(int64& nGeneratedImmature, int64& nGeneratedMature, list<pair<CTxDestination, int64> >& listReceived, list<pair<CTxDestination, int64> >& listSent, int64& nFee, string& strSentAccount) const
{
  int ifaceIndex = pwallet->ifaceIndex;

  nGeneratedImmature = nGeneratedMature = nFee = 0;
  listReceived.clear();
  listSent.clear();
  strSentAccount = strFromAccount;

  if (IsCoinBase())
  {
    if (GetBlocksToMaturity(ifaceIndex) > 0)
      nGeneratedImmature = pwallet->GetCredit(*this);
    else
      nGeneratedMature = GetCredit();
    return;
  }

  // Compute fee:
  int64 nDebit = GetDebit();
  if (nDebit > 0) // debit>0 means we signed/sent this transaction
  {
    int64 nValueOut = GetValueOut();
    nFee = nDebit - nValueOut;
  }

  // Sent/received.
  BOOST_FOREACH(const CTxOut& txout, vout)
  {
    CTxDestination address;
    vector<unsigned char> vchPubKey;
    if (!ExtractDestination(txout.scriptPubKey, address))
    {
      error(SHERR_INVAL,
          "CWalletTx::GetAmounts: Unknown transaction type found, txid %s: %s\n",
          this->GetHash().ToString().c_str(), txout.scriptPubKey.ToString().c_str());
    }

    // Don't report 'change' txouts
    if (nDebit > 0 && pwallet->IsChange(txout))
      continue;

    if (nDebit > 0)
      listSent.push_back(make_pair(address, txout.nValue));

    if (pwallet->IsMine(txout))
      listReceived.push_back(make_pair(address, txout.nValue));
  }

}

void CWalletTx::GetAccountAmounts(const string& strAccount, int64& nGenerated, int64& nReceived, int64& nSent, int64& nFee) const
{
    nGenerated = nReceived = nSent = nFee = 0;

    int64 allGeneratedImmature, allGeneratedMature, allFee;
    allGeneratedImmature = allGeneratedMature = allFee = 0;
    string strSentAccount;
    list<pair<CTxDestination, int64> > listReceived;
    list<pair<CTxDestination, int64> > listSent;
    GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount);

    if (strAccount == "")
        nGenerated = allGeneratedMature;
    if (strAccount == strSentAccount)
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& s, listSent)
            nSent += s.second;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.first))
            {
                map<CTxDestination, string>::const_iterator mi = pwallet->mapAddressBook.find(r.first);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second == strAccount)
                    nReceived += r.second;
            }
            else if (strAccount.empty())
            {
                nReceived += r.second;
            }
        }
    }
}

bool CWalletTx::WriteToDisk()
{
    return CWalletDB(pwallet->strWalletFile).WriteTx(GetHash(), *this);
}

#if 0
// Scan the block chain (starting in pindexStart) for transactions
// from or to us. If fUpdate is true, found transactions that already
// exist in the wallet will be updated.
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0;

    CBlockIndex* pindex = pindexStart;
    {
        LOCK(cs_wallet);
        while (pindex)
        {
            USDEBlock block;
            block.ReadFromDisk(pindex, true);
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }
            pindex = pindex->pnext;
        }
    }
    return ret;
}
#endif

int CWallet::ScanForWalletTransaction(const uint256& hashTx)
{
    CTransaction tx;

    if (!tx.ReadTx(ifaceIndex, hashTx)) {
      error(SHERR_INVAL, "ScanForWalletTransaction: unknown tx '%s'\n", hashTx.GetHex().c_str());
      return (0);
    }

//    tx.ReadFromDisk(COutPoint(hashTx, 0));
    if (AddToWalletIfInvolvingMe(tx, NULL, true, true))
        return 1;
    return 0;
}


void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
    BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
    {
        if (!tx.IsCoinBase())
        {
            uint256 hash = tx.GetHash();
            if (!txdb.ContainsTx(hash))
                RelayMessage(CInv(txdb.ifaceIndex, MSG_TX, hash), (CTransaction)tx);
        }
    }
    if (!IsCoinBase())
    {
        uint256 hash = GetHash();
        if (!txdb.ContainsTx(hash))
        {
            //printf("Relaying wtx %s\n", hash.ToString().substr(0,10).c_str());
            RelayMessage(CInv(txdb.ifaceIndex, MSG_TX, hash), (CTransaction)*this);
        }
    }
}







//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


int64 CWallet::GetBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal(ifaceIndex)) {
              continue;
            }
            if (!pcoin->IsConfirmed()) {
              continue;
            }
            nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

int64 CWallet::GetUnconfirmedBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal(ifaceIndex) || !pcoin->IsConfirmed())
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

int64 CWallet::GetImmatureBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& pcoin = (*it).second;
            if (pcoin.IsCoinBase() && pcoin.GetBlocksToMaturity(ifaceIndex) > 0 && pcoin.GetDepthInMainChain(ifaceIndex) >= 2)
                nTotal += GetCredit(pcoin);
        }
    }
    return nTotal;
}

// populate vCoins with vector of spendable COutputs
void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed) const
{
    vCoins.clear();

    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal(ifaceIndex))
                continue;

            if (fOnlyConfirmed && !pcoin->IsConfirmed())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity(ifaceIndex) > 0)
                continue;

            // If output is less than minimum value, then don't include transaction.
            // This is to help deal with dust spam clogging up create transactions.
            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
              opcodetype opcode;
              const CScript& script = pcoin->vout[i].scriptPubKey;
              CScript::const_iterator pc = script.begin();
              if (script.GetOp(pc, opcode) &&
                  opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
                continue; /* not avail */
              }

              CIface *iface = GetCoinByIndex(ifaceIndex);
              int64 nMinimumInputValue = MIN_INPUT_VALUE(iface);
              if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue)
                vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(ifaceIndex)));
            }
        }
    }
}

static void ApproximateBestSubset(vector<pair<int64, pair<const CWalletTx*,unsigned int> > >vValue, int64 nTotalLower, int64 nTargetValue,
                                  vector<char>& vfBest, int64& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64 nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                if (nPass == 0 ? rand() % 2 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

bool CWallet::SelectCoinsMinConf(int64 nTargetValue, int nConfMine, int nConfTheirs, vector<COutput> vCoins,
                                 set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair<int64, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<int64>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<int64, pair<const CWalletTx*,unsigned int> > > vValue;
    int64 nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    BOOST_FOREACH(COutput output, vCoins)
    {
        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe() ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;
        int64 n = pcoin->vout[i].nValue;

        pair<int64,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + CENT)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    vector<char> vfBest;
    int64 nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

#if 0
        //// debug print
        printf("SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                printf("%s ", FormatMoney(vValue[i].first).c_str());
        printf("total %s\n", FormatMoney(nBest).c_str());
#endif
    }

    return true;
}

bool CWallet::SelectCoins(int64 nTargetValue, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const
{
    vector<COutput> vCoins;
    AvailableCoins(vCoins);

    return (SelectCoinsMinConf(nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet));
}



#if 0
bool CWallet::CreateTransaction(CTxDB& txdb, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
    int64 nValue = 0;
    BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
    {
        if (nValue < 0)
            return false;
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
        return false;

    wtxNew.BindWallet(this);

    {
        LOCK2(cs_main, cs_wallet);
        // txdb must be opened before the mapWallet lock
        {
            nFeeRet = nTransactionFee;
            loop
            {
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                wtxNew.fFromMe = true;

                int64 nTotalValue = nValue + nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
                    wtxNew.vout.push_back(CTxOut(s.second, s.first));

                // Choose coins to use
                set<pair<const CWalletTx*,unsigned int> > setCoins;
                int64 nValueIn = 0;
                if (!SelectCoins(nTotalValue, setCoins, nValueIn))
                    return false;
                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
                    dPriority += (double)nCredit * pcoin.first->GetDepthInMainChain(ifaceIndex);
                }

                int64 nChange = nValueIn - nValue - nFeeRet;
                // if sub-cent change is required, the fee must be raised to at least MIN_TX_FEE
                // or until nChange becomes zero
                // NOTE: this depends on the exact behaviour of GetMinFee
                if (nFeeRet < MIN_TX_FEE && nChange > 0 && nChange < CENT)
                {
                    int64 nMoveToFee = min(nChange, MIN_TX_FEE - nFeeRet);
                    nChange -= nMoveToFee;
                    nFeeRet += nMoveToFee;
                }

                if (nChange > 0)
                {
                    // Note: We use a new key here to keep it from being obvious which side is the change.
                    //  The drawback is that by not reusing a previous key, the change may be lost if a
                    //  backup is restored, if the backup doesn't have the new private key for the change.
                    //  If we reused the old key, it would be possible to add code to look for and
                    //  rediscover unknown transactions that were written with keys of ours to recover
                    //  post-backup change.

                    // Reserve a new key pair from key pool
                    CPubKey vchPubKey = reservekey.GetReservedKey();
                    // assert(mapKeys.count(vchPubKey));

                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-bitcoin-address
                    CScript scriptChange;
                    scriptChange.SetDestination(vchPubKey.GetID());

                    // Insert change txn at random position:
                    vector<CTxOut>::iterator position = wtxNew.vout.begin()+GetRandInt(wtxNew.vout.size());
                    wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
                }
                else
                    reservekey.ReturnKey();

                // Fill vin
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

                // Sign
                int nIn = 0;
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    if (!SignSignature(*this, *coin.first, wtxNew, nIn++))
                        return false;

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION(iface));
                if (nBytes >= MAX_BLOCK_SIZE_GEN/5)
                    return false;
                dPriority /= nBytes;

                // Check that enough fee is included
                int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
                bool fAllowFree = CTransaction::AllowFree(dPriority);
                int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree, GMF_SEND);
                if (nFeeRet < max(nPayFee, nMinFee))
                {
                    nFeeRet = max(nPayFee, nMinFee);
                    continue;
                }

                // Fill vtxPrev by copying from previous transactions vtxPrev
                wtxNew.AddSupportingTransactions(txdb);
                wtxNew.fTimeReceivedIsTxTime = true;

                break;
            }
        }
    }
    return true;
}

bool CWallet::CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
    vector< pair<CScript, int64> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet);
}
#endif

#if 0
// Call after CreateTransaction unless you want to abort
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey)
{
  {
    LOCK2(cs_main, cs_wallet);
    Debug("CommitTransaction:\n%s", wtxNew.ToString().c_str());
    {
      // This is only to keep the database open to defeat the auto-flush for the
      // duration of this scope.  This is the only place where this optimization
      // maybe makes sense; please don't do it anywhere else.
      CWalletDB* pwalletdb = fFileBacked ? new CWalletDB(strWalletFile,"r") : NULL;

      // Take key pair from key pool so it won't be used again
      reservekey.KeepKey();

      // Add tx to wallet, because if it has change it's also ours,
      // otherwise just for transaction history.
      AddToWallet(wtxNew);

      // Mark old coins as spent
      set<CWalletTx*> setCoins;
      BOOST_FOREACH(const CTxIn& txin, wtxNew.vin)
      {
        CWalletTx &coin = mapWallet[txin.prevout.hash];
        coin.BindWallet(this);
        coin.MarkSpent(txin.prevout.n);
        coin.WriteToDisk();
        NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
      }

      if (fFileBacked)
        delete pwalletdb;
    }

    // Track how many getdata requests our transaction gets
    mapRequestCount[wtxNew.GetHash()] = 0;

    // Broadcast
    if (!wtxNew.AcceptToMemoryPool(ifaceIndex))
    {
      // This must not fail. The transaction has already been signed and recorded.
      printf("CommitTransaction() : Error: Transaction not valid");
      return false;
    }
    //wtxNew.RelayWalletTransaction(ifaceIndex);
    RelayWalletTransaction(wtxNew);
  }
  return true;
}
#endif




string CWallet::SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64 nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    if (!CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired))
    {
        string strError;
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

    if (fAskFee)
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
        return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}



string CWallet::SendMoneyToDestination(const CTxDestination& address, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + nTransactionFee > GetBalance())
        return _("Insufficient funds");

    // Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address);

    return SendMoney(scriptPubKey, nValue, wtxNew, fAskFee);
}




int CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return false;
    fFirstRunRet = false;
    int nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // the requires a new key.
        }
        nLoadWalletRet = DB_NEED_REWRITE;
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    CreateThread(ThreadFlushWalletDB, &strWalletFile);
    return DB_LOAD_OK;
}


bool CWallet::SetAddressBookName(const CTxDestination& address, const string& strName)
{
    std::map<CTxDestination, std::string>::iterator mi = mapAddressBook.find(address);
    mapAddressBook[address] = strName;
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address), (mi == mapAddressBook.end()) ? CT_NEW : CT_UPDATED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).WriteName(CCoinAddr(address).ToString(), strName);
}

bool CWallet::DelAddressBookName(const CTxDestination& address)
{
    mapAddressBook.erase(address);
    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address), CT_DELETED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).EraseName(CCoinAddr(address).ToString());
}


void CWallet::PrintWallet(const CBlock& block)
{
    {
        LOCK(cs_wallet);
        if (mapWallet.count(block.vtx[0].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
            printf("    mine:  %d  %d  %d", wtx.GetDepthInMainChain(ifaceIndex), wtx.GetBlocksToMaturity(ifaceIndex), wtx.GetCredit());
        }
    }
    printf("\n");
}

bool CWallet::GetTransaction(const uint256 &hashTx, CWalletTx& wtx)
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
        {
            wtx = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

bool GetWalletFile(CWallet* pwallet, string &strWalletFileOut)
{
    if (!pwallet->fFileBacked)
        return false;
    strWalletFileOut = pwallet->strWalletFile;
    return true;
}

//
// Mark old keypool keys as used,
// and generate all new keys
//
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64 nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        int64 nKeys = max(GetArg("-keypool", 100), (int64)0);
        for (int i = 0; i < nKeys; i++)
        {
            int64 nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        printf("CWallet::NewKeyPool wrote %"PRI64d" new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool()
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize = max(GetArg("-keypool", 100), 0LL);
        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64 nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool() : writing generated key failed");
            setKeyPool.insert(nEnd);
//            Debug("keypool added key %"PRI64d", size=%d\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool() : read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool() : unknown key in key pool");
        if (!keypool.vchPubKey.IsValid()) {
          Debug("ReserveKeyFromKeyPool: vchPubKey is not valid\n");
        }


//        assert(keypool.vchPubKey.IsValid());
//        Debug("keypool reserve %"PRI64d"\n", nIndex);
    }
}

int64 CWallet::AddReserveKey(const CKeyPool& keypool)
{
    {
        LOCK2(cs_main, cs_wallet);
        CWalletDB walletdb(strWalletFile);

        int64 nIndex = 1 + *(--setKeyPool.end());
        if (!walletdb.WritePool(nIndex, keypool))
            throw runtime_error("AddReserveKey() : writing added key failed");
        setKeyPool.insert(nIndex);
        return nIndex;
    }
    return -1;
}

void CWallet::KeepKey(int64 nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    //printf("keypool keep %"PRI64d"\n", nIndex);
}

void CWallet::ReturnKey(int64 nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    //printf("keypool return %"PRI64d"\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool fAllowReuse)
{
    int64 nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (fAllowReuse && vchDefaultKey.IsValid())
            {
                result = vchDefaultKey;
                return true;
            }
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64 CWallet::GetOldestKeyPoolTime()
{
    int64 nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

CPubKey CReserveKey::GetReservedKey()
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else
        {
            Debug("CReserveKey::GetReservedKey(): Warning: using default key instead of a new key, top up your keypool.");
            vchPubKey = pwallet->vchDefaultKey;
        }
    }
    assert(vchPubKey.IsValid());
    return vchPubKey;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress)
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes() : read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes() : unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
    }
}

#if 0
int SetTxMerkleBranch(CMerkleTx *tx, const CBlock *pblock)
{
  blkidx_t *blockIndex;

  if (!pblock)
    return (0);

  // Update the tx's hashBlock
  tx->hashBlock = pblock->GetHash();

  // Locate the transaction
  for (tx->nIndex = 0; tx->nIndex < (int)pblock->vtx.size(); tx->nIndex++)
    if (pblock->vtx[tx->nIndex] == *(CTransaction*)tx)
      break;
  if (tx->nIndex == (int)pblock->vtx.size())
  {
    tx->vMerkleBranch.clear();
    tx->nIndex = -1;
    error(SHERR_INVAL, "SetMerkleBranch() : couldn't find tx in block");
    return 0;
  }

  // Fill in merkle branch
  tx->vMerkleBranch = pblock->GetMerkleBranch(tx->nIndex);

  blockIndex = GetBlockTable(pblock->ifaceIndex);
  if (!blockIndex) {
    unet_log(pblock->ifaceIndex,
        "SetMerkleBranch(): error opening block table.");
    return (0);
  }

  // Is the tx in a block that's in the main chain
  CBlockIndex *pindex = (*blockIndex)[tx->hashBlock];
  if (!pindex || !pindex->IsInMainChain(pblock->ifaceIndex))
    return (0);

  CBlockIndex *pindexBest = GetBestBlockIndex(pblock->ifaceIndex);
  if (!pindexBest)
    return (0);
  return pindexBest->nHeight - pindex->nHeight + 1;
}
#endif

#if 0
static bool InitBlockChainIndex(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex;
  bc_t *bc;
  uint256 l_hash; /* = 0 */
  int height;
  int max;

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  blockIndex = GetBlockTable(ifaceIndex);

  max = bc_idx_next(bc);
  for (height = (max - 1); height >= 0; height--) {
    USDEBlock block;
    uint256 hash;

    /* read in entire block */
    if (!block.ReadBlock(height)) {
      fprintf(stderr, "DEBUG: InitBlockChainIndex: error reading block at height %d\n", height);
      return (false);
    }

    hash = block.GetHash();

    // Construct block index object
    CBlockIndex* pindexNew = InsertBlockIndex(blockIndex, hash);
    pindexNew->pprev          = InsertBlockIndex(blockIndex, block.hashPrevBlock);
    pindexNew->pnext          = InsertBlockIndex(blockIndex, l_hash);
    pindexNew->nHeight        = height;
    pindexNew->nVersion       = block.nVersion;
    pindexNew->hashMerkleRoot = block.hashMerkleRoot;
    pindexNew->nTime          = block.nTime;
    pindexNew->nBits          = block.nBits;
    pindexNew->nNonce         = block.nNonce;

    /*
       pindexNew->nFile          = diskindex.nFile;
       pindexNew->nBlockPos      = diskindex.nBlockPos;
       */

    // Watch for genesis block
    if (pindexGenesisBlock == NULL && hash == hashGenesisBlock)
      pindexGenesisBlock = pindexNew;

    if (!pindexNew->CheckIndex())
      return error(SHERR_IO, "LoadBlockIndex() : CheckIndex failed at %d", pindexNew->nHeight);

    l_hash = hash;
  }

  return true;
}
bool LoadBlockIndex(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex;

  blockIndex = GetBlockTable(ifaceIndex);
  if (!blockIndex) {
    unet_log(ifaceIndex, "error loading block table.");
    return (false);
  }

fprintf(stderr, "DEBUG: loading block chain index for iface #%d\n", ifaceIndex);
/* DEBUG: height < 1, no nFilePos avail (anexorcate block.ReadFromDisk()) */
  if (!InitBlockChainIndex(iface)) {
//    if (!LoadBlockIndexGuts(iface))
      return false;
  }

  if (fRequestShutdown)
    return true;

  // Calculate bnChainWork
  vector<pair<int, CBlockIndex*> > vSortedByHeight;
  vSortedByHeight.reserve(blockIndex->size());
  BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, (*blockIndex))
  {
    CBlockIndex* pindex = item.second;
    vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
  }
  sort(vSortedByHeight.begin(), vSortedByHeight.end());
  BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
  {
    CBlockIndex* pindex = item.second;
    pindex->bnChainWork = (pindex->pprev ? pindex->pprev->bnChainWork : 0) + pindex->GetBlockWork();
  }


  return true;
}
#endif

int64 GetTxFee(int ifaceIndex, CTransaction tx)
{
  CWallet *wallet;

  wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (0);

  return (wallet->GetTxFee(tx));
}

int64 GetAccountBalance(int ifaceIndex, CWalletDB& walletdb, const string& strAccount, int nMinDepth)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
  int64 nBalance = 0;

  /* wallet transactions */
  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
  {
    const CWalletTx& wtx = (*it).second;
    if (!wtx.IsFinal(ifaceIndex))
      continue;

    int64 nGenerated, nReceived, nSent, nFee;
    wtx.GetAccountAmounts(strAccount, nGenerated, nReceived, nSent, nFee);

    if (nReceived != 0 && wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
      nBalance += nReceived;
    nBalance += nGenerated - nSent - nFee;
  }

  /* internal accounting entries */
  nBalance += walletdb.GetAccountCreditDebit(strAccount);

  return nBalance;
}

int64 GetAccountBalance(int ifaceIndex, const string& strAccount, int nMinDepth)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  CWalletDB walletdb(wallet->strWalletFile);
  return GetAccountBalance(ifaceIndex, walletdb, strAccount, nMinDepth);
}


bool SyncWithWallets(CIface *iface, CTransaction& tx, CBlock *pblock)
{
  CWallet *pwallet;

  pwallet = GetWallet(iface);
  if (!pwallet)
    return (false);

  return (pwallet->AddToWalletIfInvolvingMe(tx, pblock, true));
}

void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
  vtxPrev.clear();

  const int COPY_DEPTH = 3;
  if (SetMerkleBranch(txdb.ifaceIndex) < COPY_DEPTH)
  {
    vector<uint256> vWorkQueue;
    BOOST_FOREACH(const CTxIn& txin, vin)
      vWorkQueue.push_back(txin.prevout.hash);

    // This critsect is OK because txdb is already open
    {
      LOCK(pwallet->cs_wallet);
      map<uint256, const CMerkleTx*> mapWalletPrev;
      set<uint256> setAlreadyDone;
      for (unsigned int i = 0; i < vWorkQueue.size(); i++)
      {
        uint256 hash = vWorkQueue[i];
        if (setAlreadyDone.count(hash))
          continue;
        setAlreadyDone.insert(hash);

        CMerkleTx tx;
        map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
        if (mi != pwallet->mapWallet.end())
        {
          tx = (*mi).second;
          BOOST_FOREACH(const CMerkleTx& txWalletPrev, (*mi).second.vtxPrev)
            mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
        }
        else if (mapWalletPrev.count(hash))
        {
          tx = *mapWalletPrev[hash];
        }
        else if (!fClient && txdb.ReadDiskTx(hash, tx))
        {
          ;
        }
        else
        {
          printf("ERROR: AddSupportingTransactions() : unsupported transaction\n");
          continue;
        }

        int nDepth = tx.SetMerkleBranch(txdb.ifaceIndex);
        vtxPrev.push_back(tx);

        if (nDepth < COPY_DEPTH)
        {
          BOOST_FOREACH(const CTxIn& txin, tx.vin)
            vWorkQueue.push_back(txin.prevout.hash);
        }
      }
    }
  }

  reverse(vtxPrev.begin(), vtxPrev.end());
}

int CMerkleTx::GetDepthInMainChain(int ifaceIndex, CBlockIndex* &pindexRet) const
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);

  if (hashBlock == 0 || nIndex == -1)
    return 0;

  // Find the block it claims to be in
  map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hashBlock);
  if (mi == blockIndex->end())
    return 0;
  CBlockIndex* pindex = (*mi).second;
  if (!pindex) {
    error(SHERR_INVAL, "GetDepthInMainChain: block'%s' not in blockIndex\n", hashBlock.GetHex().c_str());
    return 0;
  }
  if (!pindex->IsInMainChain(ifaceIndex)) {
    error(SHERR_INVAL, "GetDepthInMainChain: !pindex->IsInMainChain (height %d)\n", pindex->nHeight);
    return 0;
  }

  // Make sure the merkle branch connects to this block
  if (!fMerkleVerified)
  {
    CBlock *block = GetBlockByHeight(iface, pindex->nHeight);
    if (!block)
      return 0;
    if (block->CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot) {
delete block;
      return 0;
  }
    fMerkleVerified = true;
delete block;
  }

  pindexRet = pindex;
  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  if (!pindexBest)
    return (0);
  return pindexBest->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetBlocksToMaturity(int ifaceIndex) const
{

  if (!IsCoinBase())
    return 0;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return 0;

  return max(0, 
      ((int)iface->coinbase_maturity + 1) - GetDepthInMainChain(ifaceIndex));
}

int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{

  if (!pblock)
    return (0);

  blkidx_t *mapBlockIndex = GetBlockTable(pblock->ifaceIndex);
  if (!mapBlockIndex)
    return 0;

  // Update the tx's hashBlock
  hashBlock = pblock->GetHash();

  // Locate the transaction
  for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
    if (pblock->vtx[nIndex] == *(CTransaction*)this)
      break;
  if (nIndex == (int)pblock->vtx.size())
  {
    vMerkleBranch.clear();
    nIndex = -1;
    printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
    return 0;
  }

  // Fill in merkle branch
  vMerkleBranch = pblock->GetMerkleBranch(nIndex);

  // Is the tx in a block that's in the main chain
  map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex->find(hashBlock);
  if (mi == mapBlockIndex->end())
    return (0);

  CBlockIndex* pindex = (*mi).second;
  if (!pindex || !pindex->IsInMainChain(pblock->ifaceIndex))
    return (0);

  CBlockIndex *pindexBest = GetBestBlockIndex(pblock->ifaceIndex);
  if (!pindexBest)
    return (0);

  return (pindexBest->nHeight - pindex->nHeight + 1);
}

int CMerkleTx::SetMerkleBranch(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (0);

  CBlock *pblock = GetBlockByTx(iface, GetHash()); 
  if (!pblock)
    return (0);

  int ret = SetMerkleBranch(pblock);
  delete pblock;
  return (ret);
}


CCoinAddr GetAccountAddress(CWallet *wallet, string strAccount, bool bForceNew)
{
  CWalletDB walletdb(wallet->strWalletFile);
  CAccount account;
  bool bKeyUsed = false;

  walletdb.ReadAccount(strAccount, account);

  // Check if the current key has been used
  if (account.vchPubKey.IsValid())
  {
    CScript scriptPubKey;
    scriptPubKey.SetDestination(account.vchPubKey.GetID());
    for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin();
        it != wallet->mapWallet.end() && account.vchPubKey.IsValid();
        ++it)
    {
      const CWalletTx& wtx = (*it).second;
      BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        if (txout.scriptPubKey == scriptPubKey)
          bKeyUsed = true;
    }
  }

  // Generate a new key
  if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed)
  {
    if (!wallet->GetKeyFromPool(account.vchPubKey, false))
      return CCoinAddr();//throw JSONRPCError(-12, "Error: Keypool ran out, please call keypoolrefill first");

    wallet->SetAddressBookName(account.vchPubKey.GetID(), strAccount);
    walletdb.WriteAccount(strAccount, account);
  }

  return CCoinAddr(account.vchPubKey.GetID());
}






/** Generate a transaction with includes a specific input tx. */
bool CreateTransactionWithInputTx(CIface *iface, 
    const vector<pair<CScript, int64> >& vecSend,
    CWalletTx& wtxIn, int nTxOut, CWalletTx& wtxNew,
    CReserveKey& reservekey, int64 nTxFee)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *pwalletMain = GetWallet(iface);
  int64 nValue = 0;
  int64 nFeeRet;
  BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
    if (nValue < 0) {
      return error(SHERR_INVAL, "CreateTransactionWIthInputTx: nValue < 0\n");
    }
    nValue += s.second;
  }
  if (vecSend.empty() || nValue < 0) {
    return error(SHERR_INVAL, "CreateTransactionWIthInputTx: vecSend.empty()\n");
  }

  wtxNew.BindWallet(pwalletMain);

  {
    nFeeRet = nTransactionFee;
    loop {
      wtxNew.vin.clear();
      wtxNew.vout.clear();
      wtxNew.fFromMe = true;

      int64 nTotalValue = nValue + nFeeRet;
      double dPriority = 0;

      // vouts to the payees
      BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
        wtxNew.vout.push_back(CTxOut(s.second, s.first));

      int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

      // Choose coins to use
      set<pair<const CWalletTx*, unsigned int> > setCoins;
      int64 nValueIn = 0;
      if (nTotalValue - nWtxinCredit > 0) {
        if (!pwalletMain->SelectCoins(nTotalValue - nWtxinCredit,
              setCoins, nValueIn)) {
          return error(SHERR_INVAL, "CreateTransactionWithInputTx: error selecting coins\n"); 
        }
      }

      vector<pair<const CWalletTx*, unsigned int> > vecCoins(
          setCoins.begin(), setCoins.end());

      BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
        int64 nCredit = coin.first->vout[coin.second].nValue;
        dPriority += (double) nCredit
          * coin.first->GetDepthInMainChain(ifaceIndex);
      }

      // Input tx always at first position
      vecCoins.insert(vecCoins.begin(), make_pair(&wtxIn, nTxOut));

      nValueIn += nWtxinCredit;
      dPriority += (double) nWtxinCredit * wtxIn.GetDepthInMainChain(ifaceIndex);

      // Fill a vout back to self (new addr) with any change
      int64 nChange = MAX(0, nValueIn - nTotalValue - nTxFee);
      if (nChange >= CENT) {
        CCoinAddr returnAddr = GetAccountAddress(pwalletMain, wtxNew.strFromAccount, true);
        CScript scriptChange;

        if (returnAddr.IsValid()) {
          /* return change to sender */
          scriptChange.SetDestination(returnAddr.Get());
        } else {
          /* use supplied addr */
          CPubKey pubkey = reservekey.GetReservedKey();
          scriptChange.SetDestination(pubkey.GetID());
        }

        /* include as first transaction. */
        vector<CTxOut>::iterator position = wtxNew.vout.begin();
        wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
      }

      // Fill vin
      BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
        wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

      // Sign
      int nIn = 0;
      BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
        if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++)) {
          return error(SHERR_INVAL, "CreateTransactionWithInputTx: error signing outputs");
        }
      }

      // Limit size
      unsigned int nBytes = ::GetSerializeSize(*(CTransaction*) &wtxNew,
          SER_NETWORK, PROTOCOL_VERSION(iface));
      if (nBytes >= MAX_BLOCK_SIZE_GEN(iface)/5) {
        return error(SHERR_INVAL, "CreateTransactionWithInputTx: tx too big");
      }
      dPriority /= nBytes;

      // Check that enough fee is included
      int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
      bool fAllowFree = CTransaction::AllowFree(dPriority);
      int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree);
      if (nFeeRet < max(nPayFee, nMinFee)) {
        nFeeRet = max(nPayFee, nMinFee);
        Debug("TEST: CreateTransactionWithInputTx: re-iterating (nFreeRet = %s)\n", FormatMoney(nFeeRet).c_str());
        continue;
      }

      // Fill vtxPrev by copying from previous transactions vtxPrev
      pwalletMain->AddSupportingTransactions(wtxNew);
      wtxNew.fTimeReceivedIsTxTime = true;
      break;
    }

  }

  Debug("CreateTransactionWithInputTx: commit '%s'", wtxNew.ToString().c_str());
  return true;
}

int IndexOfExtOutput(const CTransaction& tx)
{
  int idx;

  idx = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {

    const CScript& script = out.scriptPubKey;
    opcodetype opcode;
    CScript::const_iterator pc = script.begin();
    if (script.GetOp(pc, opcode) &&
        opcode >= 0xf0 && opcode <= 0xf9) { /* ext mode */
#if 0
      if (script.GetOp(pc, opcode) && /* ext type */
          script.GetOp(pc, opcode) && /* content */
          opcode == OP_HASH160)
#endif
        break;
    }

    idx++;
  }
  if (idx == tx.vout.size())
    return (-1); /* uh oh */

  return (idx);
}

/** Commit a transaction with includes a specific input tx. */
bool SendMoneyWithExtTx(CIface *iface,
    CWalletTx& wtxIn, CWalletTx& wtxNew,
    const CScript& scriptPubKey,
    vector<pair<CScript, int64> > vecSend,
    int64 txFee)
{
  CWallet *pwalletMain = GetWallet(iface);
  CReserveKey reservekey(pwalletMain);
  int ifaceIndex = GetCoinIndex(iface);
  int nTxOut;

  nTxOut = IndexOfExtOutput(wtxIn);
  if (nTxOut == -1) {
    return error(ifaceIndex, "SendMoneyWithExtTx: error obtaining previous tx.");
  }

  /* insert as initial position. this is 'primary' operation. */
  int64 tx_val = wtxIn.vout[nTxOut].nValue;
  txFee = MAX(0, MIN(tx_val - iface->min_tx_fee, txFee));
  int64 nValue = tx_val - txFee;
  vecSend.insert(vecSend.begin(), make_pair(scriptPubKey, nValue));

	if (!CreateTransactionWithInputTx(iface,
        vecSend, wtxIn, nTxOut, wtxNew, reservekey, txFee)) {
    return error(ifaceIndex, "SendMoneyWithExtTx: error creating transaction.");
  }

	if (!pwalletMain->CommitTransaction(wtxNew, reservekey)) {
    return error(ifaceIndex, "error commiting transaction.");
  }

  return (true);
}


bool GetCoinAddr(CWallet *wallet, CCoinAddr& addrAccount, string& strAccount)
{

  BOOST_FOREACH(const PAIRTYPE(CCoinAddr, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = item.first;
    const string& account = item.second;
    if (address == addrAccount) {
      addrAccount = address;
      strAccount = account;
      return (true);
    }
  }

  return (false);
}

bool DecodeMatrixHash(const CScript& script, int& mode, uint160& hash)
{
  CScript::const_iterator pc = script.begin();
  opcodetype opcode;
  int op;

  if (!script.GetOp(pc, opcode)) {
    return false;
  }
  mode = opcode; /* extension mode (new/activate/update) */
  if (mode < 0xf0 || mode > 0xf9)
    return false;

  if (!script.GetOp(pc, opcode)) {
    return false;
  }
  if (opcode < OP_1 || opcode > OP_16) {
    return false;
  }
  op = CScript::DecodeOP_N(opcode); /* extension type */
  if (op != OP_MATRIX) {
    return false;
  }

  vector<unsigned char> vch;
  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  if (opcode != OP_HASH160)
    return (false);

  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  hash = uint160(vch);
  return (true);
}

bool VerifyMatrixTx(CTransaction& tx, int& mode)
{
  uint160 hashMatrix;
  int nOut;

  /* core verification */
  if (!tx.isFlag(CTransaction::TXF_MATRIX))
    return (false); /* tx not flagged as matrix */

  /* verify hash in pub-script matches matrix hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* no extension output */

  if (!DecodeMatrixHash(tx.vout[nOut].scriptPubKey, mode, hashMatrix))
    return (false); /* no matrix hash in output */

  CMatrix *matrix = (CMatrix *)&tx.matrix;
  if (hashMatrix != matrix->GetHash())
    return (false); /* matrix hash mismatch */

  return (true);
}

bool CMerkleTx::AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs)
{
  if (fClient)
  {
    if (!IsInMainChain(txdb.ifaceIndex) && !ClientConnectInputs(txdb.ifaceIndex))
      return false;
    return CTransaction::AcceptToMemoryPool(txdb, false);
  }
  else
  {
    return CTransaction::AcceptToMemoryPool(txdb, fCheckInputs);
  }
}


bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs)
{
  CIface *iface = GetCoinByIndex(txdb.ifaceIndex);
  CTxMemPool *pool;

  pool = GetTxMemPool(iface);
  if (!pool) {
    unet_log(txdb.ifaceIndex, "error obtaining tx memory pool");
    return (false);
  }

  {
    LOCK(pool->cs);
    // Add previous supporting transactions first
    BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
    {
      if (!tx.IsCoinBase())
      {
        uint256 hash = tx.GetHash();
        if (!pool->exists(hash) && !txdb.ContainsTx(hash))
          tx.AcceptToMemoryPool(txdb, fCheckInputs);
      }
    }
    return AcceptToMemoryPool(txdb, fCheckInputs);
  }

  return false;
}

