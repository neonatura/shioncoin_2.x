
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
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"

#ifdef WIN32
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef fcntl
#undef fcntl
#endif

#include <boost/array.hpp>
#include <share.h>
#include "walletdb.h"
#include "test/test_block.h"
#include "test/test_wallet.h"
#include "test/test_txidx.h"
#include "chain.h"

using namespace std;
using namespace boost;

TESTWallet *testWallet = new TESTWallet();
CScript TEST_COINBASE_FLAGS;


int test_UpgradeWallet(void)
{
  int nMaxVersion = 0;//GetArg("-upgradewallet", 0);
  if (nMaxVersion == 0) // the -upgradewallet without argument case
  {
    nMaxVersion = CLIENT_VERSION;
    testWallet->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
    Debug("using wallet version %d", FEATURE_LATEST);
  }
  else
    printf("Allowing wallet upgrade up to %i\n", nMaxVersion);

  if (nMaxVersion > testWallet->GetVersion()) {
    testWallet->SetMaxVersion(nMaxVersion);
  }

}

bool test_LoadWallet(void)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  std::ostringstream strErrors;

  const char* pszP2SH = "/P2SH/";
  TEST_COINBASE_FLAGS << std::vector<unsigned char>(pszP2SH, pszP2SH+strlen(pszP2SH));

#if 0
  if (!bitdb.Open(GetDataDir()))
  {
    fprintf(stderr, "error: unable to open data directory.\n");
    return (false);
  }

  if (!LoadBlockIndex(iface)) {
    fprintf(stderr, "error: unable to open load block index.\n");
    return (false);
  }
#endif

  bool fFirstRun = true;
  testWallet->LoadWallet(fFirstRun);

  if (fFirstRun)
  {

    // Create new keyUser and set as default key
    RandAddSeedPerfmon();

    CPubKey newDefaultKey;
    if (!testWallet->GetKeyFromPool(newDefaultKey, false))
      strErrors << _("Cannot initialize keypool") << "\n";
    testWallet->SetDefaultKey(newDefaultKey);
    if (!testWallet->SetAddressBookName(testWallet->vchDefaultKey.GetID(), ""))
      strErrors << _("Cannot write default address") << "\n";
  }

  printf("%s", strErrors.str().c_str());

  RegisterWallet(testWallet);

  CBlockIndex *pindexRescan = GetBestBlockIndex(TEST_COIN_IFACE);
  if (GetBoolArg("-rescan"))
    pindexRescan = TESTBlock::pindexGenesisBlock;
  else
  {
    CWalletDB walletdb("test_wallet.dat");
    CBlockLocator locator(GetCoinIndex(iface));
    if (walletdb.ReadBestBlock(locator))
      pindexRescan = locator.GetBlockIndex();
  }
  CBlockIndex *pindexBest = GetBestBlockIndex(TEST_COIN_IFACE);
  if (pindexBest != pindexRescan && pindexBest && pindexRescan && pindexBest->nHeight > pindexRescan->nHeight)
  {
    int64 nStart;

    printf("Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
    nStart = GetTimeMillis();
    testWallet->ScanForWalletTransactions(pindexRescan, true);
    printf(" rescan      %15"PRI64d"ms\n", GetTimeMillis() - nStart);
  }

  test_UpgradeWallet();

  // Add wallet transactions that aren't already in a block to mapTransactions
  testWallet->ReacceptWalletTransactions(); 

  return (true);
}


void TESTWallet::RelayWalletTransaction(CWalletTx& wtx)
{
  TESTTxDB txdb;
  wtx.RelayWalletTransaction(txdb);
  txdb.Close(); 
}


void TESTWallet::ResendWalletTransactions()
{
  // Do this infrequently and randomly to avoid giving away
  // that these are our transactions.
  static int64 nNextTime;
  if (GetTime() < nNextTime)
    return;
  bool fFirst = (nNextTime == 0);
  nNextTime = GetTime() + GetRand(30 * 60);
  if (fFirst)
    return;

  // Only do it if there's been a new block since last time
  static int64 nLastTime;
  if (TESTBlock::nTimeBestReceived < nLastTime)
    return;
  nLastTime = GetTime();

  // Rebroadcast any of our txes that aren't in a block yet
  TESTTxDB txdb;
  {
    LOCK(cs_wallet);
    // Sort them in chronological order
    multimap<unsigned int, CWalletTx*> mapSorted;
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
    {
      CWalletTx& wtx = item.second;
      // Don't rebroadcast until it's had plenty of time that
      // it should have gotten in already by now.
      if (TESTBlock::nTimeBestReceived - (int64)wtx.nTimeReceived > 5 * 60)
        mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
    }
    BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
    {
      CWalletTx& wtx = *item.second;
      wtx.RelayWalletTransaction(txdb);
    }
  }
  txdb.Close();
}

void TESTWallet::ReacceptWalletTransactions()
{
  TESTTxDB txdb;
  bool fRepeat = true;

  while (fRepeat)
  {
    LOCK(cs_wallet);
    fRepeat = false;
    vector<CDiskTxPos> vMissingTx;
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
    {
      CWalletTx& wtx = item.second;
      if (wtx.IsCoinBase() && wtx.IsSpent(0))
        continue;

      CTxIndex txindex;
      bool fUpdated = false;
      if (txdb.ReadTxIndex(wtx.GetHash(), txindex))
      {
        // Update fSpent if a tx got spent somewhere else by a copy of wallet.dat
        if (txindex.vSpent.size() != wtx.vout.size())
        {
          printf("ERROR: ReacceptWalletTransactions() : txindex.vSpent.size() %d != wtx.vout.size() %d\n", txindex.vSpent.size(), wtx.vout.size());
          continue;
        }
        for (unsigned int i = 0; i < txindex.vSpent.size(); i++)
        {
          if (wtx.IsSpent(i))
            continue;
          if (!txindex.vSpent[i].IsNull() && IsMine(wtx.vout[i]))
          {
            wtx.MarkSpent(i);
            fUpdated = true;
            vMissingTx.push_back(txindex.vSpent[i]);
          }
        }
        if (fUpdated)
        {
          printf("ReacceptWalletTransactions found spent coin %sbc %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
          wtx.MarkDirty();
          wtx.WriteToDisk();
        }
      }
      else
      {
        // Reaccept any txes of ours that aren't already in a block
        if (!wtx.IsCoinBase())
          wtx.AcceptWalletTransaction(txdb, false);
      }
    }
    if (!vMissingTx.empty())
    {
      // TODO: optimize this to scan just part of the block chain?
      if (ScanForWalletTransactions(TESTBlock::pindexGenesisBlock))
        fRepeat = true;  // Found missing transactions: re-do Reaccept.
    }
  }
}

int TESTWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0;

#if 0
    CBlockIndex* pindex = pindexStart;
    {
        LOCK(cs_wallet);
        while (pindex)
        {
            TESTBlock block;
            block.ReadFromDisk(pindex, true);
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }
            pindex = pindex->pnext;
        }
    }
#endif

    if (pindexStart)
      InitScanWalletTx(this, pindexStart->nHeight);

    return ret;
}

int64 TESTWallet::GetTxFee(CTransaction tx)
{
  map<uint256, CTxIndex> mapQueuedChanges;
  MapPrevTx inputs;
  int64 nFees;
  int i;

  if (tx.IsCoinBase())
    return (0);

  TESTTxDB txdb;

  nFees = 0;
  bool fInvalid = false;
  if (tx.FetchInputs(txdb, mapQueuedChanges, true, false, inputs, fInvalid))
    nFees += tx.GetValueIn(inputs) - tx.GetValueOut();

  txdb.Close();

  return (nFees);
}


bool TESTWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey)
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
       
    TESTTxDB txdb;
    bool ret = wtxNew.AcceptToMemoryPool(txdb);
    if (ret)
      wtxNew.RelayWalletTransaction(txdb);
    txdb.Close();
    if (!ret) {
      // This must not fail. The transaction has already been signed and recorded.
      printf("CommitTransaction() : Error: Transaction not valid");
      return false;
    }
  }
  return true;
}

bool TESTWallet::CreateTransaction(const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  int64 nValue = 0;

fprintf(stderr, "DEBUG: TESTWallet::CreateTransaction()\n");

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
    TESTTxDB txdb;
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
        if (nFeeRet < TEST_MIN_TX_FEE && nChange > 0 && nChange < CENT)
        {
          int64 nMoveToFee = min(nChange, TEST_MIN_TX_FEE - nFeeRet);
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
          if (!SignSignature(*this, *coin.first, wtxNew, nIn++)) {
            txdb.Close();
            return false;
          }

        // Limit size
        unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, TEST_PROTOCOL_VERSION);
        if (nBytes >= MAX_BLOCK_SIZE_GEN(iface)/5) {
          txdb.Close();
          return false;
        }
        dPriority /= nBytes;

        // Check that enough fee is included
        int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
        bool fAllowFree = CTransaction::AllowFree(dPriority);
        int64 nMinFee = wtxNew.GetMinFee(TEST_COIN_IFACE, 1, fAllowFree, GMF_SEND);
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
    txdb.Close();
  }
  return true;
}

bool TESTWallet::CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
    vector< pair<CScript, int64> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet);
}
