
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
#include "usde_block.h"
#include "usde_txidx.h"

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
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>


using namespace std;
using namespace boost;

bool USDETxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
  tx.SetNull();
  if (!ReadTxIndex(hash, txindex))
    return false;
  return (tx.ReadFromDisk(txindex.pos));
}

bool USDETxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
  CTxIndex txindex;
  return ReadDiskTx(hash, tx, txindex);
}

bool USDETxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
  return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool USDETxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
  CTxIndex txindex;
  return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool USDETxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
  return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}


CBlockIndex static * InsertBlockIndex(uint256 hash)
{

  if (hash == 0)
    return NULL;

  // Return existing
  blkidx_t *mapBlockIndex = GetBlockTable(USDE_COIN_IFACE);
  map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex->find(hash);
  if (mi != mapBlockIndex->end())
    return (*mi).second;

  // Create new
  CBlockIndex* pindexNew = new CBlockIndex();
  if (!pindexNew)
    throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
  mi = mapBlockIndex->insert(make_pair(hash, pindexNew)).first;
  pindexNew->phashBlock = &((*mi).first);

  return pindexNew;
}

bool USDETxDB::LoadBlockIndex()
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  blkidx_t *mapBlockIndex = GetBlockTable(USDE_COIN_IFACE);

  if (!LoadBlockIndexGuts())
    return false;

  if (fRequestShutdown)
    return true;

  // Calculate bnChainWork
  vector<pair<int, CBlockIndex*> > vSortedByHeight;
  vSortedByHeight.reserve(mapBlockIndex->size());
  BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, (*mapBlockIndex))
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

  // Load USDEBlock::hashBestChain pointer to end of best chain
  if (!ReadHashBestChain(USDEBlock::hashBestChain))
  {
    if (USDEBlock::pindexGenesisBlock == NULL)
      return true;
    return error(SHERR_INVAL, "USDETxDB::LoadBlockIndex() : USDEBlock::hashBestChain not loaded");
  }
  if (!mapBlockIndex->count(USDEBlock::hashBestChain))
    return error(SHERR_INVAL, "USDETxDB::LoadBlockIndex() : USDEBlock::hashBestChain not found in the block index");
  
 CBlockIndex *pindexBest = (*mapBlockIndex)[USDEBlock::hashBestChain];


  SetBestBlockIndex(USDE_COIN_IFACE, pindexBest);
  SetBestHeight(iface, pindexBest->nHeight);
  USDEBlock::bnBestChainWork = pindexBest->bnChainWork;

  printf("LoadBlockIndex(): USDEBlock::hashBestChain=%s  height=%d  date=%s\n",
      USDEBlock::hashBestChain.ToString().substr(0,20).c_str(), GetBestHeight(USDE_COIN_IFACE),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

  // Load bnBestInvalidWork, OK if it doesn't exist
  ReadBestInvalidWork(USDEBlock::bnBestInvalidWork);

  // Verify blocks in the best chain
  int nCheckLevel = GetArg("-checklevel", 1);
  int nCheckDepth = GetArg( "-checkblocks", 2500);
  if (nCheckDepth == 0)
    nCheckDepth = 1000000000; // suffices until the year 19000
  if (nCheckDepth > GetBestHeight(USDE_COIN_IFACE))
    nCheckDepth = GetBestHeight(USDE_COIN_IFACE);
  printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
  CBlockIndex* pindexFork = NULL;
  map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
  for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
  {
    if (fRequestShutdown || pindex->nHeight < GetBestHeight(USDE_COIN_IFACE) - nCheckDepth)
      break;
    USDEBlock block;
    if (!block.ReadFromDisk(pindex))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");
    // check level 1: verify block validity
    if (nCheckLevel>0 && !block.CheckBlock())
    {
      printf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
      pindexFork = pindex->pprev;
    }
#if 0
    // check level 2: verify transaction index validity
    if (nCheckLevel>1)
    {
      pair<unsigned int, unsigned int> pos = make_pair(pindex->nFile, pindex->nBlockPos);
      mapBlockPos[pos] = pindex;
      BOOST_FOREACH(const CTransaction &tx, block.vtx)
      {
        uint256 hashTx = tx.GetHash();
        CTxIndex txindex;
        if (ReadTxIndex(hashTx, txindex))
        {
          // check level 3: checker transaction hashes
          if (nCheckLevel>2 || pindex->nFile != txindex.pos.nFile || pindex->nBlockPos != txindex.pos.nBlockPos)
          {
            // either an error or a duplicate transaction
            CTransaction txFound;
            if (!txFound.ReadFromDisk(txindex.pos))
            {
              printf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString().c_str());
              pindexFork = pindex->pprev;
            }
            else
              if (txFound.GetHash() != hashTx) // not a duplicate tx
              {
                printf("LoadBlockIndex(): *** invalid tx position for %s\n", hashTx.ToString().c_str());
                pindexFork = pindex->pprev;
              }
          }
          // check level 4: check whether spent txouts were spent within the main chain
          unsigned int nOutput = 0;
          if (nCheckLevel>3)
          {
            BOOST_FOREACH(const CDiskTxPos &txpos, txindex.vSpent)
            {
              if (!txpos.IsNull())
              {
                pair<unsigned int, unsigned int> posFind = make_pair(txpos.nFile, txpos.nBlockPos);
                if (!mapBlockPos.count(posFind))
                {
                  printf("LoadBlockIndex(): *** found bad spend at %d, hashBlock=%s, hashTx=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str(), hashTx.ToString().c_str());
                  pindexFork = pindex->pprev;
                }
                // check level 6: check whether spent txouts were spent by a valid transaction that consume them
                if (nCheckLevel>5)
                {
                  CTransaction txSpend;
                  if (!txSpend.ReadFromDisk(txpos))
                  {
                    printf("LoadBlockIndex(): *** cannot read spending transaction of %s:%i from disk\n", hashTx.ToString().c_str(), nOutput);
                    pindexFork = pindex->pprev;
                  }
                  else if (!txSpend.CheckTransaction())
                  {
                    printf("LoadBlockIndex(): *** spending transaction of %s:%i is invalid\n", hashTx.ToString().c_str(), nOutput);
                    pindexFork = pindex->pprev;
                  }
                  else
                  {
                    bool fFound = false;
                    BOOST_FOREACH(const CTxIn &txin, txSpend.vin)
                      if (txin.prevout.hash == hashTx && txin.prevout.n == nOutput)
                        fFound = true;
                    if (!fFound)
                    {
                      printf("LoadBlockIndex(): *** spending transaction of %s:%i does not spend it\n", hashTx.ToString().c_str(), nOutput);
                      pindexFork = pindex->pprev;
                    }
                  }
                }
              }
              nOutput++;
            }
          }
        }
        // check level 5: check whether all prevouts are marked spent
        if (nCheckLevel>4)
        {
          BOOST_FOREACH(const CTxIn &txin, tx.vin)
          {
            CTxIndex txindex;
            if (ReadTxIndex(txin.prevout.hash, txindex))
              if (txindex.vSpent.size()-1 < txin.prevout.n || txindex.vSpent[txin.prevout.n].IsNull())
              {
                printf("LoadBlockIndex(): *** found unspent prevout %s:%i in %s\n", txin.prevout.hash.ToString().c_str(), txin.prevout.n, hashTx.ToString().c_str());
                pindexFork = pindex->pprev;
              }
          }
        }
      }
    }
#endif
  }
  if (pindexFork && !fRequestShutdown)
  {
    // Reorg back to the fork
    printf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->nHeight);
    USDEBlock block;
    if (!block.ReadFromDisk(pindexFork))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");
    USDETxDB txdb;
    block.SetBestChain(txdb, pindexFork);
  }

  return true;
}



bool USDETxDB::LoadBlockIndexGuts()
{
  blkidx_t *mapBlockIndex = GetBlockTable(USDE_COIN_IFACE);

  // Get database cursor
  Dbc* pcursor = GetCursor();
  if (!pcursor)
    return false;

  // Load mapBlockIndex
  unsigned int fFlags = DB_SET_RANGE;
  loop
  {
    // Read next record
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    if (fFlags == DB_SET_RANGE)
      ssKey << make_pair(string("blockindex"), uint256(0));
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
    int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
    fFlags = DB_NEXT;
    if (ret == DB_NOTFOUND)
      break;
    else if (ret != 0)
      return false;

    // Unserialize

    try {
      string strType;
      ssKey >> strType;
      if (strType == "blockindex" && !fRequestShutdown)
      {
        CDiskBlockIndex diskindex;
        ssValue >> diskindex;

        // Construct block index object
        CBlockIndex* pindexNew = InsertBlockIndex(diskindex.GetBlockHash());
        pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);
        pindexNew->pnext          = InsertBlockIndex(diskindex.hashNext);
#if 0
        pindexNew->nFile          = diskindex.nFile;
        pindexNew->nBlockPos      = diskindex.nBlockPos;
#endif
        pindexNew->nHeight        = diskindex.nHeight;
        pindexNew->nVersion       = diskindex.nVersion;
        pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
        pindexNew->nTime          = diskindex.nTime;
        pindexNew->nBits          = diskindex.nBits;
        pindexNew->nNonce         = diskindex.nNonce;

        // Watch for genesis block
        if (USDEBlock::pindexGenesisBlock == NULL && diskindex.GetBlockHash() == usde_hashGenesisBlock)
          USDEBlock::pindexGenesisBlock = pindexNew;

        if (!pindexNew->CheckIndex())
          return error(SHERR_INVAL, "LoadBlockIndex() : CheckIndex failed at %d", pindexNew->nHeight);
      }
      else
      {
        break; // if shutdown requested or finished loading block index
      }
    }    // try
    catch (std::exception &e) {
      return error(SHERR_INVAL, "%s() : deserialize error", __PRETTY_FUNCTION__);
    }
  }
  pcursor->close();

  return true;
}


bool usde_InitBlockIndex()
{
  bool ret;

  USDETxDB txdb("cr");
  ret = txdb.LoadBlockIndex();
  txdb.Close();
  if (!ret)
    return (false);

  if (!usde_CreateGenesisBlock())
    return (false);

  return (true);
}

