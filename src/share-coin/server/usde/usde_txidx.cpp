
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

bool usde_FillBlockIndex()
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(USDE_COIN_IFACE);
  bc_t *bc = GetBlockChain(iface);
  CBlockIndex *pindexBest;
  CBlockIndex *lastIndex;
  USDEBlock block;
  uint256 hash;
  int nBestIndex;
  int nHeight;

  lastIndex = NULL;
  pindexBest = NULL;
  nBestIndex = bc_idx_next(bc) - 1;
  for (nHeight = nBestIndex; nHeight >= 0; nHeight--) {
    if (!block.ReadBlock(nHeight))
      continue;
    hash = block.GetHash();

    CBlockIndex* pindexNew = InsertBlockIndex(blockIndex, hash);
    pindexNew->pprev = InsertBlockIndex(blockIndex, block.hashPrevBlock);
    if (lastIndex && lastIndex->pprev == pindexNew)
      pindexNew->pnext = InsertBlockIndex(blockIndex, lastIndex->GetBlockHash());   

    pindexNew->nHeight        = nHeight;
    pindexNew->nVersion       = block.nVersion;
    pindexNew->hashMerkleRoot = block.hashMerkleRoot;
    pindexNew->nTime          = block.nTime;
    pindexNew->nBits          = block.nBits;
    pindexNew->nNonce         = block.nNonce;

    if (!pindexNew->CheckIndex())
      return error(SHERR_INVAL, "LoadBlockIndex() : CheckIndex failed at height %d", pindexNew->nHeight);

    if (nHeight == 0)
      USDEBlock::pindexGenesisBlock = pindexNew;

    if (!pindexBest && lastIndex) {
      if (lastIndex->pprev == pindexNew)
        pindexBest = lastIndex;
    }

    lastIndex = pindexNew;
  }
  SetBestBlockIndex(iface, pindexBest);

  return true;
}

bool USDETxDB::LoadBlockIndex()
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  blkidx_t *mapBlockIndex = GetBlockTable(USDE_COIN_IFACE);
  char errbuf[1024];

#if 0
  if (!LoadBlockIndexGuts())
    return false;
#endif
  if (!usde_FillBlockIndex())
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
  uint256 hashBestChain;
  if (!ReadHashBestChain(hashBestChain))
  {
    if (USDEBlock::pindexGenesisBlock == NULL) {
      fprintf(stderr, "DEBUG: USDETxDB::LoadBlockIndex() : USDEBlock::hashBestChain not loaded\n");
      return true;
    }
    //    return error(SHERR_INVAL, "USDETxDB::LoadBlockIndex() : USDEBlock::hashBestChain not loaded");
  }

  CBlockIndex *pindexBest = (*mapBlockIndex)[hashBestChain];
  bool ok = true;
  if (!pindexBest)
    ok = false;
  else if (pindexBest->nHeight > 0 && !pindexBest->pprev)
    ok = false;
  else if (pindexBest->nHeight == 0 && pindexBest->GetBlockHash() != usde_hashGenesisBlock) 
    ok = false;
  if (!ok) {
    pindexBest = GetBestBlockIndex(iface);
    if (!pindexBest)
      return error(SHERR_INVAL, "USDETxDB::LoadBlockIndex() : USDEBlock::hashBestChain not found in the block index");
    fprintf(stderr, "DEBUG: LoadBlockIndex: falling back to highest block height %d\n", pindexBest->nHeight);
    hashBestChain = pindexBest->GetBlockHash();
  }

  if (!pindexBest) {
    fprintf(stderr, "DEBUG: USDETxDB::LoadBlockIndex: error: hashBestChain '%s' not found in block index table\n", (hashBestChain).GetHex().c_str());
  }



  SetBestBlockIndex(USDE_COIN_IFACE, pindexBest);
  //  SetBestHeight(iface, pindexBest->nHeight);
  USDEBlock::bnBestChainWork = pindexBest->bnChainWork;

  sprintf(errbuf, "USDE::LoadBlockIndex: hashBestChain=%s  height=%d  date=%s\n",
      hashBestChain.GetHex().c_str(), GetBestHeight(USDE_COIN_IFACE),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());
  unet_log(USDE_COIN_IFACE, errbuf);

  // Load bnBestInvalidWork, OK if it doesn't exist
  ReadBestInvalidWork(USDEBlock::bnBestInvalidWork);

#if 0
  // Verify blocks in the best chain
  int nCheckLevel = GetArg("-checklevel", 1);
  int nCheckDepth = GetArg( "-checkblocks", 10000);
  if (nCheckDepth == 0)
    nCheckDepth = 1000000000; // suffices until the year 19000
  if (nCheckDepth > GetBestHeight(USDE_COIN_IFACE))
    nCheckDepth = GetBestHeight(USDE_COIN_IFACE);
#endif

  int nCheckDepth = (GetBestHeight(USDE_COIN_IFACE) / 100) + 2500;
  int total = 0;
  int invalid = 0;
  int maxHeight = 0;

  CBlockIndex* pindexFork = NULL;
  map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
  for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
  {
    if (fRequestShutdown || pindex->nHeight < GetBestHeight(USDE_COIN_IFACE) - nCheckDepth)
      break;
    USDEBlock block;
    if (!block.ReadFromDisk(pindex))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");

    total++;
    // check level 1: verify block validity
    if (!block.CheckBlock())
    {
      fprintf(stderr, "DEBUG: LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().GetHex().c_str());
      pindexFork = pindex->pprev;
      invalid++;
      continue;
    }
    if (pindex->nHeight > maxHeight)
      maxHeight = pindex->nHeight;
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
    txdb.Close();

    pindexBest = pindexFork;
  }

  maxHeight++;
  sprintf(errbuf, "USDE::LoadBlockIndex: Verified %-2.2f%% of %d total blocks: %d total invalid blocks found.", (double)(100 / (double)maxHeight * (double)total), maxHeight, invalid);
  unet_log(USDE_COIN_IFACE, errbuf);

  return true;
}

#if 0
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
#endif


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

