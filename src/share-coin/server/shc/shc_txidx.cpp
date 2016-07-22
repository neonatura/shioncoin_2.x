
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
#include "shc_block.h"
#include "shc_txidx.h"
#include "chain.h"
#include "spring.h"

#include <boost/array.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>

using namespace std;
using namespace boost;



bool SHCTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
  tx.SetNull();
  if (!ReadTxIndex(hash, txindex))
    return false;
  return (tx.ReadFromDisk(txindex.pos));
}

bool SHCTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
  CTxIndex txindex;
  return ReadDiskTx(hash, tx, txindex);
}

bool SHCTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
  return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool SHCTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
  CTxIndex txindex;
  return ReadDiskTx(outpoint.hash, tx, txindex);
}



CBlockIndex static * InsertBlockIndex(uint256 hash)
{

  if (hash == 0)
    return NULL;

  // Return existing
  blkidx_t *mapBlockIndex = GetBlockTable(SHC_COIN_IFACE);
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

typedef vector<CBlockIndex*> txlist;
bool shc_FillBlockIndex(txlist& vMatrix, txlist& vSpring, txlist& vCert)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  bc_t *bc = GetBlockChain(iface);
  CBlockIndex *pindexBest;
  CBlockIndex *lastIndex;
  SHCBlock block;
  uint256 hash;
  int nBestIndex;
  int nHeight;

  int nMaxIndex = bc_idx_next(bc) - 1;
  for (nBestIndex = 0; nBestIndex <= nMaxIndex; nBestIndex++) {
    if (0 != bc_idx_get(bc, nBestIndex, NULL))
      break;
  }
  nBestIndex--;

  lastIndex = NULL;
  pindexBest = NULL;
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
      SHCBlock::pindexGenesisBlock = pindexNew;

    if (!pindexBest && lastIndex) {
      if (lastIndex->pprev == pindexNew)
        pindexBest = lastIndex;
    }

    BOOST_FOREACH(CTransaction& tx, block.vtx) {
      if (tx.IsCoinBase() &&
          tx.isFlag(CTransaction::TXF_MATRIX)) {
        int mode;
        if (VerifyMatrixTx(tx, mode)) {
          if (mode == OP_EXT_VALIDATE)
            vMatrix.push_back(pindexNew);
          else if (mode == OP_EXT_PAY)
            vSpring.push_back(pindexNew);
        }
      }
      if (tx.isFlag(CTransaction::TXF_CERTIFICATE)) {
        if (VerifyCert(tx))
          vCert.push_back(pindexNew);
      }
    }

    lastIndex = pindexNew;
  }
  SetBestBlockIndex(iface, pindexBest);

  return true;
}

static bool hasGenesisRoot(CBlockIndex *pindexBest)
{
  CBlockIndex *pindex;

  for (pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev) {
    if (pindex->nHeight == 0)
      break;
  }
  if (!pindex)
    return (false);

  if (pindex->nHeight != 0 || 
      pindex->GetBlockHash() != shc_hashGenesisBlock)
    return (false);

  return (true);
}

bool SHCTxDB::LoadBlockIndex()
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  blkidx_t *mapBlockIndex = GetBlockTable(SHC_COIN_IFACE);
  char errbuf[1024];


#if 0
  if (!LoadBlockIndexGuts())
    return false;
#endif
  txlist vSpring;
  txlist vMatrix;
  txlist vCert;
  if (!shc_FillBlockIndex(vMatrix, vSpring, vCert))
    return (false);

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

  // Load SHCBlock::hashBestChain pointer to end of best chain
  uint256 hashBestChain;
  if (!ReadHashBestChain(hashBestChain))
  {
    if (SHCBlock::pindexGenesisBlock == NULL) {
      fprintf(stderr, "DEBUG: SHCTxDB::LoadBlockIndex() : SHCBlock::hashBestChain not loaded, but pindexGenesisBlock == NULL");
      return true;
    }
    //    return error(SHERR_INVAL, "SHCTxDB::LoadBlockIndex() : SHCBlock::hashBestChain not loaded");
  }
#if 0
  if (!mapBlockIndex->count(hashBestChain)) {
    CBlockIndex *pindexBest = GetBestBlockIndex(iface);
    if (!pindexBest)
      return error(SHERR_INVAL, "SHCTxDB::LoadBlockIndex() : SHCBlock::hashBestChain not found in the block index");
    fprintf(stderr, "DEBUG: SHC:LoadBlockIndex: falling back to highest block height %d\n", pindexBest->nHeight);
    hashBestChain = pindexBest->GetBlockHash();
  }
#endif

  CBlockIndex *pindexBest = (*mapBlockIndex)[hashBestChain];
  bool ok = true;
  if (!pindexBest)
    ok = false;
  else if (pindexBest->nHeight > 0 && !pindexBest->pprev)
    ok = false;
  else if (!hasGenesisRoot(pindexBest))
    ok = false;
  if (!ok) {
    pindexBest = GetBestBlockIndex(iface);
    if (!pindexBest)
      return error(SHERR_INVAL, "SHCTxDB::LoadBlockIndex() : SHCBlock::hashBestChain not found in the block index");
    fprintf(stderr, "DEBUG: LoadBlockIndex: falling back to highest block height %d\n", pindexBest->nHeight);
    hashBestChain = pindexBest->GetBlockHash();
  }


//  fprintf(stderr, "DEBUG: SHCTxDB::LoadBlockIndex: info: verifying hashBestChain '%s'\n", (hashBestChain).GetHex().c_str());

  if (!pindexBest) {
    fprintf(stderr, "DEBUG: SHCTxDB::LoadBlockIndex: error: hashBestChain '%s' not found in block index table\n", (hashBestChain).GetHex().c_str());
  }

  SetBestBlockIndex(SHC_COIN_IFACE, pindexBest);
  //  SetBestHeight(iface, pindexBest->nHeight);
  SHCBlock::bnBestChainWork = pindexBest->bnChainWork;
  pindexBest->pnext = NULL;

  //printf("LoadBlockIndex(): SHCBlock::hashBestChain=%s  height=%d  date=%s\n", hashBestChain.ToString().substr(0,20).c_str(), GetBestHeight(iface), DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

  // Load bnBestInvalidWork, OK if it doesn't exist
  ReadBestInvalidWork(SHCBlock::bnBestInvalidWork);

#if 0
  // Verify blocks in the best chain
  int nCheckLevel = GetArg("-checklevel", 1);
  int nCheckDepth = GetArg( "-checkblocks", 10000);
  if (nCheckDepth == 0)
    nCheckDepth = 1000000000; // suffices until the year 19000
  if (nCheckDepth > GetBestHeight(SHC_COIN_IFACE))
    nCheckDepth = GetBestHeight(SHC_COIN_IFACE);
  printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
#endif

  int nCheckDepth = (GetBestHeight(SHC_COIN_IFACE) / 100) + 2500;
  int total = 0;
  int invalid = 0;
  int maxHeight = 0;
  int checkHeight = pindexBest->nHeight;

  CBlockIndex* pindexFork = NULL;
  map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
  for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
  {
    if (fRequestShutdown || pindex->nHeight < GetBestHeight(SHC_COIN_IFACE) - nCheckDepth)
      break;
    SHCBlock block;
    if (!block.ReadFromDisk(pindex)) {
      fprintf(stderr, "DEBUG: SHCBlock::LoadBlockIndex() : block.ReadFromDisk failed");
      pindexFork = pindex->pprev;
      continue;
    }
    total++;

    if (!block.CheckBlock() ||
        !block.CheckTransactionInputs(SHC_COIN_IFACE)) {
      error (SHERR_INVAL, "(shc) LoadBlockIndex: critical: found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());

      pindexFork = pindex->pprev;
      invalid++;
      continue;
    }

    if (pindex->nHeight > maxHeight)
      maxHeight = pindex->nHeight;
    if (pindex->nHeight < checkHeight)
      checkHeight = pindex->nHeight;
  }
  if (pindexFork && !fRequestShutdown)
  {
    // Reorg back to the fork
    fprintf(stderr, "DEBUG: LoadBlockIndex() : *** moving best chain pointer back to block %d '%s'\n", pindexFork->nHeight, pindexFork->GetBlockHash().GetHex().c_str());
    SHCBlock block;
    if (!block.ReadFromDisk(pindexFork))
      return error(SHERR_INVAL, "LoadBlockIndex() : block.ReadFromDisk failed");
    SHCTxDB txdb;
    block.SetBestChain(txdb, pindexFork);
    txdb.Close();

    pindexBest = pindexFork;
  }

  maxHeight++;
  sprintf(errbuf, "SHC::LoadBlockIndex: Verified %-2.2f%% of %d total blocks: %d total invalid blocks found.", (double)(100 / (double)maxHeight * (double)total), maxHeight, invalid);
  unet_log(SHC_COIN_IFACE, errbuf);

  CWallet *wallet = GetWallet(SHC_COIN_IFACE);
  InitServiceWalletEvent(wallet, checkHeight);

  /* Block-chain Validation Matrix */
  BOOST_FOREACH(CBlockIndex *pindex, vMatrix) {
    if (pindex->nHeight > pindexBest->nHeight)
      break;
    shc_Validate.Append(pindex->nHeight, pindex->GetBlockHash()); 
  }

  /* Spring Matrix */
  BOOST_FOREACH(CBlockIndex *pindex, vSpring) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    if (!block) continue;

    CTransaction id_tx;
    const CTransaction& m_tx = block->vtx[0];
    if (GetTxOfIdent(iface, m_tx.matrix.hRef, id_tx)) {
      shnum_t lat, lon;

      /* mark location as claimed */
      CIdent& ident = (CIdent&)id_tx.certificate;
      shgeo_loc(&ident.geo, &lat, &lon, NULL);
      spring_loc_claim(lat, lon);
    }

    delete block;
  }

  BOOST_FOREACH(CBlockIndex *pindex, vCert) {
    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    BOOST_FOREACH(CTransaction& tx, block->vtx) {
      if (IsCertTx(tx))
        InsertCertTable(iface, tx);
    }
    delete block;
  }

  return true;
}


#if 0
bool SHCTxDB::LoadBlockIndexGuts()
{
  blkidx_t *mapBlockIndex = GetBlockTable(SHC_COIN_IFACE);

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
        if (SHCBlock::pindexGenesisBlock == NULL && diskindex.GetBlockHash() == shc_hashGenesisBlock) {
          SHCBlock::pindexGenesisBlock = pindexNew;
fprintf(stderr, "DEBUG: initialized SHCBlock::pindexGenesisBlock (%s)\n", (SHCBlock::pindexGenesisBlock)->GetBlockHash().GetHex().c_str());
}

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


bool shc_InitBlockIndex()
{
  bool ret;

  SHCTxDB txdb("cr");
  ret = txdb.LoadBlockIndex();
  txdb.Close();
  if (!ret)
    return (false);

  if (!shc_CreateGenesisBlock())
    return (false);

  return (true);
}
