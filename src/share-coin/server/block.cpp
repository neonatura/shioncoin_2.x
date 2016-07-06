
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
#include "block.h"
#include "db.h"
#include <vector>

using namespace std;

//map<uint256, CBlockIndex*> tableBlockIndex[MAX_COIN_IFACE];
blkidx_t tableBlockIndex[MAX_COIN_IFACE];
//vector <bc_t *> vBlockChain;

blkidx_t *GetBlockTable(int ifaceIndex)
{
#ifndef TEST_SHCOIND
  if (ifaceIndex == 0)
    return (NULL);
#endif
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  return (&tableBlockIndex[ifaceIndex]);
}


/**
 * Opens a specific database of block records.
 */
bc_t *GetBlockChain(CIface *iface)
{

  if (!iface->bc_block) {
    char name[4096];

    sprintf(name, "%s_block", iface->name);
    bc_open(name, &iface->bc_block);
  }

  return (iface->bc_block);
}

void CloseBlockChain(CIface *iface)
{
  if (iface->bc_block) {
    bc_close(iface->bc_block);
    iface->bc_block = NULL;
  }
  if (iface->bc_tx) {
    bc_close(iface->bc_tx);
    iface->bc_tx = NULL;
  }
}

/**
 * Opens a specific database of block references. 
 */
bc_t *GetBlockTxChain(CIface *iface)
{

  if (!iface->bc_tx) {
    char name[4096];

    sprintf(name, "%s_tx", iface->name);
    bc_open(name, &iface->bc_tx);
  }

  return (iface->bc_tx);
}

CBlockIndex *GetBlockIndexByHeight(int ifaceIndex, unsigned int nHeight)
{
  CBlockIndex *pindex;

  pindex = GetBestBlockIndex(ifaceIndex);
  while (pindex && pindex->pprev && pindex->nHeight > nHeight)
    pindex = pindex->pprev;

  return (pindex);
}


#if 0
bool BlockChainErase(CIface *iface, size_t nHeight)
{
  bc_t *bc = GetBlockChain(iface);
  int err;

#if 0
  err = bc_purge(bc, nHeight);
  if (err)
    return error(err, "TruncateBlockChain[%s]: error truncating @ height %d.", iface->name, nHeight);
  fprintf(stderr, "DEBUG: TruncateBlockChain[%s]: PURGE @ height %d\n", iface->name, nHeight);
#endif
  int idx;
  int bestHeight = bc_idx_next(bc) - 1;
  for (idx = bestHeight; idx >= nHeight; idx--) {
    err = bc_idx_clear(bc, idx);
    if (err)
      return error(err, "BlockChainErase: error clearing height %d.", (int)nHeight);
  }

  return (true);
}
#endif

#if 0
bool BlockTxChainErase(uint256 hash)
{
return (true);
}

bool BlockChainErase(CIface *iface, size_t nHeight)
{
  bc_t *bc = GetBlockChain(iface);
  int bestHeight;
  int err;
  int idx;

  bestHeight = bc_idx_next(bc) - 1;
  if (nHeight < 0 || nHeight > bestHeight)
    return (true);

  CBlock *block = GetBlockByHeight(nHeight);
  if (block) {
    BOOST_FOREACH(const CTransaction &tx, block.vtx) {
      BlockTxChainErase(tx.GetHash());
    }
  }

  err = bc_idx_clear(bc, nHeight);
  if (err)
    return error(err, "BlockChainErase: error clearing height %d.", (int)nHeight);

  return (true);
}
#endif

void FreeBlockTable(CIface *iface)
{
  blkidx_t *blockIndex;
  char errbuf[1024];
  size_t memsize;
  size_t count;
  int ifaceIndex = GetCoinIndex(iface);

  blockIndex = GetBlockTable(ifaceIndex);
  if (!blockIndex)
    return;

  vector<CBlockIndex *> removeList;
  BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, (*blockIndex)) 
  {
    CBlockIndex* pindex = item.second;
    removeList.push_back(pindex);
  }
  blockIndex->clear();

  count = 0;
  memsize = 0;
  BOOST_FOREACH(const CBlockIndex *pindex, removeList) 
  {
    memsize += sizeof(*pindex);
    count++;
    delete pindex;
  }

  sprintf(errbuf, "FreeBlockTable: deallocated %d records (%d bytes) in block-index.", count, memsize);
  unet_log(ifaceIndex, errbuf);

}

/**
 * Closes all open block record databases.
 */
void CloseBlockChains(void)
{
  CIface *iface;
  int idx;

  for (idx = 0; idx < MAX_COIN_IFACE; idx++) {
#ifndef TEST_SHCOIND
    if (idx == 0) continue;
#endif

    iface = GetCoinByIndex(idx);
    if (!iface)
      continue;

    FreeBlockTable(iface);
    CloseBlockChain(iface);
  }
}

#if 0
bc_t *GetBlockChain(char *name)
{
  bc_t *bc;

  for(vector<bc_t *>::iterator it = vBlockChain.begin(); it != vBlockChain.end(); ++it) {
    bc = *it;
    if (0 == strcmp(bc_name(bc), name))
      return (bc);
  }

  bc_open(name, &bc);
  vBlockChain.push_back(bc);

  return (bc);
}

/**
 * Closes all open block record databases.
 */
void CloseBlockChains(void)
{
  bc_t *bc;

  for(vector<bc_t *>::iterator it = vBlockChain.begin(); it != vBlockChain.end(); ++it) {
    bc_t *bc = *it;
    bc_close(bc);
  }
  vBlockChain.clear();

}
#endif


int64 GetInitialBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = 4000 * COIN;

  if ((nHeight % 100) == 1)
  {
    nSubsidy = 100000 * COIN; //100k
  }else if ((nHeight % 50) == 1)
  {
    nSubsidy = 50000 * COIN; //50k
  }else if ((nHeight % 20) == 1)
  {
    nSubsidy = 20000 * COIN; //20k
  }else if ((nHeight % 10) == 1)
  {
    nSubsidy = 10000 * COIN; //10k
  }else if ((nHeight % 5) == 1)
  {
    nSubsidy = 5000 * COIN; //5k
  }

  //limit first blocks to protect against instamine.
  if (nHeight < 2){
    nSubsidy = 24000000 * COIN; // 1.5%
  }else if(nHeight < 500)
  {
    nSubsidy = 100 * COIN;
  }
  else if(nHeight < 1000)
  {
    nSubsidy = 500 * COIN;
  }

  nSubsidy >>= (nHeight / 139604);

  return (nSubsidy + nFees);
}

#if 0
int64 GetBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = 4000 * COIN;
  int base = nHeight;

  if (nHeight < 107500) {
    return (GetInitialBlockValue(nHeight, nFees));
  }

#if CLIENT_VERSION_REVISION > 4
  if (nHeight >= 1675248) {
    /* transition from 1.6bil cap to 1.6tril cap. */
    base /= 9;
  }
#endif

  nSubsidy >>= (base / 139604);

#if CLIENT_VERSION_REVISION > 4
  if (nHeight >= 1675248) {
    /* balance flux of reward. reduces max coin cap to 320bil */
    nSubsidy /= 5;
  }
#endif

  return nSubsidy + nFees;
}
#endif

const CTransaction *CBlock::GetTx(uint256 hash)
{
  BOOST_FOREACH(const CTransaction& tx, vtx)
    if (tx.GetHash() == hash)
      return (&tx);
  return (NULL);
}


bool CTransaction::WriteTx(int ifaceIndex, uint64_t blockHeight)
{
  bc_t *bc = GetBlockTxChain(GetCoinByIndex(ifaceIndex));
  uint256 hash = GetHash();
  char errbuf[1024];
  uint64_t blockPos;
  int txPos;
  int err;

  if (!bc) {
    unet_log(ifaceIndex, "CTransaction::WriteTx: error opening tx chain.");
    return (false);
  }

  err = bc_idx_find(bc, hash.GetRaw(), NULL, &txPos);
  if (!err) { /* exists */
    unsigned char *data;
    size_t data_len;

    err = bc_get(bc, txPos, &data, &data_len);
    if (!err) {
      if (data_len == sizeof(uint64_t)) {
        memcpy(&blockPos, data, sizeof(blockHeight));
        if (blockPos == blockHeight)
          return (true); /* and all is good */
      }
      free(data);

#if 0
      err = bc_idx_clear(bc, txPos);
      if (err)
        return error(err, "WriteTx; error clearing invalid previous hash tx [tx-idx-size %d] [tx-pos %d].", (int)data_len, (int)txPos);
fprintf(stderr, "DEBUG: WriteTx; CLEAR: cleared tx pos %u\n", (unsigned int)txPos);
#endif
    }
  }
#if 0
  if (0 == bc_idx_find(bc, hash.GetRaw(), NULL, NULL)) {
    /* transaction reference exists */
    return (true);
  }
#endif

  /* reference block height */
  err = bc_append(bc, hash.GetRaw(), &blockHeight, sizeof(blockHeight));
  if (err < 0) {
    sprintf(errbuf, "CTransaction::WriteTx: error writing block reference: %s.", sherrstr(err));
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

//fprintf(stderr, "DEBUG: CTransaction::WriteTx[iface #%d]: wrote tx '%s' for block #%d\n", ifaceIndex, hash.GetHex().c_str(), (int)blockHeight);
  return (true);
}

bool CTransaction::ReadTx(int ifaceIndex, uint256 txHash)
{
  return (ReadTx(ifaceIndex, txHash, NULL));
}

bool CTransaction::ReadTx(int ifaceIndex, uint256 txHash, uint256 *hashBlock)
{
  CIface *iface;
  bc_t *bc;
  char errbuf[1024];
  unsigned char *data;
  uint64_t blockHeight;
  size_t data_len;
  int txPos;
  int err;

  SetNull();

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface) {
    sprintf(errbuf, "CTransaction::ReadTx: unable to obtain iface #%d.", ifaceIndex); 
    return error(SHERR_INVAL, errbuf);
  }

  bc = GetBlockTxChain(iface);
  if (!bc) { 
    return error(SHERR_INVAL, "CTransaction::ReadTx: unable to open block tx database."); 
  }

  err = bc_idx_find(bc, txHash.GetRaw(), NULL, &txPos); 
  if (err) {
//fprintf(stderr, "DEBUG: CTransaction::ReadTx[iface #%d]: INFO: tx hash '%s' not found. [tot-tx:%d] [err:%d]\n", ifaceIndex, txHash.GetHex().c_str(), bc_idx_next(bc), err);
    return (false); /* not an error condition */
}

  err = bc_get(bc, txPos, &data, &data_len);
  if (err) {
    sprintf(errbuf, "CTransaction::ReadTx: tx position %d not found.", txPos);
    return error(err, errbuf);
  }
  if (data_len != sizeof(uint64_t)) {
    sprintf(errbuf, "CTransaction::ReadTx: block reference has invalid size (%d).", data_len);
    return error(SHERR_INVAL, errbuf);
  }
  memcpy(&blockHeight, data, sizeof(blockHeight));
  free(data);

  CBlock *block = GetBlankBlock(iface);
  if (!block) { 
    return error(SHERR_NOMEM, 
        "CTransaction::ReadTx: error allocating new block\n");
  }
  if (!block->ReadBlock(blockHeight)) {
    delete block;
    return error(SHERR_NOENT, "CTransaction::ReadTx: block height %d not valid.", blockHeight);
  }

  const CTransaction *tx = block->GetTx(txHash);
  if (!tx) {
    sprintf(errbuf, "CTransaction::ReadTx: block height %d does not contain tx.", blockHeight);
    delete block;
    return error(SHERR_INVAL, errbuf);
  }

  if (hashBlock) {
    *hashBlock = block->GetHash();
    if (*hashBlock == 0) {
      fprintf(stderr, "DEBUG: ReadTx: invalid hash 0 \n");
    }
  }

  Init(*tx);
  delete block;

  return (true);
}

bool CTransaction::ReadFromDisk(CDiskTxPos pos)
{
  int ifaceIndex = pos.nFile;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *tx_bc = GetBlockTxChain(iface);
  bc_t *bc = GetBlockChain(iface);
  CBlock *block;
  bc_hash_t b_hash;
  char errbuf[1024];
  uint256 hashTx;
  int err;

  if (!iface || ifaceIndex < 1 || ifaceIndex >= MAX_COIN_IFACE) {
    sprintf(errbuf, "CTransaction::ReadTx: error obtaining coin iface #%d\n", (int)pos.nFile);
    return error(SHERR_INVAL, errbuf);
  }

  err = bc_get_hash(tx_bc, pos.nTxPos, b_hash);
  if (err) {
    sprintf(errbuf, "CTransaction::ReadTx: error obtaining tx index #%u\n", (unsigned int)pos.nTxPos);
    return error(err, errbuf);
  }
  hashTx.SetRaw(b_hash);

  unsigned int nHeight = (unsigned int)pos.nBlockPos;
  block = GetBlockByHeight(iface, nHeight);
  if (!block) {
    sprintf(errbuf, "CTransaction::ReadTx: error obtaining block height %u.", nHeight);
    return error(SHERR_INVAL, errbuf);
  }

  const CTransaction *tx = block->GetTx(hashTx);
  if (!tx) {
    sprintf(errbuf, "CTransaction::ReadTx: block height %d '%s' does not contain tx '%s'.", nHeight, block->GetHash().GetHex().c_str(), hashTx.GetHex().c_str());
    delete block;
    return error(SHERR_INVAL, errbuf);
  }

  Init(*tx);
  delete block;

  if (!CheckTransaction(ifaceIndex)) {
    sprintf(errbuf, "CTransaction::ReadTx: invalid transaction '%s' for block height %d\n", hashTx.GetHex().c_str(), nHeight);
    return error(SHERR_INVAL, errbuf);
  } 

  return (true);
}
#if 0
bool CTransaction::ReadFromDisk(CDiskTxPos pos)
{
  int ifaceIndex = pos.nFile;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *tx_bc = GetBlockTxChain(iface);
  bc_t *bc = GetBlockChain(iface);
  bc_hash_t b_hash;
  char errbuf[1024];
  uint256 hash;
  int err;

  if (!iface) {
    sprintf(errbuf, "CTransaction::ReadTx: error obtaining coin iface #%d\n", (int)pos.nFile);
    return error(SHERR_INVAL, errbuf);
  }

  err = bc_get_hash(tx_bc, pos.nTxPos, b_hash);
  if (err) {
    sprintf(errbuf, "CTransaction::ReadTx: error obtaining tx index #%u\n", (unsigned int)pos.nTxPos);
    return error(err, errbuf);
  }

  hashTx.SetRaw(b_hash);
  CBlock *block = GetBlockByTx(iface, hash);
  if (!block) {
    sprintf(errbuf, "CTransaction::ReadTx: error obtaining block by tx\n");
    return error(SHERR_INVAL, errbuf);
}

  const CTransaction *tx = block->GetTx(hash);
  if (!tx) {
    sprintf(errbuf, "CTransaction::ReadTx: block '%s' does not contain tx '%s'.", block->GetHash().GetHex().c_str(), hash.GetHex().c_str());
  delete block;
    return error(SHERR_INVAL, errbuf);
  }

  Init(*tx);
  delete block;

  if (!tx->CheckTransaction(ifaceIndex)) {
//bc_idx_clear(tx_bc, pos.nTxPos);
return error(SHERR_INVAL, "ReadFromDisk(TxPos): invalid transaction '%s'\n", hash.GetHex().c_str());
 } 

  return (true);
}
#endif

#if 0 
bool CTransaction::FillTx(int ifaceIndex, CDiskTxPos &pos)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockTxChain(iface);
  bc_hash_t b_hash;
  char errbuf[1024];
  unsigned char *data;
  uint64_t blockHeight;
  size_t data_len;
  int t_pos;
  int err;

  pos.nFile = ifaceIndex;

  memcpy(b_hash, GetHash().GetRaw(), sizeof(bc_hash_t));
  err = bc_find(bc, b_hash, &t_pos);
  if (err)
    return (false);
  pos.nTxPos = t_pos; 

  err = bc_get(bc, pos.nTxPos, &data, &data_len);
  if (data_len != sizeof(uint64_t)) {
    sprintf(errbuf, "CTransaction::ReadTx: tx position %d not found.", pos.nTxPos);
    unet_log(ifaceIndex, errbuf);
    return (false);
  }
  memcpy(&blockHeight, data, sizeof(blockHeight));
  free(data);
  pos.nBlockPos = blockHeight;

  return (true);
}
#endif


#if 0
CBlock *GetBlockTemplate(int ifaceIndex)
{
  static CBlockIndex* pindexPrev;
  static unsigned int work_id;
  static time_t last_reset_t;
  CWallet *wallet = GetWallet(ifaceIndex);
  CBlock* pblock;
  int reset;

  if (!wallet) {
    unet_log(ifaceIndex, "GetBlocKTemplate: Wallet not initialized.");
    return (NULL);
  }

  CReserveKey reservekey(wallet);

  // Store the pindexBest used before CreateNewBlock, to avoid races
  CBlockIndex* pindexPrevNew = pindexBest;

  pblock = CreateNewBlock(reservekey);
 
  // Need to update only after we know CreateNewBlock succeeded
  pindexPrev = pindexPrevNew;

  pblock->UpdateTime(pindexPrev);
  pblock->nNonce = 0;

  return (pblock);
}
#endif




#if 0
extern CCriticalSection cs_main;
/** Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock */
bool GetTransaction(CIface *iface, const uint256 &hash, CTransaction &tx, uint256 &hashBlock)
{
  int ifaceIndex = GetCoinIndex(iface);
  {
    LOCK(cs_main);
    {
      LOCK(mempool.cs);
      if (mempool.exists(hash))
      {
        tx = mempool.lookup(hash);
        return true;
      }
    }

    if (tx.ReadTx(GetCoinIndex(iface), hash, hashBlock)) {
      fprintf(stderr, "DEBUG: GetTransaction: OK: read tx chain '%s'\n", tx.GetHash().GetHex().c_str());
      return (true);
    }
    fprintf(stderr, "DEBUG: GetTransaction: WARNING: using C++ CTxIndex\n");

    CTxDB txdb(ifaceIndex, "r");
    CTxIndex txindex;
    if (tx.ReadFromDisk(txdb, COutPoint(hash, 0), txindex))
    {
      CBlock *block;

      iface->block_new(iface, &block); //      USDEBlock block;
      if (block->ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
        hashBlock = block->GetHash();
      txdb.Close();
      return true;
    }
    txdb.Close();
  }
  return false;
}
#endif

bool GetTransaction(CIface *iface, const uint256 &hash, CTransaction &tx, uint256 *hashBlock)
{
  return (tx.ReadTx(GetCoinIndex(iface), hash, hashBlock));
}

CBlock *GetBlockByHeight(CIface *iface, int nHeight)
{
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction tx;
  CBlock *block;
  int err;
  
  /* sanity */
  if (!iface)
    return (NULL);

  block = GetBlankBlock(iface);
  if (!block)
    return (NULL);

  if (!block->ReadBlock(nHeight))
    return (NULL);

  return (block);
}

CBlock *GetBlockByHash(CIface *iface, const uint256 hash)
{
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex;
  CBlockIndex *pindex;
  CTransaction tx;
  CBlock *block;
  int err;
  
  /* sanity */
  if (!iface)
    return (NULL);

  blockIndex = GetBlockTable(ifaceIndex);
  if (!blockIndex)
    return (NULL);

  if (blockIndex->count(hash) == 0)
    return (NULL);

  pindex = (*blockIndex)[hash];
  if (!pindex)
    return (NULL);

  /* generate block */
  block = GetBlankBlock(iface);
  if (!block)
    return (NULL);

  if (!block->ReadFromDisk(pindex))
    return (NULL);

  /* verify integrity */
  if (block->GetHash() != hash)
    return (NULL);

  return (block);
}

CBlock *GetArchBlockByHash(CIface *iface, const uint256 hash)
{
  CBlock *block;
  int err;
  
  /* sanity */
  if (!iface)
    return (NULL);

  /* generate block */
  block = GetBlankBlock(iface);
  if (!block)
    return (NULL);

  if (!block->ReadArchBlock(hash)) {
    delete block;
    return (NULL);
  }

  return (block);
}

CBlock *GetBlockByTx(CIface *iface, const uint256 hash)
{
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction tx;
  CBlock *block;
  uint256 hashBlock;

  /* sanity */
  if (!iface)
    return (NULL);

  /* figure out block hash */
  if (!tx.ReadTx(GetCoinIndex(iface), hash, &hashBlock))
    return (NULL);

  return (GetBlockByHash(iface, hashBlock));
}

CBlock *CreateBlockTemplate(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  CBlock *block;
  char errbuf[256];
  int err;

  if (!iface->op_block_templ)
    return (NULL);

  block = NULL;
  err = iface->op_block_templ(iface, &block); 
  if (err) {
    sprintf(errbuf, "CreateBlockTemplate: error creating block template: %s.", sherrstr(err));
    unet_log(ifaceIndex, errbuf);
  }

  return (block);
}

CTxMemPool *GetTxMemPool(CIface *iface)
{
  CTxMemPool *pool;
  int err;

  if (!iface->op_tx_pool) {
    int ifaceIndex = GetCoinIndex(iface);
    unet_log(ifaceIndex, "GetTxMemPool: error obtaining tx memory pool: Operation not supported.");
    return (NULL);
  }

  err = iface->op_tx_pool(iface, &pool);
  if (err) {
    int ifaceIndex = GetCoinIndex(iface);
    char errbuf[256];
    sprintf(errbuf, "GetTxMemPool: error obtaining tx memory pool: %s [sherr %d].", sherrstr(err), err);
    unet_log(ifaceIndex, errbuf);
    return (NULL);
  }

  return (pool);
}






bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  CIface *iface = GetCoinByIndex(pblock->ifaceIndex);
  int err;

  if (!iface)
    return (false);

  if (!iface->op_block_process)
    return error(SHERR_OPNOTSUPP, "ProcessBlock[%s]: no block process operation suported.", iface->name);

  /* trace whether remote host submitted block */
  pblock->originPeer = pfrom;

  err = iface->op_block_process(iface, pblock);
  if (err) {
    char errbuf[1024];

    sprintf(errbuf, "error processing incoming block: %s [sherr %d].", sherrstr(err), err); 
    unet_log(pblock->ifaceIndex, errbuf);
    return (false);
  }

  /* reward host for completing a block */
  pblock->trust(1, "healthy block processed");

  return (true);
}





bool CTransaction::ClientConnectInputs(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTxMemPool *pool;

  if (!iface) {
    unet_log(ifaceIndex, "error obtaining coin interface.");
    return (false);
  }

  pool = GetTxMemPool(iface);
  if (!pool) {
    unet_log(ifaceIndex, "error obtaining tx memory pool.");
    return (false);
  }

  if (IsCoinBase())
    return false;

  // Take over previous transactions' spent pointers
  {
    LOCK(pool->cs);
    int64 nValueIn = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
      // Get prev tx from single transactions in memory
      COutPoint prevout = vin[i].prevout;
      if (!pool->exists(prevout.hash))
        return false;
      CTransaction& txPrev = pool->lookup(prevout.hash);

      if (prevout.n >= txPrev.vout.size())
        return false;

      // Verify signature
      if (!VerifySignature(txPrev, *this, i, true, 0))
        return error(SHERR_INVAL, "ConnectInputs() : VerifySignature failed");

      ///// this is redundant with the mempool.mapNextTx stuff,
      ///// not sure which I want to get rid of
      ///// this has to go away now that posNext is gone
      // // Check for conflicts
      // if (!txPrev.vout[prevout.n].posNext.IsNull())
      //     return error("ConnectInputs() : prev tx already used");
      //
      // // Flag outpoints as used
      // txPrev.vout[prevout.n].posNext = posThisTx;

      nValueIn += txPrev.vout[prevout.n].nValue;

      if (!MoneyRange(ifaceIndex, txPrev.vout[prevout.n].nValue) || 
          !MoneyRange(ifaceIndex, nValueIn))
        return error(SHERR_INVAL, "ClientConnectInputs() : txin values out of range");
    }
    if (GetValueOut() > nValueIn)
      return false;
  }

  return true;
}



bool CBlockIndex::IsInMainChain(int ifaceIndex) const
{
  if (pnext)
    return (true);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface) return (false);
  CBlock *block = GetBlockByHash(iface, GetBlockHash()); 
  if (!block) return (false);
  bool ret = block->IsBestChain();
  delete block;
  return (ret);
} 


uint256 CBlockLocator::GetBlockHash()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 

  // Find the first block the caller has in the main chain
  BOOST_FOREACH(const uint256& hash, vHave)
  {
    std::map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hash);
    if (mi != blockIndex->end())
    {
      CBlockIndex* pindex = (*mi).second;
      if (pindex->IsInMainChain(ifaceIndex))
        return hash;
    }
  }
  return GetGenesisBlockHash(ifaceIndex);
}
#if 0
uint256 CBlockLocator::GetBlockHash()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 

  // Find the first block the caller has in the main chain
  BOOST_FOREACH(const uint256& hash, vHave)
  {
    std::map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hash);
    if (mi != blockIndex->end())
    {
      CBlockIndex* pindex = (*mi).second;
      if (pindex->IsInMainChain(ifaceIndex))
        return hash;
    }
  }

  CBlock *block = GetBlockByHeight(iface, 0);
  if (!block) {
    uint256 hash;
    return (hash);
  }
  uint256 hashBlock = block->GetHash();
  delete block;
  return hashBlock;
//  return block->hashGenesisBlock;
}
#endif


int CBlockLocator::GetHeight()
{
  CBlockIndex* pindex = GetBlockIndex();
  if (!pindex)
    return 0;
  return pindex->nHeight;
}


CBlockIndex* CBlockLocator::GetBlockIndex()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 

  // Find the first block the caller has in the main chain
  BOOST_FOREACH(const uint256& hash, vHave)
  {
    std::map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hash);
    if (mi != blockIndex->end())
    {
      CBlockIndex* pindex = (*mi).second;
      if (pindex->IsInMainChain(ifaceIndex))
        return pindex;
    }
  }

  return (GetGenesisBlockIndex(iface));
}


void CBlockLocator::Set(const CBlockIndex* pindex)
{
  vHave.clear();
  int nStep = 1;
  while (pindex)
  {
    vHave.push_back(pindex->GetBlockHash());

    // Exponentially larger steps back
    for (int i = 0; pindex && i < nStep; i++)
      pindex = pindex->pprev;
    if (vHave.size() > 10)
      nStep *= 2;
  }
  vHave.push_back(GetGenesisBlockHash(ifaceIndex));
}
#if 0
void CBlockLocator::Set(const CBlockIndex* pindex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  int nStep = 1;

  vHave.clear();
  while (pindex)
  {
    vHave.push_back(pindex->GetBlockHash());

    // Exponentially larger steps back
    for (int i = 0; pindex && i < nStep; i++)
      pindex = pindex->pprev;
    if (vHave.size() > 10)
      nStep *= 2;
  }

  /* all the way back */
  pindex = 
  CBlock *block = GetBlockByHeight(iface, 0);
  if (block) {
    uint256 hashBlock = block->GetHash();
    vHave.push_back(hashBlock);// hashGenesisBlock);
    delete block; 
  }
}
#endif



int CBlockLocator::GetDistanceBack()
{
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);

  // Retrace how far back it was in the sender's branch
  int nDistance = 0;
  int nStep = 1;
  BOOST_FOREACH(const uint256& hash, vHave)
  {
    std::map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hash);
    if (mi != blockIndex->end())
    {
      CBlockIndex* pindex = (*mi).second;
      if (pindex->IsInMainChain(ifaceIndex))
        return nDistance;
    }
    nDistance += nStep;
    if (nDistance > 10)
      nStep *= 2;
  }
  return nDistance;
}
#if 0
int CBlockLocator::GetDistanceBack()
{
  // Retrace how far back it was in the sender's branch
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
  int nDistance = 0;
  int nStep = 1;
  BOOST_FOREACH(const uint256& hash, vHave)
  {
    std::map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hash);
    if (mi != blockIndex->end())
    {
      CBlockIndex* pindex = (*mi).second;
      if (pindex->IsInMainChain(ifaceIndex))
        return nDistance;
    }
    nDistance += nStep;
    if (nDistance > 10)
      nStep *= 2;
  }
  return nDistance;
}
#endif



bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    SetNull();
    if (!txdb.ReadTxIndex(prevout.hash, txindexRet)) {
return error(SHERR_INVAL, "CTransaction::ReadFromDisk: ReadTxIndex failure");
        return false;
}
    if (!ReadFromDisk(txindexRet.pos)) {
return error(SHERR_INVAL, "CTransaction::ReadFromDisk: ReadFromDIsk(pos) failure");
        return false;
}
    if (prevout.n >= vout.size())
    {
        SetNull();
        return false;
    }
    return true;
}









#if 0
bool CTransaction::ConnectInputs(MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fStrictPayToScriptHash)
{
  // Take over previous transactions' spent pointers
  // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
  // fMiner is true when called from the internal usde miner
  // ... both are false when called from CTransaction::AcceptToMemoryPool
  if (!IsCoinBase())
  {
    int64 nValueIn = 0;
    int64 nFees = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
      COutPoint prevout = vin[i].prevout;
      assert(inputs.count(prevout.hash) > 0);
      CTxIndex& txindex = inputs[prevout.hash].first;
      CTransaction& txPrev = inputs[prevout.hash].second;

      if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
        return DoS(100, error(SHERR_INVAL, "ConnectInputs() : %s prevout.n out of range %d %d %d prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));

      // If prev is coinbase, check that it's matured
      if (txPrev.IsCoinBase())
        for (const CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < COINBASE_MATURITY; pindex = pindex->pprev)
          //if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
          if (pindex->nHeight == txindex.pos.nBlockPos)// && pindex->nFile == txindex.pos.nFile)
            return error(SHERR_INVAL, "ConnectInputs() : tried to spend coinbase at depth %d", pindexBlock->nHeight - pindex->nHeight);

      // Check for negative or overflow input values
      nValueIn += txPrev.vout[prevout.n].nValue;
      if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
        return DoS(100, error(SHERR_INVAL, "ConnectInputs() : txin values out of range"));

    }
    // The first loop above does all the inexpensive checks.
    // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
    // Helps prevent CPU exhaustion attacks.
    for (unsigned int i = 0; i < vin.size(); i++)
    {
      COutPoint prevout = vin[i].prevout;
      assert(inputs.count(prevout.hash) > 0);
      CTxIndex& txindex = inputs[prevout.hash].first;
      CTransaction& txPrev = inputs[prevout.hash].second;

      // Check for conflicts (double-spend)
      // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
      // for an attacker to attempt to split the network.
      if (!txindex.vSpent[prevout.n].IsNull())
        return fMiner ? false : error(SHERR_INVAL, "ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,10).c_str(), txindex.vSpent[prevout.n].ToString().c_str());

      // Skip ECDSA signature verification when connecting blocks (fBlock=true)
      // before the last blockchain checkpoint. This is safe because block merkle hashes are
      // still computed and checked, and any change will be caught at the next checkpoint.
      if (!(fBlock && (nBestHeight < Checkpoints::GetTotalBlocksEstimate())))
      {
        // Verify signature
        if (!VerifySignature(txPrev, *this, i, fStrictPayToScriptHash, 0))
        {
          // only during transition phase for P2SH: do not invoke anti-DoS code for
          // potentially old clients relaying bad P2SH transactions
          if (fStrictPayToScriptHash && VerifySignature(txPrev, *this, i, false, 0))
            return error(SHERR_INVAL, "ConnectInputs() : %s P2SH VerifySignature failed", GetHash().ToString().substr(0,10).c_str());

          return DoS(100,error(SHERR_INVAL, "ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
        }
      }

      // Mark outpoints as spent
      txindex.vSpent[prevout.n] = posThisTx;

      // Write back
      if (fBlock || fMiner)
      {
        mapTestPool[prevout.hash] = txindex;
      }
    }

    if (nValueIn < GetValueOut())
      return DoS(100, error(SHERR_INVAL, "ConnectInputs() : %s value in < value out", GetHash().ToString().substr(0,10).c_str()));

    // Tally transaction fees
    int64 nTxFee = nValueIn - GetValueOut();
    if (nTxFee < 0)
      return DoS(100, error(SHERR_INVAL, "ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,10).c_str()));
    nFees += nTxFee;
    if (!MoneyRange(nFees))
      return DoS(100, error(SHERR_INVAL, "ConnectInputs() : nFees out of range"));
  }

  return true;
}
#endif



#if 0
bool CTransaction::FetchInputs(int ifaceIndex, const map<uint256, CTxIndex>& mapTestPool, bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface) {
    unet_log(ifaceIndex, "error obtaining coin interface.");
    return (false);
  }

  // FetchInputs can return false either because we just haven't seen some inputs
  // (in which case the transaction should be stored as an orphan)
  // or because the transaction is malformed (in which case the transaction should
  // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
  fInvalid = false;

  if (IsCoinBase())
    return true; // Coinbase transactions have no inputs to fetch.

  for (unsigned int i = 0; i < vin.size(); i++)
  {
    COutPoint prevout = vin[i].prevout;
    if (inputsRet.count(prevout.hash))
      continue; // Got it already

    // Read txindex
    CTxIndex& txindex = inputsRet[prevout.hash].first;
    bool fFound = true;
    if ((fBlock || fMiner) && mapTestPool.count(prevout.hash))
    {
      // Get txindex from current proposed changes
      txindex = mapTestPool.find(prevout.hash)->second;
    }
    else
    {
      // Read txindex from txdb
      fFound = txdb.ReadTxIndex(prevout.hash, txindex);
    }
    if (!fFound && (fBlock || fMiner))
      return fMiner ? false : error(SHERR_INVAL, "FetchInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());

    // Read txPrev
    CTransaction& txPrev = inputsRet[prevout.hash].second;
    if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
    {
      CTxMemPool *pool = GetTxMemPool(iface);
      // Get prev tx from single transactions in memory
      if (pool) {
        LOCK(pool->cs);
        if (!pool->exists(prevout.hash))
          return error(SHERR_INVAL, "FetchInputs() : %s mempool Tx prev not found %s", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
        txPrev = pool->lookup(prevout.hash);
      }
      if (!fFound)
        txindex.vSpent.resize(txPrev.vout.size());
    }
    else
    {
      // Get prev tx from disk
      if (!txPrev.ReadFromDisk(txindex.pos))
        return error(SHERR_INVAL, "FetchInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
    }
  }

  // Make sure all prevout.n's are valid:
  for (unsigned int i = 0; i < vin.size(); i++)
  {
    const COutPoint prevout = vin[i].prevout;
    assert(inputsRet.count(prevout.hash) != 0);
    const CTxIndex& txindex = inputsRet[prevout.hash].first;
    const CTransaction& txPrev = inputsRet[prevout.hash].second;
    if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
    {
      // Revisit this if/when transaction replacement is implemented and allows
      // adding inputs:
      fInvalid = true;
      return DoS(100, error(SHERR_INVAL, "FetchInputs() : %s prevout.n out of range %d %d %d prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
    }
  }

  return true;
}
#endif

int GetBestHeight(CIface *iface)
{
  CBlockIndex *pindex = GetBestBlockIndex(iface);
  if (!pindex)
    return (-1);
  return (pindex->nHeight);
}
int GetBestHeight(int ifaceIndex)
{
  return (GetBestHeight(GetCoinByIndex(ifaceIndex)));
}

bool IsInitialBlockDownload(int ifaceIndex)
{
  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);

  if (pindexBest == NULL);// || nBestHeight < Checkpoints::GetTotalBlocksEstimate())
    return true;

  static int64 nLastUpdate;
  static CBlockIndex* pindexLastBest;
  if (pindexBest != pindexLastBest)
  {
    pindexLastBest = pindexBest;
    nLastUpdate = GetTime();
  }
  return (GetTime() - nLastUpdate < 15 &&
      pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60);
}

uint256 GetBestBlockChain(CIface *iface)
{
  uint256 hash;
  hash.SetRaw(iface->block_besthash);
  return (hash);
}

CBlockIndex *GetGenesisBlockIndex(CIface *iface) /* DEBUG: */
{
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
  if (!blockIndex)
    return (NULL);
  CBlock *block = GetBlockByHeight(iface, 0);
  if (!block)
    return (NULL);

  uint256 hash = block->GetHash();
  delete block;

  if (blockIndex->count(hash) == 0)
    return (NULL);

  CBlockIndex *pindex = (*blockIndex)[hash];
  return (pindex);
}

void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
  nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());
}

bool CTransaction::IsFinal(int ifaceIndex, int nBlockHeight, int64 nBlockTime) const
{
  // Time based nLockTime implemented in 0.1.6
  if (nLockTime == 0)
    return true;
  if (nBlockHeight == 0)
    nBlockHeight = GetBestHeight(ifaceIndex);
  if (nBlockTime == 0)
    nBlockTime = GetAdjustedTime();
  if ((int64)nLockTime < ((int64)nLockTime < LOCKTIME_THRESHOLD ? (int64)nBlockHeight : nBlockTime))
    return true;
  BOOST_FOREACH(const CTxIn& txin, vin)
    if (!txin.IsFinal())
      return false;
  return true;
}


void SetBestBlockIndex(CIface *iface, CBlockIndex *pindex)
{
  if (!pindex)
    return;
  uint256 hash = pindex->GetBlockHash();
  memcpy(iface->block_besthash, hash.GetRaw(), sizeof(bc_hash_t));
}
void SetBestBlockIndex(int ifaceIndex, CBlockIndex *pindex)
{
  SetBestBlockIndex(GetCoinByIndex(ifaceIndex), pindex);
}
CBlockIndex *GetBestBlockIndex(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
  uint256 hash;

  if (!blockIndex)
    return (NULL);

  hash.SetRaw(iface->block_besthash);
  if (blockIndex->count(hash) == 0)
    return (NULL);
  return ((*blockIndex)[hash]);
}
CBlockIndex *GetBestBlockIndex(int ifaceIndex)
{
  return (GetBestBlockIndex(GetCoinByIndex(ifaceIndex)));
}

#if 0
bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{

  // Check it again in case a previous version let a bad block in
  if (!CheckBlock())
    return false;

  // Do not allow blocks that contain transactions which 'overwrite' older transactions,
  // unless those are already completely spent.
  // If such overwrites are allowed, coinbases and transactions depending upon those
  // can be duplicated to remove the ability to spend the first instance -- even after
  // being sent to another address.
  // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
  // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
  // already refuses previously-known transaction id's entirely.
  // This rule applies to all blocks whose timestamp is after October 1, 2012, 0:00 UTC.
  int64 nBIP30SwitchTime = 1349049600;
  bool fEnforceBIP30 = (pindex->nTime > nBIP30SwitchTime);

  // BIP16 didn't become active until October 1 2012
  int64 nBIP16SwitchTime = 1349049600;
  bool fStrictPayToScriptHash = (pindex->nTime >= nBIP16SwitchTime);

  //// issue here: it doesn't know the version
  unsigned int nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - 1 + GetSizeOfCompactSize(vtx.size());

  map<uint256, CTxIndex> mapQueuedChanges;
  int64 nFees = 0;
  unsigned int nSigOps = 0;
  BOOST_FOREACH(CTransaction& tx, vtx)
  {
    uint256 hashTx = tx.GetHash();

    if (fEnforceBIP30) {
      CTxIndex txindexOld;
      if (txdb.ReadTxIndex(hashTx, txindexOld)) {
        BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent)
          if (pos.IsNull())
            return false;
      }
    }

    nSigOps += tx.GetLegacySigOpCount();
    if (nSigOps > MAX_BLOCK_SIGOPS)
      return DoS(100, error("ConnectBlock() : too many sigops"));

    CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
    nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

    MapPrevTx mapInputs;
    if (!tx.IsCoinBase())
    {
      bool fInvalid;
      if (!tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid))
        return false;

      if (fStrictPayToScriptHash)
      {
        // Add in sigops done by pay-to-script-hash inputs;
        // this is to prevent a "rogue miner" from creating
        // an incredibly-expensive-to-validate block.
        nSigOps += tx.GetP2SHSigOpCount(mapInputs);
        if (nSigOps > MAX_BLOCK_SIGOPS)
          return DoS(100, error("ConnectBlock() : too many sigops"));
      }

      nFees += tx.GetValueIn(mapInputs)-tx.GetValueOut();

      if (!tx.ConnectInputs(mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fStrictPayToScriptHash))
        return false;
    }

    mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
  }

  // Write queued txindex changes
  for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
  {
    if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
      return error("ConnectBlock() : UpdateTxIndex failed");
  }

  if (vtx[0].GetValueOut() > GetBlockValue(pindex->nHeight, nFees))
    return false;

  // Update block index on disk without changing it in memory.
  // The memory index structure will be changed after the db commits.
  if (pindex->pprev)
  {
    CDiskBlockIndex blockindexPrev(pindex->pprev);
    blockindexPrev.hashNext = pindex->GetBlockHash();
    if (!txdb.WriteBlockIndex(blockindexPrev))
      return error("ConnectBlock() : WriteBlockIndex failed");
  }

  // Watch for transactions paying to me
  BOOST_FOREACH(CTransaction& tx, vtx)
    SyncWithWallets(tx, this, true);

  return true;
}
#endif

CBlock *GetBlankBlock(CIface *iface)
{
  CBlock *block;
  int err;

  if (!iface || !iface->op_block_new)
    return (NULL);

  block = NULL;
  err = iface->op_block_new(iface, &block);
  if (err) {
    int ifaceIndex = GetCoinIndex(iface);
    char errbuf[1024];

    sprintf(errbuf, "GetBlankBlock: error generating fresh block: %s [sherr %d].", sherrstr(err), err);
    unet_log(ifaceIndex, errbuf); 
  }

  return (block);
}
#if 0
CBlock *GetBlankBlock(CIface *iface)
{
  int ifaceIndex = GetCoinIndex(iface);
  CBlock *block;

  block = NULL;
  switch (ifaceIndex) {
    case SHC_COIN_IFACE:
      block = new SHCBlock();
      break;
    case USDE_COIN_IFACE:
      block = new USDEBlock();
      break;
  }

  return (block);
}
#endif

/* DEBUG: TODO: faster to read via nHeight */
bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc;
  int nHeight;
  int err;

  if (!iface)
    return (false);

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  err = bc_find(bc, pindex->GetBlockHash().GetRaw(), &nHeight);
  if (err)
    return false;//error(err, "bc_find '%s' [height %d]", pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight);

  return (ReadBlock(nHeight));
}
#if 0
bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  char errbuf[1024];
  bool ok;

  if (!pindex)
    return (false);

  ok = ReadBlock(pindex->nHeight);
  if (!ok) {
    sprintf(errbuf, "CBlock::ReadFromDisk: error obtaining block height %d (hash '%s').", pindex->nHeight, pindex->GetBlockHash().GetHex().c_str());
    return error(SHERR_INVAL, errbuf);
  }

//  if (pindex->pprev && GetHash() != pindex->GetBlockHash())
  if (GetHash() != pindex->GetBlockHash()) {
    /* search deleted blocks */
//    ok = ReadArchBlock(pindex->GetBlockHash());
ok = false; /* DEBUG: */
    if (!ok) {
      sprintf(errbuf, "CBlock::ReadFromDisk: block hash '%s' does not match block index '%s' for height %d:", GetHash().GetHex().c_str(), pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight);
      return error(SHERR_INVAL, errbuf);
    }
fprintf(stderr, "DEBUG: ReadFromDisk: retrieved archived record.\n"); 
  }

#if 0 /* DEBUG: */
  if (!CheckBlock()) {
    unet_log(ifaceIndex, "CBlock::ReadFromDisk: block validation failure.");
    return (false);
  }
#endif
  
  return (true);
}
#endif

#if 0
bool CBlock::ReadBlock(uint64_t nHeight)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  size_t sBlockLen;
  unsigned char *sBlockData;
  char errbuf[1024];
  bc_t *bc;
  int err;

fprintf(stderr, "DEBUG: CBlock::ReadBlock/%s: loading height %d\n", iface->name, (int)nHeight);

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  err = bc_get(bc, nHeight, &sBlockData, &sBlockLen);
  if (err) {
    sprintf(errbuf, "CBlock::ReadBlock[height %d]: %s (sherr %d).",
      (int)nHeight, sherrstr(err), err);
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

  /* serialize binary data into block */
  sBlock.write((const char *)sBlockData, sBlockLen);
  sBlock >> *this;
  free(sBlockData);

    uint256 cur_hash = GetHash();
{
uint256 t_hash;
bc_hash_t b_hash;
memcpy(b_hash, cur_hash.GetRaw(), sizeof(bc_hash_t));
t_hash.SetRaw(b_hash);
if (!bc_hash_cmp(t_hash.GetRaw(), cur_hash.GetRaw())) {
fprintf(stderr, "DEBUG: ReadBlock: error comparing self-hash ('%s' / '%s')\n", cur_hash.GetHex().c_str(), t_hash.GetHex().c_str());
}
}
  {
    uint256 db_hash;
    bc_hash_t ret_hash;
    err = bc_get_hash(bc, nHeight, ret_hash);
    if (err) {
fprintf(stderr, "DEBUG: CBlock::ReadBlock: bc_get_hash err %d\n", err); 
      return (false);
    }
    db_hash.SetRaw((unsigned int *)ret_hash);

    if (!bc_hash_cmp(db_hash.GetRaw(), cur_hash.GetRaw())) {
fprintf(stderr, "DEBUG: CBlock::ReadBlock: hash '%s' from loaded block at pos %d has invalid hash of '%s'\n", db_hash.GetHex().c_str(), nHeight, cur_hash.GetHex().c_str());
print();
        SetNull();

  return (false);
    }
  }

  if (!CheckBlock()) {
    unet_log(ifaceIndex, "CBlock::ReadBlock: block validation failure.");
    return (false);
  }

fprintf(stderr, "DEBUG: CBlock::ReadBlock: GET retrieved pos (%d): hash '%s'\n", nHeight, GetHash().GetHex().c_str());

  return (true);
}
#endif

#if 0
bool CBlock::ReadBlock(uint64_t nHeight)
{
  switch (ifaceIndex) {
    case SHC_COIN_IFACE:
      {
        SHCBlock *block = (SHCBlock *)this;
        return (block->ReadBlock(nHeight));
      }
    case USDE_COIN_IFACE:
      {
        USDEBlock *block = (USDEBlock *)this;
        return (block->ReadBlock(nHeight));
      }
  }
  return (false);
}

bool CBlock::CheckBlock()
{
  switch (ifaceIndex) {
    case SHC_COIN_IFACE:
      {
        SHCBlock *block = (SHCBlock *)this;
        return (block->CheckBlock());
      }
    case USDE_COIN_IFACE:
      {
        USDEBlock *block = (USDEBlock *)this;
        return (block->CheckBlock());
      }
  }
  return (false);
}
#endif

bool CTransaction::CheckTransaction(int ifaceIndex) const
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface)
    return (false);

  // Basic checks that don't depend on any context
  if (vin.empty())
    return error(SHERR_INVAL, "CTransaction::CheckTransaction() : vin empty");
  if (vout.empty())
    return error(SHERR_INVAL, "CTransaction::CheckTransaction() : vout empty");
  // Size limits
  if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION(iface)) > iface->max_block_size)
    return error(SHERR_INVAL, "CTransaction::CheckTransaction() : size limits failed");

  // Check for negative or overflow output values
  int64 nValueOut = 0;
  BOOST_FOREACH(const CTxOut& txout, vout)
  {
    if (txout.nValue < 0)
      return error(SHERR_INVAL, "CTransaction::CheckTransaction() : txout.nValue negative");
    if (txout.nValue > iface->max_money)
      return error(SHERR_INVAL, "CTransaction::CheckTransaction() : txout.nValue too high");
    nValueOut += txout.nValue;
    if (!MoneyRange(ifaceIndex, nValueOut))
      return error(SHERR_INVAL, "CTransaction::CheckTransaction() : txout total out of range");
  }

  // Check for duplicate inputs
  set<COutPoint> vInOutPoints;
  BOOST_FOREACH(const CTxIn& txin, vin)
  {
    if (vInOutPoints.count(txin.prevout)) {
      return error(SHERR_INVAL, "CTransaction::CheckTransaction: duplicate input specified.\n");
}
    vInOutPoints.insert(txin.prevout);
  }

  if (IsCoinBase())
  {
    if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
      return error(SHERR_INVAL, "CTransaction::CheckTransaction() : coinbase script size invalid (2 < (%d) < 100)", vin[0].scriptSig.size());
  }
  else
  {
    BOOST_FOREACH(const CTxIn& txin, vin) {
      if (txin.prevout.IsNull())
        return error(SHERR_INVAL, "CTransaction::CheckTransaction() : prevout is null");
#if 0 /* DEBUG: */
      if (!VerifyTxHash(iface, txin.prevout.hash))
        return error(SHERR_INVAL, "CTransaction::CheckTransaction(): unknown prevout hash '%s'", txin.prevout.hash.GetHex().c_str());
#endif
    }
  }

  return true;
}

bool CTransaction::FetchInputs(CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool, CBlock *pblockNew, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
{
  CIface *iface = GetCoinByIndex(txdb.ifaceIndex);

  // FetchInputs can return false either because we just haven't seen some inputs
  // (in which case the transaction should be stored as an orphan)
  // or because the transaction is malformed (in which case the transaction should
  // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
  fInvalid = false;

  if (IsCoinBase())
    return true; // Coinbase transactions have no inputs to fetch.

  for (unsigned int i = 0; i < vin.size(); i++)
  {
    COutPoint prevout = vin[i].prevout;
    if (inputsRet.count(prevout.hash))
      continue; // Got it already

    // Read txindex
    CTxIndex& txindex = inputsRet[prevout.hash].first;
    bool fFound = true;
    if ((pblockNew || fMiner) && mapTestPool.count(prevout.hash))
    {
      // Get txindex from current proposed changes
      txindex = mapTestPool.find(prevout.hash)->second;
    }
    else
    {
      // Read txindex from txdb
      fFound = txdb.ReadTxIndex(prevout.hash, txindex);
    }

    /* allows for passage past this error condition for orphans. */
    if (!fFound && (pblockNew || fMiner)) {
      if (fMiner)
        return (false);

      return error(SHERR_NOENT, "FetchInputs: %s prev tx %s index entry not found", GetHash().GetHex().c_str(), prevout.hash.GetHex().c_str());
    }

    // Read txPrev
    CTransaction& txPrev = inputsRet[prevout.hash].second;
    if (!fFound || txindex.pos == CDiskTxPos(0,0,0)) 
    {
      // Get prev tx from single transactions in memory
      CTxMemPool *mempool = GetTxMemPool(iface);
      {
        LOCK(mempool->cs);
        if (!mempool->exists(prevout.hash))
          return error(SHERR_INVAL, "FetchInputs() : %s mempool Tx prev not found %s", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
        txPrev = mempool->lookup(prevout.hash);
      }
      if (!fFound)
        txindex.vSpent.resize(txPrev.vout.size());
    }
    else
    {
      /* Get prev tx from disk */
      if (!txPrev.ReadTx(txdb.ifaceIndex, prevout.hash)) {
        const CTransaction *tx;
        Debug("CTransaction::FetchInputs[%s]: for tx %s, ReadFromDisk prev tx %s failed", iface->name, GetHash().ToString().c_str(),  prevout.hash.ToString().c_str());

        if (!pblockNew ||
            !(tx = pblockNew->GetTx(prevout.hash))) {
          return error(SHERR_INVAL, "CTransaction::FetchInputs[%s]: for tx %s, prev tx %s unknown", iface->name, GetHash().ToString().c_str(),  prevout.hash.ToString().c_str());
        }

        txPrev.Init(*tx);
#if 0
      // Get prev tx from disk
      if (!txPrev.ReadFromDisk(txindex.pos))
        return error(SHERR_INVAL, "FetchInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
#endif
      }
    }
  }

  // Make sure all prevout.n's are valid:
  for (unsigned int i = 0; i < vin.size(); i++)
  {
    const COutPoint prevout = vin[i].prevout;
    assert(inputsRet.count(prevout.hash) != 0);
    const CTxIndex& txindex = inputsRet[prevout.hash].first;
    const CTransaction& txPrev = inputsRet[prevout.hash].second;
    if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
    {
      // Revisit this if/when transaction replacement is implemented and allows
      // adding inputs:
      fInvalid = true;
      return error(SHERR_INVAL, "FetchInputs() : %s prevout.n out of range %d %d %d prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str());
    }
  }

  return true;
}



bool CBlock::WriteBlock(uint64_t nHeight)
{
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockChain(iface);
  uint64_t idx_next;
  unsigned int blockPos;
  long sBlockLen;
  char *sBlockData;
  int n_height;
  int err;

  if (!bc)
    return (false);

  uint256 hash = GetHash();

  /* check for existing record saved at height position */
  bc_hash_t rawhash;
  err = bc_get_hash(bc, (bcsize_t)nHeight, rawhash); 
  if (!err) { /* exists */
    uint256 t_hash;
    t_hash.SetRaw(rawhash);
    if (t_hash == hash)
      return (true); /* same hash as already written block */
    err = bc_clear(bc, nHeight);
    if (err)
      return error(err, "WriteBlock: clear block position %d.", (int)nHeight);
  }

  /* serialize into binary */
  sBlock << *this;
  sBlockLen = sBlock.size();
  sBlockData = (char *)calloc(sBlockLen, sizeof(char));
  if (!sBlockData)
    return error(SHERR_NOMEM, "allocating %d bytes for block data\n", (int)sBlockLen);
  sBlock.read(sBlockData, sBlockLen);
  n_height = bc_write(bc, nHeight, hash.GetRaw(), sBlockData, sBlockLen);
  if (n_height < 0)
    return error(SHERR_INVAL, "block-chain write: %s", sherrstr(n_height));
  free(sBlockData);

  /* write tx ref's */
  BOOST_FOREACH(CTransaction& tx, vtx) {
    tx.WriteTx(ifaceIndex, nHeight); 
  }

  Debug("WriteBlock: %s @ height %u\n", hash.GetHex().c_str(), (unsigned int)nHeight);

  return (true);
}

bool CBlock::WriteArchBlock()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockChain(iface);
  uint64_t idx_next;
  unsigned int blockPos;
  long sBlockLen;
  char *sBlockData;
  int n_height;
  int err;

  if (!bc)
    return (false);

  uint256 hash = GetHash();

  /* serialize into binary */
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  sBlock << *this;
  sBlockLen = sBlock.size();
  sBlockData = (char *)calloc(sBlockLen, sizeof(char));
  if (!sBlockData)
    return error(SHERR_NOMEM, "allocating %d bytes for block data\n", (int)sBlockLen);
  sBlock.read(sBlockData, sBlockLen);
  n_height = bc_arch_write(bc, hash.GetRaw(), sBlockData, sBlockLen);
  free(sBlockData);
  if (n_height < 0)
    return error(SHERR_INVAL, "block-chain write: %s", sherrstr(n_height));

  Debug("WriteArchBlock: hash '%s'\n", hash.GetHex().c_str());

  return (true);
}

bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  int err;

  if (!iface)
    return error(SHERR_INVAL, "coin iface no available.");

  // Disconnect in reverse order
  for (int i = vtx.size()-1; i >= 0; i--)
    if (!vtx[i].DisconnectInputs(txdb))
      return false;

  if (pindex->pprev)
  {
    /* bc_clear() */
    /* DEBUG: */
//    pindex->pprev->pnext = NULL;
#if 0
    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    CDiskBlockIndex blockindexPrev(pindex->pprev);
    blockindexPrev.hashNext = 0;
    if (!txdb.WriteBlockIndex(blockindexPrev))
      return error(SHERR_INVAL, "DisconnectBlock() : WriteBlockIndex failed");
#endif
  }

#if 0
  bool ret = BlockChainErase(iface, pindex->nHeight);
  if (!ret)
    return error(SHERR_INVAL, "DisconnectBlock failure at height %d.", pindex->nHeight);
  fprintf(stderr, "DEBUG: DisconnectBlock[%s]: PURGE @ height %d\n", iface->name, pindex->nHeight);
#endif

  return true;
}

bool VerifyTxHash(CIface *iface, uint256 hashTx)
{
  bc_t *bc = GetBlockTxChain(iface);
  int err;

  err = bc_idx_find(bc, hashTx.GetRaw(), NULL, NULL);
  if (err)
    return (false);

  return (true);
}

bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
  // Relinquish previous transactions' spent pointers
  if (!IsCoinBase())
  {
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
      COutPoint prevout = txin.prevout;

      // Get prev txindex from disk
      CTxIndex txindex;
      if (!txdb.ReadTxIndex(prevout.hash, txindex))
        return error(SHERR_INVAL, "DisconnectInputs() : ReadTxIndex failed");

      if (prevout.n >= txindex.vSpent.size())
        return error(SHERR_INVAL, "DisconnectInputs() : prevout.n out of range");

      // Mark outpoint as not spent
      txindex.vSpent[prevout.n].SetNull();

      // Write back
      if (!txdb.UpdateTxIndex(prevout.hash, txindex))
        return error(SHERR_INVAL, "DisconnectInputs() : UpdateTxIndex failed");
    }
  }

  // Remove transaction from index
  // This can fail if a duplicate of this transaction was in a chain that got
  // reorganized away. This is only possible if this transaction was completely
  // spent, so erasing it would be a no-op anway.
  txdb.EraseTxIndex(*this);

  /* erase from bc_tx.idx */
  EraseTx(txdb.ifaceIndex);

  return true;
}

bool CTransaction::EraseTx(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  bc_t *bc = GetBlockTxChain(iface);
  int posTx;
  int err;

  err = bc_find(bc, GetHash().GetRaw(), &posTx);
  if (err)
    return error(err, "CTransaction::EraseTx: tx '%s' not found.", GetHash().GetHex().c_str());

  err = bc_idx_clear(bc, posTx);
  if (err)
    return error(err, "CTransaction::EraseTx: error clearing tx pos %d.", posTx);
 
  Debug("CTransaction::EraseTx: cleared tx '%s'.", GetHash().GetHex().c_str());
  return (true);
}


uint256 GetGenesisBlockHash(int ifaceIndex)
{
  uint256 hash;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CBlock *block = GetBlockByHeight(iface, 0); 
  if (!block)
    return (false);
  hash = block->GetHash();
  delete block;
  return (hash);
}

/**
 * The core method of accepting a new block onto the block-chain.
 */
bool core_AcceptBlock(CBlock *pblock)
{
  int ifaceIndex = pblock->ifaceIndex;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  NodeList &vNodes = GetNodeList(ifaceIndex);
  bc_t *bc = GetBlockChain(GetCoinByIndex(ifaceIndex));
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
  uint256 hash = pblock->GetHash();
  char errbuf[1024];
  bool ret;

  if (blockIndex->count(hash))
    return error(SHERR_INVAL, "AcceptBlock() : block already in block table.");

  // Get prev block index
  map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(pblock->hashPrevBlock);
  if (mi == blockIndex->end()) {
    return (pblock->trust(-10, "(core) AcceptBlock: prev block '%s' not found", pblock->hashPrevBlock.GetHex().c_str()));
  }
  CBlockIndex* pindexPrev = (*mi).second;
  if (!pindexPrev) {
    return error(SHERR_INVAL, "AcceptBlock() : prev block '%s' not found: block index has NULL record for hash.", pblock->hashPrevBlock.GetHex().c_str());
  }

  unsigned int nHeight = pindexPrev->nHeight+1;

  // Check proof of work
  unsigned int nBits = pblock->GetNextWorkRequired(pindexPrev);
  if (pblock->nBits != nBits) {
    return (pblock->trust(-100, "(core) AcceptBlock: invalid difficulty (%x) specified (next work required is %x) for block height %d [prev '%s']\n", pblock->nBits, nBits, nHeight, pindexPrev->GetBlockHash().GetHex().c_str()));
  }

#if 0
  if (!CheckDiskSpace(::GetSerializeSize(*pblock, SER_DISK, CLIENT_VERSION))) {
    return error(SHERR_IO, "AcceptBlock() : out of disk space");
  }
#endif

  // Check timestamp against prev
  if (pblock->GetBlockTime() <= pindexPrev->GetMedianTimePast()) {
    pblock->print();
    return error(SHERR_INVAL, "AcceptBlock: block timestamp is too early");
  }

  BOOST_FOREACH(const CTransaction& tx, pblock->vtx) {
#if 0 /* not standard */
    // Check that all inputs exist
    if (!tx.IsCoinBase()) {
      BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        if (txin.prevout.IsNull())
          return error(SHERR_INVAL, "AcceptBlock(): prevout is null");
        if (!VerifyTxHash(iface, txin.prevout.hash))
          return error(SHERR_INVAL, "AcceptBlock(): unknown prevout hash '%s'", txin.prevout.hash.GetHex().c_str());
      }
    }
#endif
    // Check that all transactions are finalized 
    if (!tx.IsFinal(ifaceIndex, nHeight, pblock->GetBlockTime())) {
      return (pblock->trust(-10, "(core) AcceptBlock: block contains a non-final transaction at height %u", nHeight));
    }
  }

  // Check that the block chain matches the known block chain up to a checkpoint
  if (!pblock->VerifyCheckpoint(nHeight)) {
    return (pblock->trust(-100, "(core) AcceptBlock: rejected by checkpoint lockin at height %u", nHeight));
  }

  ret = pblock->AddToBlockIndex();
  if (!ret) {
    pblock->print();
    return error(SHERR_IO, "AcceptBlock: AddToBlockIndex failed");
  }

  /* Relay inventory [but don't relay old inventory during initial block download] */
  int nBlockEstimate = pblock->GetTotalBlocksEstimate();
  if (GetBestBlockChain(iface) == hash) {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
      if (GetBestHeight(iface) > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
        pnode->PushInventory(CInv(ifaceIndex, MSG_BLOCK, hash));
  }

  return true;
}

bool CTransaction::IsStandard() const
{

  if (!isFlag(CTransaction::TX_VERSION)) {
    return error(SHERR_INVAL, "version flag not set (%d) [CTransaction::IsStandard]", nFlag);
  }

  BOOST_FOREACH(const CTxIn& txin, vin)
  {
    // Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
    // pay-to-script-hash, which is 3 ~80-byte signatures, 3
    // ~65-byte public keys, plus a few script ops.
    if (txin.scriptSig.size() > 500) {
      return error(SHERR_INVAL, "script-sig size > 500 [CTransaction::IsStandard]");
    }
    if (!txin.scriptSig.IsPushOnly()) {
      return error(SHERR_INVAL, "script-sig is push-only [CTransaction::IsStandard]");
    }
  }

  BOOST_FOREACH(const CTxOut& txout, vout) {
    if (!::IsStandard(txout.scriptPubKey)) {
      return error(SHERR_INVAL, "pub key is not standard [CTransaction::IsStandard] %s", txout.scriptPubKey.ToString().c_str());
    }
  }

  return true;
}



CAlias *CTransaction::CreateAlias(std::string name, const uint160& hash)
{
  nFlag |= CTransaction::TXF_ALIAS;

  alias = CAlias(name, hash);
  return (&alias);
}

/*
CIdent *CTransaction::CreateEntity(const char *name, cbuff secret)
{

  if (nFlag & CTransaction::TXF_ENTITY)
    return (NULL);

  nFlag |= CTransaction::TXF_ENTITY;
  entity = CIdent(name, secret);

  return (&entity);
}
*/

CCert *CTransaction::CreateCert(const char *name, cbuff secret, int64 nLicenseFee)
{

  if (nFlag & CTransaction::TXF_CERTIFICATE)
    return (NULL);

  string strTitle(name);

  nFlag |= CTransaction::TXF_CERTIFICATE;
  certificate = CCert(strTitle);
  certificate.SetLicenseFee(nLicenseFee);
  certificate.Sign(secret);

  return (&certificate);
}

/**
 * @param lic_span The duration of the license in seconds.
 */
CLicense *CTransaction::CreateLicense(CCert *cert, uint64_t lic_crc)
{
  double lic_span;

  if (!cert->IsActive()) {
    error(SHERR_INVAL, "CTransaction::CreateLicense: !cert->IsActive");
    return (NULL);
  }

  if (nFlag & CTransaction::TXF_LICENSE)
    return (NULL);
  
  nFlag |= CTransaction::TXF_LICENSE;
  license = CLicense(cert, lic_crc);

  return (&license);
}



COffer *CTransaction::CreateOffer()
{

  if (nFlag & CTransaction::TXF_OFFER)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER;
  offer = COffer();

  return (&offer);
}

COfferAccept *CTransaction::AcceptOffer(COffer *offerIn)
{
  uint160 hashOffer;

  if (nFlag & CTransaction::TXF_OFFER_ACCEPT)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER_ACCEPT;

  int64 nPayValue = -1 * offerIn->nXferValue;
  int64 nXferValue = -1 * offerIn->nPayValue;
  hashOffer = offerIn->GetHash();
  offer = *offerIn;

  offer.vPayAddr.clear();
  offer.vXferAddr.clear();
  offer.nPayValue = nPayValue;
  offer.nXferValue = nXferValue;
  offer.hashOffer = hashOffer;

 return ((COfferAccept *)&offer);
}

COffer *CTransaction::GenerateOffer(COffer *offerIn)
{
  if (nFlag & CTransaction::TXF_OFFER)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER;
  offer = *offerIn;

 return (&offer);
}

COfferAccept *CTransaction::PayOffer(COfferAccept *accept)
{

  if (nFlag & CTransaction::TXF_OFFER_ACCEPT)
    return (NULL);

  nFlag |= CTransaction::TXF_OFFER_ACCEPT;
  offer = COffer(*accept);

 return ((COfferAccept *)&offer);
}

COffer *CTransaction::RemoveOffer(uint160 hashOffer)
{
  if (nFlag & CTransaction::TXF_OFFER)
    return (NULL);
 return (NULL); 
}


CAsset *CTransaction::CreateAsset(string strAssetName, string strAssetHash)
{

  if (nFlag & CTransaction::TXF_ASSET)
    return (NULL);

  nFlag |= CTransaction::TXF_ASSET;
  asset = CAsset(strAssetName, strAssetHash);

  return (&asset);
}

CAsset *CTransaction::UpdateAsset(const CAsset& assetIn, string strAssetName, string strAssetHash)
{

  if (nFlag & CTransaction::TXF_ASSET)
    return (NULL);

  nFlag |= CTransaction::TXF_ASSET;
  asset = assetIn;
  asset.SetLabel(strAssetName);
  asset.SetAssetHash(strAssetHash);

  return (&asset);
}

CAsset *CTransaction::SignAsset(const CAsset& assetIn, uint160 hashCert)
{

  if (nFlag & CTransaction::TXF_ASSET)
    return (NULL);

  nFlag |= CTransaction::TXF_ASSET;
  asset = assetIn;
  asset.Sign(hashCert);

  return (&asset);
}

CAsset *CTransaction::RemoveAsset(const CAsset& assetIn)
{

  if (nFlag & CTransaction::TXF_ASSET)
    return (NULL);

  nFlag |= CTransaction::TXF_ASSET;
  asset = assetIn;

  return (&asset);
}

CIdent *CTransaction::CreateIdent(CIdent *ident)
{

  if (nFlag & CTransaction::TXF_IDENT)
    return (NULL);

  nFlag |= CTransaction::TXF_IDENT;
  certificate = CCert(*ident);

  return ((CIdent *)&certificate);
}

CIdent *CTransaction::CreateIdent()
{

  if (nFlag & CTransaction::TXF_IDENT)
    return (NULL);

  nFlag |= CTransaction::TXF_IDENT;

  CIdent ident;
  cbuff empty;

  ident.Sign(empty);
  certificate = CCert(ident);

  return ((CIdent *)&certificate);
}

bool CTransaction::VerifyMatrix(CMatrix *seed, const CMatrix& matrix, CBlockIndex *pindex)
{
  CMatrix cmp_matrix;
  unsigned int height;

  if (!pindex)
    return (false);

  if (seed) {
    cmp_matrix = CMatrix(*seed);
  } else {
    cmp_matrix = CMatrix();
  }

  height = matrix.height;//(pindex->nHeight - 27);
  height /= 27;
  height *= 27;

  while (pindex && pindex->pprev && pindex->nHeight > height)
    pindex = pindex->pprev;
  if (!pindex) {
    return (false);
  }

  cmp_matrix.Append(pindex->nHeight, pindex->GetBlockHash()); 
  bool ret = (cmp_matrix == matrix);
  return (ret);
}

/**
 * @note Verified against previous matrix when the block is accepted.
 */
CMatrix *CTransaction::GenerateMatrix(int ifaceIndex, CMatrix *seed, CBlockIndex *pindex)
{
  uint32_t best_height;
  int height;

  if (nFlag & CTransaction::TXF_MATRIX)
    return (NULL);

  if (!pindex) {
    pindex = GetBestBlockIndex(ifaceIndex);
    if (!pindex)
      return (NULL);
  }


  height = (pindex->nHeight - 27);
  height /= 27;
  height *= 27;

  if (height <= 27)
    return (NULL);

  if (seed && seed->GetHeight() >= height)
    return (NULL);

  while (pindex && pindex->pprev && pindex->nHeight > height)
    pindex = pindex->pprev;
  if (!pindex) {
    return (NULL);
  }

  nFlag |= CTransaction::TXF_MATRIX;
  if (seed) {
    matrix = CMatrix(*seed);
  } else {
    matrix = CMatrix();
  }
  matrix.Append(pindex->nHeight, pindex->GetBlockHash()); 
  return (&matrix);
}



bool CBlock::trust(int deg, const char *msg, ...)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  va_list arg_ptr;
  char errbuf[4096];
  char msgbuf[4096];
  int ret;

  if (deg == 0)
    return (true);

  if (!iface || !iface->enabled)
    return ((deg > 0) ? true : false);

  va_start(arg_ptr, msg);
  memset(msgbuf, 0, sizeof(msgbuf));
  ret = vsnprintf(msgbuf, sizeof(msgbuf) - 1, msg, arg_ptr);
  va_end(arg_ptr);

  sprintf(errbuf, "TRUST %s%d", (deg >= 0) ? "+" : "", deg);
  if (msg)
    sprintf(errbuf + strlen(errbuf), " (%s)", msgbuf);

  if (deg > 0) {
    unet_log(ifaceIndex, errbuf); 
    if (originPeer && originPeer->nMisbehavior > deg)
      originPeer->nMisbehavior -= deg;
    return (true);
  }

  if (originPeer)
    originPeer->Misbehaving(-deg);

  shcoind_err(SHERR_INVAL, iface->name, errbuf);
  print();

  return (false);
}


