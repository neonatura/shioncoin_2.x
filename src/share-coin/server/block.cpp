
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
#include <vector>

using namespace std;

//map<uint256, CBlockIndex*> tableBlockIndex[MAX_COIN_IFACE];
blkidx_t tableBlockIndex[MAX_COIN_IFACE];
//vector <bc_t *> vBlockChain;

blkidx_t *GetBlockTable(int ifaceIndex)
{
  if (ifaceIndex < 1 || ifaceIndex >= MAX_COIN_IFACE)
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

/**
 * Closes all open block record databases.
 */
void CloseBlockChains(void)
{
  CIface *iface;
  int idx;

  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    iface = GetCoinByIndex(idx);
    if (!iface)
      continue;

    if (iface->bc_block) {
      bc_close(iface->bc_block);
      iface->bc_block = NULL;
    }
    if (iface->bc_tx) {
      bc_close(iface->bc_tx);
      iface->bc_tx = NULL;
    }
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
  int txPos;
  int nHeight;
  int err;

  if (!bc) {
    unet_log(ifaceIndex, "CTransaction::WriteTx: error opening tx chain.");
    return (false);
  }

  if (0 == bc_idx_find(bc, hash.GetRaw(), NULL, NULL)) {
    /* transaction reference exists */
    return (true);
  }

  /* reference block height */
  err = bc_append(bc, hash.GetRaw(), &blockHeight, sizeof(blockHeight));
  if (err < 0) {
    sprintf(errbuf, "CTransaction::WriteTx: error writing block reference: %s.", sherrstr(err));
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

fprintf(stderr, "DEBUG: CTransaction::WriteTx: wrote tx '%s' for block #%d\n", hash.GetHex().c_str(), (int)blockHeight);
  return (true);
}

bool CTransaction::ReadTx(int ifaceIndex, uint256 txHash)
{
  uint256 hashBlock; /* dummy var */
  return (ReadTx(ifaceIndex, txHash, hashBlock));
}

bool CTransaction::ReadTx(int ifaceIndex, uint256 txHash, uint256 &hashBlock)
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
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

  bc = GetBlockTxChain(iface);
  if (!bc) { 
    unet_log(ifaceIndex, "CTransaction::ReadTx: unable to open block tx database."); 
    return (false);
  }

  err = bc_idx_find(bc, txHash.GetRaw(), NULL, &txPos); 
  if (err) {
fprintf(stderr, "DEBUG: CTransaction::ReadTx: tx hash '%s' not found.\n", txHash.GetHex().c_str());
    return (false); /* not an error condition */
}

  err = bc_get(bc, txPos, &data, &data_len);
  if (data_len != sizeof(uint64_t)) {
    sprintf(errbuf, "CTransaction::ReadTx: tx position %d not found.", txPos);
    unet_log(ifaceIndex, errbuf);
    return (false);
  }
  if (data_len != sizeof(uint64_t)) {
    sprintf(errbuf, "CTransaction::ReadTx: block reference has invalid size (%d).", data_len);
    unet_log(ifaceIndex, errbuf);
    return (false);
  }
  memcpy(&blockHeight, data, sizeof(blockHeight));
  free(data);

  CBlock *block;
  err = iface->op_block_new(iface, &block);
  if (err) {
    sprintf(errbuf, "CTransaction::ReadTx: error allocating block: %s.", sherrstr(err));
    unet_log(ifaceIndex, errbuf);
    return (false);
  }
  if (!block) return (false);
  block->ReadBlock(blockHeight);

  const CTransaction *tx = block->GetTx(txHash);
  if (!tx) {
    sprintf(errbuf, "CTransaction::ReadTx: block '%s' does not contain tx '%s'.", block->GetHash().GetHex().c_str(), txHash.GetHex().c_str());
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

  Init(*tx);
  hashBlock = block->GetHash();

fprintf(stderr, "DEBUG: CTransaction::ReadTx: read tx '%s' for block #%d\n", GetHash().GetHex().c_str(), (int)blockHeight); 
  return (true);
}


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
