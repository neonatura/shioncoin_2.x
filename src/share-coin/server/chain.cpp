
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
#include "chain.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

using namespace std;
using namespace boost;

ChainOp chain;


extern CCriticalSection cs_main;


static int dlChainIndex[MAX_COIN_IFACE];

static bool ScanWalletTx(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (false);

  CWallet *wallet = GetWallet(iface);
  if (!wallet)
    return (false);

  unsigned int nBestHeight = GetBestHeight(iface);
  unsigned int nHeight = wallet->nScanHeight;
  unsigned int nMaxHeight = nHeight + 4096;

  if (nHeight >= nBestHeight)
    return (false);

  {
    LOCK(wallet->cs_wallet);

    for (; nHeight <= nBestHeight && nHeight < nMaxHeight; nHeight++) {
      CBlock *block = GetBlockByHeight(iface, nHeight);
      if (!block) continue;

      BOOST_FOREACH(const CTransaction& tx, block->vtx) {
        wallet->AddToWalletIfInvolvingMe(tx, block, false, false);
      }

      delete block;
      wallet->nScanHeight = nHeight;
    }
  }

  return (true);
}

void InitScanWalletTx(CWallet *wallet, int nHeight)
{
  wallet->nScanHeight = MIN(nHeight, wallet->nScanHeight); 
}

void ScanWalletTxUpdated(CWallet *wallet, const CBlock *pblock)
{
  blkidx_t *blockIndex = GetBlockTable(wallet->ifaceIndex);
  uint256 hash = pblock->GetHash();

  if (blockIndex->count(hash) == 0)
    return; /* nerp */

  CBlockIndex *pindex = (*blockIndex)[hash];
  if (wallet->nScanHeight == (pindex->nHeight - 1)) {
    wallet->nScanHeight = pindex->nHeight;
fprintf(stderr, "DEBUG: ScanWalletTxUpdated: wallet[#%d]->nScanHeight = %d\n", wallet->ifaceIndex, wallet->nScanHeight); 
}
}

bool LoadExternalBlockchainFile()
{
  static unsigned char pchMessageStart[4] = { 0xd9, 0xd9, 0xf9, 0xbd };
  static int nIndex = 0;
  CIface *iface = GetCoinByIndex(chain.ifaceIndex);
  int err;

  {
    LOCK(cs_main);
    try {
      FILE *fl = fopen(chain.path, "rb");
      if (!fl) {
        fprintf(stderr, "DEBUG: error open '%s': %s\n", chain.path, strerror(errno));
        return (false);
      }
      CAutoFile blkdat(fl, SER_DISK, DISK_VERSION);
      while (chain.pos != (unsigned int)-1 && blkdat.good() && !fRequestShutdown) {
        unsigned char pchData[65536];
        do {
          err = fseek(blkdat, chain.pos, SEEK_SET);
          if (err)
            return false;
          int nRead = fread(pchData, 1, sizeof(pchData), blkdat);
          if (nRead <= 8)
          {
#if 0
            chain.pos = (unsigned int)-1;
            break;
#endif
            return false;
          }
          void* nFind = memchr(pchData, pchMessageStart[0], nRead+1-sizeof(pchMessageStart));
          if (nFind)
          {
            if (memcmp(nFind, pchMessageStart, sizeof(pchMessageStart))==0)
            {
              chain.pos += ((unsigned char*)nFind - pchData) + sizeof(pchMessageStart);
              break;
            }
            chain.pos += ((unsigned char*)nFind - pchData) + 1;
          }
          else {
fprintf(stderr, "DEBUG: pchMessage not found\n");
            chain.pos += sizeof(pchData) - sizeof(pchMessageStart) + 1;
}
        } while(!fRequestShutdown);
        if (chain.pos == (unsigned int)-1)
          return (false);
        fseek(blkdat, chain.pos, SEEK_SET);
        unsigned int nSize;
        blkdat >> nSize;
        chain.pos += 4 + nSize;
        if (nSize > 0 && nSize <= iface->max_block_size)
        { /* does not handle orphans */
          CBlock *block = GetBlankBlock(iface);
          blkdat >> *block;

#if 0
CBlockIndex *bestBlock = GetBestBlockIndex(iface);
if (bestBlock->GetBlockHash() != block->hashPrevBlock)
  continue;
#endif

          if (!ProcessBlock(NULL,block)) {
fprintf(stderr, "DEBUG: IMPORT: block '%s' failed.\n", block->GetHash().GetHex().c_str());
            delete block;
            continue;
          }
#if 0
          if (!block->CheckBlock()) {
fprintf(stderr, "DEBUG: IMPORT: block '%s' failed integrity validation.\n", block->GetHash().GetHex().c_str());
            delete block;
            continue;
          }
          if (!block->AcceptBlock()) {
fprintf(stderr, "DEBUG: IMPORT: block '%s' was not accepted.\n", block->GetHash().GetHex().c_str());
            delete block;
            continue;
          }
#endif
          delete block;

          chain.total++;
          if (chain.total == chain.max)
            return (false); /* too many puppies. */

#if 0
          if (ProcessBlock(NULL,block))
          {
            chain.total++;
            nIndex++;
            if (chain.total == chain.max)
              return (false); /* too many puppies. */
          }
#endif
        }

        nIndex++;
        if (99 == (nIndex % 100)) {
fprintf(stderr, "DEBUG: ProcessBlock info: fseek(blkdat, %d, SEEK_SET)\n", chain.pos);
          /* continue later */
          nIndex++;
          return (true);
        }
      }
    }
    catch (std::exception &e) {
      fprintf(stderr, "DEBUG: %s() : Deserialize or I/O error caught during load: %s\n", __PRETTY_FUNCTION__, e.what());
      chain.pos += 4;
      return (true);
    }
  }

  return (false);
}

bool SaveExternalBlockchainFile()
{
  static unsigned char pchMessageStart[4] = { 0xd9, 0xd9, 0xf9, 0xbd };
  CIface *iface = GetCoinByIndex(chain.ifaceIndex);
  int64 idx;

  if (chain.max == 0)
    chain.max = (int64)getblockheight(chain.ifaceIndex);

  {
    LOCK(cs_main);
    try {
      FILE *fl = fopen(chain.path, "ab");
      if (!fl) {
        fprintf(stderr, "DEBUG: error open '%s': %s\n", chain.path, strerror(errno));
        return (false);
      }
      CAutoFile blkdat(fl, SER_DISK, DISK_VERSION);
      for (; chain.pos < chain.max; chain.pos++) {
        CBlock *pblock = GetBlockByHeight(iface, chain.pos);
        if (!pblock) continue; /* uh oh */
        /* hdr */
        unsigned int nSize = blkdat.GetSerializeSize(*pblock);
        blkdat << FLATDATA(pchMessageStart) << nSize;
        /* content */
        blkdat << *pblock;
        delete pblock;

        chain.total++;
        if (999 == (chain.total % 1000))
          return (true);
      }
    }
    catch (std::exception &e) {
      printf("%s() : Deserialize or I/O error caught during load\n",
          __PRETTY_FUNCTION__);
    }
  }

  return (false);
}

bool DownloadIfaceBlockchain(int ifaceIndex)
{
  static int nNodeIndex;
  NodeList &vNodes = GetNodeList(ifaceIndex);
  CIface *iface;
  CNode *pfrom;
  time_t expire_t;

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (false);

if (!iface->enabled)
return (false);

  if (vNodes.size() == 0) {
    return (false); 
}

  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  if (!pindexBest) { 

fprintf(stderr, "DEBUG: DownloadBlockchain: no best index\n");
    return (false);
  }

  if (pindexBest->nHeight == dlChainIndex[ifaceIndex])
    return (false);
  if (pindexBest->nHeight > dlChainIndex[ifaceIndex]) {
UpdateDownloadBlockchain(ifaceIndex);
    return (false);
  }

  expire_t = time(NULL) - 120;
  if (iface->net_valid < expire_t) { /* done w/ last round */
    if (iface->net_valid) fprintf(stderr, "DEBUG: DownloadBlockChain: last valid block received %ds ago\n", (time(NULL) - iface->net_valid)); 
    if (iface->net_invalid) fprintf(stderr, "DEBUG: DownloadBlockChain: last valid block received %ds ago\n", (time(NULL) - iface->net_invalid)); 
    if (iface->net_valid < iface->net_invalid) {
      fprintf(stderr, "DEBUG: net_valid < net_invalid\n");
      return (false); /* give up */
    }

    int idx = (nNodeIndex % vNodes.size());
    pfrom = vNodes[idx];
    fprintf(stderr, "DEBUG: DownloadBlockChain[iface #%d]: pfrom->PushGetBlocks(%d) from '%s'\n", ifaceIndex, pindexBest->nHeight, pfrom->addr.ToString().c_str());
    pfrom->PushGetBlocks(pindexBest, uint256(0));
    nNodeIndex++;
  }

  return (true);
}

bool DownloadBlockchain()
{
  int idx;
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    DownloadIfaceBlockchain(idx);
  }
}

void PerformBlockChainOperation(int ifaceIndex)
{
  char buf[1024];
  bool ret;

  if (ifaceIndex != chain.ifaceIndex)
    return;

  switch (chain.mode) {
    case BCOP_IMPORT:
      ret = LoadExternalBlockchainFile();
      if (!ret) {
        sprintf(buf, "PerformBlockChainOperation: loaded %u blocks from path \"%s\" [pos %d].", chain.total, chain.path, chain.pos);
        unet_log(chain.ifaceIndex, buf);
        memset(&chain, 0, sizeof(chain));
      }
      break;

    case BCOP_EXPORT:
      ret = SaveExternalBlockchainFile();
      if (!ret) {
        sprintf(buf, "PerformBlockChainOperation: saved %u blocks to path \"%s\".", chain.total, chain.path);
        unet_log(chain.ifaceIndex, buf);
        memset(&chain, 0, sizeof(chain));
      }
      break;
  }
}


#ifdef __cplusplus
extern "C" {
#endif

int InitChainImport(int ifaceIndex, const char *path, int offset)
{
  if (*chain.path)
    return (SHERR_AGAIN);

  if (ifaceIndex < 1 || ifaceIndex >= MAX_COIN_IFACE)
    return (SHERR_INVAL);

  if (!path)
    return (SHERR_INVAL);

  chain.mode = BCOP_IMPORT;
  chain.ifaceIndex = ifaceIndex;
  strncpy(chain.path, path, sizeof(chain.path)-1);
  chain.pos = offset;

fprintf(stderr, "DEBUG: InitChainImport: importing (iface #%d) from path '%s'.\n", chain.ifaceIndex, chain.path);

  return (0);
} 

int InitChainExport(int ifaceIndex, const char *path, int max)
{
  if (*chain.path)
    return (SHERR_AGAIN);

  if (ifaceIndex < 1 || ifaceIndex >= MAX_COIN_IFACE)
    return (SHERR_INVAL);

  if (!path)
    return (SHERR_INVAL);

  chain.mode = BCOP_EXPORT;
  chain.ifaceIndex = ifaceIndex;
  strncpy(chain.path, path, sizeof(chain.path)-1);
  chain.max = max;

  unlink(path);

  return (0);
} 

int InitDownloadBlockchain(int ifaceIndex, int maxHeight)
{

  dlChainIndex[ifaceIndex] = MAX(dlChainIndex[ifaceIndex], maxHeight);
  
fprintf(stderr, "DEBUG: InitDownloadBlockchain: iface(%d) max(%d)\n", ifaceIndex, dlChainIndex[ifaceIndex]);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (iface)
    iface->net_invalid = 0;
  
  return (0);
}

void UpdateDownloadBlockchain(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  

  if (!iface)
    return;

CBlockIndex *bestIndex = GetBestBlockIndex(iface);
if (!bestIndex)
return;

  iface->net_valid = time(NULL);
  dlChainIndex[ifaceIndex] = MAX(dlChainIndex[ifaceIndex], bestIndex->nHeight);
}

void event_cycle_chain(int ifaceIndex)
{

  PerformBlockChainOperation(ifaceIndex); 

  ScanWalletTx(ifaceIndex);

  DownloadBlockchain();

}
#ifdef __cplusplus
}
#endif


