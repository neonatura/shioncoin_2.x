
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
#include "chain.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

using namespace std;
using namespace boost;

ChainOp chain;

extern CCriticalSection cs_main;

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

bool DownloadBlockchain()
{
  NodeList &vNodes = GetNodeList(chain.ifaceIndex);
  CIface *iface;
  CNode *pfrom;
  time_t expire_t;

  iface = GetCoinByIndex(chain.ifaceIndex);
  if (!iface)
    return (false);

  if (vNodes.size() == 0)
    return (false); 

  CBlockIndex *pindexBest = GetBestBlockIndex(chain.ifaceIndex);
  if (!pindexBest)
    return (false);

  if ((pindexBest->nHeight+1) >= chain.max)
    return (false);

  expire_t = time(NULL) - 120;
  if (iface->net_valid < expire_t) { /* done w/ last round */
if (iface->net_valid) fprintf(stderr, "DEBUG: DownloadBlockChain: last valid block received %ds ago\n", (time(NULL) - iface->net_valid)); 
    if (iface->net_valid < iface->net_invalid)
      return (false); /* give up */

    pfrom = vNodes.front(); 
    pfrom->PushGetBlocks(pindexBest, uint256(0));
  }

  return (true);
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
    case BCOP_DOWNLOAD:
      ret = DownloadBlockchain();
      if (!ret) {
        sprintf(buf, "PerformBlockChainOperation: completed block-chain download.");
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

  if (chain.mode != BCOP_DOWNLOAD) {
    if (chain.mode != BCOP_NONE)
      return (SHERR_AGAIN);

    CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
    if (!pindexBest)
      return (0);

    if (pindexBest->nHeight >= maxHeight) {
fprintf(stderr, "DEBUG: InitDownloadBlockchain: already at best height %d\n", pindexBest->nHeight);
      return (0);
    }

    memset(&chain, 0, sizeof(chain));
    chain.ifaceIndex = ifaceIndex;
    chain.mode = BCOP_DOWNLOAD;
  }
  chain.max = MAX(chain.max, maxHeight);
fprintf(stderr, "DEBUG: InitDownloadBlockchain: iface(%d) max(%d)\n", ifaceIndex, chain.max);
  
  return (0);
}

void event_cycle_chain(int ifaceIndex)
{
  PerformBlockChainOperation(ifaceIndex); 
}
#ifdef __cplusplus
}
#endif


