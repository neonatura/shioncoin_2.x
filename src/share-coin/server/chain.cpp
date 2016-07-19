
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


#ifdef __cplusplus
extern "C" {
#endif
static void set_serv_state(CIface *iface, int flag)
{
  char errbuf[256];

  iface->flags |= flag;

  memset(errbuf, 0, sizeof(errbuf));
  if (flag & COINF_DL_SCAN) {
    strcpy(errbuf, "entering service mode: download block-chain [scan]");
  } else if (flag & COINF_DL_SYNC) {
    strcpy(errbuf, "entering service mode: download block-chain [sync]");
  } else if (flag & COINF_WALLET_SCAN) {
    strcpy(errbuf, "entering service mode: wallet tx [scan]");
  } else if (flag & COINF_WALLET_SYNC) {
    strcpy(errbuf, "entering service mode: wallet tx [sync]");
  } else if (flag & COINF_PEER_SCAN) {
    strcpy(errbuf, "entering service mode: peer list [scan]");
  } else if (flag & COINF_PEER_SYNC) {
    strcpy(errbuf, "entering service mode: peer list [sync]");
  }
  if (*errbuf)
    unet_log(GetCoinIndex(iface), errbuf);
}
static void unset_serv_state(CIface *iface, int flag)
{
  iface->flags &= ~flag;
}
static bool serv_state(CIface *iface, int flag)
{
  return (iface->flags & flag);
}
#ifdef __cplusplus
}
#endif


static bool ServiceWalletEvent(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface)
    return (false);

  CWallet *wallet = GetWallet(iface);
  if (!wallet)
    return (false); /* no-op */

  unsigned int nBestHeight = GetBestHeight(iface);
  unsigned int nHeight = wallet->nScanHeight;
  unsigned int nMaxHeight = nHeight + 1024;

  if (nHeight <= nBestHeight) {
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
  if (nHeight > nBestHeight) {
    return (false); /* done */
  }

  return (true);
}

/* deprecate */
void ServiceWalletEventUpdate(CWallet *wallet, const CBlock *pblock)
{
  blkidx_t *blockIndex = GetBlockTable(wallet->ifaceIndex);
  uint256 hash = pblock->GetHash();

  if (blockIndex->count(hash) == 0)
    return; /* nerp */

  CBlockIndex *pindex = (*blockIndex)[hash];
  wallet->nScanHeight = MAX(wallet->nScanHeight, pindex->nHeight);
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

bool ServiceBlockEvent(int ifaceIndex)
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

  if (vNodes.size() == 0)
    return (true); /* keep trying */

  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);
  if (!pindexBest)
    return (true); /* keep trying */

  if (iface->blockscan_max == 0)
    return (true); /* keep trying */

  if (pindexBest->nHeight >= iface->blockscan_max) {
    ServiceBlockEventUpdate(ifaceIndex);
    return (false);
  }

  expire_t = time(NULL) - 60;
  if (iface->net_valid < expire_t) { /* done w/ last round */
    if (iface->net_valid < iface->net_invalid) {
      return (false); /* give up */
    }

    int idx = (nNodeIndex % vNodes.size());
    pfrom = vNodes[idx];
//fprintf(stderr, "DEBUG: DownloadBlockChain[iface #%d]: pfrom->PushGetBlocks(%d) to '%s'\n", ifaceIndex, pindexBest->nHeight, pfrom->addr.ToString().c_str());
    pfrom->PushGetBlocks(pindexBest, uint256(0));
    nNodeIndex++;

    /* force next check to be later */
    iface->net_valid = time(NULL);
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
  }
}

bool ServicePeerEvent(int ifaceIndex)
{
  NodeList &vNodes = GetNodeList(ifaceIndex);
  CNode *pfrom;

  if (vNodes.empty())
    return (true); /* keep checking */

  pfrom = vNodes.front();
  if (pfrom->fGetAddr)
    return (false); /* op already performed against this node */

  if (unet_peer_total(ifaceIndex) < 500) {
    pfrom->PushMessage("getaddr");
    pfrom->fGetAddr = true;
  }

#if 0
  if (!pfrom->fInbound) {
    // Advertise our address
    if (!fNoListen && !IsInitialBlockDownload(ifaceIndex)) {
      CAddress addr = GetLocalAddress(&pfrom->addr);
      if (addr.IsRoutable()) {
        fprintf(stderr, "DEBUG: ServicePeerEvent: GetLocalAddress '%s'\n", pfrom->addr.ToString().c_str());
        pfrom->PushAddress(addr);
      }
    }
  }
#endif

  return (false); /* all done */
}

void ServiceEventState(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!serv_state(iface, COINF_DL_SCAN) &&
      !serv_state(iface, COINF_DL_SYNC)) {
    set_serv_state(iface, COINF_DL_SCAN);
  } else if (serv_state(iface, COINF_DL_SCAN)) {
    if (!ServiceBlockEvent(ifaceIndex)) {
      set_serv_state(iface, COINF_DL_SYNC);
      unset_serv_state(iface, COINF_DL_SCAN);
    }
  }

  if (serv_state(iface, COINF_DL_SYNC) &&
      !serv_state(iface, COINF_WALLET_SCAN) &&
      !serv_state(iface, COINF_WALLET_SYNC)) {
    set_serv_state(iface, COINF_WALLET_SCAN);
  } else if (serv_state(iface, COINF_WALLET_SCAN)) {
    if (!ServiceWalletEvent(ifaceIndex)) {
      set_serv_state(iface, COINF_WALLET_SYNC);
      unset_serv_state(iface, COINF_WALLET_SCAN);
    }
  }

  if (serv_state(iface, COINF_DL_SYNC) &&
      serv_state(iface, COINF_WALLET_SYNC) &&
      !serv_state(iface, COINF_PEER_SCAN) &&
      !serv_state(iface, COINF_PEER_SYNC)) {
    set_serv_state(iface, COINF_PEER_SCAN);
  } else if (serv_state(iface, COINF_PEER_SCAN)) {
    if (!ServicePeerEvent(ifaceIndex)) {
      set_serv_state(iface, COINF_PEER_SYNC);
      unset_serv_state(iface, COINF_PEER_SCAN);
    }
  }
}

void InitServiceWalletEvent(CWallet *wallet, uint64_t nHeight)
{
  CIface *iface = GetCoinByIndex(wallet->ifaceIndex);
  if (GetBestHeight(wallet->ifaceIndex) == wallet->nScanHeight))
    return; /* up-to-date, 'service wallet event' is redundant scan. */
  unset_serv_state(iface, COINF_WALLET_SYNC);
  wallet->nScanHeight = MIN(nHeight, wallet->nScanHeight); 
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

  Debug("InitChainImport: importing (iface #%d) from path '%s'.\n", chain.ifaceIndex, chain.path);

  return (0);
} 

int InitChainExport(int ifaceIndex, const char *path, int min, int max)
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
  chain.pos = min;
  chain.max = max;

  unlink(path);

  return (0);
} 

void ServiceBlockEventUpdate(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface)
    return;

  CBlockIndex *bestIndex = GetBestBlockIndex(iface);
  if (bestIndex && iface->blockscan_max == bestIndex->nHeight)
    return;

  iface->net_valid = time(NULL);
  iface->blockscan_max = MAX(iface->blockscan_max, bestIndex->nHeight);
}

void event_cycle_chain(int ifaceIndex)
{

  PerformBlockChainOperation(ifaceIndex); 

  ServiceEventState(ifaceIndex);

}

int InitServiceBlockEvent(int ifaceIndex, uint64_t nHeight)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);

  if (!iface)
    return (SHERR_INVAL);
  if (!iface->enabled)
    return (SHERR_OPNOTSUPP);

  if (nHeight < iface->blockscan_max)
    return (0); /* all done */

  /* resync */
  iface->net_invalid = 0;
  iface->blockscan_max = MAX(iface->blockscan_max, nHeight);
  unset_serv_state(iface, COINF_DL_SYNC);

  return (0);
}


#ifdef __cplusplus
}
#endif



