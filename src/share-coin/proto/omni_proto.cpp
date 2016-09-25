
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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
#include "main.h"
#include "wallet.h"
#include "coin_proto.h"
#include "omni/omni_netmsg.h"
#include "omni/omni_block.h"
#include "omni/omni_wallet.h"
#include "omni/omni_txidx.h"

OMNI_CTxMemPool OMNIBlock::mempool;
CBlockIndex *OMNIBlock::pindexGenesisBlock = NULL;
int64 OMNIBlock::nTimeBestReceived;
CBigNum OMNIBlock::bnBestChainWork;
CBigNum OMNIBlock::bnBestInvalidWork;

#if 0
int64 OMNIBlock::nTargetTimespan = 14400; /* four hours */
int64 OMNIBlock::nTargetSpacing = 180; /* three minutes */
#endif


static int omni_init(CIface *iface, void *_unused_)
{
  int ifaceIndex = GetCoinIndex(iface);
  int err;

  omniWallet = new OMNIWallet();
  SetWallet(OMNI_COIN_IFACE, omniWallet);



#if 0
  if (!bitdb.Open(GetDataDir())) /* DEBUG: */
  {
    fprintf(stderr, "error: unable to open data directory.\n");
    return (SHERR_INVAL);
  }
#endif

  if (!omni_InitBlockIndex()) {
    fprintf(stderr, "error: omni_proto: unable to initialize block index table.\n");
    return (SHERR_INVAL);
  }

  if (!omni_LoadWallet()) {
    fprintf(stderr, "error: omni_proto: unable to load wallet.\n");
    return (SHERR_INVAL);
  }

  Debug("initialized OMNI block-chain.");

  return (0);
}

static int omni_bind(CIface *iface, void *_unused_)
{
  int err;

  err = unet_bind(UNET_OMNI, OMNI_COIN_DAEMON_PORT);
  if (err) { 
    error(err, "error binding OMNI socket port");
    return (err);
  }

  unet_timer_set(UNET_OMNI, omni_server_timer); /* x10/s */
  unet_connop_set(UNET_OMNI, omni_server_accept);
  unet_disconnop_set(UNET_OMNI, omni_server_close);

  /* automatically connect to peers of 'omni' service. */
  unet_bind_flag_set(UNET_OMNI, UNETF_PEER_SCAN);

  Debug("initialized OMNI service on port %d.", (int)iface->port);

  return (0);
}
static int omni_term(CIface *iface, void *_unused_)
{
  CWallet *wallet = GetWallet(iface);
  if (wallet)
    UnregisterWallet(wallet);
  SetWallet(iface, NULL);
}

static int omni_msg_recv(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!omni_ProcessMessages(iface, pnode)) {
    /* log */
  }

return (0);
}
static int omni_msg_send(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!omni_SendMessages(iface, pnode, false)) {
    /* log */
  }

return (0);
}
static int omni_peer_add(CIface *iface, void *arg)
{
return (0);
}
static int omni_peer_recv(CIface *iface, void *arg)
{
return (0);
}
static int omni_block_new(CIface *iface, CBlock **block_p)
{
  *block_p = new OMNIBlock();
return (0);
}

static int omni_block_process(CIface *iface, CBlock *block)
{

  if (!omni_ProcessBlock(block->originPeer, block))
    return (SHERR_INVAL);

  return (0);
}

static int omni_block_templ(CIface *iface, CBlock **block_p)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CBlock* pblock;
  unsigned int median;
  int reset;
    
  if (!wallet) {
    unet_log(ifaceIndex, "GetBlocKTemplate: Wallet not initialized.");
    return (NULL);
  }

  CBlockIndex *pindexBest = GetBestBlockIndex(OMNI_COIN_IFACE);
  median = pindexBest->GetMedianTimePast() + 1;

  CReserveKey reservekey(wallet);
  pblock = omni_CreateNewBlock(reservekey);
  if (!pblock)
    return (NULL);

  pblock->nTime = MAX(median, GetAdjustedTime());
  pblock->nNonce = 0;

  *block_p = pblock;

  return (0);
}

#if 0
static int omni_block_submit(CIface *iface, CBlock *block)
{
  blkidx_t *blockIndex;

  blockIndex = GetBlockTable(OMNI_COIN_IFACE);
  if (!blockIndex) {
fprintf(stderr, "DEBUG: omni_block_submit: error obtaining tableBlockIndex[OMNI}\n"); 
    return (STERR_INVAL);
}

  // Check for duplicate
  uint256 hash = block->GetHash();
  if (blockIndex->count(hash))// || mapOrphanBlocks.count(hash))
    return (BLKERR_DUPLICATE_BLOCK);

  // Preliminary checks
  if (!block->CheckBlock()) {
    shcoind_log("c_processblock: !CheckBlock()");
    return (BLKERR_CHECKPOINT);
  }

  // Store to disk
  if (!block->AcceptBlock()) {
    shcoind_log("c_processblock: !AcceptBlock()");
    return (BLKERR_INVALID_BLOCK);
  }

  block->print();

return (0);
}
#endif

static int omni_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int omni_tx_pool(CIface *iface, CTxMemPool **pool_p)
{
  *pool_p = &OMNIBlock::mempool;
  return (0);
}

#ifdef __cplusplus
extern "C" {
#endif



coin_iface_t omni_coin_iface = {
  "omni",
  TRUE,
  COIN_IFACE_VERSION(OMNI_VERSION_MAJOR, OMNI_VERSION_MINOR,
      OMNI_VERSION_REVISION, OMNI_VERSION_BUILD), /* cli ver */
  2, /* block version */
  OMNI_PROTOCOL_VERSION, /* network protocol version */ 
  OMNI_COIN_DAEMON_PORT,
  { 0xd4, 0xcb, 0xa1, 0xef },
  OMNI_MIN_INPUT,
  OMNI_MAX_BLOCK_SIZE,
  OMNI_MAX_ORPHAN_TRANSACTIONS,
  OMNI_MIN_TX_FEE,
  OMNI_MIN_RELAY_TX_FEE,
  OMNI_MAX_MONEY,
  OMNI_COINBASE_MATURITY, 
  OMNI_MAX_SIGOPS,
  COINF(omni_init),
  COINF(omni_bind),
  COINF(omni_term),
  COINF(omni_msg_recv),
  COINF(omni_msg_send),
  COINF(omni_peer_add),
  COINF(omni_peer_recv),
  COINF(omni_block_new),
  COINF(omni_block_process),
  COINF(omni_block_templ),
  COINF(omni_tx_new),
  COINF(omni_tx_pool)
};


#ifdef __cplusplus
}
#endif
