
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
#include "coin_proto.h"
#include "shc/shc_netmsg.h"



static int shc_msg_recv(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!shc_ProcessMessages(iface, pnode)) {
    /* log */
  }

return (0);
}
static int shc_peer_add(CIface *iface, void *arg)
{
return (0);
}
static int shc_peer_recv(CIface *iface, void *arg)
{
return (0);
}
static int shc_block_new(CIface *iface, void *arg)
{
return (0);
}
static int shc_block_templ(CIface *iface, void *arg)
{
return (0);
}

static int shc_block_submit(CIface *iface, CBlock *block)
{

  // Check for duplicate
  uint256 hash = block->GetHash();
  if (mapBlockIndex.count(hash))// || mapOrphanBlocks.count(hash))
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

static int shc_block_info(CIface *iface, void *arg)
{
return (0);
}

static int shc_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int shc_tx_info(CIface *iface, void *arg)
{
return (0);
}
static int shc_addr_new(CIface *iface, void *arg)
{
return (0);
}
static int shc_addr_import(CIface *iface, void *arg)
{
return (0);
}
static int shc_addr_info(CIface *iface, void *arg)
{
return (0);
}
static int shc_account_new(CIface *iface, void *arg)
{
return (0);
}
static int shc_account_move(CIface *iface, void *arg)
{
return (0);
}
static int shc_account_info(CIface *iface, void *arg)
{
return (0);
}








#ifdef __cplusplus
extern "C" {
#endif

coin_iface_t shc_coin_iface = {
  "usde",
  COIN_IFACE_VERSION(SHC_VERSION_MAJOR, SHC_VERSION_MINOR,
      SHC_VERSION_REVISION, SHC_VERSION_BUILD),
  1, /* block version */
  SHC_COIN_DAEMON_PORT,
  SHC_MAX_BLOCK_SIZE,
  SHC_MAX_BLOCK_SIZE_GEN,
  SHC_MAX_BLOCK_SIGOPS,
  SHC_MAX_ORPHAN_TRANSACTIONS,
  SHC_MIN_TX_FEE,
  SHC_MIN_RELAY_TX_FEE,
  SHC_MAX_MONEY,
  SHC_COINBASE_MATURITY, 
  SHC_LOCKTIME_THRESHOLD,
  COINF(shc_msg_recv),
  COINF(shc_peer_add),
  COINF(shc_peer_recv),
  COINF(shc_block_new),
  COINF(shc_block_templ),
  COINF(shc_block_submit),
  COINF(shc_block_info),
  COINF(shc_tx_new),
  COINF(shc_tx_info),
  COINF(shc_addr_new),
  COINF(shc_addr_import),
  COINF(shc_addr_info),
  COINF(shc_account_new),
  COINF(shc_account_move),
  COINF(shc_account_info),
};


#ifdef __cplusplus
}
#endif
