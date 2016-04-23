
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
#include "usde/usde_netmsg.h"

static int usde_msg_recv(CIface *iface, CNode *pnode)
{

  if (!pnode)
    return (0);

  if (!usde_ProcessMessages(iface, pnode)) {
    /* log */
  }

return (0);
}
static int usde_peer_add(CIface *iface, void *arg)
{
return (0);
}
static int usde_peer_recv(CIface *iface, void *arg)
{
return (0);
}
static int usde_block_new(CIface *iface, void *arg)
{
return (0);
}
static int usde_block_templ(CIface *iface, void *arg)
{
return (0);
}

static int usde_block_submit(CIface *iface, CBlock *block)
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

static int usde_block_info(CIface *iface, void *arg)
{
return (0);
}

static int usde_tx_new(CIface *iface, void *arg)
{
return (0);
}

static int usde_tx_info(CIface *iface, void *arg)
{
return (0);
}
static int usde_addr_new(CIface *iface, void *arg)
{
return (0);
}
static int usde_addr_import(CIface *iface, void *arg)
{
return (0);
}
static int usde_addr_info(CIface *iface, void *arg)
{
return (0);
}
static int usde_account_new(CIface *iface, void *arg)
{
return (0);
}
static int usde_account_move(CIface *iface, void *arg)
{
return (0);
}
static int usde_account_info(CIface *iface, void *arg)
{
return (0);
}

#ifdef __cplusplus
extern "C" {
#endif



coin_iface_t usde_coin_iface = {
  "usde",
  COIN_IFACE_VERSION(USDE_VERSION_MAJOR, USDE_VERSION_MINOR,
      USDE_VERSION_REVISION, USDE_VERSION_BUILD),
  1, /* block version */
  USDE_COIN_DAEMON_PORT,
  USDE_MAX_BLOCK_SIZE,
  USDE_MAX_BLOCK_SIZE_GEN,
  USDE_MAX_BLOCK_SIGOPS,
  USDE_MAX_ORPHAN_TRANSACTIONS,
  USDE_MIN_TX_FEE,
  USDE_MIN_RELAY_TX_FEE,
  USDE_MAX_MONEY,
  USDE_COINBASE_MATURITY, 
  USDE_LOCKTIME_THRESHOLD,
  COINF(usde_msg_recv),
  COINF(usde_peer_add),
  COINF(usde_peer_recv),
  COINF(usde_block_new),
  COINF(usde_block_templ),
  COINF(usde_block_submit),
  COINF(usde_block_info),
  COINF(usde_tx_new),
  COINF(usde_tx_info),
  COINF(usde_addr_new),
  COINF(usde_addr_import),
  COINF(usde_addr_info),
  COINF(usde_account_new),
  COINF(usde_account_move),
  COINF(usde_account_info),
};


#ifdef __cplusplus
}
#endif
