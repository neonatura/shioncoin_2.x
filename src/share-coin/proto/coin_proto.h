
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

#ifndef __COIN_PROTO_H__
#define __COIN_PROTO_H__

#include "shcoind.h"


#ifdef __cplusplus
#include <vector>
extern "C" {
#endif



#define USDE_COIN_IFACE 1
#define SHC_COIN_IFACE 2
#define MAX_COIN_IFACE 3




#define COIN_IFACE_VERSION(_maj, _min, _rev, _bui) \
  ( \
   (1000000 * (_maj)) + \
   (10000 * (_min)) + \
   (100 * (_rev)) + \
   (1 * (_bui)) \
  )


#define MAX_BLOCK_SIGOPS(_iface) \
  ((_iface)->max_block_size / 50)

#define MAX_BLOCK_SIZE_GEN(_iface) \
  ((_iface)->max_block_size / 2)

#define MAX_ORPHAN_TRANSACTIONS(_iface) \
  ((_iface)->max_orphan_tx)


struct coin_iface_t;
typedef int (*coin_f)(struct coin_iface_t * /*iface*/, void * /* arg */);
#define COINF(_f) ((coin_f)(_f))


typedef struct coin_iface_t
{
  /* lowercase 'common' name of currency */
  char name[MAX_SHARE_NAME_LENGTH];
  int client_ver;
  int block_ver;
  int proto_ver;

  /* socket */
  int port;

  uint64_t max_block_size;
  uint64_t max_orphan_tx;
  uint64_t min_tx_fee;
  uint64_t min_relay_tx_fee;
  uint64_t max_money;
  uint64_t coinbase_maturity;

  /* coin operations */
  coin_f op_init;
  coin_f op_term;
  coin_f op_msg_recv;
  coin_f op_msg_send;
  coin_f op_peer_add;
  coin_f op_peer_recv;
  coin_f op_block_new;
  coin_f op_block_process;
  coin_f op_block_templ;
  coin_f op_tx_new;
  coin_f op_tx_pool;

  bc_t *bc_block;
  bc_t *bc_tx;
  double blk_diff; /* next block difficulty */
  uint64_t tx_tot; /* nTransactionsUpdated */
  bc_hash_t block_besthash; /* best block hash */
  time_t net_valid;
  time_t net_invalid;
} coin_iface_t;

typedef struct coin_iface_t CIface;


int GetCoinAttr(const char *name, char *attr);

int GetCoinIndex(coin_iface_t *iface);
coin_iface_t *GetCoinByIndex(int index);

coin_iface_t *GetCoin(const char *name);



/* currency interfaces */
#include "usde_proto.h"
#include "shc_proto.h"
#include "gmc_proto.h"

#ifdef __cplusplus
}

class CNode;
typedef std::vector<CNode *> NodeList;
NodeList& GetNodeList(int ifaceIndex);
NodeList& GetNodeList(CIface *iface);
#endif


#endif /* ndef __COIN_PROTO_H__ */
