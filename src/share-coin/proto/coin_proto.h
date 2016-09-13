
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


#define TEST_COIN_IFACE 0
#define SHC_COIN_IFACE 1
#define USDE_COIN_IFACE 2
#define MAX_COIN_IFACE 3


#define COINF_DL_SCAN (1 << 0)
#define COINF_DL_SYNC (1 << 1)
#define COINF_WALLET_SCAN (1 << 3)
#define COINF_WALLET_SYNC (1 << 4)
#define COINF_PEER_SCAN (1 << 5)
#define COINF_PEER_SYNC (1 << 6)


#define COIN_IFACE_VERSION(_maj, _min, _rev, _bui) \
  ( \
   (1000000 * (_maj)) + \
   (10000 * (_min)) + \
   (100 * (_rev)) + \
   (1 * (_bui)) \
  )


#define MAX_BLOCK_SIGOPS(_iface) \
  ((_iface)->max_sigops)

#define MAX_BLOCK_SIZE_GEN(_iface) \
  ((_iface)->max_block_size / 2)

#define MAX_ORPHAN_TRANSACTIONS(_iface) \
  ((_iface)->max_orphan_tx)

/**
 * The minimum fee applied to a tranaction.
 */
#define MIN_TX_FEE(_iface) \
  (int64)(iface ? ((_iface)->min_tx_fee) : 0)

/**
 * The minimum coin value allowed to be transfered in a single transaction.
 */
#define MIN_INPUT_VALUE(_iface) \
  (int64)(iface ? ((_iface)->min_input) : 0)


#define STAT_BLOCK_ACCEPTS(_iface) (_iface)->stat.tot_block_accept
#define STAT_BLOCK_SUBMITS(_iface) (_iface)->stat.tot_block_submit
#define STAT_TX_ACCEPTS(_iface) (_iface)->stat.tot_tx_accept
#define STAT_TX_SUBMITS(_iface) (_iface)->stat.tot_tx_submit

struct coin_iface_t;
typedef int (*coin_f)(struct coin_iface_t * /*iface*/, void * /* arg */);
#define COINF(_f) ((coin_f)(_f))

/**
 * A coin interface provides a specialized means to perform service operations.
 */
typedef struct coin_iface_t
{
  /* lowercase 'common' name of currency */
  char name[MAX_SHARE_NAME_LENGTH];
  int enabled;
  int client_ver;
  int block_ver;
  int proto_ver;

  /* socket */
  int port;

  unsigned char hdr_magic[4];

  uint64_t min_input;
  uint64_t max_block_size;
  uint64_t max_orphan_tx;
  uint64_t min_tx_fee;
  uint64_t min_relay_tx_fee;
  uint64_t max_money;
  uint64_t coinbase_maturity;
  uint64_t max_sigops;

  /* coin operations */
  coin_f op_init;
  coin_f op_bind;
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
  uint32_t blockscan_max;
  int flags;

  struct coin_stat_t {
    uint64_t tot_block_submit;
    uint64_t tot_block_accept;
    uint64_t tot_tx_submit;
    uint64_t tot_tx_accept;
    uint64_t tot_spring_submit;
    uint64_t tot_spring_accept;
  } stat;
} coin_iface_t;

typedef struct coin_iface_t CIface;

typedef struct coinhdr_t
{
  unsigned char magic[4];
  char cmd[12];
  uint32_t size;
  uint32_t crc;
} coinhdr_t;
#define SIZEOF_COINHDR_T 24

/**
 * Obtain a numerical attribute for a coin interface
 */
int GetCoinAttr(const char *name, char *attr);

/**
 * Get the defined index for a specified coin interface.
 */
int GetCoinIndex(coin_iface_t *iface);

/**
 * Obtain a coin interface by it's defined index.
 * @see SHC_COIN_IFACE
 */
coin_iface_t *GetCoinByIndex(int index);

/**
 * Obtain a coin interface by it's common lowercase code.
 */
coin_iface_t *GetCoin(const char *name);


/**
 * The SHC currency coin service.
 * @ingroup sharecoin
 * @defgroup sharecoin_shc The SHC currency coin service.
 * @{
 */
#include "shc_proto.h"
/**
 * @}
 */

/**
 * The USDe currency coin service.
 * @ingroup sharecoin
 * @defgroup sharecoin_usde The USDE currency coin service.
 * @{
 */
#include "usde_proto.h"
/**
 * @}
 */


bc_t *GetBlockChain(CIface *iface);

bc_t *GetBlockTxChain(CIface *iface);


#ifdef __cplusplus
}

class CNode;
typedef std::vector<CNode *> NodeList;
NodeList& GetNodeList(int ifaceIndex);
NodeList& GetNodeList(CIface *iface);
#endif




#endif /* ndef __COIN_PROTO_H__ */
