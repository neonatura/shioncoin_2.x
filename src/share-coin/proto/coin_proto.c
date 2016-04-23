
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
#include "coin_proto.h"


#ifdef __cplusplus
extern "C" {
#endif



extern coin_iface_t usde_coin_iface;
extern coin_iface_t shc_coin_iface;

static coin_iface_t blank_coin_iface;


static coin_iface_t *_iface_table[MAX_COIN_IFACE] = {
  &blank_coin_iface,
  &usde_coin_iface,
  &shc_coin_iface
};


int GetCoinIndex(coin_iface_t *iface)
{
  int idx;

  for (idx = 0; idx < MAX_COIN_IFACE; idx++) {
    if (0 == strcmp(iface->name, _iface_table[idx]->name))
      return (idx);
  }

  return (-1);
}
coin_iface_t *GetCoinByIndex(int index)
{
  if (index < 0 || index >= MAX_COIN_IFACE)
    return (NULL);

  return (_iface_table[index]);
}

coin_iface_t *GetCoin(const char *name)
{
  int i;

  if (!name)
    return (NULL);
  for (i = 0; i < MAX_COIN_IFACE; i++) {
    if (0 == strcasecmp(_iface_table[i]->name, name))
      return (_iface_table[i]);
  }
  return (NULL);
}

int GetCoinAttr(const char *name, char *attr)
{
  coin_iface_t *iface;

  if (!attr)
    return (0);

  iface = GetCoin(name);
  if (!iface)
    return (0);

  if (0 == strcasecmp(attr, "max-block-size"))
    return (iface->max_block_size);
  if (0 == strcasecmp(attr, "max-block-size-gen"))
    return (iface->max_block_size_gen);
  if (0 == strcasecmp(attr, "max-orphan-transactions"))
    return (iface->max_orphan_transactions);
  if (0 == strcasecmp(attr, "min-tx-fee"))
    return (iface->min_tx_fee);
  if (0 == strcasecmp(attr, "min-relay-tx-fee"))
    return (iface->min_relay_tx_fee);
  if (0 == strcasecmp(attr, "max-money"))
    return (iface->max_money);
  if (0 == strcasecmp(attr, "coinbase-maturity"))
    return (iface->coinbase_maturity);
  if (0 == strcasecmp(attr, "locktime-threshold"))
    return (iface->locktime_threshold);
  return (0);
}



#ifdef __cplusplus
}
#endif
