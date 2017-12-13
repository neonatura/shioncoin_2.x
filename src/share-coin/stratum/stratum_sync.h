
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

#ifndef __STRATUM__STRATUM_SYNC_H__
#define __STRATUM__STRATUM_SYNC_H__


void stratum_sync_init(void);

/**
 * 1. periodically review (every hour via 'wallet.list') to determine if tracked accounts have changed, and if so, sends as 'wallet.listaddr' to find out what coin addrs are missing locally. when coin addr(s) are found missing a 'wallet.setkey' is performed to add the missing entry.
 * 2. A duplicate set of workers is maintained (every 10min by 'stratum.remote') by periodically updating their "block_tot" and "block_cnt" matching the local stats.
 *
 * Stratum Format: stratum.remote [<worker>,<block_tot>,<block_cnt>]
 *
 * @see SYNC_WALLET_LIST
 * @see SYNC_WALLET_LISTADDR
 * @see user_t.setkey_stamp //setkey op(s) are limited to once per hour 
 * @see USER_REMOTE
 * @see user_t.mine_stamp
 * @note The coin server will only reward coins mined by it's own mining address.
 */


void stratum_sync(void)



int stratum_sync_recv_pub(int ifaceIndex, user_t *user, uint32_t pin, char *acc_name, char *pub_key);


#endif /* ndef __STRATUM__STRATUM_SYNC_H__ */


