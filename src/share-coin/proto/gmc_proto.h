

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

#ifndef __GMC_PROTO_H__
#define __GMC_PROTO_H__

#define GMC_VERSION_MAJOR       0
#define GMC_VERSION_MINOR       9
#define GMC_VERSION_REVISION    4
#define GMC_VERSION_BUILD       3

#define GMC_COIN_DAEMON_PORT 40002

#define GMC_MAX_GETADDR 2500

#define GMC_COIN (uint64_t)100000000
static const unsigned int GMC_MAX_BLOCK_SIZE = 1000000;
static const unsigned int GMC_MAX_BLOCK_SIZE_GEN = 500000;
static const unsigned int GMC_MAX_BLOCK_SIGOPS = 20000;
static const unsigned int GMC_MAX_ORPHAN_TRANSACTIONS = 100;
static const int64 GMC_MIN_TX_FEE = 10000;
static const int64 GMC_MIN_RELAY_TX_FEE = 1000;
static const int64 GMC_MAX_MONEY = 84000000 * GMC_COIN;
static const int GMC_COINBASE_MATURITY = 100;



#endif /* __GMC_PROTO_H__ */



