

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

#ifndef __OMNI_PROTO_H__
#define __OMNI_PROTO_H__

#define OMNI_VERSION_MAJOR       0
#define OMNI_VERSION_MINOR       8
#define OMNI_VERSION_REVISION    6
#define OMNI_VERSION_BUILD       2

#define OMNI_COIN_DAEMON_PORT 33813

#define OMNI_MAX_GETADDR 500

#define OMNI_MAX_ORPHAN_TRANSACTIONS 10000

#define OMNI_MAX_SIGOPS 20000

static const int OMNI_PROTOCOL_VERSION = 80007;

#define OMNI_COIN (uint64_t)100000000
static const unsigned int OMNI_MAX_BLOCK_SIZE = 1000000;
static const int64 OMNI_MIN_INPUT = 10000;
static const int64 OMNI_MIN_TX_FEE = 10000;
static const int64 OMNI_MIN_RELAY_TX_FEE = 10000;
static const int64 OMNI_MAX_MONEY = 13371337 * OMNI_COIN;

/** The official OMNI maturity is 40 depth. */
static const int OMNI_COINBASE_MATURITY = 40;



#endif /* __OMNI_PROTO_H__ */



