

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

#ifndef __TEST_PROTO_H__
#define __TEST_PROTO_H__

#define TEST_VERSION_MAJOR       0 
#define TEST_VERSION_MINOR       0
#define TEST_VERSION_REVISION    0 
#define TEST_VERSION_BUILD       1

#define TEST_COIN_DAEMON_PORT 0

#define TEST_MAX_GETADDR 2500

#define TEST_MAX_ORPHAN_TRANSACTIONS 10000

#define TEST_MAX_SIGOPS 32768

static const int TEST_PROTOCOL_VERSION = 1000000;

#define TEST_COIN (uint64_t)100000000
static const unsigned int TEST_MAX_BLOCK_SIZE = 1000000;
static const int64 TEST_MIN_INPUT = 0;
static const int64 TEST_MIN_TX_FEE = 10000;
static const int64 TEST_MIN_RELAY_TX_FEE = 10000;
static const int64 TEST_MAX_MONEY = 1600000000 * TEST_COIN;
//static const int TEST_COINBASE_MATURITY = 100;
static const int TEST_COINBASE_MATURITY = 10;



#endif /* __TEST_PROTO_H__ */



