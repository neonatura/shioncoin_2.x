

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

#ifndef __SHC_PROTO_H__
#define __SHC_PROTO_H__

#define SHC_VERSION_MAJOR  2 
#define SHC_VERSION_MINOR  27
#define SHC_VERSION_REVISION 0
#define SHC_VERSION_BUILD 0

#define SHC_COIN_DAEMON_PORT 24104

#define SHC_MAX_GETADDR 2500

#define SHC_MAX_ORPHAN_TRANSACTIONS 4096

#define SHC_MAX_SIGOPS 32768

static const int SHC_PROTOCOL_VERSION = 2000000;

#define SHC_COIN (uint64_t)100000000
static const unsigned int SHC_MAX_BLOCK_SIZE = 4096000;
static const int64 SHC_MIN_INPUT = 100;
static const int64 SHC_MIN_TX_FEE = 10000;
static const int64 SHC_MIN_RELAY_TX_FEE = 10000;
static const int64 SHC_MAX_MONEY = 1000000000 * SHC_COIN; /* 1bil max */
static const int SHC_COINBASE_MATURITY = 60;



#endif /* __SHC_PROTO_H__ */



