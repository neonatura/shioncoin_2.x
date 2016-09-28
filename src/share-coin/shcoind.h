
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

#ifndef __SHCOIND_H__
#define __SHCOIND_H__


#include <share.h>

/**
 *  The share coin daemon combines a fully-functional USDe virtual currency daemon with a built-in stratum server. The stratum server provides extended operations for managing accounts and reviewing worker status. 
 *  @brief Share Coin Daemon
 *  @defgroup sharecoin
 *  @{
 */


/**
 * The share coin daemon's 'peer' reference.
 */
extern shpeer_t *server_peer;
/**
 * The message queue id for communicating with the share daemon.
 */
extern int server_msgq;
/**
 * A message queue buffer for pooling incoming messages from the share daemon.
 */ 
extern shbuf_t *server_msg_buff;

/* blockchain database */
#include "blockchain/bc.h"

/* shcoind network engine */
#include "unet/unet.h"

#include "proto.h"
#include "server_iface.h"
#include "shcoind_version.h"
#include "shcoind_signal.h"
#include "shcoind_opt.h"
#include "shcoind_log.h"
#include "shcoind_block.h"
#include "shcoind_rpc.h"
#include "shcoind_descriptor.h"

#include "proto/coin_proto.h"
#include "proto/shc_proto.h"
#include "proto/usde_proto.h"
#include "proto/emc2_proto.h"
#include "proto/test_proto.h"

#include "stratum/stratum.h"
#include "shcoind_daemon.h"

#ifdef __cplusplus
#include <map>
#include <vector>
#include <string>
#include <db_cxx.h>

typedef std::vector<unsigned char> cbuff;

#include <boost/version.hpp>
#include <boost/foreach.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include "server/shlib.h"
#include "server/bignum.h"
#include "server/sync.h"
#include "server/uint256.h"
#include "server/serialize.h"
#include "server/block.h"
#include "server/txidx.h"
#include "server/global.h"

#endif



/**
 * @}
 */




/**
 * @mainpage Share Coin Daemon
 *
 * <h3>The Share Coin Daemon API reference manual.</h3>
 *
 * This project supplies the "shcoin" and "shcoind" programs.
 *
 * The "shcoind" program provides a fully-functional USDe currency service with a built-in stratum server.
 *
 * The "shcoin" utility program uses a SSL RPC connection to "shcoind" in order to perform administrative tasks.
 * <small>Note: The "shcoin" program must be ran as the same user as the "shcoind" daemon.</small>
 *
 * Note: Running additional programs from the share library suite is optional in order to run the coin+stratum service. The C share library is staticly linked against the coin service, and a 'make install' is not required to run the built programs.
 *
 */

#endif /* ndef __SHCOIND_H__ */


