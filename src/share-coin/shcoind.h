
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
 *
 *  @author Brian Burrell
 *  @date 2014
 */  

#ifndef __SHCOIND_H__
#define __SHCOIND_H__


#include <share.h>

extern int server_fd;
extern shpeer_t *server_peer;
extern int server_msgq;
extern shbuf_t *server_msg_buff;

#include "proto.h"
#include "server_iface.h"
#include "shcoind_version.h"
#include "stratum/stratum.h"
#include "shcoind_daemon.h"
#include "shcoind_block.h"
#include "shcoind_rpc.h"

#endif /* ndef __SHCOIND_H__ */


