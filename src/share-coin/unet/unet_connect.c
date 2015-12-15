
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura
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


/* ipv4 */
int unet_connect(int mode, struct sockaddr_in *net_addr, SOCKET *sk_p)
{
  unet_bind_t *bind;
  unet_table_t *table;
  struct sockaddr_in *addr;
  char buf[256];
  SOCKET cli_fd;

  if (!sk_p)
    return (SHERR_INVAL);

  cli_fd = shnet_sk();
  if (cli_fd < 0) 
    return (sk);

  if (cli_fd >= MAX_UNET_SOCKETS) {
    /* exceeds supported limit (hard-coded) */
    unet_log(mode, unet_printf("unet_connect: socket descriptor (%u) exceeds supported maximum.", (unsigned int)cli_fd));
    close(cli_fd);
    return (SHERR_AGAIN);
  }

  table = get_unet_table(cli_fd);
  if (!table) {
    close(cli_fd);
    return (SHERR_INVAL);
  }

  err = shnet_connect(cli_fd, net_addr, sizeof(struct sockaddr_in));
  if (err) {
    close(cli_fd);
    return (err);
  }

  table->mode = mode;
  table->fd = cli_fd;
  table->stamp = 0;
  memcpy(&table->net_addr, net_addr, sizeof(struct sockaddr_in));

  sprintf(buf, "created new '%s' connection (%s).\n", 
      unet_mode_label(mode), inet_ntoa(net_addr->sin_addr));
  unet_log(buf);

  if (_unet_bind[cli_fd].op_accept) {
    (*_unet_bind[cli_fd].op_accept)(addr);
  }

  *sk_p = cli_fd;

  return (0);
}

