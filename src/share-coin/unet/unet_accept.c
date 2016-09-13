
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

static unet_table_t _unet_table[MAX_UNET_SOCKETS];

unet_table_t *get_unet_table(SOCKET sk)
{

  if (sk <= 0 || sk >= MAX_UNET_SOCKETS)
    return (NULL);

  return (_unet_table + sk);
}

int unet_accept(int mode, SOCKET *sk_p)
{
  unet_bind_t *bind;
  struct sockaddr_in *addr;
  char buf[256];
  SOCKET cli_fd;

  bind = unet_bind_table(mode);
  if (!bind) {
    return (SHERR_INVAL);
  }

  if (bind->fd == UNDEFINED_SOCKET)
    return (SHERR_BADF);

  cli_fd = shnet_accept_nb(bind->fd);
  if (cli_fd == 0)
    return (SHERR_AGAIN);
  if (cli_fd < 0)
    return ((int)cli_fd);

  if (cli_fd >= MAX_UNET_SOCKETS) {
    char buf[256];

    sprintf(buf, "unet_accept: socket descriptor (%u) exceeds supported maximum.", (unsigned int)cli_fd);
    unet_log(mode, buf); 

    /* exceeds supported limit (hard-coded) */
    close(cli_fd);
    return (SHERR_AGAIN);
  }

  unet_add(mode, cli_fd);

{
unet_table_t *t = get_unet_table(cli_fd);
if (t) {
  t->flag |= UNETF_INBOUND; 
}
}

  if (bind->op_accept) {
    (*bind->op_accept)(cli_fd, shaddr(cli_fd));
  }

  if (sk_p)
    *sk_p = cli_fd;

fprintf(stderr, "DEBUG: unet_accept: accepted socket fd %d\n", cli_fd);

  return (0);
}

