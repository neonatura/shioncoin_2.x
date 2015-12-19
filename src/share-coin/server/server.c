
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

int get_usde_server_port(void)
{
/* todo: config */
  return (COIN_DAEMON_PORT);
}

/**
 * Called when a new socket is accepted on the shcoind stratum port (default 9448).
 */
static void usde_accept(int fd, struct sockaddr *net_addr)
{
#if 0
  sa_family_t in_fam;

  in_fam = *((sa_family_t *)net_addr);
  if (in_fam == AF_INET) {
    struct sockaddr_in *addr = (struct sockaddr_in *)net_addr;
    char buf[256];

    sprintf(buf, "stratum_accept: received connection (%s port %d).\n", inet_ntoa(addr->sin_addr), STRATUM_DAEMON_PORT);
    shcoind_log(buf);  
  }

  stratum_register_client(fd);
#endif 
}

static void usde_close(int fd, struct sockaddr *net_addr)
{
#if 0
  user_t *peer_next;
  user_t *peer_last;
  user_t *peer;

  peer_last = NULL;
  for (peer = client_list; peer; peer = peer_next) {
    peer_next = peer->next;

    if (peer->fd == fd) {
      peer->fd = -1;
    }

    if (peer->fd == -1) {
      if (peer_last)
        peer_last->next = peer_next;
      else
        client_list = peer_next;
      free(peer);
      continue;
    }

    peer_last = peer;
  }
#endif
}

static void usde_timer(void)
{
#if 0
  unet_table_t *t;
  user_t *peer;
  shbuf_t *buff;
  size_t len;
  char *data;
  int err;

  for (peer = client_list; peer; peer = peer->next) {
    if (peer->fd == -1)
      continue;

    t = get_unet_table(peer->fd);
    if (!t) continue;

    buff = t->rbuff;
    if (!buff) continue;

    /* check status of socket. */
    err = write(peer->fd, "", 0);
    if (err) {
      char buf[256];

      sprintf(buf, "stratum_timer: socket (%d) in error state: %s [errno %d].", peer->fd, strerror(errno), errno);
      shcoind_log(buf);

      /* socket is inaccesible */
      unet_close(peer->fd);
      peer->fd = -1;
      continue;
    }

    /* process incoming requests */
    len = shbuf_idx(buff, '\n');
    if (len == -1)
      continue;
    data = shbuf_data(buff);
    data[len] = '\0';

    stratum_register_client_task(peer, data);
    shbuf_trim(buff, len + 1);
  }

  stratum_task_gen();
#endif
}

void usde_server_term(void)
{

  unet_unbind(UNET_COIN);

}


int usde_server_init(void)
{
  int err;

  err = unet_bind(UNET_COIN, get_usde_server_port());
  if (err)
    return (err);

  unet_flag_set(UNET_COIN, UNETF_PEER_SCAN);

  unet_timer_set(UNET_COIN, usde_timer); /* x1/s */
  unet_connop_set(UNET_COIN, usde_accept);
  unet_disconnop_set(UNET_COIN, usde_close);

  return (0);
}

