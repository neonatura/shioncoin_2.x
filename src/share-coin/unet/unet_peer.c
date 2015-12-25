
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


int unet_peer_find(struct sockaddr *addr)
{
  sa_family_t in_fam;
  sa_family_t cmp_fam;
  unet_table_t *t;
  char hostname[MAXHOSTNAMELEN+1];
  char buf[256];
  int sk;

  in_fam = *((sa_family_t *)addr);
  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t || t->fd == UNDEFINED_SOCKET)
      continue; /* non-active */

    cmp_fam = *((sa_family_t *)&t->net_addr);
    if (cmp_fam != in_fam) {
      continue; /* different network family */
    }

    if (in_fam == AF_INET) {
      struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
      struct sockaddr_in *addr4_cmp = (struct sockaddr_in *)&t->net_addr;
      if (0 == memcmp(&addr4->sin_addr, &addr4_cmp->sin_addr, sizeof(addr4->sin_addr))) {
        return (sk);
      }
    } else if (in_fam == AF_INET6) {
      struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
      struct sockaddr_in6 *addr6_cmp = (struct sockaddr_in6 *)&t->net_addr;
      if (0 == memcmp(&addr6->sin6_addr, &addr6_cmp->sin6_addr, sizeof(addr6->sin6_addr))) {
        return (sk);
      }
   }
  }
  
  return (0);
}
void unet_peer_verify(int mode)
{
  unet_bind_t *bind;
  char buf[256];
  int err;

  bind = unet_bind_table(mode);
  if (!bind)
    return;

  err = shnet_track_verify(&bind->scan_peer, &bind->scan_fd);
  if (err != SHERR_INPROGRESS) {
    if (!err) {
      /* success */
      shnet_track_mark(&bind->scan_peer, 1);
      bind->scan_freq *= 2;

      sprintf(buf, "unet_peer_verify: connect '%s' (success).", shpeer_print(&bind->scan_peer));
      unet_log(mode, buf);

      /* initiate service connection. */
      if (!unet_peer_find(shpeer_addr(&bind->scan_peer)))
        unet_connect(mode, shpeer_addr(&bind->scan_peer), NULL);
    } else {
      /* error */
      shnet_track_mark(&bind->scan_peer, -1);
      bind->scan_freq /= 2;

      sprintf(buf, "unet_peer_verify: error: connect '%s' (%s) [sherr %d].", shpeer_print(&bind->scan_peer), sherrstr(err), err);
      unet_log(mode, buf);
    }
  } else {
    if (shtime_before(shtime_adj(bind->scan_stamp, 5), shtime())) {
      /* error */
      shnet_track_mark(&bind->scan_peer, -1);
      bind->scan_freq /= 2;


      err = SHERR_TIMEDOUT;
      sprintf(buf, "unet_peer_verify: error: connect '%s' (%s) [sherr %d].", shpeer_print(&bind->scan_peer), sherrstr(err), err);
      unet_log(mode, buf);

      shnet_close(bind->scan_fd);
      bind->scan_fd = 0;
  }
    /* DEBUG: connection timeout */
  }


  
}

void unet_peer_scan(void)
{
  unet_bind_t *bind;
  shpeer_t *peer;
  double dur;
  int mode;
  int err;

  for (mode = 0; mode < MAX_UNET_MODES; mode++) {
    bind = unet_bind_table(mode);
    if (!bind)
      continue;
    if (!(bind->flag & UNETF_PEER_SCAN))
      continue;

    if (bind->scan_fd) {
      unet_peer_verify(mode);
      continue;
    }

    dur = MAX(2, MIN(300, 300 * bind->scan_freq));
    if (shtime_after(shtime_adj(bind->scan_stamp, dur), shtime()))
      continue;
    bind->scan_stamp = shtime();

    err = shnet_track_scan(&bind->peer, &peer);
    if (err)
      continue;

    if (unet_peer_find(shpeer_addr(peer))) {
      /* already connected */
      shpeer_free(&peer);
      continue;
    }

    memcpy(&bind->scan_peer, peer, sizeof(shpeer_t));
    unet_peer_verify(mode);

  }

}


