
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

static const char *_unet_label[MAX_UNET_MODES] = 
{
  "!NONE!",
  "usde",
  "shc",
  "!RESERVED!",
  "!RESERVED!",
  "stratum",
  "rpc",
};
const char *unet_mode_label(int mode)
{
  if (mode < 0 || mode >= MAX_UNET_MODES)
    return (NULL);

  return (_unet_label[mode]);
}

int unet_add(int mode, SOCKET sk)
{
  unet_table_t *t;
  struct sockaddr *addr;
  sa_family_t in_fam;

  t = get_unet_table(sk);
  if (!t)
    return (SHERR_INVAL);

  /* fill network info */
  t->fd = sk;
  t->mode = mode;
  t->cstamp = shtime(); /* init connect time-stamp */
  t->stamp = 0; /* reset I/O timestamp */

  /* retain remote network addr (ipv4) */
  memset(&t->net_addr, 0, sizeof(t->net_addr));
  addr = shaddr(sk);
  if (addr)
    memcpy(&t->net_addr, addr, sizeof(struct sockaddr));

  in_fam = *((sa_family_t *)&t->net_addr);
  if (in_fam == AF_INET) {
    struct sockaddr_in *in = (struct sockaddr_in *)&t->net_addr;
    char buf[256];

    sprintf(buf, "unet_add: new connection '%s' (%s).", 
        unet_mode_label(mode), inet_ntoa(in->sin_addr));
    unet_log(mode, buf);
  }

  shnet_fcntl(sk, F_SETFL, O_NONBLOCK);
  return (0);
}

int unet_mode(SOCKET sk)
{
  unet_table_t *t;

  t = get_unet_table(sk);
  if (!t || t->fd == UNDEFINED_SOCKET)
    return (UNET_NONE);

  return (t->mode);
}



/**
 * The maximum desired time-span to perform the cycle.
 */
void unet_cycle(double max_t)
{
  unet_bind_t *bind;
  unet_table_t *t;
  shbuf_t *buff;
  struct timeval to;
  shtime_t start_t;
  shtime_t ts;
  fd_set r_set;
  fd_set x_set;
  SOCKET fd;
  double diff_t;
  size_t w_len;
  SOCKET sk;
  int fd_max;
  int mode;
  int err;

  start_t = shtime();

  /* add daemon listen sockets to read set for accepting new sockets */
  for (mode = 1; mode < MAX_UNET_MODES; mode++) {
    bind = unet_bind_table(mode);
    if (!bind || bind->fd == UNDEFINED_SOCKET)
      continue;

    err = unet_accept(mode, NULL);
  }

  /* process I/O for sockets */
  fd_max = 1;
  FD_ZERO(&r_set);
  FD_ZERO(&x_set);
  for (fd = 1; fd < MAX_UNET_SOCKETS; fd++) {
    t = get_unet_table(fd);
    if (!t || t->fd == UNDEFINED_SOCKET)
      continue;

    if ((t->flag & UNETF_SHUTDOWN) &&
        shbuf_size(t->wbuff) == 0) {
      /* marked for closure and write buffer is empty */
      unet_close(t->fd, "shutdown");
      continue;
    }

    /* write outgoing buffer to socket */
    if (shbuf_size(t->wbuff)) {
      timing_init("shnet_write", &ts);
      w_len = shnet_write(fd, shbuf_data(t->wbuff), shbuf_size(t->wbuff));
      timing_term("shnet_write", &ts);
      if (w_len < 0) {
        unet_close(fd, "write");
        continue;
      }

      shbuf_trim(t->wbuff, w_len);
      t->stamp = shtime();
    }

    /* handle incoming data */
    timing_init("shnet_read", &ts);
    buff = shnet_read_buf(fd);
    timing_term("shnet_read", &ts);
    if (!buff) {
      /* connection reset by peer */
      unet_close(fd, "read");
      continue;
    }
    if (shbuf_size(buff)) {
      unet_rbuff_add(fd, shbuf_data(buff), shbuf_size(buff));
      shbuf_clear(buff);
      t->stamp = shtime();
    }

#if 0
    /* flush pending writes */
    w_len = shnet_write_flush(fd);
    if (w_len == -1) {
      unet_close(fd);
      continue;
    }
#endif

    FD_SET(fd, &r_set);
    FD_SET(fd, &x_set);
    fd_max = MAX(fd, fd_max);
  }

  /* work proc */
  unet_timer_cycle();

  /* events */
  uevent_cycle();

  /* scan for new service connections */
  if (uevent_type_count(UEVENT_PEER) == 0)
    unet_peer_scan();

  /* purge idle sockets */
  unet_close_idle(); 

  memset(&to, 0, sizeof(to));
  diff_t = max_t - (shtimef(shtime()) - shtimef(start_t));
  to.tv_usec = MIN(999999, (long)((double)1000000 * MAX(0, diff_t)));
if ((double)to.tv_usec / 1000000 > max_t) {
fprintf(stderr, "DEBUG: warning: unet_cycle: max_t %f, to.tv_usec %u\n", max_t, to.tv_usec); 
}
  err = select(fd_max+1, &r_set, NULL, &x_set, &to);
  if (err > 0) {
    for (fd = 1; fd <= fd_max; fd++) {
      if (FD_ISSET(fd, &x_set)) {
        /* socket is in error state */
        unet_close(fd, "exception");
      }
    }
  }

  /* free expunged sockets */
  unet_close_free();

}


void unet_shutdown(SOCKET sk)
{
  unet_table_t *t;

  t = get_unet_table(sk);
  if (!t || t->fd == UNDEFINED_SOCKET)
    return;

  t->flag |= UNETF_SHUTDOWN;
}

