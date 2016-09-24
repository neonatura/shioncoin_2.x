
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
#include "coin_proto.h"

static const char *_unet_label[MAX_UNET_MODES] = 
{
  "!NONE!",
  "shc",
  "usde",
  "omni",
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

  t = descriptor_claim(sk, mode, DF_SERVICE);
  if (!t)
    return (SHERR_IO);

  in_fam = *((sa_family_t *)&t->net_addr);
  if (in_fam == AF_INET) {
    struct sockaddr_in *in = (struct sockaddr_in *)&t->net_addr;
    char buf[256];

    sprintf(buf, "unet_add: new connection '%s' (%s) [fd %d].", 
        unet_mode_label(mode), inet_ntoa(in->sin_addr), (int)sk);
    unet_log(mode, buf);
  }

  shnet_fcntl(sk, F_SETFL, O_NONBLOCK);
  return (0);
}

int unet_mode(SOCKET sk)
{
  unet_table_t *t;

  t = get_unet_table(sk);
  if (!t)
    return (UNET_NONE);

  return (t->mode);
}

void bc_chain_idle(void);

void unet_idle(void)
{
  CIface *iface;
  int ifaceIndex;
  bc_t *bc;

  /* purge idle sockets */
  unet_close_idle(); 

  bc_chain_idle();
}


/**
 * The maximum desired time-span to perform the cycle.
 */
void unet_cycle(double max_t)
{
  static int _printed;
  static shtime_t start_t;
  static int next_t;
  unet_bind_t *bind;
  unet_table_t *t;
  shbuf_t *buff;
  struct timeval to;
  shtime_t ts;
  fd_set r_set;
  fd_set w_set;
  fd_set x_set;
  SOCKET fd;
  unsigned long diff;
  ssize_t w_tot;
  ssize_t w_len;
  ssize_t r_len;
  SOCKET sk;
  char data[65536];
  char errbuf[256];
  double wait_t;
  time_t now;
  int fd_max;
  int mode;
  int err;

  if (start_t == SHTIME_UNDEFINED)
    start_t = shtime();

  /* add daemon listen sockets to read set for accepting new sockets */
  for (mode = 1; mode < MAX_UNET_MODES; mode++) {
    bind = unet_bind_table(mode);
    if (!bind || bind->fd == UNDEFINED_SOCKET)
      continue;

    err = unet_accept(mode, NULL);
  }


  /* work proc */
  unet_timer_cycle();

  /* events */
  uevent_cycle();

  now = time(NULL);

  if (next_t < now) {
    /* scan for new service connections */
    if (uevent_type_count(UEVENT_PEER) == 0) {
      unet_peer_scan();
    }

    unet_idle(); 

    next_t = now + 15;
  }

  /* mark sockets for I/O */
  fd_max = 0;
  FD_ZERO(&r_set);
  FD_ZERO(&w_set);
  FD_ZERO(&x_set);
  for (fd = 1; fd < MAX_UNET_SOCKETS; fd++) {
    t = get_unet_table(fd);
    if (!t)
      continue;
    if ((t->flag & DF_SOCK) &&
        (t->flag & UNETF_SHUTDOWN) &&
        shbuf_size(t->wbuff) == 0) {
      /* marked for closure and write buffer is empty */
      unet_close(fd, "shutdown");
      continue;
    }
    if (!(t->flag & DF_SERVICE))
      continue; /* not important */

    FD_SET(fd, &r_set);
    FD_SET(fd, &x_set);
    if (shbuf_size(t->wbuff))
      FD_SET(fd, &w_set);
    fd_max = MAX(fd, fd_max);
  }

  /* wait remainder of max_t */
  wait_t = shtimef(shtime()) - shtimef(start_t);
  wait_t = MAX(0, max_t - wait_t);
  diff = MAX(50, MIN(500, (unsigned long)(wait_t * 1000)));

  memset(&to, 0, sizeof(to));
  to.tv_usec = 1000 * diff; /* usec */
  err = select(fd_max+1, &r_set, &w_set, &x_set, &to);
  if (err > 0) {
    for (fd = 1; fd <= fd_max; fd++) {
      if (FD_ISSET(fd, &x_set)) {
        /* socket is in error state */
        unet_close(fd, "exception");
        continue;
      }
      if (FD_ISSET(fd, &r_set)) {
        memset(data, 0, sizeof(data));
        r_len = shnet_read(fd, data, sizeof(data));
        if (r_len < 0) {
          if (r_len != SHERR_AGAIN) {
            sprintf(errbuf, "read fd %d (%s)", fd, sherrstr(r_len));
            unet_close(fd, errbuf);
            continue;
          }
        } else if (r_len > 0) {
          descriptor_rbuff_add(fd, data, r_len);
          descriptor_mark(fd);
        }
      }
      if (FD_ISSET(fd, &w_set)) {
        t = get_unet_table(fd);
        if (!t || !t->wbuff) continue;

        w_tot = shbuf_size(t->wbuff);
        if (w_tot != 0) {
          w_len = shnet_write(fd, shbuf_data(t->wbuff), w_tot);
          if (w_len < 0) {
            if (w_len != SHERR_AGAIN) {
              sprintf(errbuf, "write fd %d (%s)", fd, sherrstr(r_len));
              unet_close(fd, errbuf);
              continue;
            }
          } else if (w_len > 0) {
            shbuf_trim(t->wbuff, w_len);
            descriptor_mark(fd);
          }
        }
      }
    }
  } else if (err < 0) {
    if (errno != EINTR) {
      sprintf(errbuf, "unet_cycle: warning: select errno %d [fd-max %d]\n", errno, fd_max);  
      shcoind_log(errbuf);
    }

    /* BADF */
    if (errno == EBADF && !_printed) {
      _printed = 1;
      descriptor_list_print();
    }
  }

  start_t = shtime();

#if 0
  /* free expunged sockets */
  unet_close_free();
#endif

}


void unet_shutdown(SOCKET sk)
{
  unet_table_t *t;

  t = get_unet_table(sk);
  if (!t)
    return;

  t->flag |= UNETF_SHUTDOWN;
}




