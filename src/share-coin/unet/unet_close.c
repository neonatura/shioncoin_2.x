
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

#define MAX_SOCKET_BUFFER_SIZE 20480000 /* 20meg */

int unet_close(SOCKET sk, char *tag)
{
  unet_table_t *table;
  unet_bind_t *bind;
  char buf[256];
  int err;

  table = get_unet_table(sk);
  if (!table || table->fd == UNDEFINED_SOCKET)
    return (SHERR_INVAL);

  /* inform user-level of socket closure. */
  bind = unet_bind_table(table->mode);
  if (bind && bind->op_close) {
    (*bind->op_close)(sk, &table->net_addr);
  }

#ifdef WIN32
  err = closesocket(sk);
#else
  err = close(sk);
#endif

  sprintf(buf, "closed connection '%s' (%-2.2fh) [%s].",
      shaddr_print(&table->net_addr), 
      shtime_diff(shtime(), table->cstamp) / 3600,
      tag ? tag : "n/a");
  unet_log(table->mode, buf);

  table->fd = UNDEFINED_SOCKET;

  return (err);
}

int unet_close_all(int mode)
{
  unet_table_t *t;
  int sk;

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t || t->fd == UNDEFINED_SOCKET)
      continue; /* not active */
    if (t->mode != mode)
      continue; /* wrong mode bra */

    unet_close(t->fd, "terminate");
  }

  return (0);
}

void unet_close_idle(void)
{
  unet_table_t *t;
  shtime_t conn_idle_t;
  shtime_t idle_t;
  shtime_t now;
  char buf[256];
  SOCKET sk;

  now = shtime();
  conn_idle_t = shtime_adj(now, -30);
  idle_t = shtime_adj(now, -300);

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t || t->fd == UNDEFINED_SOCKET)
      continue; /* non-active */
    
    if (t->stamp == UNDEFINED_TIME &&
        shtime_before(shtime_adj(t->cstamp, MAX_CONNECT_IDLE_TIME), now)) {
      sprintf(buf, "unet_close_idle: closing peer '%s' for no activity for %ds after connect.", shaddr_print(&t->net_addr), MAX_CONNECT_IDLE_TIME);
      unet_log(t->mode, buf);
      unet_shutdown(t->fd);
      continue;
    }
    if (t->stamp != UNDEFINED_TIME &&
        shtime_before(shtime_adj(t->stamp, MAX_IDLE_TIME), now)) {
      sprintf(buf, "unet_close_idle: closing peer '%s' for being idle %ds.", shaddr_print(&t->net_addr), MAX_IDLE_TIME);
      unet_log(t->mode, buf);
      unet_shutdown(t->fd);
      continue;
    }
    if (shbuf_size(t->wbuff) > MAX_SOCKET_BUFFER_SIZE ||
        shbuf_size(t->rbuff) > MAX_SOCKET_BUFFER_SIZE) {
      sprintf(buf, "unet_close_idle: closeing peer '%s' for buffer overflow (read %dk, write %dk).", shaddr_print(&t->net_addr), shbuf_size(t->rbuff), shbuf_size(t->wbuff));
      unet_log(t->mode, buf);
      unet_shutdown(t->fd);
      continue;
    }
  }

}

void unet_close_free(void)
{
  unet_table_t *t;
  int sk;

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t || t->fd != UNDEFINED_SOCKET)
      continue; /* active */
    if (t->mode == UNET_NONE)
      continue; /* already cleared */ 

    /* free [user-level] socket buffer */
    shbuf_free(&t->rbuff);
    shbuf_free(&t->wbuff);

    memset(t, '\000', sizeof(unet_table_t));
  }

}

