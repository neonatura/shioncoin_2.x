
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


int unet_close(SOCKET sk)
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

  sprintf(buf, "unet_close: closed '%s' connection (%s).",
    unet_mode_label(table->mode),  inet_ntoa(table->net_addr.sin_addr));
  unet_log(table->mode, buf);

  table->fd = UNDEFINED_SOCKET;

#if 0
  /* free [user-level] socket buffer */
  if (table->rbuff)
    shbuf_free(&table->rbuff);
  if (table->wbuff)
    shbuf_free(&table->wbuff);

  /* empty slate */
  memset(table, '\000', sizeof(unet_table_t));
#endif

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

    unet_close(t->fd);
  }

  return (0);
}

void unet_close_free(void)
{
  unet_table_t *t;
  int sk;

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t || t->fd != UNDEFINED_SOCKET)
      continue; /* active */

    /* free [user-level] socket buffer */
    if (t->rbuff || t->wbuff) {
      shbuf_free(&t->rbuff);
      shbuf_free(&t->wbuff);

      /* empty slate */
      memset(t, '\000', sizeof(unet_table_t));
    }
  }

  return (0);
}

