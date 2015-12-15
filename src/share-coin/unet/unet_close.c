
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
  char buf[256];
  int err;

  table = get_unet_table(sk);
  if (!table)
    return (SHERR_INVAL);

  sprintf(buf, "unet_close: closed '%s' connection (%s).",
    unet_mode_label(table->mode),  inet_ntoa(table->net_addr.sin_addr));
  shcoind_log(buf);

#ifdef WIN32
  err = closesocket(sk);
#else
  err = close(sk);
#endif

  /* free [user-level] socket buffer */
  if (table->rbuff)
    shbuf_free(&table->rbuff);
  if (table->wbuff)
    shbuf_free(&table->wbuff);

  /* empty slate */
  memset(table, '\000', sizeof(unet_table_t));

  return (err);
}

int unet_close_all(int mode)
{
  int sk;

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    if (_unet_table[sk].mode != mode)
      continue;
    if (_unet_table[sk] == UNDEFINED_SOCKET)
      continue;

    unet_close(_unet_table[sk].fd);
  }

  return (0);
}

