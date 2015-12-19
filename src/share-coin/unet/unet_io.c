
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


int unet_read(SOCKET sk, char *data, size_t *data_len_p)
{
  unet_table_t *t;
  size_t r_len;

  if (sk == UNDEFINED_SOCKET || sk == INVALID_SOCKET)
    return (SHERR_BADF);

  if (!data || !data_len_p)
    return (SHERR_INVAL);

  t = get_unet_table(sk);
  if (!t || t->fd == UNDEFINED_SOCKET)
    return (SHERR_INVAL);

  if (!t->rbuff)
    return (SHERR_AGAIN);

  /* determine max length */
  r_len = *data_len_p;
  r_len = MIN(r_len, shbuf_size(t->rbuff));
  if (r_len == 0)
    return (SHERR_AGAIN);

  /* fill segment into user buffer */
  memcpy(data, shbuf_data(t->rbuff), r_len);
  *data_len_p = r_len;

  /* remove segment from socket buffer */
  shbuf_trim(t->rbuff, r_len);

  return (0);
}

int unet_write(SOCKET sk, char *data, size_t data_len)
{
  unet_table_t *t;

  if (sk == UNDEFINED_SOCKET || sk == INVALID_SOCKET)
    return (SHERR_BADF);

  if (!data_len)
    return (0); /* all done */

  if (!data)
    return (SHERR_INVAL);

  t = get_unet_table(sk);
  if (!t->wbuff)
    t->wbuff = shbuf_init();
  
  /* append segment to socket buffer */
  shbuf_cat(t->wbuff, data, data_len);

  return (0);
}

