
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


int unet_rbuff_add(int sk, unsigned char *data, size_t data_len)
{
  unet_table_t *t;
  int err;

  t = get_unet_table(sk);
  if (!t) {
fprintf(stderr, "DEBUG: unet_rbuff_add: invalid fd %d\n", sk);
    return (SHERR_INVAL);
}

  if (!t->rbuff)
    t->rbuff = shbuf_init();

  shbuf_cat(t->rbuff, data, data_len);
fprintf(stderr, "DEBUG: unet_rbuff_add: fd %d <%d bytes>\n", sk, data_len);

  return (0);
}

