
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#include "test_shcoind.h"

/** 
 * @todo verify last 100 recorsd of pre-existing chain
 */
_TEST(blockchain)
{
  bc_t *bc;
  bc_hash_t hash[10];
  bc_hash_t t_hash;
  char buf[10240];
  unsigned char *t_data;
  size_t t_data_len;
  int idx;
  bcsize_t n_pos;
  bcsize_t pos;
  int err;

  err = bc_open("rawtest", &bc);
  _TRUE(err == 0);

  srand(time(NULL));

n_pos = bc_idx_next(bc);

  for (idx = 0; idx < 10; idx++) {
    buf[0] = (rand() % 254);
    buf[1] = (rand() % 254);
    buf[2] = (rand() % 254);
    memset(buf + 3, (rand() % 254), sizeof(buf) - 3);

    memcpy(hash[idx], buf + 1, sizeof(hash[idx]));

    pos = bc_append(bc, hash[idx], buf, sizeof(buf));
    _TRUE(pos >= 0);

    err = bc_find(bc, hash[idx], NULL);
    _TRUE(err == 0);

    _TRUE(((pos + 1) == bc_idx_next(bc)));

    err = bc_get(bc, pos, &t_data, &t_data_len);
    _TRUE(err == 0);
    _TRUE(t_data_len == sizeof(buf));

    _TRUE(0 == memcmp(t_data, buf, t_data_len));
    free(t_data);

    memset(t_hash, 255, sizeof(t_hash));
    err = bc_find(bc, t_hash, NULL);
    _TRUE(err == SHERR_NOENT);
  }

  err = bc_purge(bc, n_pos + 1);
  _TRUE(err == 0);

  /* re-write purged records. */
  for (idx = 1; idx < 10; idx++) {
    bcsize_t a_pos;
    _TRUE(!(err = bc_arch_find(bc, hash[idx], NULL, &a_pos)));
    _TRUE(!(err = bc_arch(bc, a_pos, &t_data, &t_data_len)));
//fprintf(stderr, "DEBUG: retrieved arch rec #%d\n", a_pos);
    _TRUEPTR(t_data);
    /* verify hash */  
    memcpy(t_hash, t_data + 1, sizeof(t_hash));
    _TRUE(0 == memcmp(hash[idx], t_hash, sizeof(bc_hash_t)));
    /* add back to main chain */
    _TRUE(0 == bc_write(bc, n_pos + idx, hash[idx], t_data, t_data_len));
    free(t_data);
  }
  

//fprintf(stderr, "OK (height %d)\n", (bc_idx_next(bc)-1));
  _TRUE(bc_idx_next(bc) == (n_pos + 10));
  bc_close(bc);


}

