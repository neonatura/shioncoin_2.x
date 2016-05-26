
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

#define BC_INDEX_PAGE_SIZE 8096

#ifdef linux
#include <stdio.h>
#endif

#define BC_INDEX_EXTENSION "idx"

int bc_idx_open(bc_t *bc)
{
  int err;

  if (!bc)
    return (SHERR_INVAL);

  if (bc->idx_map.fd != 0)
    return (0);

  /* set map file extension */
  strncpy(bc->idx_map.ext, BC_INDEX_EXTENSION, sizeof(bc->idx_map.ext)-1);

  err = bc_map_open(bc, &bc->idx_map);
  if (err)
    return (err);

  err = bc_map_alloc(bc, &bc->idx_map, 0);
  if (err)
    return (err);
  
  return (0);
}

void bc_idx_close(bc_t *bc)
{

  if (bc->idx_map.fd != 0) {
    bc_map_close(&bc->idx_map);
  }
  
}

uint32_t bc_idx_crc(bc_hash_t hash)
{
  return (shcrc(hash, sizeof(bc_hash_t)));
}

int bc_idx_find(bc_t *bc, bc_hash_t hash, bc_idx_t *ret_idx, int *ret_pos)
{
  bc_hash_t t_hash;
  bc_idx_t *idx;
  bcsize_t len;
  int crc;
  int err;
  int i;

  err = bc_idx_open(bc);
  if (err)
    return (err);

  if (ret_idx)
    memset(ret_idx, '\000', sizeof(bc_idx_t));
  if (ret_pos)
    *ret_pos = -1;

#if 0
  crc = bc_idx_crc(hash);
#endif

  idx = (bc_idx_t *)bc->idx_map.raw;
  len = bc->idx_map.hdr->of / sizeof(bc_idx_t);
  for (i = (len-1); i >= 0; i--) {
    if (idx[i].size == 0) continue;
#if 0
    if (idx[i].crc != crc)
      continue; /* hash checksum does not match */    

    err = bc_read(bc, i, t_hash, sizeof(t_hash));
    if (err)
      return (err);

    if (bc_hash_cmp(hash, t_hash)) {
      if (ret_idx)
        memcpy(ret_idx, idx + i, sizeof(bc_idx_t));
      if (ret_pos)
        *ret_pos = i;
      return (0);
    }
#endif
    if (bc_hash_cmp(hash, idx[i].hash)) {
      if (ret_idx)
        memcpy(ret_idx, idx + i, sizeof(bc_idx_t));
      if (ret_pos)
        *ret_pos = i;
      return (0);
    }
  }

  return (SHERR_NOENT);
}

int bc_idx_get(bc_t *bc, bcsize_t pos, bc_idx_t *ret_idx)
{
  bc_idx_t *idx;
  int err;

  if (!bc)
    return (SHERR_INVAL);

  if (pos < 0)
    return (SHERR_INVAL);

  err = bc_idx_open(bc);
  if (err)
    return (err);

  if (pos >= (bc->idx_map.hdr->of / sizeof(bc_idx_t)))
    return (SHERR_NOENT);

  idx = (bc_idx_t *)bc->idx_map.raw;
  if (idx[pos].size == 0)
    return (SHERR_NOENT); /* not filled in */

  if (ret_idx) {
    memcpy(ret_idx, idx + pos, sizeof(bc_idx_t));
  }

  return (0);
}

/**
 * @returns The next record index.
 */
bcsize_t bc_idx_next(bc_t *bc)
{
  bc_idx_t *idx;
  int err;

  if (!bc)
    return (SHERR_INVAL);

  err = bc_idx_open(bc);
  if (err)
    return (err);

  return MAX(0, (bc->idx_map.hdr->of / sizeof(bc_idx_t)));
}

int bc_idx_set(bc_t *bc, bcsize_t pos, bc_idx_t *idx)
{
  bc_idx_t *f_idx;
  bcsize_t of;
  int err;

  if (!bc || pos < 0) {
    return (SHERR_INVAL);
  }

  err = bc_idx_open(bc);
  if (err) {
    return (err);
  }

#if 0
  if (pos == 0) {
    bc_idx_t blank_idx;

    /* blank initial record */
    memset(&blank_idx, 0, sizeof(blank_idx));
    err = bc_map_append(bc, &bc->idx_map, &blank_idx, sizeof(bc_idx_t));
    if (err)
      return (err);

    pos++;
  }
#endif

  if (bc_idx_get(bc, pos, NULL) != SHERR_NOENT)
    return (SHERR_EXIST);

  of = (pos * sizeof(bc_idx_t));
  if (pos >= (bc->idx_map.hdr->of / sizeof(bc_idx_t)) &&
      (of + sizeof(bc_idx_t)) > bc->idx_map.size) {
    bcsize_t f_len = (of + sizeof(bc_idx_t)) - bc->idx_map.size;

    err = bc_map_alloc(bc, &bc->idx_map, f_len);
    if (err) {
fprintf(stderr, "DEBUG: bc_idx_set: bc_map_alloc <%d bytes> err %d\n", f_len, err); 
      return (err);
}
  }

  /* write to file map */
  err = bc_map_write(bc, &bc->idx_map, of, idx, sizeof(bc_idx_t)); 
  if (err)
    return (err);

  return (0);
}

/**
 * @note (odd) only reduces index count when "pos" is last record in db.
 */
int bc_idx_clear(bc_t *bc, bcsize_t pos)
{
  bc_idx_t *f_idx;
  bc_idx_t blank_idx;
  bcsize_t n_pos;
  bcsize_t of;
  int err;

  if (!bc || pos < 0) {
    return (SHERR_INVAL);
  }

  err = bc_idx_open(bc);
  if (err)
    return (err);

  n_pos = MAX(0, (bc->idx_map.hdr->of / sizeof(bc_idx_t)));
fprintf(stderr, "DEBUG: bc_idx_clear: n_pos = %d\n", n_pos);

  of = (pos * sizeof(bc_idx_t));
  if (pos >= (bc->idx_map.hdr->of / sizeof(bc_idx_t)) &&
      (of + sizeof(bc_idx_t)) > bc->idx_map.size) {
    /* no content - does not exist */
  } else {
    /* write to file map */
    memset(&blank_idx, 0, sizeof(blank_idx));
    err = bc_map_write(bc, &bc->idx_map, of, &blank_idx, sizeof(bc_idx_t)); 
    if (err)
      return (err);
  }

  if ((pos + 1) == n_pos && bc->idx_map.hdr->of >= sizeof(bc_idx_t)) {
    bc->idx_map.hdr->of -= sizeof(bc_idx_t);
fprintf(stderr, "DEBUG: bc_idx_clear: (last rec) bc->idx_map.hdr->of = %d\n", bc->idx_map.hdr->of);
  }

  return (0);
}

#define BC_BLOCKS_PER_JOURNAL 65536
uint32_t bc_idx_journal(int pos)
{
  return ( (pos / BC_BLOCKS_PER_JOURNAL) + 1 );
}


