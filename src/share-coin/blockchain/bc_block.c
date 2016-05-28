
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

#ifdef linux
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif

char *bc_name(bc_t *bc)
{

  if (!bc)
    return (NULL);

  return (bc->name);
}

int bc_open(char *name, bc_t **bc_p)
{
  bc_t *bc;
  int err;

  if (!bc_p)
    return (SHERR_INVAL);

  bc = (bc_t *)calloc(1, sizeof(bc_t));
  if (!bc)
    return (SHERR_NOMEM);

  strncpy(bc->name, name, sizeof(bc->name) - 1);

  err = bc_idx_open(bc);
  if (err)
    return (err);

  *bc_p = bc;

  return (0);
}

void bc_close(bc_t *bc)
{
  bc_map_t *map;
  int i;

  /* close index map */
  bc_idx_close(bc);

  /* close data maps */
  for (i = 0; i < bc->data_map_len; i++) {
    map = bc->data_map + i;
    bc_map_close(map);
  }

  /* free data map list */
  free(bc->data_map);
  bc->data_map = NULL;
  bc->data_map_len = 0;

  free(bc);
}

/**
 * @todo auto de-alloc maps that expire
 */
int bc_alloc(bc_t *bc, unsigned int jrnl)
{
  bc_map_t *map;
  char ext[64];
  int err;

  if (jrnl >= bc->data_map_len) {
    bc_map_t *o_data_map;
    bc_map_t *n_data_map;

    o_data_map = bc->data_map;
    n_data_map = (bc_map_t *)calloc(jrnl+1, sizeof(bc_map_t));
    if (o_data_map) {
      memcpy(n_data_map, o_data_map, bc->data_map_len * sizeof(bc_map_t));
      free(o_data_map);
    }

    bc->data_map = n_data_map;
    bc->data_map_len = jrnl+1;
  }

  map = bc->data_map + jrnl;

  if (!*map->ext) {
    sprintf(map->ext, "%u", jrnl);
  }

  err = bc_map_alloc(bc, map, 0);
  if (err)
    return (err);

  return (0);
}

#if 0
int bc_write(bc_t *bc, unsigned int jrnl, unsigned char *data, int data_len)
{
  bc_map_t *map;
  char ext[64];
  int err;

  err = bc_alloc(bc, jrnl);
  if (err)
    return (err);

  map = bc->data_map + jrnl;
  if (!*map->ext) {
    sprintf(map->ext, "%u", jrnl);
  }

  /* serialized block data */
  err = bc_map_append(bc, map, data, data_len);
  if (err)
    return (err);

  return (0);
}
#endif

static int _bc_write(bc_t *bc, bcsize_t pos, bc_hash_t hash, void *raw_data, int data_len)
{
  unsigned char *data = (unsigned char *)raw_data;
  bc_idx_t idx;
  bc_map_t *map;
  char ext[64];
  int jrnl;
  int err;

  jrnl = bc_idx_journal(pos);

  err = bc_alloc(bc, jrnl);
  if (err)
    return (err);

  map = bc->data_map + jrnl;
  if (!*map->ext)
    sprintf(map->ext, "%u", idx.jrnl);

  /* finialize block index */
  memset(&idx, 0, sizeof(idx));
  idx.jrnl = jrnl;
  idx.size = data_len;
  idx.of = map->hdr->of;
  idx.crc = shcrc32(data, data_len);
  memcpy(idx.hash, hash, sizeof(bc_hash_t));

  /* store fresh block index */
  err = bc_idx_set(bc, pos, &idx);
  if (err)
    return (err);

  /* store serialized block data */
  err = bc_map_append(bc, map, data, data_len);
  if (err) { /* uh oh */
    bc_idx_clear(bc, pos);
    return (err);
  }

  return (0);
}

int bc_write(bc_t *bc, bcsize_t pos, bc_hash_t hash, void *raw_data, int data_len)
{
  int err;

  if (!shlock_open_str(BCMAP_LOCK, 0))
    return (SHERR_NOLCK);

  err = _bc_write(bc, pos, hash, raw_data, data_len);
  shlock_close_str(BCMAP_LOCK);
  return (err);
}

/**
 * @returns The new record position or a negative error code.
 */
int bc_append(bc_t *bc, bc_hash_t hash, void *data, size_t data_len)
{
  unsigned char *raw_data = (unsigned char *)data;
  bc_idx_t idx;
bc_map_t *map;
  int pos;
  int err;

  err = bc_idx_open(bc);
  if (err)
    return (err);

  pos = bc_idx_next(bc);
  if (pos < 0)
    return (pos);

#if 0
  memset(&idx, 0, sizeof(idx));
  err = bc_idx_get(bc, pos, &idx);
  if (err)
    return (err);

  err = bc_alloc(bc, idx.jrnl);
  if (err)
    return (err);

  map = bc->data_map + idx.jrnl;
  idx.of = map->hdr->of;
  idx.size = data_len;
  idx.crc = shcrc32(data, data_len);

  err = bc_write(bc, idx.jrnl, data, data_len);
  if (err)
    return (err); 

  bc_idx_set(bc, pos, &idx);
#endif
  err = bc_write(bc, pos, hash, data, data_len);
  if (err)
    return (err); 

  return (pos);
}

/**
 * Fills a pre-allocated binary segment with a specified size from a specified record position.
 */
static int _bc_read(bc_t *bc, int pos, void *data, bcsize_t data_len)
{
  bc_map_t *map;
  bc_idx_t idx;
  int err;

  /* obtain index for record position */
  memset(&idx, 0, sizeof(idx));
  err = bc_idx_get(bc, pos, &idx);
  if (err)
    return (err);

  /* ensure journal is allocated */
  err = bc_alloc(bc, idx.jrnl);
  if (err)
    return (err);

  memset(data, 0, data_len);
  data_len = MIN(data_len, idx.size); 
  
  map = bc->data_map + idx.jrnl;

  if (shcrc32(map->raw + idx.of, idx.size) != idx.crc) {
fprintf(stderr, "DEBUG: bc_read; invalid crc {map: %x, idx: %x} mismatch at pos %d\n", shcrc32(map->raw + idx.of, idx.size), idx.crc, pos);
    return (SHERR_ILSEQ);
  }

  memcpy(data, map->raw + idx.of, data_len);

  return (0);
}

int bc_read(bc_t *bc, int pos, void *data, bcsize_t data_len)
{
  int err;

  if (!shlock_open_str(BCMAP_LOCK, 0))
    return (SHERR_NOLCK);

  err = _bc_read(bc, pos, data, data_len);
  shlock_close_str(BCMAP_LOCK);

  return (err);
}

/**
 * Obtains an allocated binary segment stored at the specified record position. 
 */
int bc_get(bc_t *bc, bcsize_t pos, unsigned char **data_p, size_t *data_len_p)
{
  bc_idx_t idx;
  unsigned char *data;
  char errbuf[1024];
  int err;

  if (!data_p) {
fprintf(stderr, "DEBUG: bc_get: no data pointer specified.\n");
    return (SHERR_INVAL);
}

  /* obtain index for record position */
  memset(&idx, 0, sizeof(idx));
  err = bc_idx_get(bc, pos, &idx);
  if (err) {
fprintf(stderr, "DEBUG: bc_get[pos %d]: bc_idx_get error '%s'\n", pos, sherrstr(err));
    return (err);
  }

/* .. deal with idx.size == 0, i.e. prevent write of 0 */

  data = (unsigned char *)calloc(idx.size, sizeof(char)); 
  if (!data)
    return (SHERR_NOMEM);

  /* read in serialized binary data */
  err = bc_read(bc, pos, data, idx.size);
  if (err) {
fprintf(stderr, "DEBUG: bc_get[pos %d]: bc_read <%d bytes> error '%s'\n", pos, idx.size, sherrstr(err));
    return (err); 
  }

  *data_p = data;
  if (data_len_p)
    *data_len_p = idx.size;

  return (0);
}

int bc_get_hash(bc_t *bc, bcsize_t pos, bc_hash_t ret_hash)
{
  bc_idx_t idx;
  int err;

  /* obtain index for record position */
  err = bc_idx_get(bc, pos, &idx);
  if (err)
    return (err);

  memcpy(ret_hash, idx.hash, sizeof(bc_hash_t));
  return (0);
}

/** 
 * Obtains the record position for a particular hash.
 */
int bc_find(bc_t *bc, bc_hash_t hash, int *pos_p)
{
  int err;

  err = bc_idx_find(bc, hash, NULL, pos_p);
  if (err)
    return (err);
  

  return (0);
}


/**
 * @bug this does not handle jrnls alloc'd past one being targeted.
 */
static int _bc_purge(bc_t *bc, bcsize_t pos)
{
  bc_map_t *map;
  bc_idx_t idx;
  int err;
  int i;

  if (pos < 0)
    return (SHERR_INVAL);

  /* obtain index for record position */
  memset(&idx, 0, sizeof(idx));
  err = bc_idx_get(bc, pos, &idx);
  if (err)
    return (err);

  /* ensure journal is allocated */
  err = bc_alloc(bc, idx.jrnl);
  if (err)
    return (err);

  map = bc->data_map + idx.jrnl;

  if (shcrc32(map->raw + idx.of, idx.size) != idx.crc) {
fprintf(stderr, "DEBUG: bc_read; invalid crc {map: %x, idx: %x} mismatch at pos %d\n", shcrc32(map->raw + idx.of, idx.size), idx.crc, pos);
    return (SHERR_ILSEQ);
  }

  /* clear index of remaining entries */
  for (i = (bc_idx_next(bc)-1); i >= pos; i--) {
    bc_idx_clear(bc, i);
  }

  /* truncate journal at offset */
  bc_map_trunc(bc, map, idx.of);

  return (0);
}

int bc_purge(bc_t *bc, bcsize_t pos)
{
  int err;

  if (!shlock_open_str(BCMAP_LOCK, 0))
    return (SHERR_NOLCK);

  err = _bc_purge(bc, pos);
  shlock_close_str(BCMAP_LOCK);
  return (err);
}


/**
 * @returns TRUE if the hashes are identical and FALSE otherwise.
 */
int bc_hash_cmp(bc_hash_t a_hash, bc_hash_t b_hash)
{
  uint32_t *a_val = (uint32_t *)a_hash;
  uint32_t *b_val = (uint32_t *)b_hash;
  int i;

  for (i = 0; i < 8; i++) {
    if (a_val[i] != b_val[i])
      return (FALSE);
  }

  return (TRUE);
}


/**
 * The base path of the blockchain database.
 */
const char *bc_path_base(void)
{
  static char ret_path[PATH_MAX+1];

  if (!*ret_path) {
    sprintf(ret_path, "%s/blockchain", get_libshare_path());
    mkdir(ret_path, 0700);
  }

  return ((const char *)ret_path);
}

void bc_idle(bc_t *bc)
{
  bc_map_t *map;
  int i;

  for (i = 0; i < bc->data_map_len; i++) {
    map = bc->data_map + i;
    if (map->fd != 0)
      bc_map_idle(bc, map);
  }

}
