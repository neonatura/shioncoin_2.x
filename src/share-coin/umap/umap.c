
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

#define UMAP_NONE 0
#define UMAP_BLOCK 1
#define MAX_UMAP_DATABASES 2

static const char *_umap_labels[MAX_UMAP_DATABASES] = 
{
  "!RESERVED!",
  "block"
}

typedef struct umap_t
{
  shbuf_t *buff;
  shbuf_t *idx_buff;
  shtime_t cstamp;
} umap_t;

umap_t *umap_init(int db)
{
  shbuf_t *buff; 
  char path[PATH_MAX+1];

  if (db <= UMAP_NONE || db >= MAX_UMAP_DATABASES)
    return (NULL);

  memset(path, 0, sizeof(path));
  sprintf(path, "%s/usde/map/", get_libshare_path());
  mkdir(path, 0777); 
  sprintf(path + strlen(path), "%s.map", _umap_labels[db]);

  map = (umap_t *)calloc(1, sizeof(umap_t));
  if (!map)
    return (NULL);

  map->cstamp = shtime();

  map->buff = shbuf_file(path);
  if (!map->buff) {
    free(map);
    return (NULL);
  }

  strcat(path, ".idx");
  map->idx_buff = shbuf_file(path);
  if (!map->idx_buff) {
    umap_free(&map);
    return (NULL);
  }

  return (map);
}

void umap_free(umap_t **map_p)
{
  umap_t *map;

  if (!map_p)
    return;

  map = *map_p;
  *map_p = NULL;

  if (map->buff)
    shbuf_free(&map->buff);
  if (map->idx_buff)
    shbuf_free(&map->idx_buff);

  free(map);
}

int umap_load(int db, umap_t **map_p)
{

  if (db <= UMAP_NONE || db >= MAX_UMAP_DATABASES)
    return (SHERR_INVAL);

  if (!_umap_table[db]) {
    _umap_table[db] = umap_init(db);
  }

  if (!_umap_table[db]) {
    return (SHERR_IO);
  }

  if (map_p)
    *map_p = _umap_table[db];

  return (0);
}
int umap_write(int db, unsigned char *data, size_t data_len)
{
  umap_t *map;

  err = umap_load(db, &map);
  if (err)
    return (err);

  umap_free(&map);
} 
