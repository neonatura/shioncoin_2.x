
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
#include <sys/mman.h>

#ifdef linux
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#endif


#define BC_MAP_BLOCK_SIZE 16384

static int _bc_map_open(bc_t *bc, bc_map_t *map)
{
  bc_hdr_t ini_hdr;
  struct stat st;
  char path[PATH_MAX+1];
  bcsize_t size;
  int err;
  int fd;

  if (map->fd != 0) {
    return (0);
  }

  sprintf(path, "%s/%s.%s", bc_path_base(), bc_name(bc), map->ext);
  fd = open(path, O_RDWR | O_CREAT, 0777);
  if (fd == -1) {
perror("bc_map_open [open]");
    return (-errno);
}

  memset(&st, 0, sizeof(st));
  err = fstat(fd, &st);
  if (err) {
perror("bc_map_open [fstat]");
    return (-errno);
}
  if (!S_ISREG(st.st_mode)) {
perror("bc_map_open [!reg]");
    close(fd);
    return (SHERR_ISDIR);
  }
  
  memset(&ini_hdr, 0, sizeof(ini_hdr));
  err = read(fd, &ini_hdr, sizeof(ini_hdr));
  if (err != sizeof(ini_hdr) ||
      ini_hdr.magic != SHMEM32_MAGIC) {
    lseek(fd, 0L, SEEK_SET);

    st.st_size = BC_MAP_BLOCK_SIZE;
    err = ftruncate(fd, st.st_size);
    if (err) {
      perror("bc_map_open [truncate]");
      return (-errno);
    }

    lseek(fd, 0L, SEEK_SET);
    memset(&ini_hdr, 0, sizeof(ini_hdr));
    ini_hdr.magic = SHMEM32_MAGIC;
    ini_hdr.stamp = shtime();
    write(fd, &ini_hdr, sizeof(ini_hdr));
  } 

  map->fd = fd;
  map->size = st.st_size;
fprintf(stderr, "DEBUG: _bc_map_open: opened fd %d\n", fd);

  return (0);
}

int bc_map_open(bc_t *bc, bc_map_t *map)
{
  int err;

  bc_lock();
  err = _bc_map_open(bc, map);
  bc_unlock();

  return (err);
}

/**
 * @param The amount to incrase the allocated size by.
 */
static int _bc_map_alloc(bc_t *bc, bc_map_t *map, bcsize_t len)
{
  struct stat st;
  unsigned char *raw;
  bcsize_t size;
  bcsize_t map_alloc;
  bcsize_t map_of;
  int err;

  /* ensure file map is open */
  err = bc_map_open(bc, map);
  if (err)
    return (err);

memset(&st, 0, sizeof(st));
  err = fstat(map->fd, &st);
  if (err)
    return (-errno);

  map_of = 0;
  size = st.st_size / BC_MAP_BLOCK_SIZE * BC_MAP_BLOCK_SIZE;
  if (!map->hdr) { /* map has not been allocated */
    bc_hdr_t hdr;

    memset(&hdr, 0, sizeof(hdr));
    lseek(map->fd, 0L, SEEK_SET);
    read(map->fd, &hdr, sizeof(bc_hdr_t));
    map_of = hdr.of;
  } else {
    /* map has already been allocated */
    map_of = map->hdr->of;

    if (sizeof(bc_hdr_t) + map_of + len < st.st_size) {
      /* map is large enough */
      return (0);
    }
    bc_map_free(map);
  }

  if (sizeof(bc_hdr_t) + map_of + len >= st.st_size) {
    /* enlarge map size */
    size = st.st_size + len;
    size = size + (size / 10); /* + 10% */
    size = ((size / BC_MAP_BLOCK_SIZE) + 1) * BC_MAP_BLOCK_SIZE;
    err = ftruncate(map->fd, size);
    if (err) {
fprintf(stderr, "DEBUG: _bc_map_alloc: %d = ftruncate(fd %d, <%d bytes>) [errno %d]\n", err, map->fd, size, errno); 
      return (-errno);
}
  }

  /* map disk to memory */
  raw = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map->fd, 0); 
  if (raw == MAP_FAILED) {
fprintf(stderr, "DEBUG: _bc_map_alloc: mmap failed on fd %d\n", map->fd); 
    return (SHERR_NOMEM); 
}

  /* fill in file map structure */
  map->hdr = (bc_hdr_t *)raw;
  map->raw = (raw + sizeof(bc_hdr_t));
  map->size = size;

  return (0);
}

int bc_map_alloc(bc_t *bc, bc_map_t *map, bcsize_t len)
{
  int err;

  bc_lock();
  err = _bc_map_alloc(bc, map, len);
  bc_unlock();

  return (err);
}

/**
 * Truncates the data-content layer of a map to a given size.
 */
static int _bc_map_trunc(bc_t *bc, bc_map_t *map, bcsize_t len)
{
  int err;

#if 0
  /* ensure file map is open */
  err = bc_map_open(bc, map);
  if (err)
    return (err);
#endif

  err = bc_map_alloc(bc, map, 0);
  if (err) {
    return (err);
  }

  if (len < map->hdr->of) {
    map->hdr->of = len;
  }

  return (0);
}

int bc_map_trunc(bc_t *bc, bc_map_t *map, bcsize_t len)
{
  int err;

  bc_lock();
  err = _bc_map_trunc(bc, map, len);
  bc_unlock();

  return (err);
}

void bc_map_free(bc_map_t *map)
{
  int err;

  if (map->hdr) {
    err = 0;
    if (!shlock_open_str(BCMAP_LOCK, 0))
      err = SHERR_NOLCK;

//    msync((void *)map->hdr, map->size, 0);
    munmap((void *)map->hdr, map->size); 
    map->hdr = NULL;
    map->raw = NULL;
    map->size = 0;
    if (!err)
      shlock_close_str(BCMAP_LOCK);
  }

}

static void _bc_map_close(bc_map_t *map)
{

fprintf(stderr, "DBEUG: _bc_map_close: fd %d\n", map->fd);
  bc_map_free(map);
  if (map->fd) {
    close(map->fd);
    map->fd = 0;
  }

}

void bc_map_close(bc_map_t *map)
{

  if (map) {
    bc_lock();
    _bc_map_close(map);
    bc_unlock();
  }

}

static int _bc_map_write(bc_t *bc, bc_map_t *map, bcsize_t of, void *raw_data, bcsize_t data_len)
{
  unsigned char *data = (unsigned char *)raw_data;
  int err;

  err = bc_map_alloc(bc, map, data_len);
  if (err) {
fprintf(stderr, "DEBUG: bc_map_write: bc_map_alloc %d\n", err);
    return (err);
  }

  memcpy(map->raw + of, data, data_len);
  map->hdr->of = MAX(map->hdr->of, (of + data_len));
  map->stamp = time(NULL);

  return (0);
}

int bc_map_write(bc_t *bc, bc_map_t *map, bcsize_t of, void *raw_data, bcsize_t data_len)
{
  int err;

  if (!shlock_open_str(BCMAP_LOCK, 0))
    return (SHERR_NOLCK);

  err = _bc_map_write(bc, map, of, raw_data, data_len);
  shlock_close_str(BCMAP_LOCK);
  if (err)
    return (err);

  return (0);
}

/**
 * Write some data to a specific filemap. 
 */
static int _bc_map_append(bc_t *bc, bc_map_t *map, void *raw_data, bcsize_t data_len)
{
  unsigned char *data = (unsigned char *)raw_data;
  int err;

  err = bc_map_alloc(bc, map, data_len);
  if (err)
    return (err);

  return (bc_map_write(bc, map, map->hdr->of, data, data_len));
}

int bc_map_append(bc_t *bc, bc_map_t *map, void *raw_data, bcsize_t data_len)
{
  int err;

  if (!shlock_open_str(BCMAP_LOCK, 0))
    return (SHERR_NOLCK);

  err = _bc_map_append(bc, map, raw_data, data_len);
  shlock_close_str(BCMAP_LOCK);
  if (err)
    return (err);

  return (0);
}

static int _bc_map_read(bc_t *bc, bc_map_t *map, unsigned char *data, bcsize_t data_of, bcsize_t data_len)
{

  if ((data_of + data_len) >= map->hdr->of)
    return (SHERR_INVAL);

  memcpy(data, map->raw + data_of, data_len);
  map->stamp = time(NULL);

  return (0);
}

/**
 * Read a segment data from a file-map
 */
int bc_map_read(bc_t *bc, bc_map_t *map, unsigned char *data, bcsize_t data_of, bcsize_t data_len)
{
  int err;

  if (!shlock_open_str(BCMAP_LOCK, 0))
    return (SHERR_NOLCK);

  err = _bc_map_read(bc, map, data, data_of, data_len);
  shlock_close_str(BCMAP_LOCK);
  if (err)
    return (err);

  return (0);
}

#define BCMAP_IDLE_TIME 100
int bc_map_idle(bc_t *bc, bc_map_t *map)
{
  time_t now;

  if (!map)
    return (0);

  now = time(NULL);
  if ((map->stamp + BCMAP_IDLE_TIME) > now)
    return (1);

  bc_lock();
  bc_map_close(map);
  bc_unlock();

  return (0);
}

unsigned int bc_fmap_total(bc_t *bc)
{
  bc_map_t *map;
  int total;
  int i;

  total = 0;
  for (i = 0; i < bc->data_map_len; i++) {
    map = bc->data_map + i;
    if (map->fd != 0)
      total++;
  }

  return (total);
}


