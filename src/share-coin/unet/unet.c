
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

static const char *_unet_label[MAX_UNET_MODES] = 
{
  "NONE",
  "STRATUM",
  "RPC",
  "COIN"
};
const char *unet_mode_label(int mode)
{
  if (mode < 0 || mode >= MAX_UNET_MODES)
    return (NULL);

  return (_unet_label[mode]);
}

int unet_add(int mode, SOCKET sk)
{
}

int unet_remove(SOCKET sk)
{
  memset(_unet_table + sk, '\000', sizeof(unet_table_t));
}

int unet_mode(SOCKET sk)
{
}

int unet_flag_set(SOCKET sk)
{
}
int unet_flag(SOCKET sk)
{
}


/**
 * The maximum desired time-span to perform the cycle.
 */
void unet_cycle(shtime_t max_t)
{
  size_t len;
  fd_set r_set;
  SOCKET fd;

  FD_ZERO(&r_set);
  start_t = shtime();
  for (fd = 1; fd < MAX_UNET_SOCKETS; fd++) {
    if (_unet_table[fd].fd == UNDEFINED_SOCKET)
      continue;

    /* flush pending writes */
    len = shnet_write_flush(fd);
    if (len == -1) {
      unet_close(fd);
      continue;
    }

    buff = shnet_read_buf(fd);
    if (!buff) {
      unet_close(fd);
      continue;
    }
    unet_buff_add(fd, shbuf_data(buff), shbuf_size(buff));
    shbuf_clear(buff);

    unet_timer_cycle();

    FD_SET(fd, &r_set);
  }

  diff_t = (shtimef(shtime()) - start_t);
  diff_t = MAX(0, 20 - (diff_t * 1000));
  memset(&to, 0, sizeof(to));
  to.tv_usec = (1000 * diff_t);
  if (to.tv_usec > 1000) {
    select(1, &r_set, NULL, NULL, &to);
  }

}


void unet_log(int mode, char *text)
{
  shcoind_log("unet", mode ? unet_mode_label(mode) : "", text);
}
