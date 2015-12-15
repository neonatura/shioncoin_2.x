
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

static unet_bind_t _unet_bind[MAX_UNET_MODES];

unet_bind_t *unet_bind_table(int mode)
{
  if (mode < 0 || mode >= MAX_UNET_MODES)
    return (NULL);
  return (_unet_bind[mode]);
}

int unet_bind(int mode, int port)
{
  int err;
  int sk;

  if (_unet_bind[mode] != UNDEFINED_SOCKET)
    return (0); /* already bound */

  sk = shnet_sk();
  if (sk == -1)
    return (-errno);

  err = shnet_bindsk(sk, NULL, port);
  if (err)
    return (err);

  _unet_bind[mode].fd = sk;
  
  return (0);
}


void unet_unbind(int mode)
{
  int err;

  if (_unet_bind[mode].fd == UNDEFINED_SOCKET)
    return (SHERR_INVAL);

  err = unet_close(_unet_bind[mode].fd);
  _unet_bind[mode].fd = UNDEFINED_SOCKET;

  return (err);
}

