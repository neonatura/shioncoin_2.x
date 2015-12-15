
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

int get_stratum_daemon_port(void)
{
/* todo: config */
  return (STRATUM_DAEMON_PORT);
}

static void stratum_timer(void)
{
  stratum_task_gen();
}

int stratum_init(void)
{
  int err;

  err = unet_bind(UNET_STRATUM, STRATUM_DAEMON_PORT);
  if (err)
    return (err);

  err = unet_timer_add(stratum_timer);
  if (err)
    return (err);

  return (0);
}

void stratum_term(void)
{

  unet_unbind(UNET_STRATUM);

}
