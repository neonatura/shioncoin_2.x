
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

#include "shcon.h"

int shcon_command_send(char **args, int arg_nr)
{
  shjson_t *param;
  shjson_t *j;
  char *mode;
  int i;

  if (arg_nr < 1)
    return (SHERR_INVAL);

  mode = args[0];

  j = shjson_init(NULL);
  if (!j)
    return (SHERR_NOMEM);

  /* attributes */
  shjson_str_add(j, "iface", opt_iface()); 
  shjson_num_add(j, "stamp", time(NULL));
  key_auth_append(j);

  /* command */
  shjson_str_add(j, "method", mode); 

  param = shjson_array_add(j, "params");
  for (i = 1; i < arg_nr; i++) {
    if (atof(args[i]) != 0.00000000) {
      shjson_num_add(param, NULL, atof(args[i]));
    } else {
      shjson_str_add(param, NULL, args[i]);
    }
  }

  net_json_send(j);

  shjson_free(&j);
  return (0);
}

int shcon_command_recv(shjson_t **resp_p)
{
  return (net_json_recv(resp_p));
}

int shcon_command(char **args, int arg_nr, shjson_t **resp_p)
{
  int err;

  err = shcon_command_send(args, arg_nr);
  if (err)
    return (err);

  err = shcon_command_recv(resp_p);
  if (err)
    return (err);

  return (0);
} 


