
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

#include "shcoind.h"


void f_shcoind_log(int err_code, const char *tag, const char *text, const char *src_fname, long src_line)
{
  static shbuf_t *buff;
  char origin[256];
  char *date_str;
  char buf[256];

  if (!err_code) {
    memset(buf, 0, sizeof(buf));
    strncpy(buf, shpref_get("shcoind.debug", ""), sizeof(buf)-1);
    if (*buf != 't' && *buf != 'T')
      return; /* all done */
  }

  if (!buff)
    buff = shbuf_init();

  if (tag) {
    shbuf_catstr(buff, (char *)tag);
    shbuf_catstr(buff, ": ");
  }
  if (text) {
    shbuf_catstr(buff, text);
    shbuf_catstr(buff, " ");
  }
  if (src_fname && src_line) {
    sprintf(origin, "(%s:%ld)", src_fname, src_line);
    shbuf_catstr(buff, origin);
  }

  if (err_code) {
    shlog(SHLOG_ERROR, err_code, shbuf_data(buff));
  } else {
    shlog(SHLOG_INFO, 0, shbuf_data(buff));
  }

  shbuf_clear(buff);
}


void timing_init(char *tag, shtime_t *stamp_p)
{
  
  *stamp_p = shtime();

}

void timing_term(char *tag, shtime_t *stamp_p)
{
  shtime_t stamp = *stamp_p;
  double diff = shtime_diff(stamp, shtime());
  char buf[1024];

  if (diff >= 0.2) {
    sprintf(buf, "TIMING[%s]: total %-2.2f seconds.", tag, diff);
    shcoind_log(buf);
  }

}


