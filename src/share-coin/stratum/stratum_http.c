
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
#include "coin_proto.h"

static const char *_stratum_user_html_template = 
"\r\n"
"Name: %s\r\n"
"Speed: %f\r\n"
"Shares: %lu\r\n"
"Accepted: %u\r\n"
"\r\n";
static const char *_stratum_html_template = 
"<div style=\"font-size : 14px; font-family : Georgia; height : 32px; width : 99%; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; padding-top : 10px;\">\r\n" /* show ver */
"<div style=\"float : left; margin-left : 16px; margin-right : 16px; font-size : 16px;\">%s</div>\r\n"
"<div style=\"float : left; margin-left : 16px;\">Block Height: %lu</div>\r\n"
"<div style=\"float : left; margin-left : 16px;\">Difficulty: %-4.4f</div>\r\n"
"<div style=\"float : left; margin-left : 16px;\">Global Speed: %-1.1fkh/s</div>\r\n"
"<div style=\"float : left; margin-left : 16px;\">Max Coins: %lu</div>\r\n"
"<div style=\"float : left; margin-left : 16px;\">Maturity: %lu</div>\r\n"
"<div style=\"clear : both;\"></div>\r\n"
"</div>\r\n"
"<hr></hr>\r\n";


char *stratum_http_response(SOCKET sk, char *url)
{
  static char ret_html[10240];
  char uname[512];

  int idx;
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) { 
    CIface *iface = GetCoinByIndex(idx);
    if (!iface || !iface->enabled) continue;

    *ret_html = '\0';
    {
      shjson_t *json = shjson_init(getmininginfo(idx));
      unsigned long height = shjson_array_num(json, "result", 0);
      sprintf(ret_html+strlen(ret_html), _stratum_html_template, 
          iface->name, height,
          shjson_array_num(json, "result", 1),
          shjson_array_num(json, "result", 2),
          (unsigned long)(iface->max_money / COIN),
          (unsigned long)iface->coinbase_maturity);
      shjson_free(&json);

      /* DEBUG: TODO: .. show mem usage .. blockIndex vs mapped files ~ */
    }

  }

  return (ret_html);
}

void stratum_http_request(SOCKET sk, char *url)
{
  user_t *user;
  shbuf_t *buff;
char ret_html[4096];

  buff = shbuf_init();
  shbuf_catstr(buff, "HTTP/1.0 200 OK\r\n"); 
  shbuf_catstr(buff, "Content-Type: text/html\r\n");
  shbuf_catstr(buff, "\r\n"); 
  shbuf_catstr(buff, "<html><body>\r\n"); 
  shbuf_catstr(buff, stratum_http_response(sk, url));

  shbuf_catstr(buff, 
      "<div style=\"width : 80%; margin-left : auto; margin-right : auto; font-size : 13px; width : 90%;\">" 
      "<table cellspacing=1 style=\"width : 100%; linear-gradient(to bottom, #1e9957,#29d889,#20ca7c,#8de8b9); color : #666;\">"
      "<tr style=\"background-color : lime; color : #999;\"><td>Worker</td><td>Speed</td><td>Shares</td><td>Blocks Submitted</td></tr>");
  for (user = client_list; user; user = user->next) {
    if (!*user->worker)
      continue;

    sprintf(ret_html,
        "<tr><td>%s</td>"
        "<td>%-4.4f</td>"
        "<td>%-4.4f</td>"
        "<td>%u</td></tr>",
        user->worker, stratum_user_speed(user),
        user->block_tot, (unsigned int)user->block_cnt);
    shbuf_catstr(buff, ret_html);
  }
  shbuf_catstr(buff, "</table>");


  shbuf_catstr(buff, "</body></html>\r\n"); 

  unet_write(sk, shbuf_data(buff), shbuf_size(buff));
  shbuf_free(&buff);

  unet_shutdown(sk);

}
