
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
"<u>%s</u>\r\n"
"<div style=\"font-size : 12px; font-family : Georgia;\">\r\n" /* show ver */
"<div style=\"float : left; margin-left : 16px;\">Ledger Blocks: %lu</div>\r\n"
"<div style=\"float : left; margin-left : 16px;\">Difficulty: %-4.4f</div>\r\n"
"<div style=\"float : left; margin-left : 16px;\">Network Speed: %-1.1fkh/s</div>\r\n"
"<div style=\"float : left; margin-left : 16px;\">Max Coins: %lu</div>\r\n"
"<div style=\"float : left; margin-left : 16px;\">Maturity: %lu</div>\r\n"
"<div style=\"clear : both;\"></div>\r\n"
"</div>\r\n"
"<hr></hr>\r\n";


char *stratum_http_response(SOCKET sk, char *url)
{
  static char ret_html[10240];
  char uname[512];

  if (0 == strncmp(url, "/user/", strlen("/user/"))) {
    user_t *user;

    memset(uname, 0, sizeof(uname));
    strncpy(uname, url + strlen("/user/"), sizeof(uname)-1); 
    strtok(uname, "/?&");

    user = stratum_user_find(uname); 
    if (!user)
      return (ret_html); /* blank */

    sprintf(ret_html, _stratum_user_html_template,
        user->worker, stratum_user_speed(user), 
        (unsigned long)user->block_tot, (unsigned int)user->block_cnt);
  } else {
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
  }

  return (ret_html);
}

void stratum_http_request(SOCKET sk, char *url)
{
  shbuf_t *buff;

  buff = shbuf_init();
  shbuf_catstr(buff, "HTTP/1.0 200 OK\r\n"); 
  shbuf_catstr(buff, "Content-Type: text/html\r\n");
  shbuf_catstr(buff, "\r\n"); 
  shbuf_catstr(buff, "<html><body>\r\n"); 
  shbuf_catstr(buff, stratum_http_response(sk, url));
  shbuf_catstr(buff, "</body></html>\r\n"); 

  unet_write(sk, shbuf_data(buff), shbuf_size(buff));
  shbuf_free(&buff);

  unet_shutdown(sk);

}
