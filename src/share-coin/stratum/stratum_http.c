
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

static const char *_stratum_html_template = 
"\r\n"
"%s\r\n"
"\r\n";

char *stratum_http_response(SOCKET sk, char *url)
{
  static char ret_html[10240];

  sprintf(ret_html, _stratum_html_template, url);

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
  unet_shutdown(sk);

}
