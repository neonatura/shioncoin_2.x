
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

void stratum_http_spring_img_html(shbuf_t *buff)
{

  shbuf_catstr(buff,
      "<div style=\"margin-top : 64px; height : 0px;\"></div>\n"
      "\n"
      "<div style=\"width : 256px; margin-left : auto; margin-right : auto;\">\n"
      "<div style=\"float : right; margin-right : 32px;\"> <span>Spring Matrix</span> </div>\n"
      "<div style=\"float : left; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 6px; padding : 4px 4px 4px 4px; font-family : Georgia; font-size : 12px; font-weight : bold;\">\n"
      "<span id=\"spring_matrix_lbl\">x1</span>\n"
      "</div>\n"
      /* expand */
      "<div style=\"float : left; margin-left : 16px; background : linear-gradient(to bottom, #1e5799 0%,#2989d8 50%,#207cca 51%,#7db9e8 100%); color : #e8e8e9; border-radius : 6px; padding : 4px 4px 4px 4px; font-family : Georgia; font-size : 12px; font-weight : bold;\"><a href=\"/image/spring_matrix.bmp?span=0.1\" id=\"spring_matrix_ref\"><img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB+AHFRcvLtjUSsgAAAGqSURBVEhL5ZVBbtRAEEV/VTViMXcB5QZhzwoWSGEBEkJwBKJIiZBAuUOEFNYBzgA3AImDsMoiyL8+i3TPmLGNx4Edb9N2d5W/67e7DOyIpBNtOJmLb/hcwN+ySEDSXMiARQJmNhcyYJHATVgk8E8syszfxj5TFpEEMJ4zEHB3kHzgvntxEQGSD8dy1jNd1wEASD4D8GkQiVmLPpJ8DmwqAnoC7r4i+drM3k1YIWAtMlAyM5jZGck3ZrZq8wUASN6VdO7uezXZJL0CcLvGCcB+T3i/CrWJqxZnZkeZeZ/k04j4BpIHJK8yU5KytoI2bpMza9cXmSL5k+TjUqtob7L8JG2huk+12lsGACT3ALx39zuoFgE4xJZFAO7V+88AvqBnkaRTM5Mkk/QdwJOI+IpGZq5Ivs1MZeZgEyUd9+w4HllXzT3tum69yeuvSNJlRBxJeqHxz7Fv38DKzISkl+5+6O6Xbb60i4ho4xnJH9sPmEPSo1LKBXB9WBujrSIiPvQPS2OiMpBEKeViLGe0VQCbivpM9aJe9YO13RvODVkkMGXRn1gk8H/+0X4B9mM0rhW8WLcAAAAASUVORK5CYII=\" style=\"width : 15px; height : 15px;\" alt=\"Expand Image\"></a></div>\n"
      "<div style=\"clear : both;\"></div>\n"
      "<hr style=\"width : 80%;\">\n"
      "<div id=\"spring_matrix\" name=\"spring_matrix\" style=\"width : 256px; height : 256px; padding : 0 0 0 0; margin : 0 0 0 0; border : 0;\" onclick=\"matrixClick(this)\">\n"
      "<img id=\"spring_matrix_img\" name=\"spring_matrix_img\" src=\"/image/spring_matrix.bmp\" style=\"width : 256px; height : 256px; border : 0; padding : 0 0 0 0; margin : 0 0 0 0;\">\n"
      "</div>\n"
      "</div>\n");


  shbuf_catstr(buff,
      "<script type=\"text/javascript\">\n"
      "document.getElementById(\"spring_matrix\").addEventListener(\"click\", clickPos, false);\n"
      "var x_of = 0, y_of = 0;\n"
      "var mClick = false;\n"
      "var zoom = 1.0;\n"
      "function matrixClick(el) {\n"
      "  x_of = el.offsetLeft;\n"
      "  y_of = el.offsetTop;\n"
      "  mClick = true;\n"
      "  return false;\n"
      "}\n"
      "var clientX = 0.0;\n"
      "var clientY = 0.0;\n"
      "function clickPos(e) {\n"
      "  if (mClick) {\n"
      "    var i = document.getElementById(\"spring_matrix_img\");\n"
      "    var l = document.getElementById(\"spring_matrix_lbl\");\n"
      "    if (i != null && l != null) {\n"
      "      if (zoom == 1.0) {\n"
      "        clientX = e.clientX - x_of;\n"
      "        clientY = e.clientY - y_of;\n"
      "        zoom = 0.5;\n"
      "        i.src = \"/image/spring_matrix.bmp?y=\" + clientY + \"&x=\" + clientX + \"&zoom=\" + zoom;\n"
      "      } else if (zoom > 0.001) {\n"
      "        zoom /= 2;\n"
      "        i.src = \"/image/spring_matrix.bmp?y=\" + clientY + \"&x=\" + clientX + \"&zoom=\" + zoom;\n"
      "      } else {\n"
      "        zoom = 1.0;\n"
      "        i.src = \"/image/spring_matrix.bmp\";\n"
      "      }\n"
      "      l.innerHTML = \"x\" + (1 / zoom);\n"
      "    }\n"
      "    mClick = false;\n"
      "  }\n"
      "}\n"
      "</script>\n");

}

void stratum_http_spring_img(char *args, shbuf_t *buff)
{
  FILE *fl;
  struct stat st;
  double x_of, y_of, zoom;
  double span;
  char *bmp_path;
  char tag[256];
  char *data;
  char str[256];
  char *ptr;

  zoom = 1.0;
  ptr = strstr(args, "zoom=");
  if (ptr)
    zoom = atof(ptr+5);

  x_of = 0;
  ptr = strstr(args, "x=");
  if (ptr)
    x_of = atof(ptr+2);

  y_of = 0;
  ptr = strstr(args, "y=");
  if (ptr)
    y_of = atoi(ptr+2);

  span = 1.0;
  ptr = strstr(args, "span=");
  if (ptr)
    span = atof(ptr+5);

  x_of = floor(x_of);
  y_of = floor(y_of);

  sprintf(tag, "spring_bmp:%f,%f,%f,%f", zoom, span, x_of, y_of);
  bmp_path = shcache_path(tag);
  if (!shcache_fresh(tag))
    spring_render_fractal(bmp_path, zoom, span, x_of, y_of);
  stat(bmp_path, &st);

  shbuf_catstr(buff, "HTTP/1.0 200 OK\r\n"); 
  shbuf_catstr(buff, "Content-Type: image/bmp\r\n");
  sprintf(str, "Content-Length: %u\r\n", st.st_size);
  shbuf_catstr(buff, str);
  shbuf_catstr(buff, "\r\n"); 

  shfs_mem_read(bmp_path, buff);
#if 0
  data = (char *)calloc(st.st_size, sizeof(char));
  fl = fopen(bmp_path, "rb");
  fread(data, sizeof(char), st.st_size, fl);
  fclose(fl);
  shbuf_cat(buff, data, st.st_size); 
  free(data);
#endif
}

void stratum_http_validate_img(char *args, shbuf_t *buff)
{
  FILE *fl;
  struct stat st;
  double x_of, y_of, zoom;
  double span;
  char *bmp_path;
  char tag[256];
  char *data;
  char str[256];
  char *ptr;

  zoom = 1.0;
  ptr = strstr(args, "zoom=");
  if (ptr)
    zoom = atof(ptr+5);

  x_of = 0;
  ptr = strstr(args, "x=");
  if (ptr)
    x_of = atof(ptr+2);

  y_of = 0;
  ptr = strstr(args, "y=");
  if (ptr)
    y_of = atoi(ptr+2);

  span = 1.0;
  ptr = strstr(args, "span=");
  if (ptr)
    span = atof(ptr+5);

  x_of = floor(x_of);
  y_of = floor(y_of);

  sprintf(tag, "validate_bmp:%f,%f,%f,%f", zoom, span, x_of, y_of);
  bmp_path = shcache_path(tag);
  if (!shcache_fresh(tag))
    validate_render_fractal(bmp_path, zoom, span, x_of, y_of);
  stat(bmp_path, &st);

  shbuf_catstr(buff, "HTTP/1.0 200 OK\r\n"); 
  shbuf_catstr(buff, "Content-Type: image/bmp\r\n");
  sprintf(str, "Content-Length: %u\r\n", st.st_size);
  shbuf_catstr(buff, str);
  shbuf_catstr(buff, "\r\n"); 

  shfs_mem_read(bmp_path, buff);
#if 0
  data = (char *)calloc(st.st_size, sizeof(char));
  fl = fopen("/tmp/validate_fractal.bmp", "rb");
  fread(data, sizeof(char), st.st_size, fl);
  fclose(fl);
  shbuf_cat(buff, data, st.st_size); 
  free(data);
#endif
}

#define SPRING_MATRIX_BMP "/image/spring_matrix.bmp"
#define VALIDATE_MATRIX_BMP "/image/validate_matrix.bmp"
void stratum_http_request(SOCKET sk, char *url)
{
  user_t *user;
  shbuf_t *buff;
char ret_html[4096];

  buff = shbuf_init();

  if (0 == strncmp(url, SPRING_MATRIX_BMP, strlen(SPRING_MATRIX_BMP))) {
    stratum_http_spring_img(url + strlen(SPRING_MATRIX_BMP), buff);
    unet_write(sk, shbuf_data(buff), shbuf_size(buff));
    shbuf_free(&buff);
    unet_shutdown(sk);
    return;
  }
  if (0 == strncmp(url, VALIDATE_MATRIX_BMP, strlen(VALIDATE_MATRIX_BMP))) {
    stratum_http_validate_img(url + strlen(VALIDATE_MATRIX_BMP), buff);
    unet_write(sk, shbuf_data(buff), shbuf_size(buff));
    shbuf_free(&buff);
    unet_shutdown(sk);
    return;
  }

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
  shbuf_catstr(buff, "</table>\r\n");


  /* attach image of current spring matrix fractal */
  stratum_http_spring_img_html(buff);

  shbuf_catstr(buff, "</body></html>\r\n"); 

  unet_write(sk, shbuf_data(buff), shbuf_size(buff));
  shbuf_free(&buff);

  unet_shutdown(sk);

}
