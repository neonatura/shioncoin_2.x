
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

/**
 * Called when a new socket is accepted on the shcoind stratum port (default 9448).
 */
static void stratum_accept(int fd, struct sockaddr *net_addr)
{
  sa_family_t in_fam;
  char buf[256];

  if (fd < 1 || !net_addr) {
    sprintf(buf, "stratum_accept: invalid fd/addr: fd(%d) net_addr(#%x)\n", fd, net_addr);
    shcoind_log(buf);
    return;
  }

  in_fam = *((sa_family_t *)net_addr);
  if (in_fam == AF_INET) {
    struct sockaddr_in *addr = (struct sockaddr_in *)net_addr;

    sprintf(buf, "stratum_accept: received connection (%s port %d).", inet_ntoa(addr->sin_addr), get_stratum_daemon_port());
    shcoind_log(buf);  
  } else {
    sprintf(buf, "stratum_accept: received connection (family %d)", in_fam);
    shcoind_log(buf);  
}

  stratum_register_client(fd);
 
}

static void stratum_close(int fd, struct sockaddr *net_addr)
{
  user_t *peer;

  if (fd < 0)
    return; /* invalid */

  for (peer = client_list; peer; peer = peer->next) {
    if (peer->flags & USER_SYSTEM)
      continue;

    if (peer->fd == fd) {
      peer->fd = -1;
    }

  }
   
}

static void stratum_close_free(void)
{
  user_t *peer_next;
  user_t *peer_last;
  user_t *peer;
  time_t now;

  peer_last = NULL;
  now = time(NULL);
  for (peer = client_list; peer; peer = peer_next) {
    peer_next = peer->next;

    if (peer->flags & USER_SYSTEM)
      continue;

    if (peer->fd == -1) {
      if (peer->work_stamp + 3000 >= now)
        continue; /* less than 50min */

      if (peer_last)
        peer_last->next = peer_next;
      else
        client_list = peer_next;
      free(peer);
      continue;
    }

    peer_last = peer;
  }
   
}

static void stratum_timer(void)
{
  static time_t last_task_t;
  unet_table_t *t;
  user_t *peer;
  shbuf_t *buff;
  size_t len;
  char *data;
  int err;

  for (peer = client_list; peer; peer = peer->next) {
    if (peer->fd == -1)
      continue;

    t = get_unet_table(peer->fd);
    if (!t || t->fd == UNDEFINED_SOCKET) {
      continue;
    }


#if 0
    /* check status of socket. */
    err = write(peer->fd, "", 0);
    if (err) {
      char buf[256];

      sprintf(buf, "stratum_timer: socket (%d) in error state: %s [errno %d].", peer->fd, strerror(errno), errno);
      shcoind_log(buf);

      /* socket is inaccesible */
      unet_close(peer->fd, "exception");
      peer->fd = -1;
      continue;
    }
#endif

#if 0
    buff = shnet_read_buf(peer->fd);
    if (!buff) continue;
#endif
    buff = t->rbuff;
    if (!buff) continue;

    /* process incoming requests */
    len = shbuf_idx(buff, '\n');
    if (len == -1)
      continue;
    data = shbuf_data(buff);
    data[len] = '\0';

    if (0 == strncmp(data, "GET ", strlen("GET "))) {
      stratum_register_html_task(peer, data + strlen("GET "));
    } else if (*data == '{') {
      stratum_register_client_task(peer, data);
    }
    shbuf_trim(buff, len + 1);
  }

  stratum_close_free();

  if (last_task_t != time(NULL)) {
    stratum_task_gen();
    last_task_t = time(NULL);
  }

}

void stratum_term(void)
{

  unet_unbind(UNET_STRATUM);

}

user_t *stratum_register_client(int fd)
{
  user_t *user;
  int err;

  user = stratum_user_init(fd);
  user->next = client_list;
  client_list = user;

  return (user);
}

int stratum_register_html_task(user_t *user, char *html_text)
{
  strtok(html_text, " ");
  return (stratum_http_request(user->fd, html_text));
}

int stratum_register_client_task(user_t *user, char *json_text)
{
  shjson_t *tree;
  int err;

  if (!*json_text) {
    return (0);
  }

  tree = shjson_init(json_text);
  if (tree == NULL) {
    return (SHERR_INVAL);
  }

  err = stratum_request_message(user, tree);
  shjson_free(&tree);

  return (err);
}

int stratum_init(void)
{
  int err;

  err = unet_bind(UNET_STRATUM, get_stratum_daemon_port());
  if (err)
    return (err);

  unet_timer_set(UNET_STRATUM, stratum_timer); /* x1/s */
  unet_connop_set(UNET_STRATUM, stratum_accept);
  unet_disconnop_set(UNET_STRATUM, stratum_close);

  return (0);
}

shjson_t *stratum_json(const char *json_text)
{
  shjson_t *tree;
  char *text;

  if (!json_text)
    return (NULL);

  text = strdup(json_text);
  tree = shjson_init(text);
  free(text);
  if (!tree)
    return (NULL);

  return (tree);
}
