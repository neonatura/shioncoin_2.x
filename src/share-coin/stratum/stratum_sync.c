
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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

typedef struct stratum_sync_t
{
  char acc_name[256];
  char acc_key[256];
  int id;
  int fd;
} stratum_sync_t;

#define MAX_PEER_LIST 64
static struct sockaddr peer_list[MAX_PEER_LIST];
static size_t peer_list_tot = -1;

#define MAX_SYNC_TABLE 256
stratum_sync_t stratum_sync_table[MAX_SYNC_TABLE];

static int stratum_sync_find(struct sockaddr *addr)
{
  static const int mode = UNET_STRATUM;
  struct sockaddr cmp_addr;
  unet_table_t *t;
  char peer_ip[512];
  socklen_t addr_len;
  int sk;

  strcpy(peer_ip, unet_netaddr_str(addr));

  for (sk = 1; sk < MAX_UNET_SOCKETS; sk++) {
    t = get_unet_table(sk);
    if (!t)
      continue; /* non-active */

    if (t->mode != mode)
      continue;

    if (!(t->flag & DF_SYNC))
      continue; /* not a stratum service */

    addr_len = sizeof(cmp_addr);
    memset(&cmp_addr, 0, sizeof(cmp_addr));
    getpeername(sk, &cmp_addr, &addr_len);
    if (0 == strcmp(peer_ip, unet_netaddr_str(&cmp_addr)))
      return (sk);
  }

  return (0);
}


void stratum_sync_init(void)
{
  struct sockaddr_in addr;
  shbuf_t *buff;
  char path[PATH_MAX+1];
  char *raw;
  char *tok;
  int err;

  if (peer_list_tot != -1)
    return; /* already init'd */

  peer_list_tot = 0;

  sprintf(path, "%s/blockchain/sync.dat", get_libshare_path());
  chmod(path, 00400);

  buff = shbuf_init();
  err = shfs_mem_read(path, buff);
  if (!err) {
    raw = shbuf_data(buff);
    tok = strtok(raw, "\n");
    while (tok) {
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons((uint16_t)STRATUM_DAEMON_PORT);
      if (0 != inet_pton(AF_INET, tok, &addr.sin_addr)) {
/* todo: ipv6 */
        memcpy(peer_list + peer_list_tot, &addr, sizeof(struct sockaddr));
        peer_list_tot++;
      }

      tok = strtok(NULL, "\n"); /* next */
    }
  }

  shbuf_free(&buff);
}

void stratum_sync_queue(char *acc_name, char *acc_key, int index, int fd)
{
  stratum_sync_t *q;
  int q_idx;

  q_idx = (index % MAX_SYNC_TABLE);
  q = (stratum_sync_table + q_idx);

  /* record request to interpret reply */
  memset(q, 0, sizeof(stratum_sync_t));
  strncpy(q->acc_name, acc_name, sizeof(q->acc_name)-1);
  strncpy(q->acc_key, acc_key, sizeof(q->acc_key)-1);
  q->id = index;
  q->fd = fd;
 
}

int stratum_sync_request(CIface *iface, int index, int fd, char *acc_name, char *acc_key)
{ 
  shjson_t *reply;
  shjson_t *data;
  user_t *user;
  int err;

  user = stratum_user_get(fd); 
  if (!user)
    return (SHERR_NOENT);

  reply = shjson_init(NULL);
  shjson_str_add(reply, "iface", iface->name);
  shjson_num_add(reply, "id", index);
  shjson_str_add(reply, "method", "wallet.validate");
  data = shjson_array_add(reply, "params");
  shjson_str_add(data, NULL, acc_key);
  shjson_str_add(data, NULL, acc_name);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

int stratum_sync_connect(struct sockaddr *addr)
{
/* .. */
return (SHERR_OPNOTSUPP);
}

void stratum_sync(void)
{
  static int _index;
  shjson_t *data;
  char acc_name[256];
  char acc_key[256];
  int ifaceIndex;
  int err;
  int idx;
  int fd;

  for (idx = 0; idx < peer_list_tot; idx++) {
    /* is site connected? */
    if (0 == (fd = stratum_sync_find(peer_list + idx))) {
      stratum_sync_connect(peer_list + idx);
      continue;
    }
      
    for (ifaceIndex = 0; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
      CIface *iface = GetCoinByIndex(ifaceIndex);

      /* cycle through accounts. */
      memset(acc_name, 0, sizeof(acc_name));
      memset(acc_key, 0, sizeof(acc_key));
      err = stratum_account_cycle(acc_name, acc_key);
      if (err)
        continue;

      /* ask site if it has account key */ 
      _index++;
      if (0 == stratum_sync_request(iface, _index, fd, acc_name, acc_key))
        stratum_sync_queue(acc_name, acc_key, _index, fd);
    }
  }

}

int stratum_sync_response(user_t *peer, char *json_text)
{
  shjson_t *tree;
  char *acc_name;
  int idx;
  int id;

  tree = stratum_json(json_text);
  if (!tree)
    return (SHERR_INVAL);

  id = (int)shjson_num(tree, "id", 0);
  for (idx = 0; idx < MAX_SYNC_TABLE; idx++) {
    if (stratum_sync_table[idx].id == id)
      break;
  }
  if (idx == MAX_SYNC_TABLE) {
    shjson_free(&tree);
    return (SHERR_INVAL);
  }

  if (peer->fd != stratum_sync_table[idx].fd) {
    shjson_free(&tree);
    return (SHERR_INVAL);
  }

  acc_name = shjson_array_astr(tree, "params", 0);
  if (acc_name && 
      0 == strcmp(acc_name, stratum_sync_table[idx].acc_name)) {
    /* account address is registered at remote stratum service. */
  } else {
    /* send over assimilation instructions. */
    /* DEBUG: .. */
  }

  shjson_free(&tree);

  return (0);
}


