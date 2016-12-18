
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




/** Loads "stratum.dat" upon proess startup. */
void stratum_sync_init(void)
{
  struct sockaddr_in addr;
  user_t *sys_user;
  shbuf_t *buff;
  char path[PATH_MAX+1];
  char *key;
  char *raw;
  char *tok;
  int err;


  sprintf(path, "%s/blockchain/stratum.dat", get_libshare_path());
  chmod(path, 00400);

  buff = shbuf_init();
  err = shfs_mem_read(path, buff);
  if (!err) {
    raw = shbuf_data(buff);
    tok = strtok(raw, "\r\n");
    while (tok) {
      key = strchr(tok, ' ');
      if (!key)
        goto next;

      *key = '\000';
      key++;

      if (unet_local_verify(tok)) {
        goto next;
      }

      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons((uint16_t)STRATUM_DAEMON_PORT);
      if (!inet_pton(AF_INET, tok, &addr.sin_addr)) {
        goto next;
      }

      sys_user = stratum_user_init(-1);
      strncpy(sys_user->worker, tok, sizeof(sys_user->worker) - 1);
      strncpy(sys_user->pass, key, sizeof(sys_user->pass) - 1);
      sys_user->flags = USER_SYNC; /* overwrite client flags */
      sys_user->next = client_list;
      client_list = sys_user;

next:
      tok = strtok(NULL, "\r\n"); /* next */
    }
  }

  shbuf_free(&buff);
}



int stratum_sync_userlist_req(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  int err;

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", MAX_COIN_IFACE);
  shjson_str_add(reply, "method", "mining.shares");
  data = shjson_array_add(reply, "params");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

int stratum_sync_user_req(int ifaceIndex, user_t *peer, char *uname)
{ 
  shjson_t *reply;
  shjson_t *data;
  int err;


  if (!*uname)
    return (SHERR_INVAL);

  if (0 == strcasecmp(uname, "anonymous"))
    return (0); /* skip system users */

  {
    CIface *iface = GetCoinByIndex(ifaceIndex);
    if (!iface || !iface->enabled)
      return (SHERR_OPNOTSUPP);

    reply = shjson_init(NULL);
    shjson_str_add(reply, "iface", iface->name);
    shjson_num_add(reply, "id", ifaceIndex);
    shjson_str_add(reply, "method", "wallet.private");
    data = shjson_array_add(reply, "params");
    shjson_str_add(data, NULL, uname);
    shjson_str_add(data, NULL, peer->pass);
    err = stratum_send_message(peer, reply);
    shjson_free(&reply);
  }

  return (err);
}

void stratum_sync(void)
{
  static int _index;
  struct sockaddr_in addr;
  shjson_t *data;
  user_t *user;
  char acc_name[256];
  char acc_key[256];
  int ifaceIndex;
  int err;
  int idx;
  int fd;
time_t expire;
user_t *u_next;

  expire = (time(NULL) - 300);

  for (user = client_list; user; user = user->next) {
    if (!(user->flags & USER_SYNC))
      continue;
    if (expire < user->work_stamp)
      continue;

    if (user->fd < 0) {
      /* connect to stratum service. */
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons((uint16_t)STRATUM_DAEMON_PORT);
      if (inet_pton(AF_INET, user->worker, &addr.sin_addr)) {
        err = unet_connect(UNET_STRATUM, (struct sockaddr *)&addr, &fd); 
fprintf(stderr, "DEBUG: %d = unet_connect('%s')\n", err, user->worker);
        if (err == 0) {
          user_t *cli_user;
          if ((cli_user = stratum_user_get(fd))) {
            cli_user->fd = -1;
          }

          user->fd = fd;
        }
      } else {
fprintf(stderr, "DEBUG: stratum_sync: error obtaining ipv4 for stratum\n"); 
}
    }
    if (user->fd < 0) {
      continue;
    }

    stratum_sync_userlist_req(user);
    user->work_stamp = time(NULL);

  }

}

user_t *stratum_find_netid(shkey_t *netid)
{
  user_t *user;

  if (!netid)
    return (FALSE);

  for (user = client_list; user; user = user->next) {
    if ((user->flags & USER_SYSTEM))
      continue;

    if (shkey_cmp(netid, &user->netid))
      return (user);

  }

  return (NULL);
}

int stratum_sync_userlist_resp(user_t *peer, shjson_t *block, int ar_len)
{
  user_t *user;
  shkey_t *netid;
  shkey_t *key;
  shjson_t *result;
  int block_cnt;
  int ifaceIndex;

  if (ar_len < 12) {
    fprintf(stderr, "DEBUG: stratum_sync_response: ar_len %d, skipping response\n", ar_len);
    return (SHERR_INVAL);
  }

  block_cnt = (size_t)shjson_array_num(block, NULL, 2);
  if (!block_cnt) {
    /* skip non-active / non-miners */
    return (0);
  }

  netid = shkey_gen(shjson_array_astr(block, NULL, 11));
  if (!(user = stratum_find_netid(netid))) {
    user = stratum_user_init(-1); 
    user->flags |= USER_REMOTE;
  }

  if (!(user->flags & USER_REMOTE))
    return (0); /* all done */

  /* emulate worker for stats generation */
  strcpy(user->worker, shjson_array_astr(block, NULL, 0));
  user->block_cnt = block_cnt;
  user->block_tot = (double)shjson_array_num(block, NULL, 3); 
  user->work_diff = shjson_array_num(block, NULL, 5);
  strncpy(user->cli_ver, shjson_array_astr(block, NULL, 8), sizeof(user->cli_ver)-1);
  user->reward_time = shjson_array_num(block, NULL, 9);
  user->reward_height = shjson_array_num(block, NULL, 10);

  /* retain netid to determine whether local or remote */
  key = shkey_gen(shjson_array_astr(block, NULL, 11));
  memcpy(&user->netid, key, sizeof(user->netid));
  shkey_free(&key);

  if (ar_len >= 14) {
    /* check whether addresses need updated */
    for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
      CIface *iface = GetCoinByIndex(ifaceIndex);
      shjson_t *ar;
      int i;
      char *str;
      uint32_t l_crc, r_crc;

      if (!iface || !iface->enabled) continue;
      ar = shjson_GetArrayItem(block, 12);
      r_crc = (uint32_t)shjson_array_num(ar, NULL, (ifaceIndex - 1));
      l_crc = stratum_addr_crc(ifaceIndex, user->worker);
      fprintf(stderr, "DEBUG: stratum_sync_response: r_crc(%u) l_crc(%u)\n", r_crc, l_crc);
      if (r_crc != l_crc) {
        char uname[512];

        memset(uname, 0, sizeof(uname));
        strncpy(uname, user->worker, sizeof(uname)-1);
        strtok(uname, ".");
        stratum_sync_user_req(ifaceIndex, peer, uname);
      }
    }

    /* check whether ext addresses need updated */
    for (ifaceIndex = 1; ifaceIndex < MAX_COIN_IFACE; ifaceIndex++) {
      CIface *iface = GetCoinByIndex(ifaceIndex);
      char *str;
      uint64_t l_crc, r_crc;
      shjson_t *ar;


      if (!iface || !iface->enabled) continue;
      ar = shjson_GetArrayItem(block, 13);
      r_crc = (uint64_t)shjson_array_num(ar, NULL, (ifaceIndex - 1));
      l_crc = stratum_ext_addr_crc(ifaceIndex, user->worker);
      if (r_crc != l_crc) {
        char uname[512];

        memset(uname, 0, sizeof(uname));
        strcpy(uname, "@");
        strncat(uname, user->worker, sizeof(uname)-2);
        strtok(uname, ".");
        stratum_sync_user_req(ifaceIndex, peer, uname);
      }
    }
  }

  return (0);
}

/* wallet.private: { "result":{"account":"","key":[]} } */
int stratum_sync_user_resp(user_t *peer, int ifaceIndex, shjson_t *result)
{
  char acc_name[256];
  int ar_len;
  int i;

  if (ifaceIndex <= 0 || ifaceIndex >= MAX_COIN_IFACE) {
    return (SHERR_INVAL);
  }

  memset(acc_name, 0, sizeof(acc_name));
  strncpy(acc_name, shjson_str(result, "account", ""), sizeof(acc_name)-1); 
  if (!*acc_name || 
      0 == strcmp(acc_name, "@")) {
    return (SHERR_INVAL);
  }

  /* import all private addresses for coin account. */
  ar_len = shjson_array_count(result, "key");
  for (i = 0; i < ar_len; i++) {
    const char *key_str = shjson_array_astr(result, "key", i);
    stratum_importaddress(ifaceIndex, acc_name, key_str); 
  }

  return (0);
}

int stratum_sync_response(user_t *peer, char *json_text)
{
  shjson_t *tree;
  shjson_t *result;
  shjson_t *block;
  char *acc_name;
  int is_update;
  int ar_len;
  int cli_idx;
  int cli_len;
  int id;

  tree = stratum_json(json_text);
  if (!tree) {
    return (SHERR_INVAL);
}

  id = (int)shjson_num(tree, "id", 0);
  cli_len = shjson_array_count(tree, "result");

  result = shjson_obj_get(tree, "result");
  for (cli_idx = 0; cli_idx < cli_len; cli_idx++) {

    if (id == MAX_COIN_IFACE) {
      block = shjson_array_get(result, cli_idx);
      ar_len = shjson_array_count(block, NULL);

      /* response from "mining.shares" user list */
      stratum_sync_userlist_resp(peer, block, ar_len);
    } else {
      stratum_sync_user_resp(peer, id, result);
    }

  }

  shjson_free(&tree);
  return (0);
}

shkey_t *stratum_sync_key(void)
{
  static shkey_t ret_key;
  static int init;

  if (!init) {
    shpeer_t *peer;
    char host[MAXHOSTNAMELEN+1];
    
    sprintf(host, "127.0.0.1:%u", opt_num(OPT_STRATUM_PORT));
    peer = shpeer_init("shcoind", host);
    memcpy(&ret_key, shpeer_kpriv(peer), sizeof(ret_key));
    shpeer_free(&peer);

    init = TRUE;
  }

  return (&ret_key);
}




