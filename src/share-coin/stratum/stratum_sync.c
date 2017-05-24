
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

#define FIVE_MINUTES 300


static unsigned int _sync_req_idx;

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


  sprintf(path, "%s/blockchain/rpc.dat", get_libshare_path());
  chmod(path, 00400);

  buff = shbuf_init();
  err = shfs_mem_read(path, buff);
  if (!err) {
    raw = shbuf_data(buff);
    tok = strtok(raw, "\r\n");
    while (tok) {
      if (*tok == '#')
        goto next;

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



#if 0
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
#endif

#if 0
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
#endif

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

  _sync_req_idx++;
  ifaceIndex = (_sync_req_idx % MAX_COIN_IFACE);
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled)
    return;

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

    stratum_sync_send_pub(iface, user);

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


#if 0
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
#endif

/**
 * Send the primary public coin address for all active workers. 
 */
int stratum_sync_send_pub(CIface *iface, user_t *peer)
{
  shjson_t *reply;
  shjson_t *param;
  shjson_t *obj;
  user_t *user;
  char acc_name[MAX_SHARE_NAME_LENGTH];
  char ext_name[MAX_SHARE_NAME_LENGTH];
  char *pub_str;
  char errbuf[256];
  int tot_cnt;
  int pin;
  int err;


  pin = get_rpc_pin(peer->worker);

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", ++_sync_req_idx);
  shjson_str_add(reply, "iface", iface->name);
  shjson_str_add(reply, "method", "wallet.sync");
  param = shjson_array_add(reply, "param");
  shjson_num_add(param, NULL, get_rpc_pin(peer->worker));
  obj = shjson_array_add(param, NULL);


  tot_cnt = 0;
  for (user = client_list; user; user = user->next) {
    if ((user->flags & USER_SYNC) ||
        (user->flags & USER_REMOTE) ||
        (user->flags & USER_SYSTEM))
      continue;

    memset(acc_name, 0, sizeof(acc_name));
    strncpy(acc_name, user->worker, sizeof(acc_name)-1);
    strtok(acc_name, " ");

    if (0 != strcmp(shjson_str(obj, acc_name, ""), ""))
      continue; /* already proccessed account */ 

    pub_str = stratum_getaccountaddress(GetCoinIndex(iface), acc_name);
    if (!pub_str)
      continue; /* unknown account */
    shjson_str_add(obj, acc_name, pub_str);
    tot_cnt++;

    sprintf(ext_name, "@%s", acc_name);
    pub_str = stratum_getaccountaddress(GetCoinIndex(iface), ext_name);
    if (!pub_str)
      continue; /* unknown account */
    shjson_str_add(obj, ext_name, pub_str);
  }

  err = 0;
  if (tot_cnt != 0) {
    err = stratum_send_message(peer, reply);
  }

  shjson_free(&reply);

  if (err) {
    sprintf(errbuf, "stratum_sync_send_pub: error sending message: %s [sherr %d].", sherrstr(err), err); 
    shcoind_log(errbuf);
  }

  return (err);
}

int stratum_sync_recv_pub(int ifaceIndex, user_t *user, uint32_t pin, char *acc_name, char *pub_key)
{
  CIface *iface;
  shjson_t *result;
  shjson_t *obj;
  shjson_t *node;
  shjson_t *reply;
  shjson_t *p;
  char *str;
  int is_update;
  int ar_len;
  int cli_idx;
  int cli_len;
  int err;

  iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled)
    return (0);

fprintf(stderr, "DEBUG: stratum_sync_recv_pub: iface(%s) user(%s) pin(%d)\n", iface->name, user->worker, pin);

/* DEBUG: verify host origin against 'worker' name  */

  err = verify_rpc_pin(user->worker, pin);
  if (err) {
    return (err);
  }

  str = stratum_getaccountaddress(GetCoinIndex(iface), acc_name);
  if (!str)
    return (SHERR_NOENT);
  if (0 == strcmp(str, pub_key))
    return (0); /* identical primary account pubkey for acocunt */
  
  err = stratum_sync_send_priv(iface, user, acc_name);
  if (err)
    return (err);

  return (0);
}

int stratum_sync_send_priv(CIface *iface, user_t *user, char *acc_name)
{
  shjson_t *reply;
  shjson_t *p;
  shjson_t *obj;
  shjson_t *data;
  const char *pub_str;
  char *str;
  int err;

fprintf(stderr, "DEBUG: stratum_sync_send_priv: acc_name(%s)\n", acc_name);

  if (!acc_name)
    return (SHERR_INVAL);

  pub_str = stratum_getaccountaddress(GetCoinIndex(iface), acc_name);
  if (!pub_str) {
fprintf(stderr, "DEBUG: stratum_sync_send_Priv: unknown primary pub key \n");
    return (SHERR_INVAL);
  }

  reply = shjson_init(NULL);
  shjson_str_add(reply, "iface", iface->name);

  p = shjson_obj_add(reply, "result");

  /* account name */
  shjson_str_add(p, "account", acc_name);

  /* primary receive coin address */
  shjson_str_add(p, "primary", (char *)pub_str);

  /* list of private addresses */
  data = shjson_array_add(p, "key");
  stratum_listaddrkey(GetCoinIndex(iface), acc_name, data);

  err = stratum_send_message(user, reply);
  shjson_free(&reply);
  if (err)
    return (err);

  return (0);
}

/**
 * Receive a list of private keys based on active works who has a inconsitent primary receive coin address.
 */
int stratum_sync_recv_priv(user_t *peer, shjson_t *tree)
{
  CIface *iface;
  shjson_t *result;
  char acc_name[256];
  char *pkey;
  int ifaceIndex;
  int ar_len;
  int id;
  int i;

  id = (int)shjson_num(tree, "id", 0);

  iface = GetCoin(shjson_astr(tree, "iface", ""));
  if (!iface || !iface->enabled)
    return (0);

  result = shjson_obj_get(tree, "result");
  if (!result)
    return (SHERR_INVAL);
  memset(acc_name, 0, sizeof(acc_name));
  strncpy(acc_name, shjson_str(result, "account", ""), sizeof(acc_name)-1); 
  if (!*acc_name || 0 == strcmp(acc_name, "@")) {
    return (SHERR_INVAL);
  }

  /* import all private addresses for coin account. */
  ifaceIndex = GetCoinIndex(iface);
  ar_len = shjson_array_count(result, "key");
  for (i = 0; i < ar_len; i++) {
    const char *key_str = shjson_array_astr(result, "key", i);
    stratum_importaddress(ifaceIndex, acc_name, key_str); 
  }

  /* set primary pub-key addr */
  pkey = shjson_str(result, "primary", "");
  if (*pkey)
    stratum_setdefaultkey(ifaceIndex, acc_name, pkey);

  return (0);
}

/**
 * Receive a JSON request on a SYNC socket
 */
int stratum_sync_recv(user_t *peer, char *json_text)
{
  CIface *iface;
  shjson_t *tree;
  shjson_t *result;
  shjson_t *obj;
  shjson_t *node;
  shjson_t *param;
  shjson_t *reply;
  char *acc_name;
  int is_update;
  int ar_len;
  int cli_idx;
  int cli_len;
  int pin;
  int err;
  int id;

  tree = stratum_json(json_text);
  if (!tree) {
    return (SHERR_INVAL);
}

  param = shjson_obj_get(tree, "params");
  if (param != NULL) {
    /* this is an incoming request. */
    shjson_free(&tree);
    return (stratum_register_client_task(peer, json_text));
  }

  /* this is a response to a 'wallet.sync' request */
  err = stratum_sync_recv_priv(peer, tree);
  shjson_free(&tree);

  return (err);
}





#if 0
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
#endif




