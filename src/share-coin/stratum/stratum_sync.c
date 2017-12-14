
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
#include "stratum/stratum.h"

#define FIVE_MINUTES 300

static unsigned int _sync_req_idx;
static char errbuf[1024];

extern shjson_t *shjson_array_get(shjson_t *json, int index);


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
      sys_user->sync_flags |= SYNC_IDENT;
      sys_user->next = client_list;
      client_list = sys_user;

next:
      tok = strtok(NULL, "\r\n"); /* next */
    }
  }

  shbuf_free(&buff);
}

int stratum_sync_connect(user_t *user)
{
  struct sockaddr_in addr;
  int err;
  int fd;

  if (!user)
    return (SHERR_INVAL);

  if (user->fd > 0)
    return (0); /* done */

  /* connect to stratum service. */
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)STRATUM_DAEMON_PORT);
  err = inet_pton(AF_INET, user->worker, &addr.sin_addr);
  if (err == 0)
    return (SHERR_PROTO);
  if (err < 0)
    return (-errno); 
  
  err = unet_connect(UNET_STRATUM, (struct sockaddr *)&addr, &fd); 
  if (err < 0)
    return (err);

  if (err == 0) {
    user_t *cli_user;
    if ((cli_user = stratum_user_get(fd))) {
      cli_user->fd = -1;
    }

    user->fd = fd;
  }

  return (0);
}

static int stratum_sync_userlist_req(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  int err;

  if (!(user->flags & USER_SYNC))
    return (SHERR_INVAL);
  if (user->sync_flags & SYNC_RESP_ALL)
    return (SHERR_AGAIN);

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", user->sync_user);
  shjson_str_add(reply, "method", "mining.shares");
  data = shjson_array_add(reply, "params");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err) {
    user->sync_flags |= SYNC_RESP_USER_LIST;
    sprintf(errbuf, "stratum_sync_cycle: info: requested mining userlist from '%s'.", user->worker);
  } else {
    sprintf(errbuf, "stratum_sync_cycle: error: mining userlist from '%s': %s.", user->worker, sherrstr(err));
  }
  shcoind_log(errbuf);

  return (err);
}

static int stratum_sync_elevate_req(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  shkey_t *skey;
  char lcl_auth[256];
  uint32_t lcl_pin;
  int err;

  skey = get_rpc_dat_password(NULL);
  if (!skey)
    return (SHERR_OPNOTSUPP);

  /* generate hash & pin */
  memset(lcl_auth, 0, sizeof(lcl_auth));
  shsha_hex(SHALG_SHA256, (unsigned char *)lcl_auth,
      (unsigned char *)skey, sizeof(shkey_t));
  lcl_pin = shsha_2fa_bin(SHALG_SHA256,
      (unsigned char *)skey, sizeof(shkey_t), RPC_AUTH_FREQ);

//  user->sync_addr = time(NULL);

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", user->sync_addr);
  shjson_str_add(reply, "method", "stratum.elevate");
  data = shjson_array_add(reply, "params");
  shjson_str_add(data, NULL, lcl_auth);
  shjson_num_add(data, NULL, lcl_pin);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err) {
    user->sync_flags |= SYNC_RESP_ELEVATE;
    sprintf(errbuf, "stratum_sync_cycle: info: requested RPC permission for account '%s'.", user->worker); 
  } else {
    sprintf(errbuf, "stratum_sync_cycle: error: RPC permission for account '%s': %s.", user->worker, sherrstr(err)); 
  }
  shcoind_log(errbuf);

  return (err);
}

static int stratum_sync_wallet_listaddr_req(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  char uname[256];
  int err;

  if (!(user->flags & USER_SYNC))
    return (SHERR_INVAL);

  if (user->sync_flags & SYNC_RESP_ALL)
    return (SHERR_AGAIN);

  memset(uname, 0, sizeof(uname));
  strncpy(uname, user->sync_acc, sizeof(uname)-1);
  strtok(uname, ".");
  if (!uname[0])
    return (0); /* done */

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", user->sync_addr);
  shjson_str_add(reply, "method", "wallet.listaddr");
  data = shjson_array_add(reply, "params");
  shjson_str_add(data, NULL, uname);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err) {
    user->sync_flags |= SYNC_RESP_WALLET_ADDR;
    sprintf(errbuf, "stratum_sync_cycle: info: requested wallet list for account '%s'.", uname);
  } else {
    sprintf(errbuf, "stratum_sync_cycle: error: wallet list for account '%s': %s.", uname, sherrstr(err));
  }
  shcoind_log(errbuf);

  return (err);
}

static int stratum_sync_ping_req(user_t *user)
{
  shjson_t *reply;
  int req_id;
  int err;

  if (!(user->flags & USER_SYNC))
    return (SHERR_INVAL);
  if (user->flags & SYNC_RESP_ALL)
    return (SHERR_AGAIN);

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", (int)shrand());
  shjson_str_add(reply, "method", "mining.ping");
  shjson_array_add(reply, "params");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err)
    user->sync_flags |= SYNC_RESP_PING;

  return (err);
}

static int stratum_sync_wallet_setkey_req(user_t *user)
{
  CIface *iface;
  shjson_t *reply;
  shjson_t *param;
  char privkey[256];
  int err;

  if (!user)
    return (SHERR_INVAL);

  if (!(user->flags & USER_SYNC))
    return (SHERR_INVAL);

  iface = GetCoinByIndex(user->ifaceIndex);
  if (!iface || !iface->enabled)
    return (SHERR_OPNOTSUPP);

  if (!user->sync_acc[0] || !user->sync_pubkey[0])
    return (0); /* done */

  memset(privkey, 0, sizeof(privkey));
  err = stratum_getaddrkey(user->ifaceIndex,
      user->sync_acc, user->sync_pubkey, privkey);
  if (err)
    return (err);

  /* send 'wallet.setkey' message. */
  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", user->sync_addr);
  shjson_str_add(reply, "iface", iface->name);
  shjson_str_add(reply, "method", "wallet.nsetkey"); /* DEBUG: TEST remove 'n' */
  param = shjson_array_add(reply, "param");
  shjson_str_add(param, NULL, user->sync_acc);
//  shjson_str_add(param, NULL, privkey); /* DEBUG: TEST: */
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err) {
    user->sync_flags |= SYNC_RESP_WALLET_SET;
    sprintf(errbuf, "stratum_sync_wallet_setkey_req [iface #%d]: info: sent new key (<%d bytes>) for account '%s'.", err, user->ifaceIndex, strlen(privkey), user->sync_acc);
  } else {
    sprintf(errbuf, "stratum_sync_wallet_setkey_req [iface #%d]: error: send new key (<%d bytes>) for account '%s': %s", err, user->ifaceIndex, strlen(privkey), user->sync_acc, sherrstr(err));
  }
  shcoind_log(errbuf);

  return (err);
}

static int stratum_sync_ident_req(user_t *user)
{
  CIface *iface;
  shjson_t *reply;
  shjson_t *param;
  char privkey[256];
  int err;

  if (!user)
    return (SHERR_INVAL);

  if (!(user->flags & USER_SYNC))
    return (SHERR_INVAL);

  iface = GetCoinByIndex(user->ifaceIndex);
  if (!iface || !iface->enabled)
    return (SHERR_OPNOTSUPP);

  if (!user->sync_acc[0] || !user->sync_pubkey[0])
    return (0); /* done */

  memset(privkey, 0, sizeof(privkey));
  err = stratum_getaddrkey(user->ifaceIndex,
      user->sync_acc, user->sync_pubkey, privkey);
  if (err)
    return (err);

  /* send 'wallet.setkey' message. */
  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", user->sync_addr);
  shjson_str_add(reply, "iface", iface->name);
  shjson_str_add(reply, "method", "wallet.nsetkey"); /* DEBUG: TEST remove 'n' */
  param = shjson_array_add(reply, "param");
  shjson_str_add(param, NULL, user->sync_acc);
//  shjson_str_add(param, NULL, privkey); /* DEBUG: TEST: */
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  if (!err)
    user->sync_flags |= SYNC_RESP_IDENT;

  return (err);
}



void stratum_sync_cycle(CIface *iface, user_t *user)
{
  user_t *r_user;
  time_t now;
  int err;

  if (!(user->flags & USER_SYNC))
    return; /* invalid */

#if 0
  if (!(user->sync_flags & SYNC_AUTH)) {
    /* send 'stratum.elevate' stratum command to remote system. */
    return;
  }
#endif
  
  if (user->sync_flags & SYNC_RESP_ALL) {
    return; /* busy waiting for response */
  }

  if (user->sync_flags & SYNC_IDENT) {
    stratum_sync_ident_req(user); 
    user->sync_flags &= ~SYNC_IDENT;
    return;
  }

  now = time(NULL);

  if (user->sync_flags & SYNC_AUTH) {
    if (user->sync_flags & SYNC_WALLET_SET) {
      /* notify */
      stratum_sync_wallet_setkey_req(user);
      /* reset */
      memset(user->sync_acc, 0, sizeof(user->sync_acc));
      memset(user->sync_pubkey, 0, sizeof(user->sync_pubkey));
      /* set next stage */
      user->sync_flags &= ~SYNC_WALLET_SET;
    } else if (user->sync_flags & SYNC_WALLET_ADDR) {
      /* user has been elevated -- perform 'wallet.listaddr' rpc command */
      stratum_sync_wallet_listaddr_req(user);
      /* set next stage. */
      user->sync_flags &= ~SYNC_WALLET_ADDR;
    } else { 
      /* clear perms incase no command was sent. */
      (void)stratum_sync_ping_req(user);
    }

    /* rpc permission has been revoked. */
    user->sync_flags &= ~SYNC_AUTH;
    return;
  }

  if ( /* !SYNC_AUTH */
#if 0 /* DEBUG: TEST: */
      user->sync_addr < (now - FIVE_MINUTES)
#else
      user->sync_addr < (now - 30)
#endif
) { /* every five minutes */
    user->sync_addr = time(NULL); /* must be set first */

    if (user->sync_flags & SYNC_WALLET_ADDR) {
      /* wallet sync */
      stratum_sync_elevate_req(user);
      return;
    }
    if (user->sync_flags & SYNC_WALLET_SET) {
      /* wallet sync */
      stratum_sync_elevate_req(user);
      return;
    }
  }


#if 0 /* DEBUG: TEST: remove me*/
  if (user->sync_user < (now - FIVE_MINUTES)) 
#else
  if (user->sync_user < (now - 30))
#endif
{
    /* request current mining statistics */
    user->sync_user = time(NULL);
    stratum_sync_userlist_req(user);
    return;
  }

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

#if 1 /* DEBUG: TEST: remove me */
  expire = (time(NULL) - 20);
#else
  expire = (time(NULL) - 300);
#endif

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

    if (user->fd <= 0)
      stratum_sync_connect(user);
    if (user->fd <= 0)
      continue;

    stratum_sync_cycle(iface, user);
    user->work_stamp = time(NULL);
  }

}

int stratum_sync_userlist_resp(user_t *user, shjson_t *tree)
{
  shjson_t *result;
  shjson_t *node;
  shjson_t *udata;
  shkey_t net_id;
  shkey_t *key;
  user_t *r_user;
  double btot;
  char worker[640];
  char cli_ver[64];
  char id_hex[64];
  char *text;
  int ar_max;
  int rem_crc;
  int crc;
  int i;

fprintf(stderr, "DEBUG: stratum_sync_userlist_resp()\n");

  result = shjson_obj_get(tree, "result");
  if (!result)
    return (SHERR_PROTO);

  ar_max = shjson_array_count(result, NULL);
  if (ar_max < 1)
    return (SHERR_PROTO);

  for (i = 0; i < ar_max; i++) {
    node = shjson_array_get(result, i);
    if (!node) continue;

    /* user->worker */
    memset(worker, 0, sizeof(worker));
    text = shjson_array_astr(node, NULL, 0);
    if (text) strncpy(worker, text, sizeof(worker)-1);
    if (!*worker)
      continue; /* not registered miner */ 

#if 0 /* DEBUG: TEST: */
    btot = shjson_array_num(node, NULL, 3);
    if (btot < 0.0001)
      continue; /* no mining contribution */
#endif

    /* user->netid */
    memset(id_hex, 0, sizeof(id_hex));
    text = shjson_array_astr(node, NULL, 11);
    if (text) strncpy(id_hex, text, sizeof(id_hex)-1);
    key = shkey_gen(id_hex); 
    if (!key) { 
fprintf(stderr, "DEBUG: stratum_sync_userlist_resp: skipping \"%s\" due to invalid net_id\n", worker); 
      continue; /* invalid / disabled */
    }
    memcpy(&net_id, key, sizeof(net_id));
    shkey_free(&key);

    r_user = stratum_find_netid(&net_id);
    if (r_user && !(r_user->flags & USER_REMOTE)) {
fprintf(stderr, "DEBUG: stratum_sync_userlist_resp: skipping \"%s\" due to netid not being USER_REMOTE [found username \"%s\"]\n", worker, r_user->worker);
#if 0 /* DEBUG: TEST: remoev me*/
      continue; /* already registered */
#endif
    }


    if (!r_user) {
      r_user = stratum_user_init(-1);
      if (!r_user) {
        sprintf(errbuf, "stratum_sync_userlist_resp: error generating new stratum [remote] user.");
        shcoind_log(errbuf);
        return (SHERR_NOMEM);
      }

      memcpy(&r_user->netid, &net_id, sizeof(user->netid));
      r_user->flags = USER_REMOTE; /* sync'd reward stats */
      r_user->next = client_list;
      client_list = r_user;
    }

    /* user->cli_ver */
    memset(cli_ver, 0, sizeof(cli_ver));
    text = shjson_array_astr(node, NULL, 8);
    if (text) strncpy(cli_ver, text, sizeof(cli_ver)-1);

    /* over-ride in case miner authorizes new worker name */
    strncpy(r_user->worker, worker, sizeof(r_user->worker) - 1);

    /* client version (i.e. bfgminer x.x) */
    strncpy(r_user->cli_ver, cli_ver, sizeof(r_user->cli_ver)-1);

    r_user->block_tot = btot;
    r_user->round_stamp = (time_t)shjson_array_num(node, NULL, 1);
    r_user->block_cnt = (size_t)shjson_array_num(node, NULL, 2);
    r_user->work_diff = (int)shjson_array_num(node, NULL, 5);

    /* normal addr crc */
    udata = shjson_array_get(node, 12);
    if (udata) {
      for (i = 1; i < MAX_COIN_IFACE; i++) {
        rem_crc = (int)shjson_array_num(udata, NULL, i);
        crc = stratum_addr_crc(i, worker);
  fprintf(stderr, "DEBUG: stratum_sync_userlist_resp [iface #%d]: rem_addr_crc %d, lcl_addr_crc %d\n", i, rem_crc, crc);
        if (crc && crc != rem_crc) {
          user->ifaceIndex = i;
          memset(user->sync_acc, 0, sizeof(user->sync_acc));
          strncpy(user->sync_acc, r_user->worker, sizeof(user->sync_acc)-1);
          strtok(user->sync_acc, ".");
          user->sync_flags |= SYNC_WALLET_ADDR;
          break;
        }
      }
    }

#if 0 /* DEBUG: TODO: */
    /* ext addr crc */
    udata = shjson_array_get(node, 13);
    if (udata) {
      for (i = 1; i < MAX_COIN_IFACE; i++) {
        rem_crc = (int)shjson_array_num(udata, NULL, i);
        crc = stratum_ext_addr_crc(i, worker);
  fprintf(stderr, "DEBUG: stratum_sync_userlist_resp [iface #%d]: (ext) rem_addr_crc %d, lcl_addr_crc %d\n", i, rem_crc, crc);
        if (crc && crc != rem_crc) {
          user->ifaceIndex = i;
          memset(user->sync_acc, 0, sizeof(user->sync_acc));
          strcpy(user->sync_acc, r_user->worker, sizeof(user->sync_acc)-1);
          strtok(user->sync_acc, ".");
          user->sync_flags |= SYNC_WALLET_EXTADDR;
          break;
        }
      }
    }
#endif

  }

#if 0 /* DEBUG: TEST */
          user->ifaceIndex = SHC_COIN_IFACE;
          user->sync_flags |= SYNC_WALLET_ADDR;
          strcpy(user->sync_acc, "anonymous");
#endif

  return (0);
}
int stratum_sync_walletlist_resp(user_t *user, shjson_t *tree)
{
  shjson_t *result;
  shkey_t *key;
  char *text;
  int ar_max;
  int err;
  int i;

fprintf(stderr, "DEBUG: tstratum_sync_walletlist_resp()\n");

  result = shjson_obj_get(tree, "result");
  if (!result)
    return (SHERR_PROTO);

  ar_max = shjson_array_count(result, NULL);
fprintf(stderr, "DEBUG: stratrum_sync_walletlist_resp: result array x%d\n", ar_max); 
  if (ar_max < 1) {
#if 0 /* DEBUG: TEST: remove me */
    {
      /* account does not have pubkey for account */
      memset(user->sync_pubkey, 0, sizeof(user->sync_pubkey));
      strncpy(user->sync_pubkey, "Rx9YKnXcc9gKygyv1UzQ3rBGus1tuMXJvi", sizeof(user->sync_pubkey)-1);
      user->sync_flags |= SYNC_WALLET_SET;
      return (0);
    }
#endif
    return (SHERR_PROTO);
}

  for (i = 0; i < ar_max; i++) {
    text = shjson_array_astr(result, NULL, i);
    if (!text || !*text) break;

    if (0 == stratum_getaddrkey(user->ifaceIndex, user->sync_acc, text, NULL)) {
fprintf(stderr, "DEBUG: stratum_sync_walletlist_resp: SYNC_WALLET_SET: skipping known pubkey '%s' for account '%s'.\n", text, user->sync_acc);
      continue; /* have pubkey for account */
    }

    /* account does not have pubkey for account */
    memset(user->sync_pubkey, 0, sizeof(user->sync_pubkey));
    strncpy(user->sync_pubkey, text, sizeof(user->sync_pubkey)-1);
    user->sync_flags |= SYNC_WALLET_SET;
fprintf(stderr, "DEBUG: stratum_sync_walletlist_resp: SYNC_WALLET_SET flag set for account \"%s\" due to pubkey \"%s\".\n", user->sync_acc, user->sync_pubkey);
    break;
  }

  return (0);
}

#if 0
int stratum_sync_walletlistaddr_resp(user_t *user, shjson_t *tree)
{
  char *text;

  text = shjson_print(tree);
  
fprintf(stderr, "DEBUG: stratum_sync_walletlistaddr_resp: %s\n", text ? text : "<NULL>");
if (text) free(text);

  return (0);
}
#endif

/* interpretates a stratum/rpc response from past request */
int stratum_sync_resp(user_t *user, shjson_t *tree)
{
  int err;

  if (user->sync_flags & SYNC_RESP_IDENT) {
    user->sync_flags &= ~SYNC_RESP_IDENT;
    return (0);
  }

  if (user->sync_flags & SYNC_RESP_ELEVATE) {
    {
      char *text = shjson_print(tree); 
      fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP_ELEVATE: %s\n", text); 
      free(text);
    }
    if (shjson_array_num(tree, "error", 0) != 0) {
fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP_ELEVATE: detected error -- canceling wallet modes.\n");
      /* remove wallet modes */
#if 0 /* DEBUG: TEST: remove me */
      user->sync_flags &= ~SYNC_WALLET_ADDR;
      user->sync_flags &= ~SYNC_WALLET_SET; 
#endif
    } else {
      /* user is now authorized to perform a RPC command */
      user->sync_flags |= SYNC_AUTH;

    }
#if 0 /* DEBUG: TEST: remove me */
      user->sync_flags |= SYNC_AUTH;
#endif

    user->sync_flags &= ~SYNC_RESP_ELEVATE;
    return (0);
  }

  if (user->sync_flags & SYNC_RESP_USER_LIST) {
fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP_USER_LIST\n");
    /* remove request flag */
    user->sync_flags &= ~SYNC_RESP_USER_LIST;

    /* this is a response to a stratum 'mining.shares' request */
    err = stratum_sync_userlist_resp(user, tree);
    if (err) {
      sprintf(errbuf, "stratum_sync_resp: SYNC_RESP_WALLET_ADDR: error processing stratum response: %s.", sherrstr(err));
      shcoind_log(errbuf);
    }
    return (err);
  }

  if (user->sync_flags & SYNC_RESP_WALLET_ADDR) {
    { /* DEBUG: TEST: remove me*/
      char *text = shjson_print(tree); 
fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP_WALLET_ADDR: %s\n", text); 
      free(text);
    }
    /* remove request flag */
    user->sync_flags &= ~SYNC_RESP_WALLET_ADDR;

    /* this is a response to a rpc 'wallet.list' request. */
    err = stratum_sync_walletlist_resp(user, tree);
    if (err) {
      sprintf(errbuf, "stratum_sync_resp: SYNC_RESP_WALLET_ADDR: error processing stratum response: %s.", sherrstr(err));
      shcoind_log(errbuf);
    }
    return (err);
  }

  if (user->sync_flags & SYNC_RESP_WALLET_SET) {
    { /* DEBUG: TEST: remove me*/
      char *text = shjson_print(tree); 
fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP_WALLET_SET: %s\n", text); 
      free(text);
    }
    /* remove request flag */
    user->sync_flags &= ~SYNC_RESP_WALLET_SET;

#if 0
    /* this is a response to a rpc 'wallet.list' request. */
    return (stratum_sync_walletset_resp(user, tree));
#endif
    return (0);
  }

  /* must be last */
  if (user->sync_flags & SYNC_RESP_PING) {
fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP_PING\n");
    /* confirmed remote server is responsive. */
    user->sync_flags &= ~SYNC_RESP_PING;
    return (0);
  }


  { /* DEBUG: */
    char *text = shjson_print(tree); 
fprintf(stderr, "DEBUG: stratum_sync_resp: SYNC_RESP[unknown response]: %s\n", text); 
    free(text);
  }

  return (0); /* ignore everything else */
}


/**
 * Receive a JSON request/response on a SYNC socket
 */
int stratum_sync_recv(user_t *peer, char *json_text)
{
  shjson_t *j;
  shjson_t *param;
  int err;

  j = stratum_json(json_text);
  if (!j)
    return (SHERR_PROTO);

  param = shjson_obj_get(j, "params");
  if (param != NULL) {
    /* this is an incoming request. */
    shjson_free(&j);
    return (stratum_register_client_task(peer, json_text));
  }

  err = stratum_sync_resp(peer, j);
  shjson_free(&j);

  return (err);
}






#if 0
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
  strncpy(acc_name, shjson_astr(result, "account", ""), sizeof(acc_name)-1); 
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
  pkey = shjson_astr(result, "primary", "");
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
