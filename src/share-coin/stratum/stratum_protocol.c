

#define __PROTO__PROTOCOL_C__
#include "shcoind.h"
#include "coin_proto.h"

#define DEFAULT_WORK_DIFFICULTY 256


char *stratum_runtime_session(void)
{
  static char buf[32];

  if (!*buf) {
    sprintf(buf, "%-8.8x", time(NULL));
  }

  return (buf);
}



uint32_t stratum_request_id(void)
{
  static uint32_t idx;

  if (!idx) {
    idx = (rand() & 0xFFFF)  + 0xFF;
  }

  return (++idx);
}

int stratum_send_difficulty(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  int err;

  strcpy(user->cur_id, "");

  reply = shjson_init(NULL);
  shjson_str_add(reply, "method", "mining.set_difficulty");
  data = shjson_array_add(reply, "params");
  shjson_num_add(data, NULL, user->work_diff);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

int stratum_send_client_ver(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  int err;

  sprintf(user->cli_id, "%u", stratum_request_id());
  strcpy(user->cur_id, user->cli_id);

  reply = shjson_init(NULL);
  shjson_str_add(reply, "method", "client.get_version");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}



int stratum_session_nonce(void)
{
  char buf[256];
  int *val;

  strcpy(buf, "SOCK");
  val = (int *)buf;
  
  return (*val);
}

/**
 * @note strtoll is used for 32bit compatibility.
 */
int stratum_validate_submit(user_t *user, shjson_t *json)
{
  shjson_t *block;
  shkey_t *key;
  shtime_t ts;
  double share_diff;
  char *worker = shjson_array_astr(json, "params", 0); 
  char *job_id = shjson_array_astr(json, "params", 1); 
  char *extranonce2 = shjson_array_astr(json, "params", 2); 
  char *ntime = shjson_array_astr(json, "params", 3); 
  char *nonce = shjson_array_astr(json, "params", 4); 
  char *dup;
  char buf[64];
  char path[PATH_MAX+1];
  char xn_hex[256];
  char cur_hash[512];
  char cb1[512];
  char share_hash[128];
  char errbuf[1024];
  char submit_hash[1024];
  double last_diff;
  uint32_t le_ntime;
//  uint32_t be_ntime;
  uint32_t le_nonce;
  uint32_t be_nonce;
  uint32_t *data32;
  uint32_t last_nonce;
  unsigned int task_id;
  int ret_err;
  int err;
  int i;

  if (!job_id)
    return (SHERR_INVAL);
  task_id = (unsigned int)strtoll(job_id, NULL, 16);
#if 0
  task = stratum_task(task_id);
  if (!task)
    return (SHERR_INVAL);
#endif

  le_ntime = (uint32_t)strtoll(ntime, NULL, 16);
  //be_ntime = htobe32(le_ntime);
  le_nonce = (uint32_t)strtoll(nonce, NULL, 16); 
  be_nonce =  htobe32(le_nonce);

  /* set worker name */
  stratum_user(user, worker);

#if 0
  /* generate new cb1 */
  memset(buf, 0, sizeof(buf));
  bin2hex(buf, &le_ntime, 4);
  memset(cb1, 0, sizeof(cb1) - 1);
  strncpy(cb1, task->cb1, sizeof(cb1) - 1);
  strncpy(cb1 + strlen(cb1) - 10, buf, 8);


  ret_err = 0;
  strncpy(task->work.xnonce2, extranonce2, sizeof(task->work.xnonce2) - 1);
  task->work.nonce = le_nonce;

  /* generate block hash */
  shscrypt_work(&user->peer, &task->work, task->merkle, task->prev_hash, cb1, task->cb2, task->nbits, ntime);
  hex2bin(&task->work.data[76], nonce, 4);

  memset(share_hash, 0, sizeof(share_hash));
  task->work.nonce = le_nonce;
  memset(task->work.hash, 0, sizeof(task->work.hash));
//  be_nonce =  htobe32(task->work.nonce);
  err = !scanhash_scrypt(task->work.midstate, task->work.data, task->work.hash, task->work.target, be_nonce+1, &last_nonce, be_nonce-2, &last_diff);
  if (!err) { 
    key = shkey_bin(task->work.data, 80);
    dup = shmap_get_str(task->share_list, key);
    bin2hex(share_hash, task->work.hash, 32);
    if (dup && 0 == strcmp(dup, share_hash)) {
      ret_err = SHERR_ALREADY;
    }
    shmap_set_str(task->share_list, key, share_hash);
    shkey_free(&key);
  } else {
    //  return (BLKERR_LOW_DIFFICULTY);
  } 

  if (!ret_err) {
    task->work.pool_diff = last_diff;
    stratum_user_block(user, task);
  }
  /* if (user->peer.diff > task->target) */
  /* submit everything to server regardless of return code. */
#endif


  memset(submit_hash, '\000', sizeof(submit_hash));
  sprintf(xn_hex, "%s%s", user->peer.nonce1, extranonce2);
  timing_init("submitblock", &ts);
  ret_err = submitblock(task_id, le_ntime, le_nonce, xn_hex,
      submit_hash, &share_diff);
  timing_term(0, "submitblock", &ts);
  if (ret_err)
    return (ret_err);

#if 0
  /* attempt 'reverse nonce' */
  if (!*submit_hash) {
    double be_diff;
    ret_err = submitblock(task_id, le_ntime, be_nonce, xn_hex,
        submit_hash, &be_diff);
    if (!ret_err && (be_diff > share_diff)) {
fprintf(stderr, "DEBUG: stratum_validate_submit: be_nonce (%x) is lower hash than le_nonce (%x) [ntime %x, xn_hex %s].\n", be_nonce, le_nonce, (unsigned int)le_ntime, xn_hex);
      share_diff = be_diff;
    }
  }
#endif

  /* add share to current round */
  stratum_user_block(user, share_diff);

  if (*submit_hash) {
    sprintf(errbuf, "stratum_validate_submit: submitted block \"%s\" for \"%s\"\n", submit_hash, user->worker);
    unet_log(UNET_STRATUM, errbuf);

    /* user's block was accepted by network. */
    user->block_acc++;
    strncpy(user->block_hash, submit_hash, sizeof(user->block_hash) - 1);
  }

  return (0);
}

static int stratum_subscribe(user_t *user)
{
  int err;

  err = stratum_send_subscribe(user);
  if (!err) 
    user->flags |= USER_SUBSCRIBE;

  ResetTemplateWeight();

  return (err);
}

int stratum_set_difficulty(user_t *user, int diff)
{
  int err;

  diff = MAX(128, diff);
  diff = MIN(16384, diff);

  user->work_diff = diff;
  err = stratum_send_difficulty(user);
  return (err);
}

void set_stratum_error(shjson_t *reply, int code, char *str)
{
  shjson_t *error;

  error = shjson_array_add(reply, "error");
  shjson_num_add(error, NULL, code);
  shjson_str_add(error, NULL, str);
  shjson_null_add(error, NULL);

}

static shjson_t *stratum_generic_error(void)
{
  shjson_t *reply;

  reply = shjson_init(NULL);
  set_stratum_error(reply, -5, "invalid");
  shjson_null_add(reply, "result");

  return (reply);
}

static int stratum_request_account_create(int ifaceIndex, user_t *user, char *account)
{
  shjson_t *reply;
  const char *json_data = "{\"result\":null,\"error\":null}";
  int err;

  reply = NULL;
  if (account) {
    /* creates a usde address for an account name */
    /* providing account does not exist; returns usde address and sha of private key */
    reply = stratum_json(stratum_create_account(ifaceIndex, account));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_address(int ifaceIndex, user_t *user, char *hash)
{
  shjson_t *reply;
  int err;

  if (hash) {
    reply = stratum_json(stratum_getaddressinfo(ifaceIndex, hash));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_secret(int ifaceIndex, user_t *user, char *hash, const char *pkey_str)
{
  shjson_t *reply;
  int err;

  if (hash) {
    reply = stratum_json(stratum_getaddresssecret(ifaceIndex, hash, pkey_str));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_import(int ifaceIndex, user_t *user, char *hash, const char *privaddr_str)
{
  shjson_t *reply;
  const char *json_data = "{\"result\":null,\"error\":null}";
  int err;

  if (hash) {
    reply = stratum_json(stratum_importaddress(ifaceIndex, hash, privaddr_str));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }
    
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

#if 0
static int stratum_request_account_transactions(int ifaceIndex, user_t *user, int idx, char *account, char *pkey_str, int duration)
{
  shjson_t *reply;
  int err;

  if (account) {
    reply = stratum_json(getaccounttransactioninfo(ifaceIndex, account, pkey_str, duration));
    if (!reply)
      reply = stratum_json(stratum_error_get(idx));
  } else {
    reply = stratum_generic_error();
  }

  shjson_num_add(reply, "id", idx);
  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}
#endif

static int stratum_request_account_transfer(int ifaceIndex, user_t *user, char *account, char *pkey_str, char *dest, double amount)
{
  shjson_t *reply;
  const char *json_data = "{\"result\":null,\"error\":null}";
  int err;

  if (account && pkey_str && dest) {
    reply = stratum_json(stratum_create_transaction(ifaceIndex, account, pkey_str, dest, amount));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_account_info(int ifaceIndex, user_t *user, char *account, char *pkey_str)
{
  shjson_t *reply;
  int err;

  if (account && pkey_str) {
    reply = stratum_json(stratum_getaccountinfo(ifaceIndex, account, pkey_str));
    if (!reply)
      reply = stratum_json(stratum_error_get(atoi(user->cur_id)));
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

static int stratum_request_wallet_private_info(int ifaceIndex, user_t *user, char *account, char *key_str)
{
  shkey_t *r_key;
  shjson_t *reply;
  int ok;
  int err;

  /* verify "stratum sync key" */
  r_key = shkey_gen(key_str);
  if (!r_key) {
    ok = FALSE;
  } else {
//fprintf(stderr, "DEBUG: stratum_request_wallet_private_info: invalid key '%s'\n", key_str);
    ok = shkey_cmp(r_key, stratum_sync_key());

/* DEBUG: todo.. verify shaddr(user->fd) == a USER_SYNC node */

/* DEBUG: todo.. shkey_cmp(pkey(acc)) */
  }
  shkey_free(&r_key);
  if (ok) {
    const char *json_str = stratum_walletkeylist(ifaceIndex, account);
    if (json_str)
      reply = stratum_json(json_str);
    else
      reply = stratum_generic_error();
  } else {
    reply = stratum_generic_error();
  }

  err = stratum_send_message(user, reply);
  shjson_free(&reply);

  return (err);
}

/**
 * @returns The coin interface with the specified name.
 */
int stratum_get_iface(char *iface_str)
{
  CIface *iface;
  double t_diff;
  double diff;
  int ifaceIndex;
  int idx;

  if (!*iface_str)
    return (0); /* not specified */

  diff = 0;
  ifaceIndex = 0;
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    iface = GetCoinByIndex(idx); 
    if (!iface) continue;

    if (0 == strcasecmp(iface->name, iface_str))
      return (idx);
  }
  
  return (-1); /* invalid */
}

/**
 * @returns The coin interface with the hardest mining difficulty.
 */
int stratum_default_iface(void)
{
  CIface *iface;
  double t_diff;
  double diff;
  double span;
  int ifaceIndex;
  int idx;

  diff = 0;
  ifaceIndex = 0;
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    iface = GetCoinByIndex(idx);
    if (!iface || !iface->enabled) continue;

    span = (double)(60 - MAX(59, time(NULL) - iface->net_valid));
    t_diff = (double)GetNextDifficulty(idx) / span;
    t_diff = MAX(0.0001, t_diff);

    if (t_diff >= diff) {
      ifaceIndex = idx;
      diff = t_diff;
    }
  }
  
  return (ifaceIndex);
}

extern int DefaultWorkIndex;

/**
 * @todo: leave stale worker users (without open fd) until next round reset. current behavior does not payout if connection is severed.
 */ 
int stratum_request_message(user_t *user, shjson_t *json)
{
  shjson_t *reply;
  user_t *t_user;
  shtime_t ts;
  char iface_str[256];
  char buf[256];
  char uname[256];
  char *method;
  char *text;
  uint32_t val;
  double block_avg;
  int ifaceIndex;
  int err;
  int i;

  memset(user->cur_id, 0, sizeof(user->cur_id));
  val = shjson_num(json, "id", 0);
  if (val) {
    sprintf(user->cur_id, "%u", (unsigned int)val);
  } else {
    text = shjson_str(json, "id", "");
    if (text && *text)
      strncpy(user->cur_id, text, sizeof(user->cur_id)-1);
  }

  if (0 == strcmp(user->cur_id, user->cli_id) && 
      shjson_strlen(json, "result")) {
    /* response from 'client.get_version' method. */ 
    strncpy(user->cli_ver, shjson_astr(json, "result", ""), sizeof(user->cli_ver));
    return (0);
  }

  memset(iface_str, 0, sizeof(iface_str));
  strncpy(iface_str, shjson_astr(json, "iface", ""), sizeof(iface_str)-1); 
  ifaceIndex = stratum_get_iface(iface_str);
  if (ifaceIndex < 1)
    ifaceIndex = stratum_default_iface();
  if (ifaceIndex < 1 || ifaceIndex >= MAX_COIN_IFACE) {
    return (SHERR_INVAL);
  }
    

  method = shjson_astr(json, "method", NULL);
  if (!method) {
    /* no operation method specified. */
    return (SHERR_INVAL);
  }
//fprintf(stderr, "DEBUG: STRATUM '%s'\n", method);

  timing_init(method, &ts);

  if (0 == strcmp(method, "mining.ping")) {
    reply = shjson_init(NULL);
    shjson_null_add(reply, "error");
    shjson_null_add(reply, "result");
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }

  if (0 == strcmp(method, "mining.subscribe")) {
    err = stratum_subscribe(user);
    if (!err) {
      stratum_set_difficulty(user, DEFAULT_WORK_DIFFICULTY);
    }

    //reset_task_work_time();

    return (err);
  } 

  if (0 == strcmp(method, "mining.authorize") ||
      0 == strcmp(method, "stratum.authorize")) {
    shjson_t *param;
    char username[1024];
    char password[1024];

    memset(username, 0, sizeof(username));
    strncpy(username, shjson_array_astr(json, "params", 0), sizeof(username)-1);

    memset(password, 0, sizeof(password));
    strncpy(password, shjson_array_astr(json, "params", 1), sizeof(password)-1);

    t_user = NULL;
    if (*username) {
      t_user = stratum_user(user, username);
#if 0
    } else {
      t_user = stratum_sync_user(user, password);
#endif
    }

    /* Note: Support for "x:<diff>" is not permitted. */


    if (!t_user) {
      reply = shjson_init(NULL);
      set_stratum_error(reply, -2, "unknown user");
      shjson_bool_add(reply, "result", FALSE);
      err = stratum_send_message(user, reply);
      shjson_free(&reply);
      return (err);
    }

    reply = shjson_init(NULL);
    shjson_bool_add(reply, "result", TRUE);
    shjson_null_add(reply, "error"); 
    err = stratum_send_message(user, reply);
    shjson_free(&reply);

    /* ask client for their version */
    stratum_send_client_ver(user);

    /* redundant */
    user->work_diff = DEFAULT_WORK_DIFFICULTY;

    return (err);
  }

  if (0 == strcmp(method, "mining.resume")) {
    char *sess_id;

    sess_id = shjson_array_astr(json, "params", 0);

    reply = shjson_init(NULL);

    /* compare previous session hash */
    if (0 != strcmp(sess_id, stratum_runtime_session()))
      return (stratum_send_error(user, BLKERR_BAD_SESSION));

    shjson_bool_add(reply, "result", TRUE);
    shjson_null_add(reply, "error"); 
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }

  if (0 == strcmp(method, "mining.submit")) {
    err = stratum_validate_submit(user, json);

    reply = shjson_init(NULL);
    if (!err) {
      shjson_bool_add(reply, "result", TRUE);
      shjson_null_add(reply, "error");
    } else {
      shjson_bool_add(reply, "result", FALSE);
/*
 * {"error": [-2, "Incorrect size of extranonce2. Expected 8 chars", null], "id": 2, "result": null}
 * {"error": [-2, "Connection is not subscribed for mining", null], "id": 3, "result": null}
 * {"error": [-2, "Ntime out of range", null], "id": 3, "result": null}
 * {"error": [-2, "Job 'b416' not found", null], "id": 4, "result": null}
 */
      if (err == SHERR_ALREADY) {
        set_stratum_error(reply, -2, "duplicate");
      } else if (err == SHERR_TIME) {
        set_stratum_error(reply, -2, "stale");
      } else if (err == SHERR_PROTO) {
        set_stratum_error(reply, -2, "H-not-zero");
      } else if (err == SHERR_INVAL) {
        set_stratum_error(reply, -2, "unknown task id");
      } else {
        set_stratum_error(reply, -2, "invalid");
      }
    }
    stratum_send_message(user, reply);
    shjson_free(&reply);

    if (err == SHERR_PROTO) {
      stratum_send_difficulty(user);
    }

    return (0);
  }

  if (0 == strcmp(method, "mining.shares")) {
    shjson_t *data;
    shjson_t *udata;

    reply = shjson_init(NULL);
    data = shjson_array_add(reply, "result");
    for (t_user = client_list; t_user; t_user = t_user->next) {
/*
      if (t_user->block_tot == 0 &&
          t_user->block_avg <= 0.00000000)
        continue;
*/

      memset(uname, 0, sizeof(uname));
      strncpy(uname, t_user->worker, sizeof(uname) - 1);
      strtok(uname, ".");
      if (!*uname)
        continue;

      block_avg = 0;
      for (i = 0; i < MAX_ROUNDS_PER_HOUR; i++)
        block_avg += t_user->block_avg[i]; 
      if (block_avg != 0)
        block_avg /= 3600; /* average reported is per second. */

      udata = shjson_array_add(data, NULL);
      shjson_str_add(udata, NULL, t_user->worker);
      shjson_num_add(udata, NULL, t_user->round_stamp);
      shjson_num_add(udata, NULL, t_user->block_cnt);
      shjson_num_add(udata, NULL, t_user->block_tot);
      shjson_num_add(udata, NULL, block_avg);
      shjson_num_add(udata, NULL, t_user->work_diff); /* miner share difficulty */
      shjson_num_add(udata, NULL, stratum_user_speed(t_user)); /* khs */
      shjson_str_add(udata, NULL, t_user->block_hash);
      shjson_str_add(udata, NULL, t_user->cli_ver);
//      shjson_num_add(udata, NULL, t_user->reward_val);
      shjson_num_add(udata, NULL, t_user->reward_time);
      shjson_num_add(udata, NULL, t_user->reward_height);

      shjson_str_add(udata, NULL, shkey_print(&t_user->netid));

      udata = shjson_array_add(data, NULL);
      for (i = 1; i < MAX_COIN_IFACE; i++) {
        shjson_num_add(udata, NULL, stratum_addr_crc(i, t_user));
      }

      udata = shjson_array_add(data, NULL);
      for (i = 1; i < MAX_COIN_IFACE; i++) {
        shjson_num_add(udata, NULL, stratum_ext_addr_crc(i, t_user));
      }
    }
    shjson_null_add(reply, "error");
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }
  if (0 == strcmp(method, "mining.info")) {
    reply = shjson_init(getmininginfo(ifaceIndex));
    if (reply) {
      err = stratum_send_message(user, reply);
      shjson_free(&reply);
      return (err);
    }
  }
  if (0 == strcmp(method, "mining.get_transactions")) {
    char *work_id_str;
    char *json_str;
    unsigned int work_id;

    work_id_str = (char *)shjson_array_astr(json, "params", 0);
    if (!work_id_str) {
      set_stratum_error(reply, -2, "invalid task id");
      shjson_null_add(reply, "result");
    } else {
      work_id = (unsigned int)strtoll(work_id_str, NULL, 16);

      json_str = getminingtransactioninfo((user->ifaceIndex?user->ifaceIndex:DefaultWorkIndex), work_id);

      reply = shjson_init(json_str);
      if (!json_str) {
        set_stratum_error(reply, -2, "invalid task id");
        shjson_null_add(reply, "result");
      }
    }
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }

  if (0 == strcmp(method, "block.info")) {
    const char *json_data = "{\"result\":null,\"error\":null}";
    shtime_t ts2;
    char *hash;
    int mode;

    mode = shjson_array_num(json, "params", 0);
    hash = shjson_array_astr(json, "params", 1);

    switch (mode) {
      case 1: /* block by hash */
        if (hash) {
          timing_init("getblockinfo", &ts2);
          json_data = getblockinfo(ifaceIndex, hash);
          timing_term(ifaceIndex, "getblockinfo", &ts2);
        }
        break;
      case 2: /* tx */
        if (hash) {
          timing_init("gettransactioninfo", &ts2);
          json_data = gettransactioninfo(ifaceIndex, hash);
          timing_term(ifaceIndex, "gettransactioninfo", &ts2);
        }
        break;
      case 3: /* block by height [or last] */
        timing_init("getlastblockinfo", &ts2);
        json_data = getlastblockinfo(ifaceIndex, shjson_array_num(json, "params", 1));
        timing_term(ifaceIndex, "getlastblockinfo", &ts2);
        break;
    }

    if (!json_data) {
      reply = shjson_init(NULL);
      set_stratum_error(reply, -5, "invalid");
      shjson_null_add(reply, "result");
    } else {
      reply = shjson_init(json_data);
    }
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }

  if (0 == strcmp(method, "account.create")) {
    return (stratum_request_account_create(ifaceIndex, user,
          shjson_array_astr(json, "params", 0)));
  }
#if 0
  if (0 == strcmp(method, "account.transactions")) {
    return (stratum_request_account_transactions(ifaceIndex, user, idx, 
          shjson_array_astr(json, "params", 0),
          shjson_array_astr(json, "params", 1),
          shjson_array_num(json, "params", 2)));
  }
#endif
  if (0 == strcmp(method, "account.address")) {
    return (stratum_request_account_address(ifaceIndex, user,
          shjson_array_astr(json, "params", 0)));
  }
  if (0 == strcmp(method, "account.secret")) {
    return (stratum_request_account_secret(ifaceIndex, user,
          shjson_array_astr(json, "params", 0),
          shjson_array_astr(json, "params", 1)));
  }
  if (0 == strcmp(method, "account.import")) {
    return (stratum_request_account_import(ifaceIndex, user,
          shjson_array_astr(json, "params", 0),
          shjson_array_astr(json, "params", 1)));
  }
  if (0 == strcmp(method, "account.transfer")) {
    return (stratum_request_account_transfer(ifaceIndex, user,
          shjson_array_astr(json, "params", 0),
          shjson_array_astr(json, "params", 1),
          shjson_array_astr(json, "params", 2),
          shjson_array_num(json, "params", 3)));
  }
  if (0 == strcmp(method, "account.info")) {
    return (stratum_request_account_info(ifaceIndex, user,
          shjson_array_astr(json, "params", 0),
          shjson_array_astr(json, "params", 1)));
  }
  if (0 == strcmp(method, "wallet.private")) {
    return (stratum_request_wallet_private_info(ifaceIndex, user,
          shjson_array_astr(json, "params", 0),
          shjson_array_astr(json, "params", 1)));
  }

  {
    const char *ret_json;
    char account[256];

    memset(account, 0, sizeof(account));
    strncpy(account, user->worker, sizeof(account)-1);
    strtok(account, ".");
    ret_json = ExecuteStratumRPC(ifaceIndex, (const char *)account, json); 
    if (!ret_json) {
fprintf(stderr, "DEBUG: stratum_request_message: error executing rpc call for '%s'\n", user->worker);
      reply = shjson_init(NULL);
      set_stratum_error(reply, -5, "invalid");
      shjson_null_add(reply, "result");
      stratum_send_message(user, reply);
      shjson_free(&reply);
      return (SHERR_INVAL);
    }

    reply = shjson_init(ret_json);
    if (!reply) {
fprintf(stderr, "DEBUG: stratum_request_message: error parsing JSON: %s\n", ret_json);
      reply = shjson_init(NULL);
      set_stratum_error(reply, -5, "invalid");
      shjson_null_add(reply, "result");
      stratum_send_message(user, reply);
      shjson_free(&reply);
      return (SHERR_INVAL);
    }

    /* send RPC response */
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (0);
  }

  timing_term(ifaceIndex, method, &ts);

  /* unknown request in proper JSON format. */
  reply = shjson_init(NULL);
  set_stratum_error(reply, -5, "invalid");
  shjson_null_add(reply, "result");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);
  return (err);
}



