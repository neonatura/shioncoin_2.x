

#define __PROTO__PROTOCOL_C__
#include "shcoind.h"




char *stratum_runtime_session(void)
{
  static char buf[32];

  if (!*buf) {
    sprintf(buf, "%-8.8x", time(NULL));
  }

  return (buf);
}



int stratum_request_id(void)
{
  static int idx;
  return (++idx);
}

int stratum_send_difficulty(user_t *user)
{
  shjson_t *reply;
  shjson_t *data;
  int err;

  reply = shjson_init(NULL);
  shjson_null_add(reply, "id");
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

  user->cli_id = stratum_request_id();

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", user->cli_id);
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
int stratum_validate_submit(user_t *user, int req_id, shjson_t *json)
{
  shjson_t *block;
  task_t *task;
  shkey_t *key;
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
const char *submit_hash;
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

  task_id = (unsigned int)strtoll(job_id, NULL, 16);
  task = stratum_task(task_id);
  if (!task)
    return (SHERR_INVAL);

  le_ntime = (uint32_t)strtoll(ntime, NULL, 16);
  //be_ntime = htobe32(le_ntime);
  le_nonce = (uint32_t)strtoll(nonce, NULL, 16); 
  be_nonce =  htobe32(le_nonce);

  /* generate new cb1 */
  memset(buf, 0, sizeof(buf));
  bin2hex(buf, &le_ntime, 4);
  memset(cb1, 0, sizeof(cb1) - 1);
  strncpy(cb1, task->cb1, sizeof(cb1) - 1);
  strncpy(cb1 + strlen(cb1) - 10, buf, 8);

  /* set worker name */
  stratum_user(user, worker);

  strncpy(task->work.xnonce2, extranonce2, sizeof(task->work.xnonce2) - 1);
  task->work.nonce = le_nonce;

  /* generate block hash */
  shscrypt_work(&user->peer, &task->work, task->merkle, task->prev_hash, cb1, task->cb2, task->nbits, ntime);
  hex2bin(&task->work.data[76], nonce, 4);

  ret_err = 0;
  memset(share_hash, 0, sizeof(share_hash));
  task->work.nonce = le_nonce;
  memset(task->work.hash, 0, sizeof(task->work.hash));
//  be_nonce =  htobe32(task->work.nonce);
  err = !scanhash_scrypt(task->work.midstate, task->work.data, task->work.hash, task->work.target, be_nonce+1, &last_nonce, be_nonce-2, &last_diff);
  if (!err) { 
    key = shkey_bin(task->work.data, 80);
    dup = shmeta_get_str(task->share_list, key);
    bin2hex(share_hash, task->work.hash, 32);
    if (dup && 0 == strcmp(dup, share_hash)) {
      ret_err = SHERR_ALREADY;
    }
    shmeta_set_str(task->share_list, key, share_hash);
    shkey_free(&key);
  } else {
    fprintf(stderr, "DEBUG: err %d = scanhash_scrypt(%d)\n", err, be_nonce);
    //  return (BLKERR_LOW_DIFFICULTY);
  } 

  if (!ret_err) {
    task->work.pool_diff = last_diff;
    stratum_user_block(user, task);
  }

  /* if (user->peer.diff > task->target) */

  /* submit everything to server regardless of return code. */
  sprintf(xn_hex, "%s%s", user->peer.nonce1, task->work.xnonce2); 
  submit_hash = submitblock(task->task_id, le_ntime, task->work.nonce, xn_hex);
  if (submit_hash) {
    ret_err = 0;
fprintf(stderr, "DEBUG: user->block_hash = \"%s\"\n", submit_hash);
    /* user's block was accepted by network. */
    user->block_acc++;
    strncpy(user->block_hash, submit_hash, sizeof(user->block_hash) - 1);
  }

  return (ret_err);
}

int stratum_subscribe(user_t *user, int req_id)
{
  int err;

  err = stratum_send_subscribe(user, req_id);
  if (!err) 
    user->flags |= USER_SUBSCRIBE;

  return (err);
}

int stratum_set_difficulty(user_t *user, int diff)
{
  int err;

  user->work_diff = diff;
  err = stratum_send_difficulty(user);
//fprintf(stderr, "DEBUG: %d = stratum_send_difficulty(diff %d)", err, user->work_diff);
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

/**
 * @todo: leave stale worker users (without open fd) until next round reset. current behavior does not payout if connection is severed.
 */ 
int stratum_request_message(user_t *user, shjson_t *json)
{
  shjson_t *reply;
  user_t *t_user;
  char uname[256];
  char *method;
  double block_avg;
  long idx;
  int err;
  int i;

  idx = (int)shjson_num(json, "id", -1);
  if (idx != -1 && idx == user->cli_id && shjson_strlen(json, "result")) {
    /* response from 'client.get_version' method. */ 
    strncpy(user->cli_ver, shjson_astr(json, "result", ""), sizeof(user->cli_ver));
//fprintf(stderr, "DEBUG: set client version '%s'\n", user->cli_ver);
    return (0);
  }

  method = shjson_astr(json, "method", NULL);
  if (!method) {
    /* no operation method specified. */
//fprintf(stderr, "DEBUG: no 'method' specified.\n");
    return (SHERR_INVAL);
  }

//fprintf(stderr, "DEBUG: JSON REQUEST '%s' [idx %d].\n", method, idx);
  if (0 == strcmp(method, "mining.ping")) {
    reply = shjson_init(NULL);
    shjson_num_add(reply, "id", idx);
    shjson_null_add(reply, "error");
    shjson_null_add(reply, "result");
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }

  if (0 == strcmp(method, "mining.subscribe")) {
    err = stratum_subscribe(user, idx);
    if (!err)
      stratum_set_difficulty(user, 32);

    reset_task_work_time();

    return (err);
  } 

  if (0 == strcmp(method, "mining.authorize")) {
    shjson_t *param;
    char *username;
    char *password;
    int diff = 0;

    /* todo: set diff off "username/<diff>" syntax. */
    username = shjson_array_astr(json, "params", 0);
    password = shjson_array_astr(json, "params", 1);
    user = stratum_user(user, username);
    if (!user) {
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

    diff = MAX(32, diff);
    stratum_set_difficulty(user, diff);
    //stratum_set_difficulty(user, MAX(32, atoi(password)));
    stratum_send_client_ver(user);
    return (err);
  }

  if (0 == strcmp(method, "mining.resume")) {
    char *sess_id;

    sess_id = shjson_array_astr(json, "params", 0);

    reply = shjson_init(NULL);
    shjson_num_add(reply, "id", idx);

    /* compare previous session hash */
    if (0 != strcmp(sess_id, stratum_runtime_session()))
      return (stratum_send_error(user, idx, BLKERR_BAD_SESSION));

    shjson_bool_add(reply, "result", TRUE);
    shjson_null_add(reply, "error"); 
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }

  if (0 == strcmp(method, "mining.submit")) {
    err = stratum_validate_submit(user, idx, json);

    reply = shjson_init(NULL);
    shjson_num_add(reply, "id", idx);
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
        block_avg /= 3600; /* average reported is per minute. */

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
    }
    shjson_null_add(reply, "error");
    shjson_num_add(reply, "id", idx);
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }
  if (0 == strcmp(method, "mining.info")) {
    reply = shjson_init(getmininginfo());
//    shjson_null_add(reply, "error");
    shjson_num_add(reply, "id", idx);
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }
  if (0 == strcmp(method, "mining.get_transactions")) {
    char *work_id_str;
    char *json_str;
    unsigned int work_id;

    work_id_str = (char *)shjson_array_astr(json, "params", 0);
    work_id = (unsigned int)strtoll(work_id_str, NULL, 16);

    json_str = getminingtransactioninfo(work_id);

    reply = shjson_init(json_str);
    if (!json_str) {
      set_stratum_error(reply, -2, "invalid task id");
      shjson_null_add(reply, "result");
    }
    shjson_num_add(reply, "id", idx);
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }

  if (0 == strcmp(method, "block.info")) {
    const char *json_data = "{\"result\":null,\"error\":null}";
    char *hash;
    int mode;

    mode = shjson_array_num(json, "params", 0);
    hash = shjson_array_astr(json, "params", 1);

    switch (mode) {
      case 1: /* block by hash */
        if (hash)
          json_data = getblockinfo(hash);
        break;
      case 2: /* tx */
        if (hash)
          json_data = gettransactioninfo(hash);
        break;
      case 3: /* block by height [or last] */
        json_data = getlastblockinfo(shjson_array_num(json, "params", 1));
        break;
    }

    if (!json_data) {
      reply = shjson_init(NULL);
      set_stratum_error(reply, -5, "invalid");
      shjson_null_add(reply, "result");
    } else {
      reply = shjson_init(json_data);
    }
    shjson_num_add(reply, "id", idx);
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }

  if (0 == strcmp(method, "account.address")) {
    const char *json_data = "{\"result\":null,\"error\":null}";
    char *hash;
    int mode;

    mode = shjson_array_num(json, "params", 0);
    hash = shjson_array_astr(json, "params", 1);

    switch (mode) {
      case 1: /* addr */
        if (hash)
          json_data = getaddressinfo(hash);
        break;
      case 3: /* addr-tx */
        if (hash)
          json_data = getaddresstransactioninfo(hash);
        break;
    }

    if (!json_data) {
      reply = shjson_init(NULL);
      set_stratum_error(reply, -5, "invalid");
      shjson_null_add(reply, "result");
    } else {
      reply = shjson_init(json_data);
    }
    shjson_num_add(reply, "id", idx);
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }
  if (0 == strcmp(method, "account.transfer")) {
    const char *json_data = "{\"result\":null,\"error\":null}";
    char *account;
    char *pkey;
    char *dest;
    double amount;

    account = shjson_array_astr(json, "params", 0);
    pkey = shjson_array_astr(json, "params", 1);
    dest = shjson_array_astr(json, "params", 2);
    amount = shjson_array_num(json, "params", 3);

    if (account && pkey && dest) {
      /* checks sha of account's private keys to determine if valid; sends amount to dest */
      /* returns transaction id */
      json_data = stratum_create_transaction(account, pkey, dest, amount);
    }

    if (!json_data) {
      reply = shjson_init(NULL);
      set_stratum_error(reply, -5, "invalid");
      shjson_null_add(reply, "result");
    } else {
      reply = shjson_init(json_data);
    }
    shjson_num_add(reply, "id", idx);
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }
  if (0 == strcmp(method, "account.create")) {
    const char *json_data = "{\"result\":null,\"error\":null}";
    char *acc_name;

    acc_name = shjson_array_astr(json, "params", 0);

    if (acc_name) {
      /* creates a usde address for an account name */
      /* providing account does not exist; returns usde address and sha of private key */
      json_data = stratum_create_account(acc_name);
    }

    if (!json_data) {
      reply = shjson_init(NULL);
      set_stratum_error(reply, -5, "invalid");
      shjson_null_add(reply, "result");
    } else {
      reply = shjson_init(json_data);
    }
    shjson_num_add(reply, "id", idx);
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }
  if (0 == strcmp(method, "account.info")) {
    const char *json_data = "{\"result\":null,\"error\":null}";
    char *account;
    char *pkey;

    account = shjson_array_astr(json, "params", 0);
    pkey = shjson_array_astr(json, "params", 1);

    if (account && pkey)
      json_data = stratum_getaccountinfo(account, pkey);

    if (!json_data) {
      reply = shjson_init(NULL);
      set_stratum_error(reply, -5, "invalid");
      shjson_null_add(reply, "result");
    } else {
      reply = shjson_init(json_data);
    }
    shjson_num_add(reply, "id", idx);
    err = stratum_send_message(user, reply);
    shjson_free(&reply);
    return (err);
  }

  reply = shjson_init(NULL);
  shjson_num_add(reply, "id", idx);
  set_stratum_error(reply, -5, "invalid");
  shjson_null_add(reply, "result");
  err = stratum_send_message(user, reply);
  shjson_free(&reply);
  return (err);
}



