
#include "shcoind.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CRED_SECRET_LEN 28

void get_rpc_cred(char *username, char *password)
{
  char *in_name = (char *)get_rpc_username();
  char *in_pass = (char *)get_rpc_password(NULL); 
  int err;

  if (!in_pass) {
    /* generate new key for local use */
    shkey_t *key = shkey_uniq();
    err = set_rpc_dat_password(NULL, key);
    shkey_free(&key);
    if (err) {
      fprintf(stderr, "DEBUG: get_rpc_cred: !set_rpc_dat_password (%d)\n", err);
    }

    in_pass = shkey_print(key);
  }

  strcpy(username, in_name);
  strcpy(password, in_pass);

}

const char *get_rpc_username(void)
{
  static char uname[MAX_SHARE_NAME_LENGTH];
  shpeer_t *peer;

  peer = shpeer_init("shcoind", NULL);

  /* the EC224-PUBKEY of the priveleged peer key */
  strcpy(uname, shkey_print(shapp_kpriv(peer)));

  shpeer_free(&peer);

  return (uname);
}

const char *get_rpc_password(char *host)
{
  static char ret_str[256];
  shkey_t *key;

  key = get_rpc_dat_password(host);
  if (!key)
    return (NULL);

  memset(ret_str, 0, sizeof(ret_str));
  strncpy(ret_str, shkey_print(key), sizeof(ret_str)-1);

  return (ret_str);
}

shkey_t *get_rpc_dat_password(char *host)
{
  shkey_t *key;
  shbuf_t *buff;
  char *tok_ctx;
  char path[PATH_MAX+1];
  char *raw;
  char *key_str;
  char *tok;
  int err;

  if (!host)
    host = "127.0.0.1";

  sprintf(path, "%s/blockchain/rpc.dat", get_libshare_path());
  chmod(path, 00400);

  buff = shbuf_init();
  err = shfs_mem_read(path, buff);
  if (!err) {
    raw = shbuf_data(buff);
    tok = strtok_r(raw, "\r\n", &tok_ctx);
    while (tok) {
      key_str = strchr(tok, ' ');
      if (key_str) {
        *key_str = '\000';
        key_str++;

        if (0 == strcmp(host, "127.0.0.1") &&
            unet_local_verify(tok)) {
          key = shkey_gen(key_str);         
          shbuf_free(&buff);
          return (key);
        }

        if (0 == strcasecmp(host, tok)) {
          key = shkey_gen(key_str);         
          shbuf_free(&buff);
          return (key);
        }
      }

      tok = strtok_r(NULL, "\r\n", &tok_ctx);
    }
  }

  shbuf_free(&buff);
  return (NULL);
}

int set_rpc_dat_password(char *host, shkey_t *in_key)
{
  shkey_t *key;
  shbuf_t *buff;
  shbuf_t *w_buff;
  char path[PATH_MAX+1];
  char *raw;
  char *key_str;
  char *tok;
  int err;

  if (!host)
    host = "127.0.0.1";

  sprintf(path, "%s/blockchain/rpc.dat", get_libshare_path());
  chmod(path, 00400);

  w_buff = shbuf_init();
  shbuf_catstr(w_buff, "## Automatically Generated (do not modify) ##\n\n");

  buff = shbuf_init();
  err = shfs_mem_read(path, buff);
  if (!err) {
    raw = shbuf_data(buff);
    tok = strtok(raw, "\r\n");
    while (tok) {
      if (!*tok || *tok == '#')
        continue;

      key_str = strchr(tok, ' ');
      if (!key_str)
        goto next;

      *key_str = '\000';
      key_str++;

      if (0 == strcmp(host, "127.0.0.1") &&
          unet_local_verify(tok))
        goto next;

      if (0 == strcasecmp(host, tok))
        goto next;

      shbuf_catstr(w_buff, tok);
      shbuf_catstr(w_buff, " ");
      shbuf_catstr(w_buff, key_str);
      shbuf_catstr(w_buff, "\n");

  next:
      tok = strtok(NULL, "\r\n");
    }
    shbuf_free(&buff);
  }

  /* add updated record */
  shbuf_catstr(w_buff, host);
  shbuf_catstr(w_buff, " ");
  shbuf_catstr(w_buff, shkey_print(in_key));
  shbuf_catstr(w_buff, "\n");

  err = shfs_mem_write(path, w_buff);
  if (err)
    return (err);
  
  shbuf_free(&w_buff);

  return (0);
}

#define FIVE_MINUTES 300
uint32_t get_rpc_pin(char *host)
{
  unsigned char *raw;
  shkey_t *key;
  uint32_t ret_pin;

  key = get_rpc_dat_password(host);
  if (!key)
    return (0);
fprintf(stderr, "DEBUG: get_rpc_pin: '%s'\n", shkey_print(key));

  raw = ((unsigned char *)key) + sizeof(uint32_t);
  ret_pin = shsha_2fa_bin(SHALG_SHA224, raw, CRED_SECRET_LEN, FIVE_MINUTES);
  shkey_free(&key);
  if (ret_pin == 0)
    return (0);

fprintf(stderr, "DEBUG: get_rpc_pin: PIN %u\n", ret_pin);
  return (ret_pin);
}

int verify_rpc_pin(char *host, uint32_t pin)
{
  unsigned char *raw;
  shkey_t *key;
  int err;

  key = get_rpc_dat_password(host);
  if (!key) {
fprintf(stderr, "DEBUG: verify_rpc_pin: ERR_NOENT\n");
    return (SHERR_NOENT); 
}
fprintf(stderr, "DEBUG: verify_rpc_pin: '%s' [pin %u]\n", shkey_print(key), pin);

  raw = ((unsigned char *)key) + sizeof(uint32_t);
  err = shsha_2fa_bin_verify(SHALG_SHA224, 
      raw, CRED_SECRET_LEN, FIVE_MINUTES, pin);
  shkey_free(&key);
fprintf(stderr, "DEBUG: verify_rpc_pin: 2fa_bin_verify err %d\n", err);

  return (err);
}



#ifdef __cplusplus
}
#endif
