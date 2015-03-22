
#include "shcoind.h"

#ifdef __cplusplus
extern "C" {
#endif

void get_rpc_cred(char *username, char *password)
{
  shpeer_t *peer;
  shfs_t *tree;
  shfs_ino_t *fl;  
  shkey_t *app_key;
  shbuf_t *buff;
  size_t data_len;
  int err;

  peer = shpeer_init("shcoind", NULL);

  tree = shfs_init(peer);
  fl = shfs_file_find(tree, "/config/cred");

  buff = shbuf_init();
  err = shfs_read(fl, buff);

  app_key = shbuf_data(buff);
  data_len = shbuf_size(buff);

  if (err || !app_key) {
    /* generate new password */
    shkey_t *u_key = shkey_uniq();
    shbuf_clear(buff);
    shbuf_cat(buff, u_key, sizeof(shkey_t));
    shfs_write(fl, buff);
    shkey_free(&u_key);

    app_key = shbuf_data(buff);
    data_len = shbuf_size(buff);
  }

  shfs_free(&tree);

  strcpy(username, shkey_print(shpeer_kpub(peer)));
  strcpy(password, shkey_print(app_key));


  if (err || data_len != sizeof(shkey_t)) {
    char path[PATH_MAX+1];
    char buf[1024];

    sprintf(path, "%s/usde/", get_libshare_path());
    mkdir(path, 0777);
    strcat(path, "usde.conf");
    sprintf(buf, "rpcuser=%s\nrpcpassword=%s\n", username, password); 
    shfs_write_mem(path, buf, strlen(buf));
  }

}

#ifdef __cplusplus
}
#endif
