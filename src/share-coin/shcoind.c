
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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
#include <signal.h>

shpeer_t *server_peer;
int server_msgq;
shbuf_t *server_msg_buff;
int server_fd;

void daemon_signal(int sig_num)
{
  signal(sig_num, SIG_DFL);

fprintf(stderr, "DEBUG: daemon_signal sig_num(%d)\n", sig_num);


  block_close();
  daemon_close_clients();
  if (server_fd != -1) {
    shclose(server_fd);
fprintf(stderr, "DEBUG: closing server fd %d\n", server_fd);
    server_fd = -1;
  }
  shpeer_free(&server_peer);
shbuf_free(&server_msg_buff);

  /* terminate usde server */
  server_shutdown();
}

void usage_help(void)
{
  fprintf(stdout,
      "Usage: shcoind [OPTIONS]\n"
      "USDe currency daemon for the Share Library Suite.\n"
      "\n"
      "Options:\n"
      "\t--loadblock <path>\tLoad a blk001.dat file.\n"
//      "\t--rescan\t\tRescan blocks for missing wallet transactions.\n"
      "\n"
      "Visit 'http://docs.sharelib.net/' for libshare API documentation."
      "Report bugs to <support@neo-natura.com>.\n"
      );
}
void usage_version(void)
{
  fprintf(stdout,
      "shcoind version %s\n"
      "\n"
      "Copyright 2013 Neo Natura\n" 
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n"
      "This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n",
      get_libshare_version());
}

int main(int argc, char *argv[])
{
  char blockfile_path[PATH_MAX];
  int fd;
  int err;
  int i;

  if (argc >= 2 && 0 == strcmp(argv[1], "--help")) {
    usage_help();
    return (0);
  }
  if (argc >= 2 && 0 == strcmp(argv[1], "--version")) {
    usage_version();
    return (0);
  }

  /* always perform 'fresh' tx rescan */

  memset(blockfile_path, 0, sizeof(blockfile_path));
  for (i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "--blockfile")) {
      if (i + 1 < argc)
        strncpy(blockfile_path, argv[i], sizeof(blockfile_path)-1);
#if 0
    } else if (0 == strcmp(argv[i], "--rescan")) {
      SoftSetBoolArg("-rescan", true);
#endif
    }
  }

  daemon(0, 1);

  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, daemon_signal);
  signal(SIGQUIT, daemon_signal);
  signal(SIGINT, daemon_signal);

  /* initialize libshare */
  server_peer = shapp_init("usde", "127.0.0.1:54449", 0);
  server_msgq = shmsgget(NULL); /* shared server msg-queue */
  server_msg_buff = shbuf_init();

 
  fd = shnet_sk();
  if (fd == -1) {
    perror("shnet_sk");
    return (-1);
  }

  err = shnet_bindsk(fd, NULL, STRATUM_DAEMON_PORT);
  if (err) {
    perror("shbindport");
    shnet_close(fd);
    return (err);
  }

  shapp_listen(TX_APP, server_peer);
  shapp_listen(TX_IDENT, server_peer);
  shapp_listen(TX_SESSION, server_peer);
  shapp_listen(TX_BOND, server_peer);

  server_fd = fd;
  block_init();
  load_wallet();

  if (*blockfile_path)
    reloadblockfile(blockfile_path);

  load_peers();

  start_node();

/*
 * main 'tx fee' account is ""
  if (!getaddressbyaccount("bank"))
    getnewaddress("bank"); 
*/

  daemon_server();

  return (0);
}


