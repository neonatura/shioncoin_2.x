
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

static int opt_no_fork;

static int _usde_thread_running;



void shcoind_term(void)
{
  /* terminate stratum server */
  stratum_term();

  /* terminate usde server */
  usde_server_term();

  /* close sharefs partition */
  block_close();

  shpeer_free(&server_peer);
  shbuf_free(&server_msg_buff);

  if (_usde_thread_running) {
    /* terminate usde server */
    server_shutdown();
  }
}
void daemon_signal(int sig_num)
{
  signal(sig_num, SIG_DFL);

  set_shutdown_timer();
#if 0
  shcoind_term();
#endif
}

void usage_help(void)
{
  fprintf(stdout,
      "Usage: shcoind [OPTIONS]\n"
      "USDe currency daemon for the Share Library Suite.\n"
      "\n"
      "Network Options:\n"
      "\t--maxconn <#>\tThe maximum number of incoming connections (usde server).\n"
      "\n"
      "Block Options:\n"
      "\t--blockfile <path>\tLoad a blk001.dat file.\n"
      "\n"
      "Diagnostic Options:\n"
      "\t-nf\t\tRun daemon in foreground (no fork).\n"
      "\n"
      "Visit 'http://docs.sharelib.net/' for libshare API documentation."
      "Report bugs to <support@neo-natura.com>.\n"
      );
//      "\t--rescan\t\tRescan blocks for missing wallet transactions.\n"
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
  char buf[1024];
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
    } else if (0 == strcmp(argv[i], "-nf")) {
      opt_no_fork = TRUE;
    } else if (0 == strcmp(argv[i], "--maxconn")) {
      if (i + 1 < argc && isdigit(argv[i+1][0])) {
        i++;
        opt_max_conn = MAX(129, atoi(argv[i]));
      }
#if 0
    } else if (0 == strcmp(argv[i], "--rescan")) {
      SoftSetBoolArg("-rescan", true);
#endif
    }
  }

  if (!opt_no_fork)
    daemon(0, 1);

  signal(SIGSEGV, SIG_DFL);
  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  signal(SIGTERM, daemon_signal);
  signal(SIGQUIT, daemon_signal);
  signal(SIGINT, daemon_signal);

  /* initialize libshare */
  server_peer = shapp_init("usde", "127.0.0.1:54449", 0);
  server_msgq = shmsgget(NULL); /* shared server msg-queue */
  server_msg_buff = shbuf_init();

 
#if 0
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
#endif

  shapp_listen(TX_APP, server_peer);
  shapp_listen(TX_IDENT, server_peer);
  shapp_listen(TX_SESSION, server_peer);
  shapp_listen(TX_BOND, server_peer);

#if 0
  server_fd = fd;
#endif

  /* initialize stratum server */
  err = stratum_init();
  if (err) {
    fprintf(stderr, "critical: init stratum: %s. [sherr %d]", sherrstr(err), err);
    return (-1);
  }
sprintf(buf, "info: initialized stratum server on port %d.", get_stratum_daemon_port());
shcoind_log(buf);

  /* open app's sharefs partition */
  block_init();

  /* open 'wallet.dat' */
  load_wallet();

  /* debug: cmdline option */
  if (*blockfile_path)
    reloadblockfile(blockfile_path);

  /* debug: performed auto. in original required manual 'upgrade'. */
  upgrade_wallet();

  /* debug; replace with shnet_track */
  load_peers();

  err = usde_server_init();
  if (err) {
    fprintf(stderr, "critical: init usde server: %s. [sherr %d]", sherrstr(err), err);
    return (-1);
  }

  /* debug: usde_server_init() */
  _usde_thread_running = TRUE;
  start_node();

  /* debug: invokes unet_cycle() loop */
  daemon_server();

/*
 * main 'tx fee' account is ""
  if (!getaddressbyaccount("bank"))
    getnewaddress("bank"); 
*/


  return (0);
}


