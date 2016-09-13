
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
#include "coin_proto.h"

shpeer_t *server_peer;
int server_msgq;
shbuf_t *server_msg_buff;

static int opt_no_fork;

static int _rpc_thread_running;



void shcoind_term(void)
{
  int idx;

  /* terminate stratum server */
  stratum_term();

  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
#ifndef USDE_SERVICE
    if (idx == USDE_COIN_IFACE)
      continue;
#endif
    unet_unbind(idx);
  }
#if 0
  /* terminate usde server */
  usde_server_term();
  shc_server_term();
#endif

#if 0
  /* close sharefs partition */
  block_close();
#endif

  shpeer_free(&server_peer);
  shbuf_free(&server_msg_buff);

  if (_rpc_thread_running) {
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

extern bc_t *GetBlockChain(CIface *iface);

int main(int argc, char *argv[])
{
  CIface *iface;
  bc_t *bc;
  char blockfile_path[PATH_MAX];
  char buf[1024];
  int idx;
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
  server_peer = shapp_init("shcoind", "127.0.0.1:9448", 0);
  server_msgq = shmsgget(NULL); /* shared server msg-queue */
  server_msg_buff = shbuf_init();

  shapp_listen(TX_APP, server_peer);
  shapp_listen(TX_IDENT, server_peer);
  shapp_listen(TX_SESSION, server_peer);
  shapp_listen(TX_BOND, server_peer);

  /* initialize coin interface's block-chain */
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    CIface *iface = GetCoinByIndex(idx);
    if (!iface || !iface->enabled)
      continue;

#ifndef USDE_SERVICE
    if (idx == USDE_COIN_IFACE) {
      iface->enabled = FALSE;
      continue;
    }
#endif

    if (iface->op_init) {
      err = iface->op_init(iface, NULL);
      if (err) {
        fprintf(stderr, "critical: unable to initialize %s service (%s).", iface->name, sherrstr(err));
        exit(1);
      }
    }
  }

  /* initialize coin interface's network service */
  for (idx = 1; idx < MAX_COIN_IFACE; idx++) {
    CIface *iface = GetCoinByIndex(idx);
    if (!iface || !iface->enabled)
      continue;

#ifndef USDE_SERVICE
    if (idx == USDE_COIN_IFACE) {
      iface->enabled = FALSE;
      continue;
    }
#endif

    if (iface->op_init) {
      err = iface->op_bind(iface, NULL);
      if (err) {
        fprintf(stderr, "critical: unable to initialize %s service (%s).", iface->name, sherrstr(err));
        exit(1);
      }
    }
  }

#ifdef STRATUM_SERVICE
  /* initialize stratum server */
  err = stratum_init();
  if (err) {
    fprintf(stderr, "critical: init stratum: %s. [sherr %d]", sherrstr(err), err);
    raise(SIGTERM);
  }
#endif

  start_node();

#ifdef RPC_SERVICE
  _rpc_thread_running = TRUE;
  start_rpc_server();
#endif

  /* unet_cycle() */
  daemon_server();


  return (0);
}

shpeer_t *shcoind_peer(void)
{
  return (server_peer);
}
