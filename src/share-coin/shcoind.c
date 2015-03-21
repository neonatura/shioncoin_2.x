
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

  block_close();
  daemon_close_clients();
  if (server_fd != -1) {
    shnet_close(server_fd);
    server_fd = -1;
  }
  shpeer_free(&server_peer);
shbuf_free(&server_msg_buff);
}

void usage_help(void)
{
  fprintf(stdout,
      "Usage: shcoind\n"
      "USDe currency daemon for the Share Library Suite.\n"
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
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n",
      get_libshare_version());
}

int main(int argc, char *argv[])
{
  int fd;
  int err;

  if (argc >= 2 && 0 == strcmp(argv[1], "--help")) {
    usage_help();
    return (0);
  }
  if (argc >= 2 && 0 == strcmp(argv[1], "--version")) {
    usage_version();
    return (0);
  }

  daemon(0, 1);

  signal(SIGHUP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, daemon_signal);
  signal(SIGQUIT, daemon_signal);
  signal(SIGINT, daemon_signal);

  /* initialize libshare */
  server_peer = shapp_init("shcoind", "127.0.0.1:54449", 0);
  server_msgq = shmsgget(NULL); /* shared server msg-queue */
  server_msg_buff = shbuf_init();

  shapp_listen(TX_APP, server_peer);
  shapp_listen(TX_IDENT, server_peer);
  shapp_listen(TX_SESSION, server_peer);
  shapp_listen(TX_BOND, server_peer);
 
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

  server_fd = fd;
  block_init();
  load_wallet();
  start_node();
  daemon_server();

  return (0);
}


