
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
#include "main.h"
#include "net.h"
#include "rpc_proto.h"
#include "db.h"
#include "addrman.h"
#include "shcoind_rpc.h"
#include <share.h>
#include "proto/coin_proto.h"

#ifndef WIN32
#include <signal.h>
#endif


using namespace std;
using namespace boost;

shtime_t server_start_t;

extern void IRCDiscover(void);
extern void PrintPeers(void);
//extern void ListPeers(void);

void shcoind_tool_version(void)
{
  fprintf(stdout,
      "shcoin version %s\n"
      "\n"
      "Copyright 2013 Neo Natura\n" 
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n"
      "This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n",
      get_libshare_version());
}

void shcoind_tool_usage(void)
{
  fprintf(stdout,
      "Usage: shcoin [COMMAND] [PARAMS]\n"
      "Perform RPC operations on the share-coin daemon.\n"
      "\n"
      "Commands:\n"
      "\tUse the \"help\" command in order to list all available RPC operations.\n"
      "\n"
      "Visit 'http://docs.sharelib.net/' for libshare API documentation."
      "Report bugs to <support@neo-natura.com>.\n"
      );
}


int main(int argc, char *argv[])
{
  char username[256];
  char password[256];
  int ret;
  int i;

  server_start_t = shtime();

  /* load rpc credentials */
  get_rpc_cred(username, password);
  string strUser(username);
  string strPass(username);
  mapArgs["-rpcuser"] = strUser;
  mapArgs["-rpcpassword"] = strPass; 

  for (i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "-h") ||
        0 == strcmp(argv[i], "--help")) {
      shcoind_tool_usage();
      return (0);
    }
    if (0 == strcmp(argv[i], "-v") ||
        0 == strcmp(argv[i], "--version")) {
      shcoind_tool_version();
      return (0);
    }
  }

  if (argc >= 2 && 0 == strcasecmp(argv[1], "discover")) {
    IRCDiscover();
    return (0);
  }
#if 0
  if (argc >= 2 && 0 == strcasecmp(argv[1], "importpeers")) {
    /* load 'peers.dat' into sharefs peer db */
    ImportPeers();
    return (0);
  }
#endif
  if (argc >= 2 && 0 == strcasecmp(argv[1], "printpeers")) {
    PrintPeers();
    return (0);
  }
#if 0
  if (argc >= 2 && 0 == strcasecmp(argv[1], "listpeers")) {
    ListPeers();
    return (0);
  }
#endif

  /* perform rpc operation */
  ret = CommandLineRPC(argc, argv);

  return (ret);
}


#if 0
CAddrMan addrman;
void shcoind_tool_LoadPeers(void)
{
  int64 nStart;

  nStart = GetTimeMillis();
  {
    CAddrDB adb;
    if (!adb.Read(addrman))
      printf("Invalid or missing peers.dat; recreating\n");
  }
  printf("Loaded %i addresses from peers.dat  %"PRI64d"ms\n",
      addrman.size(), GetTimeMillis() - nStart);

/*
  RandAddSeedPerfmon();
  pwalletMain->ReacceptWalletTransactions();
*/
}
#endif

#if 0
void ImportPeers(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  char addr_str[256];
  shpeer_t *peer;
  shpeer_t *serv_peer;

  if (!iface)
    return;

  serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

  shcoind_tool_LoadPeers();

  vector<CAddress> vAddr = addrman.GetAddr();

  fprintf(stdout, "Import Peers:\n");
  BOOST_FOREACH(const CAddress &addr, vAddr) {
    sprintf(addr_str, "%s %d", addr.ToStringIP().c_str(), addr.GetPort());
    peer = shpeer_init(iface->name, addr_str);
    shnet_track_add(peer);
    shpeer_free(&peer);
    fprintf(stdout, "\t%s\n", addr_str);
  }

  shpeer_free(&serv_peer);

}
#endif
void PrintPeers(void)
{
  shdb_t *db;
  shjson_t *json;
  shpeer_t *serv_peer;
  char *text;

  serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

  db = shdb_open("net");
  json = shdb_json(db, "track", 0, 0);
  text = shjson_print(json);
  shjson_free(&json);
  shdb_close(db);

  fwrite(text, sizeof(char), strlen(text), stdout);
  free(text);

  shpeer_free(&serv_peer);

}

#if 0
void ListPeers(void)
{
  shdb_t *db;
  shpeer_t **peer_list;
  shpeer_t *serv_peer;
  int i;

  serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

  db = shdb_open("net");
  peer_list = shnet_track_list(serv_peer, 16);
  shdb_close(db);

  for (i = 0; peer_list[i]; i++) {
    fprintf(stdout, "%s\n", shpeer_print(peer_list[i]));
    free(peer_list[i]);
  }
  free(peer_list);


  shpeer_free(&serv_peer);

}
#endif


