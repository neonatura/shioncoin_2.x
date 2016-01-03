

#include "server/main.h"
#include "server/net.h"
#include "server/rpc_proto.h"
#include "server/db.h"
#include "server/addrman.h"
#include "shcoind_rpc.h"
#include <share.h>

#ifndef WIN32
#include <signal.h>
#endif


using namespace std;
using namespace boost;

extern void IRCDiscover(void);
extern void ImportPeers(void);
extern void PrintPeers(void);
extern void ListPeers(void);


int main(int argc, char *argv[])
{
  char username[256];
  char password[256];
  int ret;

  /* load rpc credentials */
  get_rpc_cred(username, password);
  string strUser(username);
  string strPass(username);
  mapArgs["-rpcuser"] = strUser;
  mapArgs["-rpcpassword"] = strPass; 

  if (argc >= 2) {
    string param = argv[1];
    if (0 == strcmp(param.c_str(), "--help")) {
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
      return (0);
    }
    if (0 == strcmp(param.c_str(), "--version")) {
      fprintf(stdout,
          "shcoin version %s\n"
          "\n"
          "Copyright 2013 Neo Natura\n" 
          "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n"
          "This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n",
          get_libshare_version());
      return (0);
    }
  }

  if (argc >= 2 && 0 == strcasecmp(argv[1], "discover")) {
    IRCDiscover();
    return (0);
  }
  if (argc >= 2 && 0 == strcasecmp(argv[1], "importpeers")) {
    /* load 'peers.dat' into sharefs peer db */
    ImportPeers();
    return (0);
  }
  if (argc >= 2 && 0 == strcasecmp(argv[1], "printpeers")) {
    /* load 'peers.dat' into sharefs peer db */
    PrintPeers();
    return (0);
  }
  if (argc >= 2 && 0 == strcasecmp(argv[1], "listpeers")) {
    /* load 'peers.dat' into sharefs peer db */
    ListPeers();
    return (0);
  }

  /* perform rpc operation */
  ret = CommandLineRPC(argc, argv);

  return (ret);
}


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

void ImportPeers(void)
{
  char addr_str[256];
  shpeer_t *peer;
  shpeer_t *serv_peer;

  serv_peer = shapp_init("usde", NULL, SHAPP_LOCAL);

  shcoind_tool_LoadPeers();

  vector<CAddress> vAddr = addrman.GetAddr();

  fprintf(stdout, "Import Peers:\n");
  BOOST_FOREACH(const CAddress &addr, vAddr) {
    sprintf(addr_str, "%s %d", addr.ToStringIP().c_str(), addr.GetPort());
    peer = shpeer_init("usde", addr_str);
    shnet_track_add(peer);
    shpeer_free(&peer);
    fprintf(stdout, "\t%s\n", addr_str);
  }

  shpeer_free(&serv_peer);

}
void PrintPeers(void)
{
  shdb_t *db;
  shjson_t *json;
  shpeer_t *serv_peer;
  char *text;

  serv_peer = shapp_init("usde", NULL, SHAPP_LOCAL);

  db = shdb_open("net");
  json = shdb_json(db, "track", 0, 0);
  text = shjson_print(json);
  shjson_free(&json);
  shdb_close(db);

  fwrite(text, sizeof(char), strlen(text), stdout);
  free(text);

  shpeer_free(&serv_peer);

}
void ListPeers(void)
{
  shdb_t *db;
  shpeer_t **peer_list;
  shpeer_t *serv_peer;
  int i;

  serv_peer = shapp_init("usde", NULL, SHAPP_LOCAL);

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


