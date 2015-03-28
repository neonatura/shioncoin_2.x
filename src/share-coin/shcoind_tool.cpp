

#include "server/main.h"
#include "server/net.h"
#include "server/rpc_proto.h"
#include "shcoind_rpc.h"
#include <share.h>

#ifndef WIN32
#include <signal.h>
#endif


using namespace std;
using namespace boost;


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
          "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n",
          get_libshare_version());
      return (0);
    }
  }

  /* perform rpc operation */
  ret = CommandLineRPC(argc, argv);

  return (ret);
}




