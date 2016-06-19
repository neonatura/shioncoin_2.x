
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

#undef GNULIB_NAMESPACE
#include "shcoind.h"

#include "init.h"
#include "ui_interface.h"
#include "base58.h"
#include "rpc_proto.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"

#include <boost/asio.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/assign/list_of.hpp>
#include <list>

#include "certificate.h"

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace json_spirit;
using namespace boost::assign;


static vector<unsigned char> vchFromValue(const Value& value) {
  string strName = value.get_str();
  unsigned char *strbeg = (unsigned char*) strName.c_str();
  return vector<unsigned char>(strbeg, strbeg + strName.size());
}



Value rpc_alias_addr(CIface *iface, const Array& params, bool fHelp) 
{

  if (fHelp || params.size() != 2)
    throw runtime_error(
        "alias.addr <name> <coin-addr>\n"
        "Generate an alias for a given coin address.\n");

  int ifaceIndex = GetCoinIndex(iface);
  string vchTitleStr = params[0].get_str();
  string vchDataStr = params[1].get_str();
  vector<unsigned char> vchTitle = vchFromValue(params[0]);
  vector<unsigned char> vchData = vchFromValue(params[1]);
  int err;

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.\n");

  if(vchTitle.size() < 1)
    throw runtime_error("A label must be specified.");

  if(vchTitle.size() >= MAX_SHARE_NAME_LENGTH)
    throw runtime_error("The label exceeds 135 characters.");

  if (vchData.size() < 1)
    throw runtime_error("An invalid coin address was specified.");

  if (vchData.size() >= MAX_SHARE_HASH_LENGTH)
    throw runtime_error("The coin address exceeds 135 characters.");

  CWalletTx wtx;
  uint160 hash(vchDataStr.c_str());
  err = init_alias_addr_tx(iface, vchTitleStr.c_str(), hash, wtx); 
  if (err) {
    if (err == SHERR_INVAL)
      throw JSONRPCError(-5, "Invalid coin address specified.");
    if (err == SHERR_NOENT)
      throw JSONRPCError(-5, "Coin address not located in wallet.");
    if (err == SHERR_AGAIN)
      throw JSONRPCError(-5, "Not enough coins in account to create alias.");
    throw JSONRPCError(-5, "Unable to generate transaction.");
  }

  return (wtx.GetHash().GetHex());
}




