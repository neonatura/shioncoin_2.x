
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
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "chain.h"
#include "certificate.h"
#include "rpc_proto.h"
#include "rpccert_proto.h"
#include "rpcalias_proto.h"


using namespace std;
using namespace boost;

extern Value rpc_wallet_keyphrase(CIface *iface, const Array& params, bool fHelp);
extern Value rpc_wallet_setkeyphrase(CIface *iface, const Array& params, bool fHelp);

const RPCOp WALLET_CSEND = {
  &rpc_wallet_csend, 4, {RPC_ACCOUNT, RPC_STRING, RPC_DOUBLE, RPC_STRING},
  "Syntax: <account> <address> <value> <cert-hash>\n"
  "Summary: Send a certified coin transaction."
};

const RPCOp WALLET_DONATE = {
  &rpc_wallet_donate, 2, {RPC_ACCOUNT, RPC_DOUBLE, RPC_STRING},
  "Syntax: <account> <value> [<cert-hash>]\n"
    "Summary: Donate coins as a block transaction fee identified by the specified certificate.\n"
    "Params: [ <account> The coin account name., <value> The coin value to donate, <cert-hash> The associated certificate's hash. ]\n"
    "\n"
    "Donated coins are given as part of an upcoming block reward. All donations require assocatied a pre-created certificate."
};

const RPCOp WALLET_KEYPHRASE = {
  &rpc_wallet_keyphrase, 1, {RPC_STRING},
  "Syntax: <address>\n"
    "Summary: Reveals the private key corresponding to a public coin address as a phrase of common words..\n"
    "Params: [ <address> The coin address. ]\n"
    "\n"
    "The 'wallet.key' command provides a method to obtain the private key associated\n"
    "with a particular coin address.\n"
    "\n"
    "The coin address must be available in the local wallet in order to print it's pr\n"
    "ivate address.\n"
    "\n"
    "The private coin address can be imported into another system via the 'wallet.setkey' command.\n"
    "\n"
    "The entire wallet can be exported to a file via the 'wallet.export' command."
};

const RPCOp WALLET_SETKEYPHRASE = {
  &rpc_wallet_setkeyphrase, 2, {RPC_STRING, RPC_ACCOUNT},
  "Syntax: \"<phrase>\" <account>\n"
    "Adds a private key to your wallet from a key phrase."
};

const RPCOp WALLET_STAMP = {
  &rpc_wallet_stamp, 2, {RPC_ACCOUNT, RPC_STRING},
  "Syntax: <account> \"<comment>\"\n"
    "Summary: Create a 'ident stamp' transaction which optionally references a particular geodetic location.\n"
    "Params: [ <account> The coin account name., <comment> Use the format \"geo:<lat>,<lon>\" to specify a location. ]\n"
    "\n"
    "A single coin reward can be achieved by creating an ident stamp transaction on a location present in the \"spring matrix\". The reward will be given, at most, once per location. A minimum transaction fee will apply and is sub-sequently returned once the transaction has been processed."
};


/* ext tx: alias */
const RPCOp ALIAS_INFO = {
  &rpc_alias_info, 0, {},
  "Get general information on aliases."
};
const RPCOp ALIAS_FEE = {
  &rpc_alias_fee, 0, {},
  "Get current service fee to perform an alias operation."
};
const RPCOp ALIAS_PUBADDR = {
  &rpc_alias_pubaddr, 1, {RPC_STRING, RPC_STRING},
  "Syntax: <name> [<coin-address>]\n"
  "Summary: Generate, transfer, or obtain a published coin-address alias.\n"
  "Params: [ <name> The alias's label, <coin-address> The alias's referenced coin address. ]\n"
  "When a coin address is specified the alias label will be published onto the block chain in reference. If the alias label already exists, then a transfer will occur providing you are the original owner.\n"
  "The assigned coin address, if one exists, is printed if a specific coin address is not specified."
};
const RPCOp ALIAS_GET = {
  &rpc_alias_get, 1, {RPC_STRING},
  "Syntax: <alias-hash>\n"
  "Summary: Obtain specific information about an alias.\n"
  "Params: [ <alias-hash> The alias hash being referenced. ]\n"
  "\n"
  "Print indepth information about a particular alias based on it's hash."
};
const RPCOp ALIAS_GETADDR = {
  &rpc_alias_getaddr, 1, {RPC_STRING},
  "Syntax: <coin-address>\n"
  "Summary: Obtain specific information about an alias.\n"
  "Params: [ <name> The alias label being referenced. ]\n"
  "\n"
  "Print indepth information about a particular alias based on it's label."
};
const RPCOp ALIAS_LISTADDR = {
  &rpc_alias_listaddr, 0, {RPC_STRING},
  "Syntax: [<keyword>]\n"
  "List all published coin address aliases with optional keyword."
};



/* ext tx; certificate */
const RPCOp CERT_EXPORT = {
  &rpc_cert_export, 1, {RPC_STRING, RPC_STRING},
  "Syntax: <cert-hash> [<path>]\n"
  "Summary: Export the credentials neccessary to own a certificate.\n"
  "Params: [ <cert-hash> The certificate's reference hash. ]\n"
  "\n"
  "Ownership and management of a certificate depends on having specific coin address key(s) in the coin wallet. Exporting a certificate provides JSON formatted content which can be used with \"wallet.import\" command to attain ownership of a certificate."
};
const RPCOp CERT_INFO = {
  &rpc_cert_info, 0, {},
  "Print general certificate related information."
};
const RPCOp CERT_GET = {
  &rpc_cert_get, 1, {RPC_STRING},
  "Syntax: <cert-hash>\n"
  "Print information about a certificate."
};
const RPCOp CERT_LIST = {
  &rpc_cert_get, 0, {RPC_STRING},
  "Syntax: [<keyword>]\n"
  "List all certificates with an optional keyword."
};
const RPCOp CERT_NEW = {
  &rpc_cert_new, 2, {RPC_ACCOUNT, RPC_STRING, RPC_STRING, RPC_INT64},
  "Syntax: <account> <name> [<hex-seed>] [<fee>]\n"
  "Summary: Creates a new certificate suitable for authorizing another certificate or license.\n"
  "Params: [ <account> The coin account name., <name> The title or the certificate, <hex-seed> A hexadecimal string to create the private key from, <fee> the coin value to license or have issued. ]\n"
  "\n"
  "A certificate can either be designated for issueing other certificates or granting licenses, but not both. Either form of the certificate may be used in order to donate or send a certified coin transfer."
};





void shc_RegisterRPCOp()
{
  int ifaceIndex = SHC_COIN_IFACE;

  RegisterRPCOpDefaults(ifaceIndex);

  RegisterRPCOp(ifaceIndex, "alias.info", ALIAS_INFO);
  RegisterRPCOp(ifaceIndex, "alias.fee", ALIAS_FEE);
  RegisterRPCOp(ifaceIndex, "alias.pubaddr", ALIAS_PUBADDR);
  RegisterRPCOp(ifaceIndex, "alias.list", ALIAS_FEE);
  RegisterRPCOp(ifaceIndex, "alias.get", ALIAS_GET);
  RegisterRPCOp(ifaceIndex, "alias.getaddr", ALIAS_GETADDR);

  RegisterRPCOp(ifaceIndex, "cert.export", CERT_EXPORT);
  RegisterRPCOp(ifaceIndex, "cert.info", CERT_INFO);
  RegisterRPCOp(ifaceIndex, "cert.get", CERT_GET);
  RegisterRPCOp(ifaceIndex, "cert.list", CERT_LIST);
  RegisterRPCOp(ifaceIndex, "cert.new", CERT_NEW);

  RegisterRPCOp(ifaceIndex, "wallet.csend", WALLET_CSEND);
  RegisterRPCOp(ifaceIndex, "wallet.donate", WALLET_DONATE);
  RegisterRPCOp(ifaceIndex, "wallet.keyphrase", WALLET_KEYPHRASE);
  RegisterRPCOp(ifaceIndex, "wallet.setkeyphrase", WALLET_SETKEYPHRASE);
  RegisterRPCOp(ifaceIndex, "wallet.stamp", WALLET_STAMP);
}

