
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

#include "wallet.h"
#include "certificate.h"

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace json_spirit;
using namespace boost::assign;




extern json_spirit::Value ValueFromAmount(int64 amount);
extern int64 AmountFromValue(const Value& value);
extern string AccountFromValue(const Value& value);
extern bool IsAccountValid(CIface *iface, std::string strAccount);


static bool fHelp = false;


Value rpc_cert_info(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || 0 != params.size())
    throw runtime_error(
        "cert.info\n"
        "Summary: Print general certificate related information."
        );

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

  int64 nFee = GetCertOpFee(iface, (int)GetBestHeight(ifaceIndex));
  Object result;

  result.push_back(Pair("fee", ValueFromAmount(nFee)));
  result.push_back(Pair("total", (int64_t)GetTotalCertificates(ifaceIndex)));
  //result.push_back(Pair("local", (int64_t)GetTotalLocalCertificates(ifaceIndex)));
  
  return (result);
}

Value rpc_cert_list(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 1)
    throw runtime_error(
        "cert.list [<keyword>]\n"
    );

  string kwd("");
  if (params.size() > 0)
    kwd = params[0].get_str();

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

  cert_list *certs = GetCertTable(ifaceIndex);

  Object result;
  Object active;
  Object pending;
  for (cert_list::const_iterator mi = certs->begin(); mi != certs->end(); ++mi) {
    const uint160 hCert = mi->first;
    const uint256 hTx = mi->second;
    CTransaction tx;

    if (!GetTransaction(iface, hTx, tx, NULL)) {
      CTxMemPool *mempool = GetTxMemPool(iface);
      {
        LOCK(mempool->cs);
        if (!mempool->exists(hTx))
          continue;

        tx = mempool->lookup(hTx);
      }
    }

    if (!IsCertTx(tx)) {
//      error();
      continue;
    }

    CCert& cert = tx.certificate;
    if (kwd.length() != 0) {
      if (cert.GetLabel().find(kwd) == std::string::npos)
        continue;
    }

    active.push_back(Pair(cert.GetLabel().c_str(), hCert.GetHex()));
  }
  result.push_back(Pair("active", active));
  result.push_back(Pair("pending", pending));

  return (result);
}

Value rpc_cert_get(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "cert.get <cert-hash>\n"
    );

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

  uint160 hCert(params[0].get_str());

  cert_list *certs = GetCertTable(ifaceIndex);
  if (certs->count(hCert) == 0)
    throw JSONRPCError(-5, "Invalid certificate hash specified.");


  CTransaction tx;
  if (!GetTxOfCert(iface, hCert, tx)) {
    uint256 hTx = (*certs)[hCert];

    CTxMemPool *mempool = GetTxMemPool(iface);
    {
      LOCK(mempool->cs);
      if (!mempool->exists(hTx))
        throw JSONRPCError(-5, "Invalid certificate hash specified.");

      tx = mempool->lookup(hTx);
    }
  }
 
  CCert& cert = tx.certificate;
  Object result = cert.ToValue();

  result.push_back(Pair("txid", tx.GetHash().GetHex()));

  return (result);
}

Value rpc_cert_new(CIface *iface, const Array& params, bool fStratum) 
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  int err;

  if (fHelp || params.size() > 5 || params.size() < 2)
    throw runtime_error(
        "cert.new <account> <name> [<hex-seed>] [<fee>]\n"
        "Summary: Creates a new certificate suitable for authorizing another certificate or license.\n"
        "Params: [ <account> The coin account name., <name> The title or the certificate, <hex-seed> A hexadecimal string to create the private key from, <fee> the coin value to license or have issued. ]\n"
        "\n" 
        "A certificate can either be designated for issueing other certificates or granting licenses, but not both. Either form of the certificate may be used in order to donate or send a certified coin transfer."
        );

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

  string strAccount = AccountFromValue(params[0]);
  if (!IsAccountValid(iface, strAccount))
    throw JSONRPCError(SHERR_INVAL, "Invalid account name specified.");

  string strTitle = params[1].get_str();
  if (strTitle.length() == 0 || strTitle.length() > 135)
    throw JSONRPCError(-5, "Certificate name must be between 1 and 135 characters.");

  if (wallet->mapCertLabel.count(strTitle))
    throw JSONRPCError(-5, "Certificate name must be unique.");

  cbuff vSeed;
  if (params.size() > 2)
    vSeed = ParseHex(params[2].get_str());

  int64 nFee = 0;
  if (params.size() > 3) {
    nFee = AmountFromValue(params[3]);
    if (nFee < 0)
      throw JSONRPCError(-5, "Invalid coin fee value.");
  }

#if 0
  uint160 hIssuer;
  if (params.size() > 4)
    hIssuer = uint160(params[4].get_str());
#endif

  CWalletTx wtx;
  err = init_cert_tx(iface, strAccount, strTitle, vSeed, nFee, wtx);
  if (err)
    throw JSONRPCError(err, "Failure initializing transaction.");

  return (wtx.ToValue(ifaceIndex));
}

/**
 * Donate tx fee to block miner with optional certificate reference.
 */
Value rpc_wallet_donate(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
  int64 nBalance;
  int err;

  if (fHelp || (params.size() != 2 && params.size() != 3))
    throw runtime_error(
        "wallet.donate <account> <value> [<cert-hash>]\n"
        "Summary: Donate coins as a block transaction fee identified by the specified certificate.\n"
        "Params: [ <account> The coin account name., <value> The coin value to donate, <cert-hash> The associated certificate's hash. ]\n"
        "\n" 
        "Donated coins are given as part of an upcoming block reward. All donations require assocatied a pre-created certificate."
        );

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

  string strAccount = AccountFromValue(params[0]);
  if (!IsAccountValid(iface, strAccount))
    throw JSONRPCError(SHERR_INVAL, "Invalid account name specified.");

  int64 nValue = AmountFromValue(params[1]);
  if (nValue < iface->min_tx_fee || nValue >= iface->max_money)
    throw JSONRPCError(err, "Invalid coin value specified.");

  uint160 hCert;
  if (params.size() > 2) {
    hCert = uint160(params[2].get_str().c_str());
    if (!VerifyCertHash(iface, hCert)) 
      throw JSONRPCError(err, "Invalid certificate hash specified.");
  }

  nBalance = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (nBalance < nValue)
    throw JSONRPCError(err, "Insufficient funds available for amount specified.");

  CWalletTx wtx;
  err = init_ident_donate_tx(iface, strAccount, nValue, hCert, wtx);
  if (err)
    throw JSONRPCError(err, "Failure initializing transaction.");
    
  return (wtx.ToValue(ifaceIndex));
}

Value rpc_wallet_csend(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
  int64 nBalance;
  int err;

  if (fHelp || params.size() != 4)
    throw runtime_error(
        "wallet.csend <account> <address> <value> <cert-hash>\n"
        "Summary: Send a certified coin transaction.\n"
    );

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

  string strAccount = AccountFromValue(params[0]);
  if (!IsAccountValid(iface, strAccount))
    throw JSONRPCError(SHERR_INVAL, "Invalid account name specified.");

  string strAddress = params[1].get_str();
  CCoinAddr addr(strAddress);
  if (!addr.IsValid())
    throw JSONRPCError(err, "Invalid coin address specified.");

  int64 nValue = AmountFromValue(params[2]);
  if (nValue < iface->min_input || nValue >= iface->max_money)
    throw JSONRPCError(err, "Invalid coin value specified.");

  uint160 hCert(params[3].get_str().c_str());
  if (!VerifyCertHash(iface, hCert)) 
    throw JSONRPCError(err, "Invalid certificate hash specified.");

  nBalance = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (nBalance < nValue)
    throw JSONRPCError(err, "Insufficient funds available for amount specified.");

  CWalletTx wtx;
  err = init_ident_certcoin_tx(iface, strAccount, nValue, hCert, addr, wtx);
  if (err)
    throw JSONRPCError(err, "Failure initializing transaction.");
    
  return (wtx.ToValue(ifaceIndex));
}


Value rpc_wallet_stamp(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
  int64 nBalance;
  int err;

  if (fHelp || params.size() != 2) {
    throw runtime_error(
        "wallet.stamp <account> <comment>\n"
        "Summary: Create a 'ident stamp' transaction which optionally references a particular geodetic location.\n"
        "Params: [ <account> The coin account name., <comment> Use the format \"geo:<lat>,<lon>\" to specify a location. ]\n"
        "\n" 
        "A single coin reward can be achieved by creating an ident stamp transaction on a location present in the \"spring matrix\". The reward will be given, at most, once per location. A minimum transaction fee will apply and is sub-sequently returned once the transaction has been processed.\n"
        );
  }

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

  string strAccount = AccountFromValue(params[0]);
  string strComment = params[1].get_str();
  int64 nValue = iface->min_tx_fee;

  if (!IsAccountValid(iface, strAccount))
    throw JSONRPCError(SHERR_INVAL, "Invalid account name specified.");

  if (strComment.length() == 0 || strComment.length() > 135)
    throw JSONRPCError(SHERR_INVAL, "The comment must be between 1 and 135 characters.");

  nBalance = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (nBalance < nValue)
    throw JSONRPCError(SHERR_AGAIN, "Insufficient funds available for account specified.");

  CWalletTx wtx;
  err = init_ident_stamp_tx(iface, strAccount, strComment, wtx);
  if (err)
    throw JSONRPCError(err, "transaction generation failure");
    
  return (wtx.ToValue(ifaceIndex));
}

Value rpc_cert_export(CIface *iface, const Array& params, bool fStratum) 
{
  int ifaceIndex = GetCoinIndex(iface);
  int64 nBalance;
  int err;

  if (fStratum)
    throw runtime_error("unsupported operation");

  if (ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("unsupported operation");

  if ((params.size() != 1 && params.size() != 2))
    throw runtime_error("invalid parameters");

  uint160 hCert(params[0].get_str().c_str());
  if (!VerifyCertHash(iface, hCert)) 
    throw JSONRPCError(err, "Invalid certificate hash specified.");

  CTransaction tx;
  if (!GetTxOfCert(iface, hCert, tx))
    throw JSONRPCError(err, "Unable to obtain certificate specified.");

  CWallet *wallet = GetWallet(iface);
  const CIdent& ident = (CIdent&)tx.certificate;
  Object obj;

  CCoinAddr cert_addr(stringFromVch(ident.vAddr));
  if (!cert_addr.IsValid())
    throw JSONRPCError(err, "Certificate coin address is invalid.");

  if (!IsMine(*wallet, cert_addr.Get()))
    throw JSONRPCError(err, "Certificate specified references a non-local coin address.");



  bool fExtAddr = false;
  CTxDestination ext_addr;
  int nOut = IndexOfExtOutput(tx);
  if (nOut != -1) {
    const CTxOut& txout = tx.vout[nOut];
    if (ExtractDestination(txout.scriptPubKey, ext_addr) && IsMine(*wallet, ext_addr)) {
      fExtAddr = true;
    }
  }
  if (!fExtAddr) {
    throw JSONRPCError(err, "Certificate extended coin address is invalid.");
  }


  Array result;
  map<string, int64> mapAccountBalances;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, wallet->mapAddressBook) {
    CTxDestination dest = entry.first;
    string strLabel = entry.second;

    if (!IsMine(*wallet, dest))
      continue;

    CCoinAddr addr(ifaceIndex, dest);
    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
      continue;//throw JSONRPCError(-3, "Address does not refer to a key");

    CSecret vchSecret;
    bool fCompressed;
    if (!wallet->GetSecret(keyID, vchSecret, fCompressed))
      continue;//throw JSONRPCError(-4,"Private key for address " + strLabel + " is not known");

    if (dest == cert_addr.Get() || dest == ext_addr) {
      Object entry;
      string strKey = CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();
      entry.push_back(Pair("key", strKey));
      entry.push_back(Pair("label", strLabel));
      entry.push_back(Pair("addr", addr.ToString()));
      result.push_back(entry);
    }
  }
  obj.push_back(Pair(iface->name, result));

  if (params.size() > 1) {
    string strPath = params[1].get_str(); 
    string strJson = write_string(Value(obj), false);
    const char *json = (const char *)strJson.c_str();
    FILE *fl;

    fl = fopen(strPath.c_str(), "wb");
    if (!fl)
      throw JSONRPCError(SHERR_INVAL, "Invalid path specified.");
    fwrite(json, strlen(json), sizeof(char), fl);
    fclose(fl);

    Object info;
    info.push_back(Pair("mode", "cert.export"));
    info.push_back(Pair("path", strPath.c_str()));
    info.push_back(Pair("state", "finished")); 
    return (info);
  }

  return (obj);
}




