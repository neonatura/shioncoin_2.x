
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





Value rpc_cert_fee(CIface *iface, const Array& params, bool fHelp) 
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || 0 != params.size())
    throw runtime_error(
        "cert.fee\n"
        "get current fee for certificate transactions\n");

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    throw runtime_error("Unsupported operation for coin service.");

  return ValueFromAmount(GetCertOpFee(iface, (int)GetBestHeight(ifaceIndex)));
}


#if 0
Value rpc_cert_newent(CIface *iface, const Array& params, bool fHelp) 
{

  if (fHelp || params.size() != 2)
    throw runtime_error(
        "cert.newent <name> <secret>\n"
        "<title> title, 255 bytes max."
        "<data> data, 64KB max.");

  string vchTitleStr = params[0].get_str();
  vector<unsigned char> vchTitle = vchFromValue(params[0]);
  vector<unsigned char> vchData = vchFromValue(params[1]);

  if(vchTitle.size() < 1)
    throw runtime_error("certificate title < 1 bytes!\n");

  if(vchTitle.size() > 255)
    throw runtime_error("certificate title > 255 bytes!\n");

  if (vchData.size() < 1)
    throw runtime_error("certificate data < 1 bytes!\n");

  if (vchData.size() > 64 * 1024)
    throw runtime_error("certificate data > 65536 bytes!\n");

  CWallet *wallet = GetWallet(iface);

  CWalletTx wtx;
  CCertEnt *ent = wtx.CreateEntity(vchTitleStr.c_str(), vchData);

#if 0
  // generate rand identifier
  uint64 rand = GetRand((uint64) -1);
  vector<unsigned char> vchRand = CBigNum(rand).getvch();
  vector<unsigned char> vchCertIssuer = vchFromString(HexStr(vchRand));
  vector<unsigned char> vchToHash(vchRand);
  vchToHash.insert(vchToHash.end(), vchCertIssuer.begin(), vchCertIssuer.end());
  uint160 certissuerHash = Hash160(vchToHash);

  // build certissuer object
  CCertIssuer newCertIssuer;
  newCertIssuer.vchRand = vchCertIssuer;
  newCertIssuer.vchTitle = vchTitle;
  newCertIssuer.vchData = vchData;

  string bdata = newCertIssuer.SerializeToString();
#endif

  uint160 certissuerHash = ent->GetHash();

  // create transaction keys
  CPubKey newDefaultKey;
  wallet->GetKeyFromPool(newDefaultKey, false);
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_CERTISSUER) << OP_HASH160 << certissuerHash << OP_2DROP << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  // send transaction
  {
    string strError = wallet->SendMoney(scriptPubKey,
        (int64)iface->min_tx_fee, wtx, false);
    if (strError != "")
      throw runtime_error(strError);
    mapCertIssuers[certissuerHash] = wtx.GetHash();
  }

  Debug("SENT:CERTNEW : title=%s, tx=%s\n", vchTitleStr.c_str(), wtx.GetHash().GetHex().c_str());

#if 0
  // return results
  vector<Value> res;
  res.push_back(wtx.GetHash().GetHex());
  res.push_back(HexStr(vchRand));

  return res;
#endif

  return (wtx.GetHash().GetHex());
}
#endif


#if 0 /* DEBUG: */
Value rpc_cert_pubent(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *wallet = GetWallet(iface);
  CBlockIndex *pindexBest = GetBestBlockIndex(iface);

  if (fHelp || (params.size() < 1 || params.size() > 2)) {
    throw runtime_error(
        "cert.pubent <ent-hash> [account]\n"
        "Activates a certificate issuer after creating one with the 'cert.new' command.\n");
  }

  vector<unsigned char> vchHash = ParseHex(params[0].get_str());
  string strAccountName = "";
  if (params.size() == 2)
    strAccountName = params[1].get_str();

#if 0
  // gather inputs
  vector<unsigned char> vchRand = ParseHex(params[0].get_str());
  vector<unsigned char> vchCertIssuer = vchFromValue(params[0]);
#endif

  CWalletTx wtx;

  // check for existing pending certissuers
  {
#if 0
    LOCK2(cs_main, wallet->cs_wallet);
    if (mapCertIssuerPending.count(vchCertIssuer)
        && mapCertIssuerPending[vchCertIssuer].size()) {
      error( "certissueractivate() : there are %d pending operations on that certificate issuer, including %s",
          (int) mapCertIssuerPending[vchCertIssuer].size(),
          mapCertIssuerPending[vchCertIssuer].begin()->GetHex().c_str());
      throw runtime_error("there are pending operations on that certissuer");
    }

    // look for an certificate issuer with identical hex rand keys. wont happen.
    CTransaction tx;
    if (GetTxOfCertIssuer(*pcertdb, vchCertIssuer, tx)) {
      error( "certissueractivate() : this certificate issuer is already active with tx %s",
          tx.GetHash().GetHex().c_str());
      throw runtime_error("this certificate issuer is already active");
    }

    EnsureWalletIsUnlocked();

    // Make sure there is a previous certissuernew tx on this certificate issuer and that the random value matches
    uint256 wtxInHash;
    if (params.size() == 1) {
      if (!mapMyCertIssuers.count(vchCertIssuer))
        throw runtime_error(
            "could not find a coin with this certissuer, try specifying the certissuernew transaction id");
      wtxInHash = mapMyCertIssuers[vchCertIssuer];
    } else
      wtxInHash.SetHex(params[1].get_str());
    if (!wallet->mapWallet.count(wtxInHash))
      throw runtime_error("previous transaction is not in the wallet");

    // verify previous txn was certissuernew
    CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];
    vector<unsigned char> vchHash;

    bool found = false;
    BOOST_FOREACH(CTxOut& out, wtxIn.vout) {
      vector<vector<unsigned char> > vvch;
      int op;
      if (DecodeCertScript(out.scriptPubKey, op, vvch)) {
        if (op != OP_CERTISSUER_NEW)
          throw runtime_error(
              "previous transaction wasn't a certissuernew");
        vchHash = vvch[0]; found = true;
        break;
      }
    }
    if (!found)
      throw runtime_error("Could not decode certissuer transaction");
#endif

    int64 nNetFee = GetCertNetworkFee(pindexBest->nHeight);

    /* grab originating tx id */
    uint256 wtxInHash;
    uint160 hash = Hash160(vchHash);
    if (!mapCertIssuers.count(hash)) {
      throw runtime_error(
          "could not find specified entity hash.");
    }
    wtxInHash = mapCertIssuers[hash];

    CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];
    if(!(wtxIn.nFlag & CTransaction::TXF_ENTITY)) {
      throw runtime_error(
          "could not unserialize certissuer from txn");
    }
    CCertEnt newCertIssuer = *wtxIn.entity;

#if 0
    // unserialize certissuer object from txn, serialize back
    CCertIssuer newCertIssuer;
    if(!newCertIssuer.UnserializeFromTx(wtxIn)) {
      throw runtime_error(
          "could not unserialize certissuer from txn");
    }

    newCertIssuer.vchRand = vchCertIssuer;
    newCertIssuer.nFee = nNetFee;

    string bdata = newCertIssuer.SerializeToString();
    vector<unsigned char> vchbdata = vchFromString(bdata);

    // check this hash against previous, ensure they match
    vector<unsigned char> vchToHash(vchRand);
    vchToHash.insert(vchToHash.end(), vchCertIssuer.begin(), vchCertIssuer.end());


    //create certissueractivate txn keys
    CPubKey newDefaultKey;
    wallet->GetKeyFromPool(newDefaultKey, false);
    CScript scriptPubKeyOrig;
    scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
    CScript scriptPubKey;
    scriptPubKey << CScript::EncodeOP_N(OP_CERTISSUER_ACTIVATE) << vchCertIssuer
      << vchRand << newCertIssuer.vchTitle << OP_2DROP << OP_2DROP;
    scriptPubKey += scriptPubKeyOrig;
#endif

    const char *chName = newCertIssuer.GetName().c_str();
    vector<unsigned char> vchTitle(chName, chName + strlen(chName));
    CPubKey newDefaultKey;
    wallet->GetKeyFromPool(newDefaultKey, false);
    CScript scriptPubKeyOrig;
    scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
    CScript scriptPubKey;
    scriptPubKey << CScript::EncodeOP_N(OP_CERTISSUER_ACTIVATE)
      << vchHash << vchTitle << OP_2DROP << OP_2DROP;
    scriptPubKey += scriptPubKeyOrig;

    // send the tranasction
    string strError = SendMoneyWithInputTx(iface,
      scriptPubKey, nNetFee, wtxIn, wtx, reservekey);
    if (strError != "")
      throw runtime_error(strError);

    Debug("SENT:CERTACTIVATE: title=%s, ent-hash=%s, tx=%s\n",
        newCertIssuer.GetName().c_str(), 
        hash.GetHex().c_str(), wtx.GetHash().GetHex().c_str());
  } 

  return wtx.GetHash().GetHex();
}
#endif


