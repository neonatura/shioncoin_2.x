
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
#include "main.h"
#undef fcntl
#include "wallet.h"
#include "db.h"
#include "walletdb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "base58.h"
#include "rpc_proto.h"
#include "../server_iface.h" /* BLKERR_XXX */
#include "addrman.h"
#include "util.h"
#include "chain.h"
#include "mnemonic.h"

#undef fcntl
#undef GNULIB_NAMESPACE
#include <boost/asio.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/bind.hpp>
#define BOOST_NO_CXX11_SCOPED_ENUMS
#include <boost/filesystem.hpp>
#undef BOOST_NO_CXX11_SCOPED_ENUMS
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


#undef fcntl
#undef GNULIB_NAMESPACE

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace json_spirit;
using namespace boost::assign;



#include "rpccert_proto.h"

#include "SSLIOStreamDevice.h"

void ThreadRPCServer2(void* parg);

static std::string strRPCUserColonPass;
static CCriticalSection cs_THREAD_RPCHANDLER;

static int64 nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

extern Value rpc_getrawtransaction(CIface *iface, const Array& params, bool fHelp); // in rcprawtransaction.cpp
extern Value rpc_tx_signraw(CIface *iface, const Array& params, bool fHelp);
extern Value rpc_sendrawtransaction(CIface *iface, const Array& params, bool fHelp);
extern bool OpenNetworkConnection(const CAddress& addrConnect, const char *strDest = NULL);
extern json_spirit::Value ValueFromAmount(int64 amount);
extern bool IsAccountValid(CIface *iface, std::string strAccount);
extern Value rpc_cert_export(CIface *iface, const Array& params, bool fHelp);


const Object emptyobj;


class JSONRequest
{
public:
    Value id;
    string strMethod;
    Array params;
    CIface *iface;

    JSONRequest() { id = Value::null; }
    void parse(const Value& valRequest);
};

Object JSONRPCError(int code, const string& message)
{
    Object error;
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}
void RPCTypeCheck(const Array& params,
                  const list<Value_type>& typesExpected)
{
    unsigned int i = 0;
    BOOST_FOREACH(Value_type t, typesExpected)
    {
        if (params.size() <= i)
            break;

       const Value& v = params[i];
        if (v.type() != t)
        {
            string err = strprintf("Expected type %s, got %s",
                                   Value_type_name[t], Value_type_name[v.type()]);
            throw JSONRPCError(-3, err);
        }
        i++;
    }
}
void RPCTypeCheck(const Object& o,
                  const map<string, Value_type>& typesExpected)
{
    BOOST_FOREACH(const PAIRTYPE(string, Value_type)& t, typesExpected)
    {
        const Value& v = find_value(o, t.first);
        if (v.type() == null_type)
            throw JSONRPCError(-3, strprintf("Missing %s", t.first.c_str()));
        if (v.type() != t.second)
        {
            string err = strprintf("Expected type %s for %s, got %s",
                                   Value_type_name[t.second], t.first.c_str(), Value_type_name[v.type()]);
            throw JSONRPCError(-3, err);
        }
    }
}

double GetDifficulty(int ifaceIndex, const CBlockIndex* blockindex = NULL)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (GetBestBlockIndex(ifaceIndex) == NULL)
            return 1.0;
        else
            blockindex = GetBestBlockIndex(ifaceIndex);
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}


int64 AmountFromValue(const Value& value)
{
    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > 84000000.0)
        throw JSONRPCError(-3, "Invalid amount");
    int64 nAmount = roundint64(dAmount * COIN);
#if 0
    if (!MoneyRange(nAmount))
        throw JSONRPCError(-3, "Invalid amount");
#endif
    return nAmount;
}

std::string HexBits(unsigned int nBits)
{
    union {
        int32_t nBits;
        char cBits[4];
    } uBits;
    uBits.nBits = htonl((int32_t)nBits);
    return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}

std::string HelpRequiringPassphrase()
{
#if 0
    return pwalletMain->IsCrypted()
        ? "\nrequires wallet passphrase to be set with walletpassphrase first"
        : "";
#endif
return "";
}

void EnsureWalletIsUnlocked()
{
#if 0
    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");
#endif
}

void WalletTxToJSON(int ifaceIndex, const CWalletTx& wtx, Object& entry)
{
    int confirms = wtx.GetDepthInMainChain(ifaceIndex);
    entry.push_back(Pair("confirmations", confirms));
    if (confirms)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
    } else {
//      fprintf(stderr, "DEBUG: WalletTxToJSON: ifaceIndex(%d) wtx(%s): !confirmed; depth = %d\n", ifaceIndex, wtx.GetHash().GetHex().c_str(), confirms);
    }
    entry.push_back(Pair("txid", wtx.GetHash().GetHex()));
    entry.push_back(Pair("time", (boost::int64_t)wtx.GetTxTime()));
    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

string AccountFromValue(const Value& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
      throw JSONRPCError(-11, "Invalid account name");
    if (strAccount.length() > 0 && strAccount.at(0) == '@')
      throw JSONRPCError(-11, "Invalid account name");

    return strAccount;
}

#if 0
Object blockToJSON(CIface *iface, const CBlock& block, const CBlockIndex* blockindex)
{
  int ifaceIndex = GetCoinIndex(iface);
  Object result;

  result.push_back(Pair("hash", block.GetHash().GetHex()));
#if 0
  CMerkleTx txGen(block.vtx[0]);
  txGen.SetMerkleBranch(&block);
  result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
#endif
  result.push_back(Pair("confirmations", 
        GetBlockDepthInMainChain(iface, block.GetHash())));
  result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION(iface))));
  result.push_back(Pair("height", blockindex->nHeight));
  result.push_back(Pair("version", block.nVersion));
  result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
  Array txs;
  BOOST_FOREACH(const CTransaction&tx, block.vtx)
    txs.push_back(tx.GetHash().GetHex());
  result.push_back(Pair("tx", txs));
  result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
  result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
  result.push_back(Pair("bits", HexBits(block.nBits)));
  result.push_back(Pair("difficulty", GetDifficulty(ifaceIndex, blockindex)));

  if (blockindex->pprev)
    result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
  if (blockindex->pnext)
    result.push_back(Pair("nextblockhash", blockindex->pnext->GetBlockHash().GetHex()));
  return result;
}
#endif

string CRPCTable::help(CIface *iface, string strCommand) const
{
    string strRet;
    set<rpcfn_type> setDone;
    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
    {
        const CRPCCommand *pcmd = mi->second;
        string strMethod = mi->first;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos)
            continue;
        if (strCommand != "" && strMethod != strCommand)
            continue;
        try
        {
            Array params;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(iface, params, true);
        }
        catch (std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand.c_str());
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}


Value stop(const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "stop\n"
        "Stop coin server.");

  set_shutdown_timer();
#if 0
    // Shutdown will take long enough that the response should get back
    StartServerShutdown();
#endif

  return "coin server has now stopped running!";
}


#if 0
Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight;
}
#endif

#if 0 
Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.");

    return GetDifficulty();
}
#endif


// coin: Return average network hashes per second based on last number of blocks.
Value GetNetworkHashPS(int ifaceIndex, int lookup) 
{
  CBlockIndex *pindexBest = GetBestBlockIndex(ifaceIndex);

  if (pindexBest == NULL)
    return 0;

  // If lookup is -1, then use blocks since last difficulty change.
  if (lookup <= 0)
    lookup = pindexBest->nHeight % 2016 + 1;

  // If lookup is larger than chain, then set it to chain length.
  if (lookup > pindexBest->nHeight)
    lookup = pindexBest->nHeight;

  CBlockIndex* pindexPrev = pindexBest;
  for (int i = 0; i < lookup; i++)
    pindexPrev = pindexPrev->pprev;

  double timeDiff = pindexBest->GetBlockTime() - pindexPrev->GetBlockTime();
  double timePerBlock = timeDiff / lookup;

  return (boost::int64_t)(((double)GetDifficulty(ifaceIndex) * pow(2.0, 32)) / timePerBlock);
}

#if 0
Value getnetworkhashps(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnetworkhashps [blocks]\n"
            "Returns the estimated network hashes per second based on the last 120 blocks.\n"
            "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.");

    return GetNetworkHashPS(params.size() > 0 ? params[0].get_int() : 120);
}
#endif




#if 0
int64 GetAccountBalance(CIface *iface, const string& strAccount, int nMinDepth)
{
  CWallet *wallet;

  wallet = GetWallet(iface);
  if (!wallet) {
    unet_log(GetCoinIndex(iface),
        "GetAccountBalance: error retriving master wallet.");
    return (0);
  }

  CWalletDB walletdb(wallet->strWalletFile);
  return GetAccountBalance(wallet->ifaceIndex, walletdb, strAccount, nMinDepth);
}
#endif


static void GetAccountAddresses(CWallet *wallet, string strAccount, set<CTxDestination>& setAddress)
{
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CTxDestination& address = item.first;
    const string& strName = item.second;
    if (strName == strAccount)
      setAddress.insert(address);
  }
}

struct tallyitem
{
    int64 nAmount;
    int nConf;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
    }
};
static Value ListReceived(CWallet *wallet, const Array& params, bool fByAccounts)
{
  int ifaceIndex = wallet->ifaceIndex;

  // Minimum confirmations
  int nMinDepth = 1;
  if (params.size() > 0)
    nMinDepth = params[0].get_int();

  // Whether to include empty accounts
  bool fIncludeEmpty = false;
  if (params.size() > 1)
    fIncludeEmpty = params[1].get_bool();

  // Tally
  map<CCoinAddr, tallyitem> mapTally;
  for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
  {
    const CWalletTx& wtx = (*it).second;

    if (wtx.IsCoinBase()) {
      if (wtx.vout.size() == 1)
      continue;
      nMinDepth = 1;
    } else {
      nMinDepth = 1;
    }
    if (!wtx.IsFinal(wallet->ifaceIndex))
      continue;
#if 0
    if (wtx.IsCoinBase() || !wtx.IsFinal(wallet->ifaceIndex))
      continue;
#endif

    int nDepth = wtx.GetDepthInMainChain(ifaceIndex);
    if (nDepth < nMinDepth)
      continue;

    BOOST_FOREACH(const CTxOut& txout, wtx.vout)
    {
      CTxDestination address;
      if (!ExtractDestination(txout.scriptPubKey, address) || !IsMine(*wallet, address))
        continue;

      CCoinAddr c_addr(wallet->ifaceIndex, address);
      tallyitem& item = mapTally[c_addr];
      item.nAmount += txout.nValue;
      item.nConf = min(item.nConf, nDepth);
    }
  }

  // Reply
  Array ret;
  map<string, tallyitem> mapAccountTally;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
    const string& strAccount = item.second;
    map<CCoinAddr, tallyitem>::iterator it = mapTally.find(address);
    if (it == mapTally.end() && !fIncludeEmpty)
      continue;

    int64 nAmount = 0;
    int nConf = std::numeric_limits<int>::max();
    if (it != mapTally.end())
    {
      nAmount = (*it).second.nAmount;
      nConf = (*it).second.nConf;
    }

    if (fByAccounts)
    {
      tallyitem& item = mapAccountTally[strAccount];
      item.nAmount += nAmount;
      item.nConf = min(item.nConf, nConf);
    }
    else
    {
      Object obj;
      obj.push_back(Pair("address",       address.ToString()));
      obj.push_back(Pair("account",       strAccount));
      obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
      obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
      ret.push_back(obj);
    }
  }

  if (fByAccounts)
  {
    for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
    {
      int64 nAmount = (*it).second.nAmount;
      int nConf = (*it).second.nConf;
      Object obj;
      obj.push_back(Pair("account",       (*it).first));
      obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
      obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
      ret.push_back(obj);
    }
  }

  return ret;
}
void ListTransactions(int ifaceIndex, const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret)
{
  CWallet *pwalletMain = GetWallet(ifaceIndex);
//  int64 nGeneratedImmature, nGeneratedMature, nFee;
  int64 nFee;
  string strSentAccount;
  list<pair<CTxDestination, int64> > listReceived;
  list<pair<CTxDestination, int64> > listSent;

//  wtx.GetAmounts(nGeneratedImmature, nGeneratedMature);
  wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount);

  bool fAllAccounts = (strAccount == string("*"));

#if 0
  // Generated blocks assigned to account ""
  if ((nGeneratedMature+nGeneratedImmature) != 0 && (fAllAccounts || strAccount == ""))
  {
    Object entry;
    entry.push_back(Pair("account", string("")));
    if (nGeneratedImmature)
    {
      entry.push_back(Pair("category", wtx.GetDepthInMainChain(ifaceIndex) ? "immature" : "orphan"));
      entry.push_back(Pair("amount", ValueFromAmount(nGeneratedImmature)));
    }
    else
    {
      entry.push_back(Pair("category", "generate"));
      entry.push_back(Pair("amount", ValueFromAmount(nGeneratedMature)));
    }
    if (fLong)
      WalletTxToJSON(ifaceIndex, wtx, entry);
    ret.push_back(entry);
  }
#endif

  // Sent
  if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
  {
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& s, listSent)
    {
      Object entry;
      entry.push_back(Pair("account", strSentAccount));
      entry.push_back(Pair("address", CCoinAddr(ifaceIndex, s.first).ToString()));
      entry.push_back(Pair("category", "send"));
      entry.push_back(Pair("amount", ValueFromAmount(-s.second)));
      entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
      if (fLong)
        WalletTxToJSON(ifaceIndex, wtx, entry);
      ret.push_back(entry);
    }
  }

  // Received
  if (listReceived.size() > 0 && wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
  {
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& r, listReceived)
    {
      string account;
      if (pwalletMain->mapAddressBook.count(r.first))
        account = pwalletMain->mapAddressBook[r.first];
      if (fAllAccounts || (account == strAccount))
      {
        Object entry;
        entry.push_back(Pair("account", account));
        entry.push_back(Pair("address", CCoinAddr(ifaceIndex, r.first).ToString()));
        entry.push_back(Pair("category", "receive"));
        entry.push_back(Pair("amount", ValueFromAmount(r.second)));
        if (fLong)
          WalletTxToJSON(ifaceIndex, wtx, entry);
        ret.push_back(entry);
      }
    }
  }
}











Value rpc_help(CIface *iface, const Array& params, bool fHelp)
{
  if (fHelp || params.size() > 1)
    throw runtime_error(
        "help [command]\n"
        "List all available commands.");

  string strCommand;
  if (params.size() > 0)
    strCommand = params[0].get_str();

  return tableRPC.help(iface, strCommand);
}

Value rpc_stop(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "shutdown\n"
        "Stop shcoind server.");

  set_shutdown_timer();

  return "The shcoind daemon has been shutdown.";
}

Value rpc_peer_count(CIface *iface, const Array& params, bool fHelp)
{
  NodeList &vNodes = GetNodeList(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "peer.count\n"
        "Returns the number of connections to other nodes.");

  LOCK(cs_vNodes);
  return (int)vNodes.size();
}

Value rpc_net_hashps(CIface *iface, const Array& params, bool fHelp)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 1)
    throw runtime_error(
        "net.hashps [blocks]\n"
        "Returns the estimated network hashes per second based on the last 120 blocks.\n"
        "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.");

  return GetNetworkHashPS(ifaceIndex, params.size() > 0 ? params[0].get_int() : 120);
}

Value rpc_net_info(CIface *iface, const Array& params, bool fHelp)
{
  NodeList &vNodes = GetNodeList(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "net.info\n"
        "Statistical and runtime information on network operations.");

  Object obj;

  obj.push_back(Pair("clientversion",   (int)CLIENT_VERSION));
  obj.push_back(Pair("protocolversion", (int)PROTOCOL_VERSION(iface)));
  obj.push_back(Pair("socketport",      (int)iface->port));
  obj.push_back(Pair("connections",     (int)vNodes.size()));
  obj.push_back(Pair("networkhashps",   rpc_net_hashps(iface, params, false)));
  obj.push_back(Pair("errors",          GetWarnings(ifaceIndex, "statusbar")));

  return obj;
}

Value rpc_sys_info(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  bc_t *bc;
  char tbuf[256];

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "sys.info\n"
        "The system attributes that control how the coin-service operates.");

  Object obj;

  /* versioning */
  obj.push_back(Pair("version",       (int)iface->proto_ver));
  obj.push_back(Pair("blockversion",  (int)iface->block_ver));
  obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));

  /* attributes */
  obj.push_back(Pair("paytxfee",      ValueFromAmount(nTransactionFee)));
  obj.push_back(Pair("mininput",      ValueFromAmount(MIN_INPUT_VALUE(iface))));
  obj.push_back(Pair("maxblocksize",  (int)iface->max_block_size));
  obj.push_back(Pair("mintxfee",      ValueFromAmount(MIN_TX_FEE(iface))));
  obj.push_back(Pair("maxmoney",      ValueFromAmount(iface->max_money)));
  obj.push_back(Pair("maturity",      (int)iface->coinbase_maturity));
  obj.push_back(Pair("maxsigops",     (int)iface->max_sigops));

  /* stats */
  obj.push_back(Pair("blocksubmit",  (int)iface->stat.tot_block_submit));
  obj.push_back(Pair("blockaccept",  (int)iface->stat.tot_block_accept));
  obj.push_back(Pair("txsubmit",  (int)iface->stat.tot_tx_submit));
  obj.push_back(Pair("txaccept",  (int)iface->stat.tot_tx_accept));

  bc = GetBlockChain(iface);
  obj.push_back(Pair("blockfmaps", (int)bc_fmap_total(bc)));
  bc = GetBlockTxChain(iface); 
  obj.push_back(Pair("txfmaps", (int)bc_fmap_total(bc)));

  if (iface->net_valid) {
    sprintf(tbuf, "%-20.20s", ctime(&iface->net_valid));
    string val_str(tbuf);
    obj.push_back(Pair("lastvalidblock", val_str));
  }

  if (iface->net_invalid) {
    sprintf(tbuf, "%-20.20s", ctime(&iface->net_invalid));
    string inval_str(tbuf);
    obj.push_back(Pair("lastinvalidblock", inval_str));
  }

  return obj;
}

Value rpc_block_info(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "block.info\n"
        "Statistical and runtime information on block operations.");


  Object obj;

  obj.push_back(Pair("version",       (int)iface->proto_ver));
  obj.push_back(Pair("blockversion",  (int)iface->block_ver));
  obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));

  obj.push_back(Pair("blocks",        (int)GetBestHeight(iface)));
  obj.push_back(Pair("difficulty",    (double)GetDifficulty(ifaceIndex)));

  CTxMemPool *pool = GetTxMemPool(iface);
  obj.push_back(Pair("pooledtx",      (uint64_t)pool->size()));

  CBlockIndex *pindexBest = GetBestBlockIndex(iface);
  if (pindexBest)
    obj.push_back(Pair("currentblockhash",     pindexBest->GetBlockHash().GetHex()));
#if 0
  obj.push_back(Pair("currentblocksize",(uint64_t)nLastBlockSize));
  obj.push_back(Pair("currentblocktx",(uint64_t)nLastBlockTx));
#endif

  obj.push_back(Pair("errors",        GetWarnings(ifaceIndex, "statusbar")));

  return obj;
}

Value rpc_block_count(CIface *iface, const Array& params, bool fHelp)
{
  if (fHelp || params.size() != 0)
    throw runtime_error(
        "block.count\n"
        "Returns the number of blocks in the longest block chain.");

  return (int)GetBestHeight(iface);
}

Value rpc_block_hash(CIface *iface, const Array& params, bool fHelp)
{
  bc_t *bc = GetBlockChain(iface);
  int ifaceIndex = GetCoinIndex(iface);
  bc_hash_t ret_hash;
  uint256 hash;
  int err;

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "block.hash <index>\n"
        "Returns hash of block in best-block-chain at <index>.");

  int nHeight = params[0].get_int();
  if (nHeight < 0 || nHeight > GetBestHeight(iface))
    throw runtime_error("Block number out of range.");

  err = bc_get_hash(bc, nHeight, ret_hash);
  if (err) 
    throw runtime_error("Error reading from block-chain.");

  hash.SetRaw((unsigned int *)ret_hash);
  return (hash.GetHex());
}

Value rpc_block_difficulty(CIface *iface, const Array& params, bool fHelp)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "block.difficulty\n"
        "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.");

  return GetDifficulty(ifaceIndex);
}

Value rpc_block_export(CIface *iface, const Array& params, bool fHelp)
{
  blkidx_t *blockIndex;
  int ifaceIndex = GetCoinIndex(iface);
  unsigned int minHeight = 0;
  unsigned int maxHeight = 0;
  int err;

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "block.export <path> [min-height] [<max-height>]\n"
        "Exports a blockchain to an external file.");

  std::string strPath = params[0].get_str();
  if (params.size() > 1)
    minHeight = params[1].get_int();
  if (params.size() > 2)
    maxHeight = params[2].get_int();

  err = InitChainExport(ifaceIndex, strPath.c_str(), minHeight, maxHeight);
  if (err)
    throw JSONRPCError(-5, sherrstr(err));

  Object result;
  result.push_back(Pair("mode", "export-block"));
  result.push_back(Pair("minheight", (int)minHeight));
  result.push_back(Pair("maxheight", (int)maxHeight));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "init"));
  return (result);
}

Value rpc_block_import(CIface *iface, const Array& params, bool fHelp)
{
  blkidx_t *blockIndex;
  int ifaceIndex = GetCoinIndex(iface);
  unsigned int posFile = 0;
  int err;

  if (fHelp || params.size() == 0 || params.size() > 2)
    throw runtime_error(
        "block.import <path> [<offset>]\n"
        "Imports a blockchain from an external file.");

  std::string strPath = params[0].get_str();
  if (params.size() > 1)
    posFile = params[1].get_int();

  err = InitChainImport(ifaceIndex, strPath.c_str(), posFile);
  if (err)
    throw JSONRPCError(-5, sherrstr(err));

  Object result;
  result.push_back(Pair("mode", "import-block"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "init"));

  return (result);
}

Value rpc_block_free(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "block.free\n"
        "Deallocate cached resources used to map the block-chain.");

  CloseBlockChain(iface);

  return (true);
}

Value rpc_block_get(CIface *iface, const Array& params, bool fHelp)
{
  blkidx_t *blockIndex;
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "block.get <hash>\n"
        "Returns details of a block with the given block-hash.");

  blockIndex = GetBlockTable(ifaceIndex);
  if (!blockIndex)
    throw JSONRPCError(-5, "error loading block table.");

  std::string strHash = params[0].get_str();
  uint256 hash(strHash);

  if (blockIndex->count(hash) == 0)
    throw JSONRPCError(-5, "Block not found");

  CBlockIndex* pblockindex = (*blockIndex)[hash];
  if (!pblockindex)
    throw JSONRPCError(-5, "Block index not found");

  CBlock *block = GetBlockByHeight(iface, pblockindex->nHeight);
  if (!block) {
fprintf(stderr, "DEBUG: rpc_block_get: error loading '%s' block @ height %d\n", iface->name, pblockindex->nHeight); 
    throw JSONRPCError(-5, "Unable to load block");
  }

  //Object ret = blockToJSON(iface, *block, pblockindex);
  Object ret = block->ToValue();

  ret.push_back(Pair("confirmations", 
        GetBlockDepthInMainChain(iface, block->GetHash())));
  if (pblockindex->pprev)
    ret.push_back(Pair("previousblockhash",
          pblockindex->pprev->GetBlockHash().GetHex()));
  if (pblockindex->pnext)
    ret.push_back(Pair("nextblockhash", 
          pblockindex->pnext->GetBlockHash().GetHex()));

  delete block;

  return (ret);
}

#if 0
Value rpc_block_template(CIface *iface, const Array& params, bool fHelp)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "block.template [params]\n"
        "If [params] does not contain a \"data\" key, returns data needed to construct a block to work on:\n"
        "  \"version\" : block version\n"
        "  \"previousblockhash\" : hash of current highest block\n"
        "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
        "  \"coinbaseaux\" : data that should be included in coinbase\n"
        "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
        "  \"target\" : hash target\n"
        "  \"mintime\" : minimum timestamp appropriate for next block\n"
        "  \"curtime\" : current timestamp\n"
        "  \"mutable\" : list of ways the block template may be changed\n"
        "  \"noncerange\" : range of valid nonces\n"
        "  \"sigoplimit\" : limit of sigops in blocks\n"
        "  \"sizelimit\" : limit of block size\n"
        "  \"bits\" : compressed target of next block\n"
        "  \"height\" : height of the next block\n"
        "If [params] does contain a \"data\" key, tries to solve the block and returns null if it was successful (and \"rejected\" if not)\n"
        "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

  const Object& oparam = params[0].get_obj();
  std::string strMode;

  {
    const Value& modeval = find_value(oparam, "mode");
    if (modeval.type() == str_type)
      strMode = modeval.get_str();
    else
      if (find_value(oparam, "data").type() == null_type)
        strMode = "template";
      else
        strMode = "submit";
  }

  if (strMode == "template") {
    if (vNodes.empty())
      throw JSONRPCError(-9, "coin is not connected!");

    if (IsInitialBlockDownload())
      throw JSONRPCError(-10, "coin is downloading blocks...");

    static CReserveKey reservekey(pwalletMain);

    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64 nStart;
    static CBlock* pblock;
    if (pindexPrev != pindexBest ||
        (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
      nTransactionsUpdatedLast = nTransactionsUpdated;
      pindexPrev = pindexBest;
      nStart = GetTime();

      // Create new block
      if(pblock)
        delete pblock;
#if 0
      pblock = CreateNewBlock(reservekey);
      if (!pblock)
        throw JSONRPCError(-7, "Out of memory");
#endif
      pblock = CreateBlockTemplate(iface);
      if (!pblock)
        throw JSONRPCError(-7, "Out of memory");
    }

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    Array transactions;
    map<uint256, int64_t> setTxIndex;
    int i = 0;
    CTxDB txdb(ifaceIndex, "r");
    BOOST_FOREACH (CTransaction& tx, pblock->vtx)
    {
      uint256 txHash = tx.GetHash();
      setTxIndex[txHash] = i++;

      if (tx.IsCoinBase())
        continue;

      Object entry;

      CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface));
      ssTx << tx;
      entry.push_back(Pair("data", HexStr(ssTx.begin(), ssTx.end())));

      entry.push_back(Pair("hash", txHash.GetHex()));

      MapPrevTx mapInputs;
      map<uint256, CTxIndex> mapUnused;
      bool fInvalid = false;
      if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
      {
        entry.push_back(Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));

        Array deps;
        BOOST_FOREACH (MapPrevTx::value_type& inp, mapInputs)
        {
          if (setTxIndex.count(inp.first))
            deps.push_back(setTxIndex[inp.first]);
        }
        entry.push_back(Pair("depends", deps));

        int64_t nSigOps = tx.GetLegacySigOpCount();
        nSigOps += tx.GetP2SHSigOpCount(mapInputs);
        entry.push_back(Pair("sigops", nSigOps));
      }

      transactions.push_back(entry);
    }
    txdb.Close();

    Object aux;
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    static Array aMutable;
    if (aMutable.empty())
    {
      aMutable.push_back("time");
      aMutable.push_back("transactions");
      aMutable.push_back("prevblock");
    }

    Object result;
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions", transactions));
    result.push_back(Pair("coinbaseaux", aux));
    result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
    result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS));
    result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE));
    result.push_back(Pair("curtime", (int64_t)pblock->nTime));
    result.push_back(Pair("bits", HexBits(pblock->nBits)));
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));

    return result;
  } else if (strMode == "submit") {
      // Parse parameters
      CDataStream ssBlock(ParseHex(find_value(oparam, "data").get_str()), SER_NETWORK, PROTOCOL_VERSION(iface));
      CBlock pblock;
      ssBlock >> pblock;

      bool fAccepted = ProcessBlock(NULL, &pblock);

      return fAccepted ? Value::null : "rejected";
    }

  throw JSONRPCError(-8, "Invalid mode");
}
#endif

Value rpc_block_work(CIface *iface, const Array& params, bool fHelp)
{
  NodeList &vNodes = GetNodeList(iface);
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 1)
    throw runtime_error(
        "block.work [data]\n"
        "If [data] is not specified, returns formatted hash data to work on:\n"
        "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
        "  \"data\" : block data\n"
        "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
        "  \"target\" : little endian hash target\n"
        "If [data] is specified, tries to solve the block and returns true if it was successful.");

  if (vNodes.empty())
    throw JSONRPCError(-9, "coin service is not connected!");

  if (IsInitialBlockDownload(ifaceIndex))
    throw JSONRPCError(-10, "coin service is downloading blocks...");

  typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
  static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
  static vector<CBlock*> vNewBlock;
  static CReserveKey reservekey(pwalletMain);

  if (params.size() == 0)
  {
    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64 nStart;
    static CBlock* pblock;
    if (pindexPrev != GetBestBlockIndex(iface) ||
        (STAT_TX_ACCEPTS(iface) != nTransactionsUpdatedLast && GetTime() - nStart > 60))
    {
      if (pindexPrev != GetBestBlockIndex(iface))
      {
        // Deallocate old blocks since they're obsolete now
        mapNewBlock.clear();
        BOOST_FOREACH(CBlock* pblock, vNewBlock)
          delete pblock;
        vNewBlock.clear();
      }
      nTransactionsUpdatedLast = STAT_TX_ACCEPTS(iface);
      pindexPrev = GetBestBlockIndex(iface);
      nStart = GetTime();

#if 0
      // Create new block
      pblock = CreateNewBlock(reservekey);
      if (!pblock)
        throw JSONRPCError(-7, "Out of memory");
#endif

      pblock = CreateBlockTemplate(iface);
      if (!pblock)
        throw JSONRPCError(-7, "Out of memory");

      vNewBlock.push_back(pblock);
    }

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    // Update nExtraNonce
    static unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

    // Save
    mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

    // Prebuild hash buffers
    char pmidstate[32];
    char pdata[128];
    char phash1[64];
    FormatHashBuffers(pblock, pmidstate, pdata, phash1);

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    Object result;
    result.push_back(Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
    result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
    result.push_back(Pair("hash1",    HexStr(BEGIN(phash1), END(phash1)))); // deprecated
    result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));
    result.push_back(Pair("algorithm", "scrypt:1024,1,1"));  // specify that we should use the scrypt algorithm
    return result;
  }
  else
  {
    // Parse parameters
    vector<unsigned char> vchData = ParseHex(params[0].get_str());
    if (vchData.size() != 128)
      throw JSONRPCError(-8, "Invalid parameter");
    CBlock* pdata = (CBlock*)&vchData[0];

    // Byte reverse
    for (int i = 0; i < 128/4; i++)
      ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

    // Get saved block
    if (!mapNewBlock.count(pdata->hashMerkleRoot))
      return false;
    CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

    pblock->nTime = pdata->nTime;
    pblock->nNonce = pdata->nNonce;
    pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();

    return CheckWork(pblock, *pwalletMain, reservekey);
  }
}

Value rpc_block_workex(CIface *iface, const Array& params, bool fHelp)
{
  NodeList &vNodes = GetNodeList(iface);
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 2)
    throw runtime_error(
        "block.workex [data, coinbase]\n"
        "If [data, coinbase] is not specified, returns extended work data.\n"
        );

  if (vNodes.empty())
    throw JSONRPCError(-9, "coin service is not connected!");

  if (IsInitialBlockDownload(ifaceIndex))
    throw JSONRPCError(-10, "coin service is downloading blocks...");

  typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
  static mapNewBlock_t mapNewBlock;
  static vector<CBlock*> vNewBlock;
  static CReserveKey reservekey(pwalletMain);

  if (params.size() == 0)
  {
    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64 nStart;
    static CBlock* pblock;
    if (pindexPrev != GetBestBlockIndex(iface) ||
        (STAT_TX_ACCEPTS(iface) != nTransactionsUpdatedLast && GetTime() - nStart > 60))
    {
      if (pindexPrev != GetBestBlockIndex(iface)) {
        // Deallocate old blocks since they're obsolete now
        mapNewBlock.clear();
        BOOST_FOREACH(CBlock* pblock, vNewBlock)
          delete pblock;
        vNewBlock.clear();
      }
      nTransactionsUpdatedLast = STAT_TX_ACCEPTS(iface);
      pindexPrev = GetBestBlockIndex(iface);
      nStart = GetTime();

#if 0
      // Create new block
      pblock = CreateNewBlock(iface, reservekey);
      if (!pblock)
        throw JSONRPCError(-7, "Out of memory");
#endif

      pblock = CreateBlockTemplate(iface);
      if (!pblock)
        throw JSONRPCError(-7, "Out of memory");

      vNewBlock.push_back(pblock);
    }

    // Update nTime
    pblock->nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());
    pblock->nNonce = 0;

    // Update nExtraNonce
    static unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

    // Save
    mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

    // Prebuild hash buffers
    char pmidstate[32];
    char pdata[128];
    char phash1[64];
    FormatHashBuffers(pblock, pmidstate, pdata, phash1);

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    CTransaction coinbaseTx = pblock->vtx[0];
    std::vector<uint256> merkle = pblock->GetMerkleBranch(0);

    Object result;
    result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
    result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface));
    ssTx << coinbaseTx;
    result.push_back(Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));

    Array merkle_arr;

    BOOST_FOREACH(uint256 merkleh, merkle) {
      merkle_arr.push_back(HexStr(BEGIN(merkleh), END(merkleh)));
    }

    result.push_back(Pair("merkle", merkle_arr));


    return result;
  }
  else
  {
    // Parse parameters
    vector<unsigned char> vchData = ParseHex(params[0].get_str());
    vector<unsigned char> coinbase;

    if(params.size() == 2)
      coinbase = ParseHex(params[1].get_str());

    if (vchData.size() != 128)
      throw JSONRPCError(-8, "Invalid parameter");

    CBlock* pdata = (CBlock*)&vchData[0];

    // Byte reverse
    for (int i = 0; i < 128/4; i++)
      ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

    // Get saved block
    if (!mapNewBlock.count(pdata->hashMerkleRoot))
      return false;
    CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

    pblock->nTime = pdata->nTime;
    pblock->nNonce = pdata->nNonce;

    if(coinbase.size() == 0)
      pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
    else
      CDataStream(coinbase, SER_NETWORK, PROTOCOL_VERSION(iface)) >> pblock->vtx[0]; // FIXME - HACK!

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();

    return CheckWork(pblock, *pwalletMain, reservekey);
  }
}

Value rpc_msg_sign(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  if (fHelp || params.size() != 2)
    throw runtime_error(
        "msg.sign <coin-addr> <message>\n"
        "Sign a message with the private key of an address");

  EnsureWalletIsUnlocked();

  string strAddress = params[0].get_str();
  string strMessage = params[1].get_str();

  CCoinAddr addr(strAddress);
  if (!addr.IsValid())
    throw JSONRPCError(-3, "Invalid address");

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    throw JSONRPCError(-3, "Address does not refer to key");

  CKey key;
  if (!pwalletMain->GetKey(keyID, key))
    throw JSONRPCError(-4, "Private key not available");

  string strMessageMagic;
  if (0 == strcasecmp(iface->name, "emc2"))
    strMessage.append("Einsteinium");
  else
    strMessage.append(iface->name);
  strMessage.append(" Signed Message:\n");
//const string strMessageMagic = "usde Signed Message:\n";


  CDataStream ss(SER_GETHASH, 0);
  ss << strMessageMagic;
  ss << strMessage;

  vector<unsigned char> vchSig;
  if (!key.SignCompact(Hash(ss.begin(), ss.end()), vchSig))
    throw JSONRPCError(-5, "Sign failed");

  return EncodeBase64(&vchSig[0], vchSig.size());
}

Value rpc_msg_verify(CIface *iface, const Array& params, bool fHelp)
{
  if (fHelp || params.size() != 3)
    throw runtime_error(
        "msg.verify <coin-address> <signature> <message>\n"
        "Verify a signed message");

  string strAddress  = params[0].get_str();
  string strSign     = params[1].get_str();
  string strMessage  = params[2].get_str();

  CCoinAddr addr(strAddress);
  if (!addr.IsValid())
    throw JSONRPCError(-3, "Invalid address");

  CKeyID keyID;
  if (!addr.GetKeyID(keyID))
    throw JSONRPCError(-3, "Address does not refer to key");

  bool fInvalid = false;
  vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

  if (fInvalid)
    throw JSONRPCError(-5, "Malformed base64 encoding");

  string strMessageMagic;
  if (0 == strcasecmp(iface->name, "emc2"))
    strMessage.append("Einsteinium");
  else
    strMessage.append(iface->name);
  strMessage.append(" Signed Message:\n");

  CDataStream ss(SER_GETHASH, 0);
  ss << strMessageMagic;
  ss << strMessage;

  CKey key;
  if (!key.SetCompactSignature(Hash(ss.begin(), ss.end()), vchSig))
    return false;

  return (key.GetPubKey().GetID() == keyID);
}

Value rpc_wallet_balance(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 2)
    throw runtime_error(
        "wallet.balance [account] [minconf=1]\n"
        "If [account] is not specified, returns the server's total available balance.\n"
        "If [account] is specified, returns the balance in the account.");

  if (params.size() == 0)
    return  ValueFromAmount(pwalletMain->GetBalance());

  int nMinDepth = 1;
  if (params.size() > 1)
    nMinDepth = params[1].get_int();

  if (params[0].get_str() == "*") {
    // Calculate total balance a different way from GetBalance()
    // (GetBalance() sums up all unspent TxOuts)
    // getbalance and getbalance '*' should always return the same number.
    int64 nBalance = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
      const CWalletTx& wtx = (*it).second;
      if (!wtx.IsFinal(ifaceIndex))
        continue;

      int64 allGeneratedImmature, allGeneratedMature, allFee;
      allGeneratedImmature = allGeneratedMature = allFee = 0;
      string strSentAccount;
      list<pair<CTxDestination, int64> > listReceived;
      list<pair<CTxDestination, int64> > listSent;
      wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount);
      //wtx.GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount);
      if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
      {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listReceived)
          nBalance += r.second;
      }
      BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listSent)
        nBalance -= r.second;
      nBalance -= allFee;
//      nBalance += allGeneratedMature;
    }
    return  ValueFromAmount(nBalance);
  }

  string strAccount = AccountFromValue(params[0]);

  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);

  return ValueFromAmount(nBalance);
}

Value rpc_wallet_export(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.export <path>\n"
        "Export the coin wallet to the specified path in JSON format.");

  std::string strPath = params[0].get_str();

  int ifaceIndex = GetCoinIndex(iface);
  shjson_t *json = shjson_init(NULL);
  shjson_t *tree = shjson_array_add(json, iface->name);
  shjson_t *node;
  FILE *fl;
  char *text;

  CWallet *pwalletMain = GetWallet(iface);

  std::set<CKeyID> keys;
  pwalletMain->GetKeys(keys);
  BOOST_FOREACH(const CKeyID& key, keys) {
    if (pwalletMain->mapAddressBook.count(key) == 0) { /* loner */

#if 0
/* DEBUG: commented out; takes too long with large wallet */
      /* was this key ever used. */
      int nTxInput = 0;
      int nTxSpent = 0;
      BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
        const CWalletTx& tx = item.second;
        int i;
        for (i = 0; i < tx.vout.size(); i++) {
          CTxDestination dest;
          if (!ExtractDestination(tx.vout[i].scriptPubKey, dest))
            continue;
          CKeyID k1;
          CCoinAddr(ifaceIndex, dest).GetKeyID(k1);
          if (k1 == key) {
            if (tx.IsSpent(i)) {
              nTxSpent++;
            }
            nTxInput++;
          }
        }
      }
      if (nTxInput == 0 || (nTxSpent >= nTxInput))
        continue; /* never used or spent */
#endif

      /* pub key */
      CCoinAddr addr(ifaceIndex, key);

      /* priv key */
      CSecret vchSecret;
      bool fCompressed;
      if (!pwalletMain->GetSecret(key, vchSecret, fCompressed))
        continue;
      CCoinSecret csec(ifaceIndex, vchSecret, fCompressed);
      string strKey = csec.ToString();

      node = shjson_obj_add(tree, NULL);
      shjson_str_add(node, "key", (char *)strKey.c_str()); 
      shjson_str_add(node, "label", "coinbase");
      shjson_str_add(node, "addr", (char *)addr.ToString().c_str());
      shjson_str_add(node, "phrase", (char *)EncodeMnemonicSecret(csec).c_str());
//      shjson_num_add(node, "inputs", (nTxInput - nTxSpent));
    }
  }
  

  map<string, int64> mapAccountBalances;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
    CTxDestination dest = entry.first;
    string strLabel = entry.second;

    if (!IsMine(*pwalletMain, dest))
      continue;

#if 0
    CCoinAddr address;
    if (!address.SetString(strLabel))
      continue;//throw JSONRPCError(-5, "Invalid address");
#endif

    CCoinAddr addr(ifaceIndex, dest);
    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
      continue;//throw JSONRPCError(-3, "Address does not refer to a key");

    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
      continue;//throw JSONRPCError(-4,"Private key for address " + strLabel + " is not known");
    CCoinSecret csec(ifaceIndex, vchSecret, fCompressed);
    string strKey = csec.ToString();

    node = shjson_obj_add(tree, NULL);
    shjson_str_add(node, "key", (char *)strKey.c_str()); 
    shjson_str_add(node, "label", (char *)strLabel.c_str());
    shjson_str_add(node, "addr", (char *)addr.ToString().c_str());
    shjson_str_add(node, "phrase", (char *)EncodeMnemonicSecret(csec).c_str());
  }

  text = shjson_print(json);
  shjson_free(&json);

  fl = fopen(strPath.c_str(), "wb");
  if (fl) {
    fwrite(text, sizeof(char), strlen(text), fl);
    fclose(fl);
  }
  free(text);

  return Value::null;
}

bool BackupWallet(const CWallet& wallet, const string& strDest)
{
  if (!wallet.fFileBacked)
    return false;
  while (!fShutdown)
  {
    {
      LOCK(bitdb.cs_db);
      if (!bitdb.mapFileUseCount.count(wallet.strWalletFile) || bitdb.mapFileUseCount[wallet.strWalletFile] == 0)
      {
        // Flush log data to the dat file
        bitdb.CloseDb(wallet.strWalletFile);
        bitdb.CheckpointLSN(wallet.strWalletFile);
        bitdb.mapFileUseCount.erase(wallet.strWalletFile);

        // Copy wallet.dat
        filesystem::path pathSrc = GetDataDir() / wallet.strWalletFile;
        filesystem::path pathDest(strDest);
        if (filesystem::is_directory(pathDest))
          pathDest /= wallet.strWalletFile;

        try {
#if 0
#if BOOST_VERSION >= 104000
          filesystem::copy_file(pathSrc, pathDest, filesystem::copy_option::overwrite_if_exists);
#else
          filesystem::copy_file(pathSrc, pathDest);
#endif
#endif
          filesystem::copy_file(pathSrc, pathDest);
          printf("copied wallet.dat to %s\n", pathDest.string().c_str());
          return true;
        } catch(const filesystem::filesystem_error &e) {
          printf("error copying wallet.dat to %s - %s\n", pathDest.string().c_str(), e.what());
          return false;
        }
      }
    }
    Sleep(100);
  }
  return false;
}

Value rpc_wallet_exportdat(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.exportdat <path>\n"
        "Export the coin wallet to the specified path (dir or file).");

  CWallet *wallet = GetWallet(iface);
  if (!wallet)
    throw runtime_error("Wallet not available.");

  string strDest = params[0].get_str();
  if (!BackupWallet(*wallet, strDest))
    throw runtime_error("Failure writing wallet datafile.");

  return Value::null;
}

Value rpc_wallet_get(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.get <coin address>\n"
        "Returns the account associated with the given address.");

  CCoinAddr address(params[0].get_str());
  if (!address.IsValid())
    throw JSONRPCError(-5, "Invalid coin address");

  string strAccount;
  map<CTxDestination, string>::iterator mi = pwalletMain->mapAddressBook.find(address.Get());
  if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
    strAccount = (*mi).second;
  return strAccount;
}

Value rpc_wallet_key(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.key <address>\n"
        "Summary: Reveals the private key corresponding to a public coin address.\n"
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
        "The entire wallet can be exported to a file via the 'wallet.export' command.\n"
        );

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  string strAddress = params[0].get_str();
  CCoinAddr address(strAddress);
  if (!address.IsValid())
    throw JSONRPCError(-5, "Invalid address");
  CKeyID keyID;
  if (!address.GetKeyID(keyID))
    throw JSONRPCError(-3, "Address does not refer to a key");
  CSecret vchSecret;
  bool fCompressed;
  if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
    throw JSONRPCError(-4,"Private key for address " + strAddress + " is not known");
  return CCoinSecret(ifaceIndex, vchSecret, fCompressed).ToString();
}

Value rpc_wallet_info(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "wallet.info\n"
        "Statistical and runtime information on wallet operations.");


  Object obj;
  obj.push_back(Pair("version",       (int)CLIENT_VERSION));
  obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));

  obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));

  obj.push_back(Pair("keypoololdest", (boost::int64_t)pwalletMain->GetOldestKeyPoolTime()));
  obj.push_back(Pair("keypoolsize",   pwalletMain->GetKeyPoolSize()));
  obj.push_back(Pair("txcachecount",   (int)pwalletMain->mapWallet.size()));

  obj.push_back(Pair("errors",        GetWarnings(ifaceIndex, "statusbar")));

  return obj;

}

Value rpc_wallet_import(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 1) {
    throw runtime_error(
        "wallet.import <path>\n"
        "Import a JSON wallet file.");
  }

  std::string strPath = params[0].get_str();

  {
  shjson_t *json;
  shjson_t *tree;
shjson_t *node;
char *text;
struct stat st;
FILE *fl;
    char label[256];
    char addr[256];
    char key[256];

    memset(label, 0, sizeof(label));
    memset(addr, 0, sizeof(addr));
    memset(key, 0, sizeof(key));

    fl = fopen(strPath.c_str(), "rb");
    if (!fl)
      throw runtime_error("error opening file.");

    memset(&st, 0, sizeof(st));
    fstat(fileno(fl), &st);
    if (st.st_size == 0)
      throw runtime_error("file is not in JSON format.");

    text = (char *)calloc(st.st_size + 1, sizeof(char));
    if (!text)
      throw runtime_error("not enough memory to allocate file.");

    fread(text, sizeof(char), st.st_size, fl);
    fclose(fl);

    //    serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

    json = shjson_init(text);
    free(text);
    if (!json) {
      throw runtime_error("file is not is JSON format.");
    }

    tree = json->child;
    if (tree && tree->string) {
      if (0 != strcmp(tree->string, iface->name))
        throw runtime_error("wallet file references incorrect coin service.");

      for (node = tree->child; node; node = node->next) {
        strncpy(label, shjson_astr(node, "label", ""), sizeof(label)-1);
        strncpy(addr, shjson_astr(node, "addr", ""), sizeof(addr)-1);
        strncpy(key, shjson_astr(node, "key", ""), sizeof(key)-1);
        if (!*key) continue;

        string strSecret(key);
        string strLabel(label);

        CCoinSecret vchSecret;
        bool fGood = vchSecret.SetString(strSecret);
        if (!fGood) {
//fprintf(stderr, "DEBUG: invalid private key '%s'\n", key);
          continue;// throw JSONRPCError(-5,"Invalid private key");
}

        CKey key;
        bool fCompressed;
        CSecret secret = vchSecret.GetSecret(fCompressed);
        key.SetSecret(secret, fCompressed);
        CKeyID vchAddress = key.GetPubKey().GetID();
        {
          LOCK2(cs_main, pwalletMain->cs_wallet);

          pwalletMain->MarkDirty();
          pwalletMain->SetAddressBookName(vchAddress, strLabel);

          if (!pwalletMain->AddKey(key)) {
            continue; //throw JSONRPCError(-4,"Error adding key to wallet");
          }

        }
      }
    }

    shjson_free(&json);
  }
pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
pwalletMain->ReacceptWalletTransactions();

#if 0
  string strSecret = params[0].get_str();
  string strLabel = "";
//  if (params.size() > 1)
    strLabel = params[1].get_str();
  CCoinSecret vchSecret;
  bool fGood = vchSecret.SetString(strSecret);

  if (!fGood) throw JSONRPCError(-5,"Invalid private key");

  CKey key;
  bool fCompressed;
  CSecret secret = vchSecret.GetSecret(fCompressed);
  key.SetSecret(secret, fCompressed);
  CKeyID vchAddress = key.GetPubKey().GetID();
  {
    LOCK2(cs_main, pwalletMain->cs_wallet);

    pwalletMain->MarkDirty();
    pwalletMain->SetAddressBookName(vchAddress, strLabel);

    if (!pwalletMain->AddKey(key))
      throw JSONRPCError(-4,"Error adding key to wallet");

    pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
    pwalletMain->ReacceptWalletTransactions();
  }
#endif

  return Value::null;
}

Value rpc_wallet_list(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 1)
    throw runtime_error(
        "wallet.list [minconf=1]\n"
        "Returns Object that has account names as keys, account balances as values.");

  int nMinDepth = 1;
  if (params.size() > 0)
    nMinDepth = params[0].get_int();

  map<string, int64> mapAccountBalances;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
    if (IsMine(*pwalletMain, entry.first)) { // This address belongs to me
      mapAccountBalances[entry.second] = 0;
}
  }

  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
  {
    const CWalletTx& wtx = (*it).second;
    //int64 nGeneratedImmature, nGeneratedMature, nFee;
    int64 nFee;
    string strSentAccount;
    list<pair<CTxDestination, int64> > listReceived;
    list<pair<CTxDestination, int64> > listSent;
    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount);

    if (nFee != 0) {
      mapAccountBalances[strSentAccount] -= nFee;
    }

    BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& s, listSent) {
      int64 nValue = s.second;
      if (nValue <= 0)
        continue;

      mapAccountBalances[strSentAccount] -= nValue;
    }

    if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
    {
      BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& r, listReceived) {
        if (pwalletMain->mapAddressBook.count(r.first)) {
          mapAccountBalances[pwalletMain->mapAddressBook[r.first]] += r.second;
        } else {
          mapAccountBalances[""] += r.second;
        }
      }
    }

    /* add in change */
    BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
      if (wtx.GetDebit() > 0 && pwalletMain->IsChange(txout)) {
        mapAccountBalances[strSentAccount] += txout.nValue; 
      }
    }
  }

  list<CAccountingEntry> acentries;
  CWalletDB(pwalletMain->strWalletFile).ListAccountCreditDebit("*", acentries);
  BOOST_FOREACH(const CAccountingEntry& entry, acentries) {
    mapAccountBalances[entry.strAccount] += entry.nCreditDebit;
  }

  Object ret;
  BOOST_FOREACH(const PAIRTYPE(string, int64)& accountBalance, mapAccountBalances) {
    ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
  }
  return ret;
}

Value rpc_wallet_addr(CIface *iface, const Array& params, bool fHelp)
{
  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.addr <account>\n"
        "Returns the current hash address for receiving payments to this account.");

  // Parse the account first so we don't generate a key if there's an error
  string strAccount = AccountFromValue(params[0]);

  Value ret;

  ret = GetAccountAddress(GetWallet(iface), strAccount).ToString();

  return ret;
}

Value rpc_wallet_recvbyaccount(CIface *iface, const Array& params, bool fHelp)
{
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() < 1 || params.size() > 2)
    throw runtime_error(
        "wallet.recvbyaccount <account> [minconf=1]\n"
        "Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");

  CWallet *wallet = GetWallet(iface);

  // Minimum confirmations
  int nMinDepth = 1;
  if (params.size() > 1)
    nMinDepth = params[1].get_int();

  // Get the set of pub keys assigned to account
  string strAccount = AccountFromValue(params[0]);
  set<CTxDestination> setAddress;
  GetAccountAddresses(wallet, strAccount, setAddress);

  // Tally
  int64 nAmount = 0;
  for (map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
  {
    const CWalletTx& wtx = (*it).second;
    if (wtx.IsCoinBase() || !wtx.IsFinal(ifaceIndex))
      continue;

    BOOST_FOREACH(const CTxOut& txout, wtx.vout)
    {
      CTxDestination address;
      if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*wallet, address) && setAddress.count(address))
        if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
          nAmount += txout.nValue;
    }
  }

  return (double)nAmount / (double)COIN;
}

Value rpc_wallet_recvbyaddr(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() < 1 || params.size() > 2)
    throw runtime_error(
        "wallet.recvbyaddr <coin-address> [minconf=1]\n"
        "Returns the total amount received by <coin-address> in transactions with at least [minconf] confirmations.");

  CCoinAddr address = CCoinAddr(params[0].get_str());
  if (!address.IsValid())
    throw JSONRPCError(-5, "Invalid coin address");

  CScript scriptPubKey;
  scriptPubKey.SetDestination(address.Get());
  if (!IsMine(*pwalletMain,scriptPubKey))
    return (double)0.0;

  // Minimum confirmations
  int nMinDepth = 1;
  if (params.size() > 1)
    nMinDepth = params[1].get_int();

  // Tally
  int64 nAmount = 0;
  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
  {
    const CWalletTx& wtx = (*it).second;
    if (wtx.IsCoinBase() && wtx.vout.size() == 1)
      continue;
    if (!wtx.IsFinal(ifaceIndex))
      continue;


    BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
      CTxDestination out_addr;
      ExtractDestination(txout.scriptPubKey, out_addr);
      if (address.Get() == out_addr)
        if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
          nAmount += txout.nValue;
#if 0
      if (txout.scriptPubKey == scriptPubKey)
        if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
          nAmount += txout.nValue;
#endif
    }
  }

  return  ValueFromAmount(nAmount);
}

Value rpc_wallet_rescan(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "wallet.rescan\n"
        "Rescan the block-chain for personal wallet transactions.\n");

  wallet->nScanHeight = 0;
  InitServiceWalletEvent(wallet, 0);

  return Value::null;
}

Value rpc_wallet_send(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() < 3 || params.size() > 6)
    throw runtime_error(
        "wallet.send <fromaccount> <toaddress> <amount> [minconf=1] [comment] [comment-to]\n"
        "<amount> is a real and is rounded to the nearest 0.00000001"
        + HelpRequiringPassphrase());

  /* originating account  */
  string strAccount = AccountFromValue(params[0]);

  /* destination coin address */
  CCoinAddr address(params[1].get_str());
  if (!address.IsValid())
    throw JSONRPCError(-5, "Invalid coin address");
  if (address.GetVersion() != CCoinAddr::GetCoinAddrVersion(ifaceIndex))
    throw JSONRPCError(-5, "Invalid address for coin service.");

  int64 nAmount = AmountFromValue(params[2]);
  int nMinDepth = 1;
  if (params.size() > 3)
    nMinDepth = params[3].get_int();

  CWalletTx wtx;
  wtx.strFromAccount = strAccount;
  if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
    wtx.mapValue["comment"] = params[4].get_str();
  if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
    wtx.mapValue["to"]      = params[5].get_str();

  EnsureWalletIsUnlocked();

  // Check funds
  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
  if (nAmount > nBalance)
    throw JSONRPCError(-6, "Account has insufficient funds");

  // Send
  string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
  if (strError != "")
    throw JSONRPCError(-4, strError);

  return wtx.GetHash().GetHex();
}

Value rpc_wallet_set(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "wallet.set <coin-address> <account>\n"
            "Sets the account associated with the given address.");

    CCoinAddr address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(-5, "Invalid coin address");


    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Detect when changing the account of an address that is the 'unused current key' of another account:
    if (pwalletMain->mapAddressBook.count(address.Get()))
    {
        string strOldAccount = pwalletMain->mapAddressBook[address.Get()];
        if (address == GetAccountAddress(GetWallet(iface), strOldAccount))
            GetAccountAddress(GetWallet(iface), strOldAccount, true);
    }

    pwalletMain->SetAddressBookName(address.Get(), strAccount);

    return Value::null;
}

Value rpc_wallet_setkey(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 2) {
    throw runtime_error(
        "wallet.setkey <priv-key> <account>\n"
        "Adds a private key (as returned by wallet.key) to your wallet.");
  }

  string strSecret = params[0].get_str();
  string strLabel = "";
//  if (params.size() > 1)
    strLabel = params[1].get_str();
  CCoinSecret vchSecret;
  bool fGood = vchSecret.SetString(strSecret);

  if (!fGood) throw JSONRPCError(-5,"Invalid private key");

  CKey key;
  bool fCompressed;
  CSecret secret = vchSecret.GetSecret(fCompressed);
  key.SetSecret(secret, fCompressed);
  CKeyID vchAddress = key.GetPubKey().GetID();
  {
    LOCK2(cs_main, pwalletMain->cs_wallet);

    pwalletMain->MarkDirty();
    pwalletMain->SetAddressBookName(vchAddress, strLabel);

    if (!pwalletMain->AddKey(key))
      throw JSONRPCError(-4,"Error adding key to wallet");

    pwalletMain->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
    pwalletMain->ReacceptWalletTransactions();
  }

  return Value::null;
}

Value rpc_wallet_setkeyphrase(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 2) {
    throw runtime_error(
        "wallet.setkeyphrase \"<phrase>\" <account>\n"
        "Adds a private key to your wallet from a key phrase..");
  }

  CCoinSecret vchSecret;
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  bool ret = DecodeMnemonicSecret(ifaceIndex, params[0].get_str(), vchSecret);
  if (!ret)
    throw JSONRPCError(-5, "Invalid private key");

  string strLabel = params[1].get_str();
  bool fGood = vchSecret.IsValid();
  if (!fGood) throw JSONRPCError(-5,"Invalid private key");

  CKey key;
  bool fCompressed;
  CSecret secret = vchSecret.GetSecret(fCompressed);
  key.SetSecret(secret, fCompressed);
  CKeyID vchAddress = key.GetPubKey().GetID();
  {
    LOCK2(cs_main, wallet->cs_wallet);

    std::map<CTxDestination, std::string>::iterator mi = wallet->mapAddressBook.find(vchAddress);
    if (mi != wallet->mapAddressBook.end()) {
      throw JSONRPCError(SHERR_NOTUNIQ, "Address already exists in wallet.");
    }

    wallet->MarkDirty();
    wallet->SetAddressBookName(vchAddress, strLabel);

    if (!wallet->AddKey(key))
      throw JSONRPCError(-4,"Error adding key to wallet");

    wallet->ScanForWalletTransactions(GetGenesisBlockIndex(iface), true);
    wallet->ReacceptWalletTransactions();
  }

  return Value::null;
}


Value rpc_wallet_unspent(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 2)
    throw runtime_error(
        "wallet.unspent [minconf=1] [maxconf=999999]\n"
        "Returns array of unspent transaction outputs\n"
        "with between minconf and maxconf (inclusive) confirmations.\n"
        "Results are an array of Objects, each of which has:\n"
        "{txid, vout, scriptPubKey, amount, confirmations}");

  RPCTypeCheck(params, list_of(int_type)(int_type));

  int nMinDepth = 1;
  if (params.size() > 0)
    nMinDepth = params[0].get_int();

  int nMaxDepth = 999999;
  if (params.size() > 1)
    nMaxDepth = params[1].get_int();

  Array results;
  vector<COutput> vecOutputs;
  pwalletMain->AvailableCoins(vecOutputs, false);
  BOOST_FOREACH(const COutput& out, vecOutputs)
  {
    if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
      continue;

    int64 nValue = out.tx->vout[out.i].nValue;
    const CScript& pk = out.tx->vout[out.i].scriptPubKey;
    Object entry;
    entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
    entry.push_back(Pair("vout", out.i));
    entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
    entry.push_back(Pair("amount",ValueFromAmount(nValue)));
    entry.push_back(Pair("confirmations",out.nDepth));
    results.push_back(entry);
  }

  return results;
}

Value rpc_wallet_unconfirm(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "wallet.unconfirm\n"
        "Display a list of all unconfirmed transactions.\n");

  Array results;
  {
    LOCK(pwalletMain->cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
      const CWalletTx& pcoin = (*it).second;
      if (!pcoin.IsCoinBase()) continue;
      int depth = pcoin.GetBlocksToMaturity(ifaceIndex);
      if (depth > 0 && pcoin.GetDepthInMainChain(ifaceIndex) >= 2) {
        CTransaction& tx = (CTransaction&)pcoin;
        results.push_back(tx.ToValue(ifaceIndex));
      }
    }
  }

  return results;
} 

Value rpc_wallet_validate(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.validate <coin-address>\n"
        "Return information about <coin-address>.");

  CCoinAddr address(params[0].get_str());
  bool isValid = address.IsValid();

  Object ret;
  ret.push_back(Pair("isvalid", isValid));
  if (isValid)
  {
    CTxDestination dest = address.Get();
    string currentAddress = address.ToString();
    ret.push_back(Pair("address", currentAddress));
    bool fMine = IsMine(*pwalletMain, dest);
    ret.push_back(Pair("ismine", fMine));
#if 0
    if (fMine) {
      Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
      ret.insert(ret.end(), detail.begin(), detail.end());
    }
#endif
    if (pwalletMain->mapAddressBook.count(dest))
      ret.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));
  }
  return ret;
}

Value rpc_wallet_addrlist(CIface *iface, const Array& params, bool fHelp)
{
  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.addrlist <account>\n"
        "Returns the list of coin addresses for the given account.");

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strAccount = AccountFromValue(params[0]);
  if (!IsAccountValid(iface, strAccount))
    throw JSONRPCError(-8, "Invalid account name specified.");

  // Find all addresses that have the given account
  Array ret;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
    const string& strName = item.second;
    if (strName == strAccount)
      ret.push_back(address.ToString());
  }
  return ret;
}

Value rpc_wallet_listbyaddr(CIface *iface, const Array& params, bool fHelp)
{
  if (fHelp || params.size() > 2)
    throw runtime_error(
        "wallet.listbyaddr [minconf=1] [includeempty=false]\n"
        "[minconf] is the minimum number of confirmations before payments are included.\n"
        "[includeempty] whether to include addresses that haven't received any payments.\n"
        "Returns an array of objects containing:\n"
        "  \"address\" : receiving address\n"
        "  \"account\" : the account of the receiving address\n"
        "  \"amount\" : total amount received by the address\n"
        "  \"confirmations\" : number of confirmations of the most recent transaction included");

  return ListReceived(GetWallet(iface), params, false);
}

Value rpc_block_purge(CIface *iface, const Array& params, bool fHelp)
{
  uint256 hash;
  int err;

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "block.purge <index>\n"
        "Truncate the block-chain to height <index>.\n");

  int nHeight = params[0].get_int();
  if (nHeight < 0 || nHeight > GetBestHeight(iface))
    throw runtime_error("Block number out of range.");

  CBlock *block = GetBlockByHeight(iface, nHeight);
  if (!block)
    throw runtime_error("Block not found in block-chain.");

  hash = block->GetHash();
  block->Truncate();
  delete block;

  return (hash.GetHex());
}

Value rpc_block_listsince(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  CBlockIndex *pindexBest = GetBestBlockIndex(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp)
    throw runtime_error(
        "block.listsince [blockhash] [target-confirmations]\n"
        "Get all transactions in blocks since block [blockhash], or all transactions if omitted");

  CBlockIndex *pindex = NULL;
  int target_confirms = 1;

  if (params.size() > 0)
  {
    uint256 blockId = 0;

    blockId.SetHex(params[0].get_str());
    pindex = CBlockLocator(ifaceIndex, blockId).GetBlockIndex();
  }

  if (params.size() > 1)
  {
    target_confirms = params[1].get_int();

    if (target_confirms < 1)
      throw JSONRPCError(-8, "Invalid parameter");
  }

  int depth = pindex ? (1 + GetBestHeight(iface) - pindex->nHeight) : -1;

  Array transactions;

  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
  {
    CWalletTx tx = (*it).second;

    if (depth == -1 || tx.GetDepthInMainChain(ifaceIndex) < depth)
      ListTransactions(ifaceIndex, tx, "*", 0, true, transactions);
  }

  uint256 lastblock;

  if (target_confirms == 1)
  {
    //lastblock = hashBestChain;
    lastblock = GetBestBlockChain(iface);
  }
  else
  {
    int target_height = pindexBest->nHeight + 1 - target_confirms;

    CBlockIndex *block;
    for (block = pindexBest;
        block && block->nHeight > target_height;
        block = block->pprev)  { }

    lastblock = block ? block->GetBlockHash() : 0;
  }

  Object ret;
  ret.push_back(Pair("transactions", transactions));
  ret.push_back(Pair("lastblock", lastblock.GetHex()));

  return ret;
}

Value rpc_wallet_listbyaccount(CIface *iface, const Array& params, bool fHelp)
{
  if (fHelp || params.size() > 2)
    throw runtime_error(
        "wallet.listbyaccount [minconf=1] [includeempty=false]\n"
        "[minconf] is the minimum number of confirmations before payments are included.\n"
        "[includeempty] whether to include accounts that haven't received any payments.\n"
        "Returns an array of objects containing:\n"
        "  \"account\" : the account of the receiving addresses\n"
        "  \"amount\" : total amount received by addresses with this account\n"
        "  \"confirmations\" : number of confirmations of the most recent transaction included");

  return ListReceived(GetWallet(iface), params, true);
}

Value rpc_wallet_move(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);

  if (fHelp || params.size() < 3 || params.size() > 5)
    throw runtime_error(
        "wallet.move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
        "Move from one account in your wallet to another.");

  string strFrom = AccountFromValue(params[0]);
  string strTo = AccountFromValue(params[1]);
  int64 nAmount = AmountFromValue(params[2]);
  if (params.size() > 3)
    // unused parameter, used to be nMinDepth, keep type-checking it though
    (void)params[3].get_int();
  string strComment;
  if (params.size() > 4)
    strComment = params[4].get_str();

  CWalletDB walletdb(pwalletMain->strWalletFile);
  if (!walletdb.TxnBegin())
    throw JSONRPCError(-20, "database error");

  int64 nNow = GetAdjustedTime();

  // Debit
  CAccountingEntry debit;
  debit.strAccount = strFrom;
  debit.nCreditDebit = -nAmount;
  debit.nTime = nNow;
  debit.strOtherAccount = strTo;
  debit.strComment = strComment;
  walletdb.WriteAccountingEntry(debit);

  // Credit
  CAccountingEntry credit;
  credit.strAccount = strTo;
  credit.nCreditDebit = nAmount;
  credit.nTime = nNow;
  credit.strOtherAccount = strFrom;
  credit.strComment = strComment;
  walletdb.WriteAccountingEntry(credit);

  if (!walletdb.TxnCommit())
    throw JSONRPCError(-20, "database error");

  return true;
}

Value rpc_wallet_multisend(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() < 2 || params.size() > 4)
    throw runtime_error(
        "wallet.multisend <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
        "amounts are double-precision floating point numbers"
        + HelpRequiringPassphrase());

  string strAccount = AccountFromValue(params[0]);
  Object sendTo = params[1].get_obj();
  int nMinDepth = 1;
  if (params.size() > 2)
    nMinDepth = params[2].get_int();

  CWalletTx wtx;
  wtx.strFromAccount = strAccount;
  if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
    wtx.mapValue["comment"] = params[3].get_str();

  set<CCoinAddr> setAddress;
  vector<pair<CScript, int64> > vecSend;

  int64 totalAmount = 0;
  BOOST_FOREACH(const Pair& s, sendTo)
  {
    CCoinAddr address(s.name_);
    if (!address.IsValid())
      throw JSONRPCError(-5, string("Invalid coin address:")+s.name_);

    if (setAddress.count(address))
      throw JSONRPCError(-8, string("Invalid parameter, duplicated address: ")+s.name_);
    setAddress.insert(address);

    CScript scriptPubKey;
    scriptPubKey.SetDestination(address.Get());
    int64 nAmount = AmountFromValue(s.value_);
    totalAmount += nAmount;

    vecSend.push_back(make_pair(scriptPubKey, nAmount));
  }

  EnsureWalletIsUnlocked();

  // Check funds
  int64 nBalance = GetAccountBalance(ifaceIndex, strAccount, nMinDepth);
  if (totalAmount > nBalance)
    throw JSONRPCError(-6, "Account has insufficient funds");

  // Send
  CReserveKey keyChange(pwalletMain);
  int64 nFeeRequired = 0;
  bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired);
  if (!fCreated)
  {
    if (totalAmount + nFeeRequired > pwalletMain->GetBalance())
      throw JSONRPCError(-6, "Insufficient funds");
    throw JSONRPCError(-4, "Transaction creation failed");
  }
  if (!pwalletMain->CommitTransaction(wtx, keyChange))
    throw JSONRPCError(-4, "Transaction commit failed");

  return wtx.GetHash().GetHex();
}

Value rpc_wallet_newaddr(CIface *iface, const Array& params, bool fHelp)
{
  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.new <account>\n"
        "Returns a new address for receiving payments to the specified account.");

  // Parse the account first so we don't generate a key if there's an error
  string strAccount = AccountFromValue(params[0]);

  Value ret;

  ret = GetAccountAddress(GetWallet(iface), strAccount).ToString();

  return ret;
}

Value rpc_peer_add(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "peer.add <host>[:<port>]\n"
        "Submit a new peer connection for the coin server.\n");

  string strHost;
  CService vserv;
  char buf[256];
  char *ptr;
  int port;

  strHost = params[0].get_str();

  port = 0;
  memset(buf, 0, sizeof(buf));
  strncpy(buf, strHost.c_str(), sizeof(buf)-1);
  ptr = strchr(buf, ':');
  if (!ptr)
    ptr = strchr(buf, ' '); /* ipv6 */
  if (ptr) {
    port = atoi(ptr+1);
    *ptr = '\000';
  }
  if (port == 0)
    port = iface->port;

  if (Lookup(strHost.c_str(), vserv, port, false)) {
    shpeer_t *peer;
    char buf2[1024];
    char buf[1024];

    sprintf(buf, "%s %d", strHost.c_str(), port);
    peer = shpeer_init(iface->name, buf);
    create_uevent_connect_peer(GetCoinIndex(iface), peer); /* keep alloc'd */

    sprintf(buf2, "addpeer: initiating peer connection to '%s'.\n",
        shpeer_print(peer));
    unet_log(GetCoinIndex(iface), buf2);
  }

  return "initiated new peer connection.";
}

static void CopyNodeStats(CIface *iface, std::vector<CNodeStats>& vstats)
{
  NodeList &vNodes = GetNodeList(iface);

  vstats.clear();

  LOCK(cs_vNodes);
  vstats.reserve(vNodes.size());
  BOOST_FOREACH(CNode* pnode, vNodes) {
    CNodeStats stats;
    pnode->copyStats(stats);
    vstats.push_back(stats);
  }
}

Value rpc_peer_export(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "peer.export <path>\n"
        "Export entire database of network peers in JSON format.");

  std::string strPath = params[0].get_str();

  {
    FILE *fl;
//    shpeer_t *serv_peer;
    shjson_t *json;
    shdb_t *db;
    char *text;

//    serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

    db = shnet_track_open(iface->name);
    if (!db) 
      throw JSONRPCError(-5, "Error opening peer track database.");
    json = shdb_json(db, SHPREF_TRACK, 0, 0);
    text = shjson_print(json);
    shjson_free(&json);
    shnet_track_close(db);

    fl = fopen(strPath.c_str(), "wb");
    if (fl) {
      if (text)
        fwrite(text, sizeof(char), strlen(text), fl);
      fclose(fl);
    }
    free(text);

//    shpeer_free(&serv_peer);
  }


  Object result;
  result.push_back(Pair("mode", "peer.export"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "finished"));

  return (result);
}

Value rpc_peer_import(CIface *iface, const Array& params, bool fHelp)
{
  int ifaceIndex = GetCoinIndex(iface);
  FILE *fl;
  struct stat st;
  shpeer_t *peer;
  shjson_t *json;
  shjson_t *node;
  shdb_t *db;
  char hostname[PATH_MAX+1];
  char *text;

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "peer.import <path>\n"
        "Export entire database of network peers in JSON format.");

  std::string strPath = params[0].get_str();

  {
    fl = fopen(strPath.c_str(), "rb");
    if (!fl)
      throw runtime_error("error opening file.");

    memset(&st, 0, sizeof(st));
    fstat(fileno(fl), &st);
    if (st.st_size == 0)
      throw runtime_error("file is not in JSON format.");

    text = (char *)calloc(st.st_size + 1, sizeof(char));
    if (!text)
      throw runtime_error("not enough memory to allocate file.");

    fread(text, sizeof(char), st.st_size, fl);
    fclose(fl);
    
//    serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

    json = shjson_init(text);
    free(text);
    if (!json) {
      throw runtime_error("file is not is JSON format.");
    }

    if (json->child) {
      unet_bind_t *bind = unet_bind_table(ifaceIndex);
      if (bind && bind->peer_db) {
        for (node = json->child; node; node = node->next) {
          char *host = shjson_astr(node, "host", "");
          char *label = shjson_astr(node, "label", "");
          if (!*host || !*label) continue;

          peer = shpeer_init(label, host);
          shnet_track_add(bind->peer_db, peer);
          shpeer_free(&peer);
        }
      }
    }

    shjson_free(&json);
  }


  Object result;
  result.push_back(Pair("mode", "peer-import"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "finished"));

  return (result);
}


Value rpc_peer_list(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "peer.list\n"
        "Statistical and runtime information on network peers.");

  vector<CNodeStats> vstats;
  CopyNodeStats(iface, vstats);

  Array ret;

  BOOST_FOREACH(const CNodeStats& stats, vstats) {
    Object obj;

    obj.push_back(Pair("addr", stats.addrName));
    obj.push_back(Pair("services", strprintf("%08"PRI64x, stats.nServices)));
    obj.push_back(Pair("lastsend", (boost::int64_t)stats.nLastSend));
    obj.push_back(Pair("lastrecv", (boost::int64_t)stats.nLastRecv));
    obj.push_back(Pair("conntime", (boost::int64_t)stats.nTimeConnected));
    obj.push_back(Pair("version", stats.nVersion));
    obj.push_back(Pair("subver", stats.strSubVer));
    obj.push_back(Pair("inbound", stats.fInbound));
    obj.push_back(Pair("releasetime", (boost::int64_t)stats.nReleaseTime));
    obj.push_back(Pair("startingheight", stats.nStartingHeight));
    obj.push_back(Pair("banscore", stats.nMisbehavior));

    ret.push_back(obj);
  }

  return ret;
}

Value rpc_peer_importdat(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "peer.importdat <path>\n"
        "Import a legacy 'peers.dat' datafile.");

  std::string strPath = params[0].get_str();

  int ifaceIndex = GetCoinIndex(iface);
  char addr_str[256];
  shpeer_t *peer;
  shpeer_t *serv_peer;

  if (!iface)
    throw runtime_error("peer db not available.");

//  serv_peer = shapp_init("shcoind", NULL, SHAPP_LOCAL);

  CAddrMan addrman;
  {
    long nStart = GetTimeMillis();
    {
      CAddrDB adb(strPath.c_str());
      if (!adb.Read(addrman))
        throw runtime_error("specified path is not a peers.dat database.");
    }
    Debug("Exported %d addresses from peers.dat  %dms\n",
        (int)addrman.size(), (int)(GetTimeMillis() - nStart));
  }

  vector<CAddress> vAddr = addrman.GetAddr();

  unet_bind_t *bind = unet_bind_table(ifaceIndex);
  if (bind && bind->peer_db) {
    BOOST_FOREACH(const CAddress &addr, vAddr) {
      sprintf(addr_str, "%s %d", addr.ToStringIP().c_str(), addr.GetPort());
      peer = shpeer_init(iface->name, addr_str);
      shnet_track_add(bind->peer_db, peer);
      shpeer_free(&peer);
    }
  }


  Object result;
  result.push_back(Pair("mode", "peer.importdat"));
  result.push_back(Pair("path", strPath.c_str()));
  result.push_back(Pair("state", "success"));

  return (result);
}






#if 0 
Value getmininginfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getmininginfo\n"
            "Returns an object containing mining-related information.");

    Object obj;
    obj.push_back(Pair("blocks",        (int)nBestHeight));
    obj.push_back(Pair("currentblocksize",(uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblocktx",(uint64_t)nLastBlockTx));
    obj.push_back(Pair("difficulty",    (double)GetDifficulty()));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    obj.push_back(Pair("networkhashps", getnetworkhashps(params, false)));
    obj.push_back(Pair("pooledtx",      (uint64_t)mempool.size()));
    obj.push_back(Pair("testnet",       fTestNet));
    return obj;
}
#endif


#if 0
Value getnewaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnewaddress [account]\n"
            "Returns a new coin address for receiving payments.  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey, false))
        throw JSONRPCError(-12, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBookName(keyID, strAccount);

    return CCoinAddr(keyID).ToString();
}
#endif


#if 0
Value getaccountaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccountaddress <account>\n"
            "Returns the current coin address for receiving payments to this account.");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]);

    Value ret;

    ret = GetAccountAddress(pwalletMain, strAccount).ToString();

    return ret;
}
#endif






Value settxfee(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    // Amount
    int64 nAmount = 0;
    if (params[0].get_real() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nTransactionFee = nAmount;
    return true;
}

#if 0
Value setmininput(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "setmininput <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    // Amount
    int64 nAmount = 0;
    if (params[0].get_real() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nMinimumInputValue = nAmount;
    return true;
}
#endif

#if 0
Value sendtoaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendtoaddress <coin-address> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001"
            + HelpRequiringPassphrase());

    CCoinAddr address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(-5, "Invalid coin address");

    // Amount
    int64 nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 2 && params[2].type() != null_type && !params[2].get_str().empty())
        wtx.mapValue["comment"] = params[2].get_str();
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["to"]      = params[3].get_str();

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(-4, strError);

    return wtx.GetHash().GetHex();
}
#endif

#if 0
Value signmessage(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signmessage <coin-address> <message>\n"
            "Sign a message with the private key of an address");

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    string strMessage = params[1].get_str();

    CCoinAddr addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(-3, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(-3, "Address does not refer to key");

    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        throw JSONRPCError(-4, "Private key not available");

    CDataStream ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(Hash(ss.begin(), ss.end()), vchSig))
        throw JSONRPCError(-5, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

Value verifymessage(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage <coin-address> <signature> <message>\n"
            "Verify a signed message");

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();

    CCoinAddr addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(-3, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(-3, "Address does not refer to key");

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(-5, "Malformed base64 encoding");

    CDataStream ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CKey key;
    if (!key.SetCompactSignature(Hash(ss.begin(), ss.end()), vchSig))
        return false;

    return (key.GetPubKey().GetID() == keyID);
}
#endif






#if 0
int64 GetAccountBalance(const string& strAccount, int nMinDepth)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth);
}


Value getbalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getbalance [account] [minconf=1]\n"
            "If [account] is not specified, returns the server's total available balance.\n"
            "If [account] is specified, returns the balance in the account.");

    if (params.size() == 0)
        return  ValueFromAmount(pwalletMain->GetBalance());

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    if (params[0].get_str() == "*") {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and getbalance '*' should always return the same number.
        int64 nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (!wtx.IsFinal())
                continue;

            int64 allGeneratedImmature, allGeneratedMature, allFee;
            allGeneratedImmature = allGeneratedMature = allFee = 0;
            string strSentAccount;
            list<pair<CTxDestination, int64> > listReceived;
            list<pair<CTxDestination, int64> > listSent;
            wtx.GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount);
            if (wtx.GetDepthInMainChain(ifaceIndex) >= nMinDepth)
            {
                BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listReceived)
                    nBalance += r.second;
            }
            BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listSent)
                nBalance -= r.second;
            nBalance -= allFee;
            nBalance += allGeneratedMature;
        }
        return  ValueFromAmount(nBalance);
    }

    string strAccount = AccountFromValue(params[0]);

    int64 nBalance = GetAccountBalance(strAccount, nMinDepth);

    return ValueFromAmount(nBalance);
}
#endif


#if 0
Value movecmd(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
            "Move from one account in your wallet to another.");

    string strFrom = AccountFromValue(params[0]);
    string strTo = AccountFromValue(params[1]);
    int64 nAmount = AmountFromValue(params[2]);
    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    if (!walletdb.TxnBegin())
        throw JSONRPCError(-20, "database error");

    int64 nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    walletdb.WriteAccountingEntry(debit);

    // Credit
    CAccountingEntry credit;
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    walletdb.WriteAccountingEntry(credit);

    if (!walletdb.TxnCommit())
        throw JSONRPCError(-20, "database error");

    return true;
}
#endif


#if 0
Value sendfrom(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 6)
        throw runtime_error(
            "sendfrom <fromaccount> <to-address> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001"
            + HelpRequiringPassphrase());

    string strAccount = AccountFromValue(params[0]);
    CCoinAddr address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(-5, "Invalid coin address");
    int64 nAmount = AmountFromValue(params[2]);
    int nMinDepth = 1;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str();
    if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
        wtx.mapValue["to"]      = params[5].get_str();

    EnsureWalletIsUnlocked();

    // Check funds
    int64 nBalance = GetAccountBalance(strAccount, nMinDepth);
    if (nAmount > nBalance)
        throw JSONRPCError(-6, "Account has insufficient funds");

    // Send
    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(-4, strError);

    return wtx.GetHash().GetHex();
}
#endif


#if 0
Value sendmany(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers"
            + HelpRequiringPassphrase());

    string strAccount = AccountFromValue(params[0]);
    Object sendTo = params[1].get_obj();
    int nMinDepth = 1;
    if (params.size() > 2)
        nMinDepth = params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();

    set<CCoinAddr> setAddress;
    vector<pair<CScript, int64> > vecSend;

    int64 totalAmount = 0;
    BOOST_FOREACH(const Pair& s, sendTo)
    {
        CCoinAddr address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(-5, string("Invalid coin address:")+s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(-8, string("Invalid parameter, duplicated address: ")+s.name_);
        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        int64 nAmount = AmountFromValue(s.value_);
        totalAmount += nAmount;

        vecSend.push_back(make_pair(scriptPubKey, nAmount));
    }

    EnsureWalletIsUnlocked();

    // Check funds
    int64 nBalance = GetAccountBalance(strAccount, nMinDepth);
    if (totalAmount > nBalance)
        throw JSONRPCError(-6, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwalletMain);
    int64 nFeeRequired = 0;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired);
    if (!fCreated)
    {
        if (totalAmount + nFeeRequired > pwalletMain->GetBalance())
            throw JSONRPCError(-6, "Insufficient funds");
        throw JSONRPCError(-4, "Transaction creation failed");
    }
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(-4, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}
#endif

#if 0
Value addmultisigaddress(const Array& params, bool fHelp)
{

  
    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        string msg = "addmultisigaddress <nrequired> <'[\"key\",\"key\"]'> [account]\n"
            "Add a nrequired-to-sign multisignature address to the wallet\"\n"
            "each key is a coin address or hex-encoded public key\n"
            "If [account] is specified, assign address to [account].";
        throw runtime_error(msg);
    }

    int nRequired = params[0].get_int();
    const Array& keys = params[1].get_array();
    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %d keys, but need at least %d to redeem)", keys.size(), nRequired));
    std::vector<CKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();

        // Case 1: coin address and we have full public key:
        CCoinAddr address(ks);
        if (address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("%s does not refer to a key",ks.c_str()));
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("no full public key for address %s",ks.c_str()));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
                throw runtime_error(" Invalid public key: "+ks);
        }

        // Case 2: hex public key
        else if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
                throw runtime_error(" Invalid public key: "+ks);
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner;
    inner.SetMultisig(nRequired, pubkeys);
    CScriptID innerID = inner.GetID();
    pwalletMain->AddCScript(inner);

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return CCoinAddr(innerID).ToString();
}
#endif



#if 0
Value listreceivedbyaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaddress [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include addresses that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"address\" : receiving address\n"
            "  \"account\" : the account of the receiving address\n"
            "  \"amount\" : total amount received by the address\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(pwalletMain, params, false);
}
#endif

#if 0
Value listreceivedbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaccount [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include accounts that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"account\" : the account of the receiving addresses\n"
            "  \"amount\" : total amount received by addresses with this account\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(pwalletMain, params, true);
}
#endif

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        Object entry;
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", (boost::int64_t)acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

#if 0
Value listtransactions(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listtransactions [account] [count=10] [from=0]\n"
            "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();

    if (nCount < 0)
        throw JSONRPCError(-8, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(-8, "Negative from");

    Array ret;
    CWalletDB walletdb(pwalletMain->strWalletFile);

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
    typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef multimap<int64, TxPair > TxItems;
    TxItems txByTime;

    // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
    // would make this much faster for applications that do this a lot.
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txByTime.insert(make_pair(wtx->GetTxTime(), TxPair(wtx, (CAccountingEntry*)0)));
    }
    list<CAccountingEntry> acentries;
    walletdb.ListAccountCreditDebit(strAccount, acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
    }

    // iterate backwards until we have nCount items to return:
    for (TxItems::reverse_iterator it = txByTime.rbegin(); it != txByTime.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount+nFrom)) break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;
    Array::iterator first = ret.begin();
    std::advance(first, nFrom);
    Array::iterator last = ret.begin();
    std::advance(last, nFrom+nCount);

    if (last != ret.end()) ret.erase(last, ret.end());
    if (first != ret.begin()) ret.erase(ret.begin(), first);

    std::reverse(ret.begin(), ret.end()); // Return oldest to newest

    return ret;
}
#endif

#if 0
Value listaccounts(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "listaccounts [minconf=1]\n"
            "Returns Object that has account names as keys, account balances as values.");

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    map<string, int64> mapAccountBalances;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
        if (IsMine(*pwalletMain, entry.first)) // This address belongs to me
            mapAccountBalances[entry.second] = 0;
    }

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        int64 nGeneratedImmature, nGeneratedMature, nFee;
        string strSentAccount;
        list<pair<CTxDestination, int64> > listReceived;
        list<pair<CTxDestination, int64> > listSent;
        wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount);
        mapAccountBalances[strSentAccount] -= nFee;
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& s, listSent)
            mapAccountBalances[strSentAccount] -= s.second;
        if (wtx.GetDepthInMainChain() >= nMinDepth)
        {
            mapAccountBalances[""] += nGeneratedMature;
            BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& r, listReceived)
                if (pwalletMain->mapAddressBook.count(r.first))
                    mapAccountBalances[pwalletMain->mapAddressBook[r.first]] += r.second;
                else
                    mapAccountBalances[""] += r.second;
        }
    }

    list<CAccountingEntry> acentries;
    CWalletDB(pwalletMain->strWalletFile).ListAccountCreditDebit("*", acentries);
    BOOST_FOREACH(const CAccountingEntry& entry, acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    Object ret;
    BOOST_FOREACH(const PAIRTYPE(string, int64)& accountBalance, mapAccountBalances) {
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
    }
    return ret;
}
#endif

#if 0
Value listsinceblock(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listsinceblock [blockhash] [target-confirmations]\n"
            "Get all transactions in blocks since block [blockhash], or all transactions if omitted");

    CBlockIndex *pindex = NULL;
    int target_confirms = 1;

    if (params.size() > 0)
    {
        uint256 blockId = 0;

        blockId.SetHex(params[0].get_str());
        pindex = CBlockLocator(blockId).GetBlockIndex();
    }

    if (params.size() > 1)
    {
        target_confirms = params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(-8, "Invalid parameter");
    }

    int depth = pindex ? (1 + nBestHeight - pindex->nHeight) : -1;

    Array transactions;

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListTransactions(tx, "*", 0, true, transactions);
    }

    uint256 lastblock;

    if (target_confirms == 1)
    {
        lastblock = hashBestChain;
    }
    else
    {
        int target_height = pindexBest->nHeight + 1 - target_confirms;

        CBlockIndex *block;
        for (block = pindexBest;
             block && block->nHeight > target_height;
             block = block->pprev)  { }

        lastblock = block ? block->GetBlockHash() : 0;
    }

    Object ret;
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}
#endif

#if 0
Value gettransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gettransaction <txid>\n"
            "Get detailed information about in-wallet transaction <txid>");

    uint256 hash;
    hash.SetHex(params[0].get_str());

    Object entry;
    if (!pwalletMain->mapWallet.count(hash))
        throw JSONRPCError(-5, "Invalid or non-wallet transaction id");
    const CWalletTx& wtx = pwalletMain->mapWallet[hash];

    int64 nCredit = wtx.GetCredit();
    int64 nDebit = wtx.GetDebit();
    int64 nNet = nCredit - nDebit;
    int64 nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);

    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
    if (wtx.IsFromMe())
        entry.push_back(Pair("fee", ValueFromAmount(nFee)));

    WalletTxToJSON(wtx, entry);

    Array details;
    ListTransactions(wtx, "*", 0, false, details);
    entry.push_back(Pair("details", details));

    return entry;
}
#endif


#if 0
Value backupwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "backupwallet <destination>\n"
            "Safely copies wallet.dat to destination, which can be a directory or a path with filename.");

    string strDest = params[0].get_str();
    BackupWallet(*pwalletMain, strDest);

    return Value::null;
}
#endif

#if 0
Value keypoolrefill(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "keypoolrefill\n"
            "Fills the keypool."
            + HelpRequiringPassphrase());

    EnsureWalletIsUnlocked();

    pwalletMain->TopUpKeyPool();

    if (pwalletMain->GetKeyPoolSize() < GetArg("-keypool", 100))
        throw JSONRPCError(-4, "Error refreshing keypool.");

    return Value::null;
}
#endif


#if 0
void ThreadTopUpKeyPool(void* parg)
{
    // Make this thread recognisable as the key-topping-up thread
    RenameThread("bitcoin-key-top");

    pwalletMain->TopUpKeyPool();
}
#endif

#if 0
void ThreadCleanWalletPassphrase(void* parg)
{
    // Make this thread recognisable as the wallet relocking thread
    RenameThread("bitcoin-lock-wa");

    int64 nMyWakeTime = GetTimeMillis() + *((int64*)parg) * 1000;

    ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);

    if (nWalletUnlockTime == 0)
    {
        nWalletUnlockTime = nMyWakeTime;

        do
        {
            if (nWalletUnlockTime==0)
                break;
            int64 nToSleep = nWalletUnlockTime - GetTimeMillis();
            if (nToSleep <= 0)
                break;

            LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);
            Sleep(nToSleep);
            ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);

        } while(1);

        if (nWalletUnlockTime)
        {
            nWalletUnlockTime = 0;
            pwalletMain->Lock();
        }
    }
    else
    {
        if (nWalletUnlockTime < nMyWakeTime)
            nWalletUnlockTime = nMyWakeTime;
    }

    LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);

    delete (int64*)parg;
}
#endif

#if 0
Value walletpassphrase(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    if (!pwalletMain->IsLocked())
        throw JSONRPCError(-17, "Error: Wallet is already unlocked.");

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
            throw JSONRPCError(-14, "Error: The wallet passphrase entered was incorrect.");
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    CreateThread(ThreadTopUpKeyPool, NULL);
    int64* pnSleepTime = new int64(params[1].get_int64());
    CreateThread(ThreadCleanWalletPassphrase, pnSleepTime);

    return Value::null;
}
#endif


#if 0
Value walletpassphrasechange(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
        throw JSONRPCError(-14, "Error: The wallet passphrase entered was incorrect.");

    return Value::null;
}
#endif


#if 0
Value walletlock(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 0))
        throw runtime_error(
            "walletlock\n"
            "Removes the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an unencrypted wallet, but walletlock was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        pwalletMain->Lock();
        nWalletUnlockTime = 0;
    }

    return Value::null;
}
#endif


#if 0
Value encryptwallet(const Array& params, bool fHelp)
{
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() != 1))
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");
    if (fHelp)
        return true;
    if (pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an encrypted wallet, but encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwalletMain->EncryptWallet(strWalletPass))
        throw JSONRPCError(-16, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys.  So:
    StartServerShutdown();
    return "wallet encrypted; coin server stopping, restart to run with encrypted wallet";
}
#endif

#if 0
class DescribeAddressVisitor : public boost::static_visitor<Object>
{
public:
    Object operator()(const CNoDestination &dest) const { return Object(); }

    Object operator()(const CKeyID &keyID) const {
        Object obj;
        CPubKey vchPubKey;
        pwalletMain->GetPubKey(keyID, vchPubKey);
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("pubkey", HexStr(vchPubKey.Raw())));
        obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        return obj;
    }

    Object operator()(const CScriptID &scriptID) const {
        Object obj;
        obj.push_back(Pair("isscript", true));
        CScript subscript;
        pwalletMain->GetCScript(scriptID, subscript);
        std::vector<CTxDestination> addresses;
        txnouttype whichType;
        int nRequired;
        ExtractDestinations(subscript, whichType, addresses, nRequired);
        obj.push_back(Pair("script", GetTxnOutputType(whichType)));
        Array a;
        BOOST_FOREACH(const CTxDestination& addr, addresses)
            a.push_back(CCoinAddr(addr).ToString());
        obj.push_back(Pair("addresses", a));
        if (whichType == TX_MULTISIG)
            obj.push_back(Pair("sigsrequired", nRequired));
        return obj;
    }
};
#endif




#if 0
Value getblocktemplate(const Array& params, bool fHelp)
{
  if (fHelp || params.size() != 1)
    throw runtime_error(
        "getblocktemplate [params]\n"
        "If [params] does not contain a \"data\" key, returns data needed to construct a block to work on:\n"
        "  \"version\" : block version\n"
        "  \"previousblockhash\" : hash of current highest block\n"
        "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
        "  \"coinbaseaux\" : data that should be included in coinbase\n"
        "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
        "  \"target\" : hash target\n"
        "  \"mintime\" : minimum timestamp appropriate for next block\n"
        "  \"curtime\" : current timestamp\n"
        "  \"mutable\" : list of ways the block template may be changed\n"
        "  \"noncerange\" : range of valid nonces\n"
        "  \"sigoplimit\" : limit of sigops in blocks\n"
        "  \"sizelimit\" : limit of block size\n"
        "  \"bits\" : compressed target of next block\n"
        "  \"height\" : height of the next block\n"
        "If [params] does contain a \"data\" key, tries to solve the block and returns null if it was successful (and \"rejected\" if not)\n"
        "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

                                                                           const Object& oparam = params[0].get_obj();
                                                                           std::string strMode;
                                                                           {
                                                                             const Value& modeval = find_value(oparam, "mode");
                                                                             if (modeval.type() == str_type)
                                                                               strMode = modeval.get_str();
                                                                             else
                                                                               if (find_value(oparam, "data").type() == null_type)
                                                                                 strMode = "template";
                                                                               else
                                                                                 strMode = "submit";
                                                                           }

                                                                           if (strMode == "template")
                                                                           {
                                                                             if (vNodes.empty())
                                                                               throw JSONRPCError(-9, "coin is not connected!");

                                                                             if (IsInitialBlockDownload())
                                                                               throw JSONRPCError(-10, "coin is downloading blocks...");

                                                                             static CReserveKey reservekey(pwalletMain);

                                                                             // Update block
                                                                             static unsigned int nTransactionsUpdatedLast;
                                                                             static CBlockIndex* pindexPrev;
                                                                             static int64 nStart;
                                                                             static CBlock* pblock;
                                                                             if (pindexPrev != pindexBest ||
                                                                                 (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 5))
                                                                             {
                                                                               nTransactionsUpdatedLast = nTransactionsUpdated;
                                                                               pindexPrev = pindexBest;
                                                                               nStart = GetTime();

                                                                               // Create new block
                                                                               if(pblock)
                                                                                 delete pblock;
                                                                               pblock = CreateNewBlock(reservekey);
                                                                               if (!pblock)
                                                                                 throw JSONRPCError(-7, "Out of memory");
                                                                             }

                                                                             // Update nTime
                                                                             pblock->UpdateTime(pindexPrev);
                                                                             pblock->nNonce = 0;

                                                                             Array transactions;
                                                                             map<uint256, int64_t> setTxIndex;
                                                                             int i = 0;
                                                                             CTxDB txdb(ifaceIndex, "r");
                                                                             BOOST_FOREACH (CTransaction& tx, pblock->vtx)
                                                                             {
                                                                               uint256 txHash = tx.GetHash();
                                                                               setTxIndex[txHash] = i++;

                                                                               if (tx.IsCoinBase())
                                                                                 continue;

                                                                               Object entry;

                                                                               CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
                                                                               ssTx << tx;
                                                                               entry.push_back(Pair("data", HexStr(ssTx.begin(), ssTx.end())));

                                                                               entry.push_back(Pair("hash", txHash.GetHex()));

                                                                               MapPrevTx mapInputs;
                                                                               map<uint256, CTxIndex> mapUnused;
                                                                               bool fInvalid = false;
                                                                               if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
                                                                               {
                                                                                 entry.push_back(Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));

                                                                                 Array deps;
                                                                                 BOOST_FOREACH (MapPrevTx::value_type& inp, mapInputs)
                                                                                 {
                                                                                   if (setTxIndex.count(inp.first))
                                                                                     deps.push_back(setTxIndex[inp.first]);
                                                                                 }
                                                                                 entry.push_back(Pair("depends", deps));

                                                                                 int64_t nSigOps = tx.GetLegacySigOpCount();
                                                                                 nSigOps += tx.GetP2SHSigOpCount(mapInputs);
                                                                                 entry.push_back(Pair("sigops", nSigOps));
                                                                               }

                                                                               transactions.push_back(entry);
                                                                             }
                                                                             txdb.Close();

                                                                             Object aux;
                                                                             aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

                                                                             uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

                                                                             static Array aMutable;
                                                                             if (aMutable.empty())
                                                                             {
                                                                               aMutable.push_back("time");
                                                                               aMutable.push_back("transactions");
                                                                               aMutable.push_back("prevblock");
                                                                             }

                                                                             Object result;
                                                                             result.push_back(Pair("version", pblock->nVersion));
                                                                             result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
                                                                             result.push_back(Pair("transactions", transactions));
                                                                             result.push_back(Pair("coinbaseaux", aux));
                                                                             result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
                                                                             result.push_back(Pair("target", hashTarget.GetHex()));
                                                                             result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
                                                                             result.push_back(Pair("mutable", aMutable));
                                                                             result.push_back(Pair("noncerange", "00000000ffffffff"));
                                                                             result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS));
                                                                             result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE));
                                                                             result.push_back(Pair("curtime", (int64_t)pblock->nTime));
                                                                             result.push_back(Pair("bits", HexBits(pblock->nBits)));
                                                                             result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));

                                                                             return result;
                                                                           }
                                                                           else
                                                                             if (strMode == "submit")
                                                                             {
                                                                               // Parse parameters
                                                                               CDataStream ssBlock(ParseHex(find_value(oparam, "data").get_str()), SER_NETWORK, PROTOCOL_VERSION);
                                                                               CBlock pblock;
                                                                               ssBlock >> pblock;

                                                                               bool fAccepted = ProcessBlock(NULL, &pblock);

                                                                               return fAccepted ? Value::null : "rejected";
                                                                             }

                                                                           throw JSONRPCError(-8, "Invalid mode");
}
#endif

#if 0
Value getrawmempool(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");

    vector<uint256> vtxid;
    mempool.queryHashes(vtxid);

    Array a;
    BOOST_FOREACH(const uint256& hash, vtxid)
        a.push_back(hash.ToString());

    return a;
}
#endif

#if 0
Value getblockhash(const Array& params, bool fHelp)
{
  if (fHelp || params.size() != 1)
    throw runtime_error(
        "getblockhash <index>\n"
        "Returns hash of block in best-block-chain at <index>.");

  int nHeight = params[0].get_int();
  if (nHeight < 0 || nHeight > nBestHeight)
    throw runtime_error("Block number out of range.");
  {
    bc_t *bc = GetBlockChain(GetCoinByIndex(USDE_COIN_IFACE));
    bc_hash_t ret_hash;
    int err;

    err = bc_get_hash(bc, nHeight, ret_hash);
    if (!err) {
      uint256 hash;
      hash.SetRaw((unsigned int *)ret_hash);
    }
  }

  CBlockIndex* pblockindex = mapBlockIndex[hashBestChain];
  while (pblockindex->nHeight > nHeight)
    pblockindex = pblockindex->pprev;
  return pblockindex->phashBlock->GetHex();
}
#endif

#if 0
Value getblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblock <hash>\n"
            "Returns details of a block with given block-hash.");

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(-5, "Block not found");

    USDEBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex);
}
#endif

Value rpc_tx_decode(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "tx.decode <hex string>\n"
        "Return a JSON object representing the serialized, hex-encoded transaction.");

  int ifaceIndex = GetCoinIndex(iface);
  RPCTypeCheck(params, list_of(str_type));
  vector<unsigned char> txData(ParseHex(params[0].get_str()));
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION(iface));
  CTransaction tx;
  try {
    ssData >> tx;
  }
  catch (std::exception &e) {
    throw JSONRPCError(-22, "TX decode failed");
  }

  return (tx.ToValue(ifaceIndex));
}

Value rpc_tx_list(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() > 3)
    throw runtime_error(
        "tx.list [account] [count=10] [from=0]\n"
        "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");

  string strAccount = "*";
  if (params.size() > 0)
    strAccount = params[0].get_str();
  int nCount = 10;
  if (params.size() > 1)
    nCount = params[1].get_int();
  int nFrom = 0;
  if (params.size() > 2)
    nFrom = params[2].get_int();

  if (nCount < 0)
    throw JSONRPCError(-8, "Negative count");
  if (nFrom < 0)
    throw JSONRPCError(-8, "Negative from");

  Array ret;
  CWalletDB walletdb(pwalletMain->strWalletFile);

  // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
  typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
  typedef multimap<int64, TxPair > TxItems;
  TxItems txByTime;

  // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
  // would make this much faster for applications that do this a lot.
  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
  {
    CWalletTx* wtx = &((*it).second);
    txByTime.insert(make_pair(wtx->GetTxTime(), TxPair(wtx, (CAccountingEntry*)0)));
  }
  list<CAccountingEntry> acentries;
  walletdb.ListAccountCreditDebit(strAccount, acentries);
  BOOST_FOREACH(CAccountingEntry& entry, acentries)
  {
    txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
  }

  // iterate backwards until we have nCount items to return:
  for (TxItems::reverse_iterator it = txByTime.rbegin(); it != txByTime.rend(); ++it)
  {
    CWalletTx *const pwtx = (*it).second.first;
    if (pwtx != 0)
      ListTransactions(ifaceIndex, *pwtx, strAccount, 0, true, ret);
    CAccountingEntry *const pacentry = (*it).second.second;
    if (pacentry != 0)
      AcentryToJSON(*pacentry, strAccount, ret);

    if ((int)ret.size() >= (nCount+nFrom)) break;
  }
  // ret is newest to oldest

  if (nFrom > (int)ret.size())
    nFrom = ret.size();
  if ((nFrom + nCount) > (int)ret.size())
    nCount = ret.size() - nFrom;
  Array::iterator first = ret.begin();
  std::advance(first, nFrom);
  Array::iterator last = ret.begin();
  std::advance(last, nFrom+nCount);

  if (last != ret.end()) ret.erase(last, ret.end());
  if (first != ret.begin()) ret.erase(ret.begin(), first);

  std::reverse(ret.begin(), ret.end()); // Return oldest to newest

  return ret;
}

Value rpc_tx_pool(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "tx.pool\n"
        "Returns all transaction awaiting confirmation.");

  CTxMemPool *pool = GetTxMemPool(iface);
  int ifaceIndex = GetCoinIndex(iface);

  Array a;
  Object obj;
  if (pool) {
    LOCK(pool->cs);

    BOOST_FOREACH(const PAIRTYPE(uint256, CTransaction)& r, pool->mapTx) {
      CTransaction *tx = (CTransaction *)(&r.second);
      a.push_back(tx->ToValue(ifaceIndex));
    }
  }

  return a;
}

Value rpc_tx_prune(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "tx.prune\n"
        "Revert pool transactions with an unknown or spent input.\n"
        );

  CTxMemPool *pool = GetTxMemPool(iface);
  CWallet *wallet = GetWallet(iface);

  Array a;
  if (iface->enabled && pool && wallet) {
    LOCK(pool->cs);

    vector<uint256> pool_revert; 
    BOOST_FOREACH(const PAIRTYPE(uint256, CTransaction)& r, pool->mapTx) {
      const CTransaction& tx = r.second;
      vector<CWalletTx> revert;
      bool fValid = true;

      BOOST_FOREACH(const CTxIn& in, tx.vin) {
        if (pool->mapTx.count(in.prevout.hash) != 0)
          continue; /* dependant on another tx in pool */

        CTransaction prevtx;
        const uint256& prevhash = in.prevout.hash;

        if (!GetTransaction(iface, prevhash, prevtx, NULL)) {
          /* the input tx is unknown. */
          fValid = false;
          continue;
        }

        const CTxOut& out = prevtx.vout[in.prevout.n];
        if (!wallet->IsMine(out)) {
          /* we are attempting to spend someone else's input */
          fValid = false;
          continue;
        }

        CWalletTx wtx(wallet, prevtx);
        if (wtx.IsSpent(in.prevout.n)) {
          /* we are attempting to double-spend */
          revert.push_back(wtx);
          fValid = false;
          continue;
        }
      }
      if (fValid)
        continue; /* a-ok boss */

      BOOST_FOREACH(const CWalletTx& wtx, revert) {
        /* insert prevout transaction back into wallet. */
        uint256 tx_hash = wtx.GetHash();
        wallet->mapWallet[tx_hash] = wtx;
      }

      pool_revert.push_back(tx.GetHash());
    }

    /* erase invalid entries from pool */
    BOOST_FOREACH(uint256 hash, pool_revert) {
      pool->mapTx.erase(hash);
    }
  }

  return a;
}

Value rpc_tx_purge(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 0)
    throw runtime_error(
        "tx.purge\n"
        "Reverts all transaction awaiting confirmation.");

  CTxMemPool *pool = GetTxMemPool(iface);
  CWallet *wallet = GetWallet(iface);

  Array a;
  Object obj;
  if (iface->enabled && pool && wallet) {
    LOCK(pool->cs);

    BOOST_FOREACH(const PAIRTYPE(uint256, CTransaction)& r, pool->mapTx) {
      const CTransaction& tx = r.second;
      CTransaction prevtx;

      BOOST_FOREACH(const CTxIn& in, tx.vin) {
        const uint256& prevhash = in.prevout.hash;

        if (pool->mapTx.count(prevhash) != 0)
          continue; /* moot */

        if (!GetTransaction(iface, prevhash, prevtx, NULL))
          continue; /* dito */

        if (!wallet->IsMine(prevtx))
          continue; /* no longer owner */

        CWalletTx wtx(wallet, prevtx);
        if (wtx.IsSpent(in.prevout.n))
          continue; /* already spent */

        /* push pool transaction's inputs back into wallet. */
        uint256 tx_hash = wtx.GetHash();
        wallet->mapWallet[tx_hash] = wtx;

        a.push_back(tx_hash.GetHex());
      }
    }

    pool->mapTx.clear();
  }

  return a;
}


Value rpc_addmultisigaddress(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        string msg = "addmultisigaddress <nrequired> <'[\"key\",\"key\"]'> [account]\n"
            "Add a nrequired-to-sign multisignature address to the wallet\"\n"
            "each key is a coin address or hex-encoded public key\n"
            "If [account] is specified, assign address to [account].";
        throw runtime_error(msg);
    }

    int nRequired = params[0].get_int();
    const Array& keys = params[1].get_array();
    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %d keys, but need at least %d to redeem)", keys.size(), nRequired));
    std::vector<CKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();

        // Case 1: coin address and we have full public key:
        CCoinAddr address(ks);
        if (address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("%s does not refer to a key",ks.c_str()));
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("no full public key for address %s",ks.c_str()));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
                throw runtime_error(" Invalid public key: "+ks);
        }

        // Case 2: hex public key
        else if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
                throw runtime_error(" Invalid public key: "+ks);
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner;
    inner.SetMultisig(nRequired, pubkeys);
    CScriptID innerID = inner.GetID();
    pwalletMain->AddCScript(inner);

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return CCoinAddr(innerID).ToString();
}

Value rpc_tx_get(CIface *iface, const Array& params, bool fHelp)
{
  int ifaceIndex = GetCoinIndex(iface);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
  CWallet *pwalletMain = GetWallet(iface);

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "tx.get <txid>\n"
        "Get detailed information about a block transaction."
        );

  uint256 hash;
  hash.SetHex(params[0].get_str());


  CTransaction tx;
  uint256 hashBlock;

  if (!tx.ReadTx(ifaceIndex, hash, &hashBlock))
    throw JSONRPCError(-5, "Invalid transaction id");

  Object entry = tx.ToValue(ifaceIndex);

  if (hashBlock != 0)
  {
    entry.push_back(Pair("blockhash", hashBlock.GetHex()));
    map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hashBlock);
    if (mi != blockIndex->end() && (*mi).second)
    {
      CBlockIndex* pindex = (*mi).second;
      if (pindex->IsInMainChain(ifaceIndex))
      {
        entry.push_back(Pair("confirmations", (int)(1 + GetBestHeight(iface) - pindex->nHeight)));
        entry.push_back(Pair("time", (boost::int64_t)pindex->nTime));
      }
      else
        entry.push_back(Pair("confirmations", 0));
    }
  }

  return entry;
}

Value rpc_wallet_tx(CIface *iface, const Array& params, bool fHelp)
{
  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.tx <txid>\n"
        "Get detailed information about in-wallet transaction <txid>");

  uint256 hash;
  hash.SetHex(params[0].get_str());

  Object entry;

  if (pwalletMain->mapWallet.count(hash))
    throw JSONRPCError(-5, "Invalid transaction id");

  const CWalletTx& wtx = pwalletMain->mapWallet[hash];

  int64 nCredit = wtx.GetCredit();
  int64 nDebit = wtx.GetDebit();
  int64 nNet = nCredit - nDebit;
  int64 nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);

  entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
  if (wtx.IsFromMe())
    entry.push_back(Pair("fee", ValueFromAmount(nFee)));

  WalletTxToJSON(ifaceIndex, wtx, entry);

  Array details;
  ListTransactions(ifaceIndex, wtx, "*", 0, true, details);
  entry.push_back(Pair("details", details));

  return entry;
}

Value rpc_wallet_keyphrase(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() != 1)
    throw runtime_error(
        "wallet.keyphrase <address>\n"
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
        "The entire wallet can be exported to a file via the 'wallet.export' command.\n"
        );

  CWallet *pwalletMain = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strAddress = params[0].get_str();
  CCoinAddr address(ifaceIndex);
  if (!address.SetString(strAddress))
    throw JSONRPCError(-5, "Invalid address");
  CKeyID keyID;
  if (!address.GetKeyID(keyID))
    throw JSONRPCError(-3, "Address does not refer to a key");
  CSecret vchSecret;
  bool fCompressed;
  if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
    throw JSONRPCError(-4,"Private key for address " + strAddress + " is not known");

  CCoinSecret secret(ifaceIndex, vchSecret, fCompressed);
  string phrase = EncodeMnemonicSecret(secret);

  return (phrase);
}

Value core_block_verify(CIface *iface, int nDepth)
{
  char errbuf[1024];
  uint64_t nBestHeight = GetBestHeight(iface);
  uint64_t nHeight;
  int idx;
  bool fRet;

  if (nDepth < 0 || nDepth > nBestHeight)
    throw runtime_error("Block depth out of range.");

  if (nDepth == 0)
    nDepth = 1024; /* default */

  Object result;
  int invalid = 0;
  uint256 lastHash = 0;
  uint256 hash;

  nHeight = MAX(0, nBestHeight - nDepth);
  result.push_back(Pair("height", (boost::int64_t)nHeight));

  for (idx = 0; idx < nDepth && nHeight < nBestHeight; idx++) {
    CBlock *block = GetBlockByHeight(iface, nHeight);
    if (!block) throw runtime_error("Block not found in block-chain.");
    fRet = block->CheckBlock();
    if (!fRet)
      hash = block->GetHash();
    delete block;

    if (!fRet) {
      invalid++;
      lastHash = hash;

      sprintf(errbuf, "invalid '%s' block detected '%s' at height %u.", iface->name, hash.GetHex().c_str(), (unsigned int)nHeight);
      shcoind_info("database error", errbuf);
    }

    nHeight++;
  }

  result.push_back(Pair("invalid", (int)invalid));
  if (invalid) {
    result.push_back(Pair("invalhash", lastHash.GetHex()));
  }

  return (result);
}

Value rpc_block_verify(CIface *iface, const Array& params, bool fHelp)
{

  if (fHelp || params.size() >= 2)
    throw runtime_error(
        "block.verify <block depth>\n"
        "Verify a set of blocks from the end of the block-chain. (default: 1024).\n");

  int nDepth = 1024;
  if (params.size() > 0)
    nDepth = params[0].get_int();
  return (core_block_verify(iface, nDepth));
}



//
// Call Table
//


static const CRPCCommand vRPCCommands[] =
{
    { "help",                 &rpc_help},
    { "shutdown",             &rpc_stop},
    { "block.info",           &rpc_block_info},
    { "block.count",          &rpc_block_count},
    { "block.hash",           &rpc_block_hash},
    { "block.difficulty",     &rpc_block_difficulty},
    { "block.export",         &rpc_block_export},
    { "block.free",           &rpc_block_free},
    { "block.get",            &rpc_block_get},
    { "block.import",         &rpc_block_import},
    { "block.listsince",      &rpc_block_listsince},
    { "block.purge",          &rpc_block_purge},
//    { "block.template",       &rpc_block_template},
    { "block.verify",         &rpc_block_verify},
    { "block.work",           &rpc_block_work},
    { "block.workex",         &rpc_block_workex},
    { "cert.export",          &rpc_cert_export},
    { "cert.info",            &rpc_cert_info},
    { "cert.get",             &rpc_cert_get},
    { "cert.list",            &rpc_cert_list},
    { "cert.new",             &rpc_cert_new},
    { "msg.sign",             &rpc_msg_sign},
    { "msg.verify",           &rpc_msg_verify},
    { "net.info",             &rpc_net_info},
    { "net.hashps",           &rpc_net_hashps},
    { "peer.add",             &rpc_peer_add},
    { "peer.count",           &rpc_peer_count},
    { "peer.import",          &rpc_peer_import},
    { "peer.importdat",          &rpc_peer_importdat},
    { "peer.list",            &rpc_peer_list},
    { "peer.export",          &rpc_peer_export},
    { "sys.info",             &rpc_sys_info},
    { "tx.decode",            &rpc_tx_decode},
    { "tx.get",               &rpc_tx_get},
    { "tx.getraw",            &rpc_getrawtransaction},
    { "tx.list",              &rpc_tx_list},
    { "tx.pool",              &rpc_tx_pool},
    { "tx.prune",             &rpc_tx_prune},
    { "tx.purge",             &rpc_tx_purge},
    { "wallet.addr",          &rpc_wallet_addr},
    { "wallet.addrlist",      &rpc_wallet_addrlist},
    { "wallet.balance",       &rpc_wallet_balance},
    { "wallet.donate",        &rpc_wallet_donate},
    { "wallet.export",        &rpc_wallet_export},
    { "wallet.exportdat",     &rpc_wallet_exportdat},
    { "wallet.get",           &rpc_wallet_get},
    { "wallet.info",          &rpc_wallet_info},
    { "wallet.import",        &rpc_wallet_import},
    { "wallet.key",           &rpc_wallet_key},
    { "wallet.keyphrase",     &rpc_wallet_keyphrase},
    { "wallet.list",          &rpc_wallet_list},
    { "wallet.listbyaccount", &rpc_wallet_listbyaccount},
    { "wallet.listbyaddr",    &rpc_wallet_listbyaddr},
    { "wallet.move",          &rpc_wallet_move},
    { "wallet.multisend",     &rpc_wallet_multisend},
    { "wallet.new",           &rpc_wallet_newaddr},
    { "wallet.recvbyaccount", &rpc_wallet_recvbyaccount},
    { "wallet.recvbyaddr",    &rpc_wallet_recvbyaddr},
    { "wallet.rescan",        &rpc_wallet_rescan},
    { "wallet.send",          &rpc_wallet_send},
    { "wallet.csend",         &rpc_wallet_csend},
    { "wallet.set",           &rpc_wallet_set},
    { "wallet.setkey",        &rpc_wallet_setkey},
    { "wallet.setkeyphrase",  &rpc_wallet_setkeyphrase},
    { "wallet.stamp",         &rpc_wallet_stamp},
    { "wallet.tx",            &rpc_wallet_tx},
    { "wallet.unconfirm",     &rpc_wallet_unconfirm},
    { "wallet.unspent",       &rpc_wallet_unspent},
    { "wallet.validate",      &rpc_wallet_validate},
//    { "tx.sendraw",           &rpc_sendrawtransaction},
//    { "tx.signraw",           &rpc_tx_signraw},
    { "addmultisigaddress",   &rpc_addmultisigaddress}
};

#if 0
static const CRPCCommand vRPCCommands[] =
{ //  name                      function                 safe mode?
  //  ------------------------  -----------------------  ----------
//    { "help",                   &help,                   true },
//    { "stop",                   &stop,                   true },
//    { "getblockcount",          &getblockcount,          true },
//    { "getconnectioncount",     &getconnectioncount,     true },
//    { "getpeerinfo",            &getpeerinfo,            true },
//    { "addpeer",                &addpeer,                true },
//    { "getdifficulty",          &getdifficulty,          true },
//    { "getnetworkhashps",       &getnetworkhashps,       true },
//    { "getmininginfo",          &getmininginfo,          true },
//    { "getnewaddress",          &getnewaddress,          true },
//    { "getaccountaddress",      &getaccountaddress,      true },
//    { "getaddressesbyaccount",  &getaddressesbyaccount,  true },
    { "sendtoaddress",          &sendtoaddress,          false },
//    { "listreceivedbyaddress",  &listreceivedbyaddress,  false },
//    { "listreceivedbyaccount",  &listreceivedbyaccount,  false },
//    { "backupwallet",           &backupwallet,           true },
    { "keypoolrefill",          &keypoolrefill,          true },
//    { "walletpassphrase",       &walletpassphrase,       true },
//    { "walletpassphrasechange", &walletpassphrasechange, false },
//    { "walletlock",             &walletlock,             true },
//    { "encryptwallet",          &encryptwallet,          false },
//    { "getbalance",             &getbalance,             false },
    { "move",                   &movecmd,                false },
//    { "sendfrom",               &sendfrom,               false },
//    { "sendmany",               &sendmany,               false },
    { "addmultisigaddress",     &addmultisigaddress,     false },
//    { "getrawmempool",          &getrawmempool,          true },
//    { "getblock",               &getblock,               false },
//    { "getblockhash",           &getblockhash,           false },
//    { "gettransaction",         &gettransaction,         false },
//    { "listtransactions",       &listtransactions,       false },
//    { "signmessage",            &signmessage,            false },
//    { "verifymessage",          &verifymessage,          false },
//    { "listaccounts",           &listaccounts,           false },
    { "settxfee",               &settxfee,               false },
// NOT IMPLEMENTED    { "setmininput",            &setmininput,            false },
//    { "getblocktemplate",       &getblocktemplate,       true },
//    { "listsinceblock",         &listsinceblock,         false },
//    { "listunspent",            &listunspent,            false },
//    { "getrawtransaction",      &getrawtransaction,      false },
// NOT IMPLEMENTED    { "createrawtransaction",   &createrawtransaction,   false },
//  { "decoderawtransaction",   &decoderawtransaction,   false },
//    { "signrawtransaction",     &signrawtransaction,     false },
//    { "sendrawtransaction",     &sendrawtransaction,     false },
};
#endif

CRPCTable::CRPCTable()
{
  unsigned int vcidx;
  for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
  {
    const CRPCCommand *pcmd;

    pcmd = &vRPCCommands[vcidx];
    mapCommands[pcmd->name] = pcmd;
  }
}

const CRPCCommand *CRPCTable::operator[](string name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field
// and to be compatible with other JSON-RPC implementations.
//

string HTTPPost(const string& strMsg, const map<string,string>& mapRequestHeaders)
{
    ostringstream s;
    s << "POST / HTTP/1.1\r\n"
      << "User-Agent: shcoind-json-rpc/" << FormatFullVersion() << "\r\n"
      << "Host: 127.0.0.1\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << strMsg.size() << "\r\n"
      << "Connection: close\r\n"
      << "Accept: application/json\r\n";
    BOOST_FOREACH(const PAIRTYPE(string, string)& item, mapRequestHeaders)
        s << item.first << ": " << item.second << "\r\n";
    s << "\r\n" << strMsg;

    return s.str();
}

string rfc1123Time()
{
    char buffer[64];
    time_t now;
    time(&now);
    struct tm* now_gmt = gmtime(&now);
    string locale(setlocale(LC_TIME, NULL));
    setlocale(LC_TIME, "C"); // we want posix (aka "C") weekday/month strings
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S +0000", now_gmt);
    setlocale(LC_TIME, locale.c_str());
    return string(buffer);
}

static string HTTPReply(int nStatus, const string& strMsg, bool keepalive)
{
    if (nStatus == 401)
        return strprintf("HTTP/1.0 401 Authorization Required\r\n"
            "Date: %s\r\n"
            "Server: shcoind-json-rpc/%s\r\n"
            "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 296\r\n"
            "\r\n"
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
            "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
            "<HTML>\r\n"
            "<HEAD>\r\n"
            "<TITLE>Error</TITLE>\r\n"
            "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
            "</HEAD>\r\n"
            "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
            "</HTML>\r\n", rfc1123Time().c_str(), FormatFullVersion().c_str());
    const char *cStatus;
         if (nStatus == 200) cStatus = "OK";
    else if (nStatus == 400) cStatus = "Bad Request";
    else if (nStatus == 403) cStatus = "Forbidden";
    else if (nStatus == 404) cStatus = "Not Found";
    else if (nStatus == 500) cStatus = "Internal Server Error";
    else cStatus = "";
    return strprintf(
            "HTTP/1.1 %d %s\r\n"
            "Date: %s\r\n"
            "Connection: %s\r\n"
            "Content-Length: %d\r\n"
            "Content-Type: application/json\r\n"
            "Server: shcoind-json-rpc/%s\r\n"
            "\r\n"
            "%s",
        nStatus,
        cStatus,
        rfc1123Time().c_str(),
        keepalive ? "keep-alive" : "close",
        strMsg.size(),
        FormatFullVersion().c_str(),
        strMsg.c_str());
}

int ReadHTTPStatus(std::basic_istream<char>& stream, int &proto)
{
    string str;
    getline(stream, str);
    vector<string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return 500;
    proto = 0;
    const char *ver = strstr(str.c_str(), "HTTP/1.");
    if (ver != NULL)
        proto = atoi(ver+7);
    return atoi(vWords[1].c_str());
}

int ReadHTTPHeader(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet)
{
    int nLen = 0;
    loop
    {
        string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        string::size_type nColon = str.find(":");
        if (nColon != string::npos)
        {
            string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            string strValue = str.substr(nColon+1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
                nLen = atoi(strValue.c_str());
        }
    }
    return nLen;
}

int ReadHTTP(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet, string& strMessageRet)
{
    mapHeadersRet.clear();
    strMessageRet = "";

    // Read status
    int nProto = 0;
    int nStatus = ReadHTTPStatus(stream, nProto);

    // Read header
    int nLen = ReadHTTPHeader(stream, mapHeadersRet);
    if (nLen < 0 || nLen > (int)MAX_SIZE)
        return 500;

    // Read message
    if (nLen > 0)
    {
        vector<char> vch(nLen);
        stream.read(&vch[0], nLen);
        strMessageRet = string(vch.begin(), vch.end());
    }

    string sConHdr = mapHeadersRet["connection"];

    if ((sConHdr != "close") && (sConHdr != "keep-alive"))
    {
        if (nProto >= 1)
            mapHeadersRet["connection"] = "keep-alive";
        else
            mapHeadersRet["connection"] = "close";
    }

    return nStatus;
}

bool HTTPAuthorized(map<string, string>& mapHeaders)
{
    string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0,6) != "Basic ")
        return false;
    string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
    string strUserPass = DecodeBase64(strUserPass64);
    return strUserPass == strRPCUserColonPass;
}

//
// JSON-RPC protocol.  coin speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
//
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//

string JSONRPCRequest(const string& strMethod, const Array& params, const Value& id)
{
    Object request;
    request.push_back(Pair("method", strMethod));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", id));
    return write_string(Value(request), false) + "\n";
}

Object JSONRPCReplyObj(const Value& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return reply;
}

string JSONRPCReply(const Value& result, const Value& error, const Value& id)
{
    Object reply = JSONRPCReplyObj(result, error, id);
    return write_string(Value(reply), false) + "\n";
}

void ErrorReply(std::ostream& stream, const Object& objError, const Value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = 500;
    int code = find_value(objError, "code").get_int();
    if (code == -32600) nStatus = 400;
    else if (code == -32601) nStatus = 404;
    string strReply = JSONRPCReply(Value::null, objError, id);
    stream << HTTPReply(nStatus, strReply, false) << std::flush;
}

bool ClientAllowed(const boost::asio::ip::address& address)
{
    // Make sure that IPv4-compatible and IPv4-mapped IPv6 addresses are treated as IPv4 addresses
    if (address.is_v6()
     && (address.to_v6().is_v4_compatible()
      || address.to_v6().is_v4_mapped()))
        return ClientAllowed(address.to_v6().to_v4());

    if (address == boost::asio::ip::address_v4::loopback()
     || address == boost::asio::ip::address_v6::loopback()
     || (address.is_v4()
         // Chech whether IPv4 addresses match 127.0.0.0/8 (loopback subnet)
      && (address.to_v4().to_ulong() & 0xff000000) == 0x7f000000))
        return true;

    const string strAddress = address.to_string();
    const vector<string>& vAllow = mapMultiArgs["-rpcallowip"];
    BOOST_FOREACH(string strAllow, vAllow)
        if (WildcardMatch(strAddress, strAllow))
            return true;
    return false;
}



void ThreadRPCServer(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadRPCServer(parg));

    // Make this thread recognisable as the RPC listener
    RenameThread("bitcoin-rpclist");

    try
    {
        vnThreadsRunning[THREAD_RPCLISTENER]++;
        ThreadRPCServer2(parg);
        vnThreadsRunning[THREAD_RPCLISTENER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_RPCLISTENER]--;
        PrintException(&e, "ThreadRPCServer()");
    } catch (...) {
        vnThreadsRunning[THREAD_RPCLISTENER]--;
        PrintException(NULL, "ThreadRPCServer()");
    }
}

// Forward declaration required for RPCListen
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             boost::asio::ssl::context& context,
                             bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error);

/**
 * Sets up I/O resources to accept and handle a new connection.
 */
template <typename Protocol, typename SocketAcceptorService>
static void RPCListen(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                   boost::asio::ssl::context& context,
                   const bool fUseSSL)
{
    // Accept connection
    AcceptedConnectionImpl<Protocol>* conn = new AcceptedConnectionImpl<Protocol>(acceptor->get_io_service(), context, fUseSSL);

    acceptor->async_accept(
            conn->sslStream.lowest_layer(),
            conn->peer,
            boost::bind(&RPCAcceptHandler<Protocol, SocketAcceptorService>,
                acceptor,
                boost::ref(context),
                fUseSSL,
                conn,
                boost::asio::placeholders::error));
}

static Object JSONRPCExecOne(const Value& req)
{
    Object rpc_result;

    JSONRequest jreq;
    try {
        jreq.parse(req);

        Value result = tableRPC.execute(jreq.iface, jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, Value::null, jreq.id);
    }
    catch (Object& objError)
    {
        rpc_result = JSONRPCReplyObj(Value::null, objError, jreq.id);
    }
    catch (std::exception& e)
    {
        rpc_result = JSONRPCReplyObj(Value::null,
                                     JSONRPCError(-32700, e.what()), jreq.id);
    }

    return rpc_result;
}

static string JSONRPCExecBatch(const Array& vReq)
{
    Array ret;
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return write_string(Value(ret), false) + "\n";
}

void ThreadRPCServer3(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadRPCServer3(parg));

    // Make this thread recognisable as the RPC handler
    RenameThread("bitcoin-rpchand");

    {
        LOCK(cs_THREAD_RPCHANDLER);
        vnThreadsRunning[THREAD_RPCHANDLER]++;
    }
    AcceptedConnection *conn = (AcceptedConnection *) parg;

    bool fRun = true;
    loop {
        if (fShutdown || !fRun)
        {
            conn->close();
            delete conn;
            {
                LOCK(cs_THREAD_RPCHANDLER);
                --vnThreadsRunning[THREAD_RPCHANDLER];
            }
            return;
        }
        map<string, string> mapHeaders;
        string strRequest;

        ReadHTTP(conn->stream(), mapHeaders, strRequest);

        // Check authorization
        if (mapHeaders.count("authorization") == 0)
        {
            conn->stream() << HTTPReply(401, "", false) << std::flush;
            break;
        }
        if (!HTTPAuthorized(mapHeaders))
        {
            Debug("ThreadRPCServer incorrect password attempt from %s\n", conn->peer_address_to_string().c_str());
            /* Deter brute-forcing short passwords.
               If this results in a DOS the user really
               shouldn't have their RPC port exposed.*/
            if (mapArgs["-rpcpassword"].size() < 20)
                Sleep(250);

            conn->stream() << HTTPReply(401, "", false) << std::flush;
            break;
        }
        if (mapHeaders["connection"] == "close")
            fRun = false;

        JSONRequest jreq;
        try
        {
            // Parse request
            Value valRequest;
            if (!read_string(strRequest, valRequest))
                throw JSONRPCError(-32700, "Parse error");

            string strReply;

            // singleton request
            if (valRequest.type() == obj_type) {
                jreq.parse(valRequest);

                Value result = tableRPC.execute(jreq.iface, jreq.strMethod, jreq.params);

                // Send reply
                strReply = JSONRPCReply(result, Value::null, jreq.id);

            // array of requests
            } else if (valRequest.type() == array_type)
                strReply = JSONRPCExecBatch(valRequest.get_array());
            else
                throw JSONRPCError(-32700, "Top-level object parse error");
                
            conn->stream() << HTTPReply(200, strReply, fRun) << std::flush;
        }
        catch (Object& objError)
        {
            ErrorReply(conn->stream(), objError, jreq.id);
            break;
        }
        catch (std::exception& e)
        {
            ErrorReply(conn->stream(), JSONRPCError(-32700, e.what()), jreq.id);
            break;
        }
    }

    delete conn;
    {
        LOCK(cs_THREAD_RPCHANDLER);
        vnThreadsRunning[THREAD_RPCHANDLER]--;
    }
}
/**
 * Accept and handle incoming connection.
 */
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             boost::asio::ssl::context& context,
                             const bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& err)
{
    vnThreadsRunning[THREAD_RPCLISTENER]++;

    // Immediately start accepting new connections, except when we're canceled or our socket is closed.
    if (err != boost::asio::error::operation_aborted
     && acceptor->is_open())
        RPCListen(acceptor, context, fUseSSL);

    AcceptedConnectionImpl<ip::tcp>* tcp_conn = dynamic_cast< AcceptedConnectionImpl<ip::tcp>* >(conn);

    // TODO: Actually handle errors !
    if (err)
    {
        delete conn;
    }

    // Restrict callers by IP.  It is important to
    // do this before starting client thread, to filter out
    // certain DoS and misbehaving clients.
    else if (tcp_conn
          && !ClientAllowed(tcp_conn->peer.address()))
    {
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        if (!fUseSSL)
            conn->stream() << HTTPReply(403, "", false) << std::flush;
        delete conn;
    }

    // start HTTP client thread
    else if (!CreateThread(ThreadRPCServer3, conn)) {
        Debug("Failed to create RPC server client thread");
        delete conn;
    }

    vnThreadsRunning[THREAD_RPCLISTENER]--;
}

void ThreadRPCServer2(void* parg)
{

    strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"];
    if (mapArgs["-rpcpassword"] == "")
    {
/*
        unsigned char rand_pwd[32];
        RAND_bytes(rand_pwd, 32);
        string strWhatAmI = "To use usded";
        if (mapArgs.count("-server"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-server\"");
        else if (mapArgs.count("-daemon"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-daemon\"");
*/
        StartServerShutdown();
        return;
    }

    const bool fUseSSL = GetBoolArg("-rpcssl");

    boost::asio::io_service io_service;

    boost::asio::ssl::context context(io_service, boost::asio::ssl::context::sslv23);
    if (fUseSSL)
    {
        context.set_options(boost::asio::ssl::context::no_sslv2);

        filesystem::path pathCertFile(GetArg("-rpcsslcertificatechainfile", "server.cert"));
        if (!pathCertFile.is_complete()) pathCertFile = filesystem::path(GetDataDir()) / pathCertFile;
        if (filesystem::exists(pathCertFile)) context.use_certificate_chain_file(pathCertFile.string());
        else fprintf(stderr, "ThreadRPCServer ERROR: missing server certificate file %s\n", pathCertFile.string().c_str());

        filesystem::path pathPKFile(GetArg("-rpcsslprivatekeyfile", "server.pem"));
        if (!pathPKFile.is_complete()) pathPKFile = filesystem::path(GetDataDir()) / pathPKFile;
        if (filesystem::exists(pathPKFile)) context.use_private_key_file(pathPKFile.string(), boost::asio::ssl::context::pem);
        else fprintf(stderr, "ThreadRPCServer ERROR: missing server private key file %s\n", pathPKFile.string().c_str());

        string strCiphers = GetArg("-rpcsslciphers", "TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH");
        SSL_CTX_set_cipher_list(context.impl(), strCiphers.c_str());
    }

    // Try a dual IPv6/IPv4 socket, falling back to separate IPv4 and IPv6 sockets
    const bool loopback = !mapArgs.count("-rpcallowip");
    boost::asio::ip::address bindAddress = loopback ? boost::asio::ip::address_v6::loopback() : boost::asio::ip::address_v6::any();
    ip::tcp::endpoint endpoint(bindAddress, GetArg("-rpcport", 54448));
    boost::system::error_code v6_only_error;
    boost::shared_ptr<ip::tcp::acceptor> acceptor(new ip::tcp::acceptor(io_service));

    boost::signals2::signal<void ()> StopRequests;

    bool fListening = false;
    std::string strerr;
    try
    {
        acceptor->open(endpoint.protocol());
        acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

        // Try making the socket dual IPv6/IPv4 (if listening on the "any" address)
        acceptor->set_option(boost::asio::ip::v6_only(loopback), v6_only_error);

        acceptor->bind(endpoint);
        acceptor->listen(socket_base::max_connections);

        RPCListen(acceptor, context, fUseSSL);
        // Cancel outstanding listen-requests for this acceptor when shutting down
        StopRequests.connect(signals2::slot<void ()>(
                    static_cast<void (ip::tcp::acceptor::*)()>(&ip::tcp::acceptor::close), acceptor.get())
                .track(acceptor));

            fListening = true;
        }
        catch(boost::system::system_error &e)
        {
            strerr = strprintf(_("An error occurred while setting up the RPC port %i for listening on IPv6, falling back to IPv4: %s"), endpoint.port(), e.what());
        }

        try {
        // If dual IPv6/IPv4 failed (or we're opening loopback interfaces only), open IPv4 separately
        if (!fListening || loopback || v6_only_error)
        {
            bindAddress = loopback ? boost::asio::ip::address_v4::loopback() : boost::asio::ip::address_v4::any();
            endpoint.address(bindAddress);

            acceptor.reset(new ip::tcp::acceptor(io_service));
            acceptor->open(endpoint.protocol());
            acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
            acceptor->bind(endpoint);
            acceptor->listen(socket_base::max_connections);

            RPCListen(acceptor, context, fUseSSL);
            // Cancel outstanding listen-requests for this acceptor when shutting down
            StopRequests.connect(signals2::slot<void ()>(
                        static_cast<void (ip::tcp::acceptor::*)()>(&ip::tcp::acceptor::close), acceptor.get())
                    .track(acceptor));

            fListening = true;
        }
    }
    catch(boost::system::system_error &e)
    {
        strerr = strprintf(_("An error occurred while setting up the RPC port %i for listening on IPv4: %s"), endpoint.port(), e.what());
    }

    if (!fListening) {
        StartServerShutdown();
        return;
    }

    vnThreadsRunning[THREAD_RPCLISTENER]--;
    while (!fShutdown)
        io_service.run_one();
    vnThreadsRunning[THREAD_RPCLISTENER]++;
    StopRequests();
}


void JSONRequest::parse(const Value& valRequest)
{

  // Parse request
  if (valRequest.type() != obj_type)
    throw JSONRPCError(-32600, "Invalid Request object");
  const Object& request = valRequest.get_obj();

  // Parse id now so errors from here on will have the id
  id = find_value(request, "id");

  /* determine coin iface */
  Value ifaceVal = find_value(request, "iface");
  if (ifaceVal.type() == str_type) {
    string iface_str = ifaceVal.get_str();
    iface = GetCoin(iface_str.c_str());
  }
  if (!iface) {
    /* default */
    iface = GetCoinByIndex(USDE_COIN_IFACE);
  }

  // Parse method
  Value valMethod = find_value(request, "method");
  if (valMethod.type() == null_type)
    throw JSONRPCError(-32600, "Missing method");
  if (valMethod.type() != str_type)
    throw JSONRPCError(-32600, "Method must be a string");
  strMethod = valMethod.get_str();
  if (strMethod != "getwork" && strMethod != "getblocktemplate") {
    Debug("ThreadRPCServer method=%s\n", strMethod.c_str());
  }

  // Parse params
  Value valParams = find_value(request, "params");
  if (valParams.type() == array_type)
    params = valParams.get_array();
  else if (valParams.type() == null_type)
    params = Array();
  else
    throw JSONRPCError(-32600, "Params must be an array");
}





json_spirit::Value CRPCTable::execute(CIface *iface, const std::string &strMethod, const json_spirit::Array &params) const
{
  CWallet *pwalletMain = GetWallet(iface);
  std::string method;

  /* backwards compatibility */
  if (strMethod == "getblockcount")
    method = "block.count";
  else if (strMethod == "getdifficulty")
    method = "block.difficulty";
  else if (strMethod == "getinfo")
    method = "block.info";
  else if (strMethod == "getwork")
    method = "block.work";
  else if (strMethod == "getworkex")
    method = "block.workex";
  else if (strMethod == "getnetworkhashps")
    method = "net.hashps";
  else if (strMethod == "getconnectioncount")
    method = "peer.count";
  else if (strMethod == "getpeerinfo")
    method = "peer.list";
  else if (strMethod == "dumpprivkey")
    method = "wallet.key";
  else if (strMethod == "sendfrom")
    method = "wallet.send";
  else if (strMethod == "importprivkey")
    method = "wallet.setkey";
  else
    method = strMethod;


  // Find method
  const CRPCCommand *pcmd = tableRPC[method];

  if (!pcmd)
    throw JSONRPCError(-32601, "Method not found");

#if 0
  // Observe safe mode
  string strWarning = GetWarnings("rpc");
  if (strWarning != "" && !GetBoolArg("-disablesafemode") &&
      !pcmd->okSafeMode)
    throw JSONRPCError(-2, string("Safe mode: ") + strWarning);
#endif

  if (!pwalletMain)
    throw JSONRPCError(-32601, "Wallet not accessible.");

  try
  {
    // Execute
    Value result;
    {
      LOCK2(cs_main, pwalletMain->cs_wallet);
      result = pcmd->actor(iface, params, false);
    }
    return result;
  }
  catch (std::exception& e)
  {
    throw JSONRPCError(-1, e.what());
  }
}

template<typename T>
void ConvertTo(Value& value)
{
    if (value.type() == str_type)
    {
        // reinterpret string as unquoted json value
        Value value2;
        string strJSON = value.get_str();
        if (!read_string(strJSON, value2))
            throw runtime_error(string("Error parsing JSON:")+strJSON);
        value = value2.get_value<T>();
    }
    else
    {
        value = value.get_value<T>();
    }
}



const CRPCTable tableRPC;

#if 0
string blocktemplate_json; 
const char *c_getblocktemplate(void)
{

/*
    if (vNodes.empty())
      return (NULL);
*/
//        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "CryptogenicBullion is not connected!");

/*
 *
    if (IsInitialBlockDownload())
      return (NULL);
*/
//        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "CryptogenicBullion is downloading blocks...");

    static CReserveKey reservekey(pwalletMain);

    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
//    static int64 nStart;
//    static CBlock* pblock;
    CBlock* pblock;
    static unsigned int work_id;

/*
    if (pindexPrev != pindexBest ||
        nTransactionsUpdated != nTransactionsUpdatedLast) 
    {
*/
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Create new block
        if(pblock)
        {
            //delete pblock;
            pblock = NULL;
        }

        if (pindexPrev != NULL && pindexPrev->nHeight != pindexBest->nHeight) {
          /* delete all worker blocks. */
          for (map<int, CBlock*>::const_iterator mi = mapWork.begin(); mi != mapWork.end(); ++mi)
          {
            CBlock *tblock = mi->second;
            delete tblock;
          }
          mapWork.clear();
        }

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrevNew = pindexBest;
//        nStart = GetTime();

        pblock = CreateNewBlock(reservekey);
        if (!pblock)
          return (NULL);
            //throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;

        /* store "worker" block for until height increment. */
        work_id++;
        mapWork[work_id] = pblock; 
/*
    }
*/

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    Array transactions;
    //map<uint256, int64_t> setTxIndex;
    int i = 0;
    CTxDB txdb("r");
    BOOST_FOREACH (CTransaction& tx, pblock->vtx)
    {
        uint256 txHash = tx.GetHash();
     //   setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;
        transactions.push_back(txHash.GetHex());
        //transactions.push_back(HexStr(ssTx.begin(), ssTx.end()));

/*
        Object entry;

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << tx;
        entry.push_back(Pair("data", HexStr(ssTx.begin(), ssTx.end())));

        entry.push_back(Pair("hash", txHash.GetHex()));

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            entry.push_back(Pair("fee", (int64_t)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));

            Array deps;
            BOOST_FOREACH (MapPrevTx::value_type& inp, mapInputs)
            {
                if (setTxIndex.count(inp.first))
                    deps.push_back(setTxIndex[inp.first]);
            }
            entry.push_back(Pair("depends", deps));

            int64_t nSigOps = tx.GetLegacySigOpCount();
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            entry.push_back(Pair("sigops", nSigOps));
        }

        transactions.push_back(entry);
*/
    }

/*
    Object aux;
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));
*/

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

/*
    static Array aMutable;
    if (aMutable.empty())
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }
*/


 
  Object result;

  /* all pool mining is defunc when "connections=0". */
  result.push_back(Pair("connections",   (int)vNodes.size()));

  result.push_back(Pair("version", pblock->nVersion));
  result.push_back(Pair("task", (int64_t)work_id));
  result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
  result.push_back(Pair("transactions", transactions));
//  result.push_back(Pair("coinbaseaux", aux));
  result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
  result.push_back(Pair("target", hashTarget.GetHex()));
/*
  result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
  result.push_back(Pair("mutable", aMutable));
  result.push_back(Pair("noncerange", "00000000ffffffff"));
  result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS));
*/
  result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SIZE));
  result.push_back(Pair("curtime", (int64_t)pblock->nTime));
  result.push_back(Pair("bits", HexBits(pblock->nBits)));

  if (!pindexPrev) {
    /* mining is defunct when "height < 2" */
    result.push_back(Pair("height", (int64_t)0));
  } else {
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));
  }

  /* dummy nExtraNonce */
  SetExtraNonce(pblock, "f0000000f0000000");

  /* coinbase */
  CTransaction coinbaseTx = pblock->vtx[0];
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface));
  ssTx << coinbaseTx;
  result.push_back(Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));
//  result.push_back(Pair("sigScript", HexStr(pblock->vtx[0].vin[0].scriptSig.begin(), pblock->vtx[0].vin[0].scriptSig.end())));
  result.push_back(Pair("coinbaseflags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

  /* merkle root */
  //pblock->hashMerkleRoot = pblock->BuildMerkleTree();
  //result.push_back(Pair("merkleroot", pblock->hashMerkleRoot.GetHex()));


  blocktemplate_json = JSONRPCReply(result, Value::null, Value::null);
  return (blocktemplate_json.c_str());
}
#endif

/*
int c_submitblock(char *hashPrevBlock, char *hashMerkleRoot, unsigned int nTime, unsigned int nBits, unsigned int nNonce)
{
  std::string prevhash = hashPrevBlock;
  std::string merklehash = hashMerkleRoot;
  CBlock *block = new CBlock();

  block->nVersion = block->CURRENT_VERSION;
  block->hashPrevBlock.SetHex(prevhash);
  block->hashMerkleRoot.SetHex(merklehash);
  block->nTime = nTime;
  block->nBits = nBits;
  block->nNonce = nNonce;

  bool fAccepted = ProcessBlock(NULL, block);
  if (!fAccepted)
    return -1;

  return 0;
}
*/
#if 0
int c_processblock(CBlock* pblock)
{
  CNode *pfrom = NULL;

  // Check for duplicate
  uint256 hash = pblock->GetHash();
  if (mapBlockIndex.count(hash))// || mapOrphanBlocks.count(hash))
    return (BLKERR_DUPLICATE_BLOCK);

  // Preliminary checks
  if (!pblock->CheckBlock()) {
    return (BLKERR_INVALID_FORMAT);
  }

  // If don't already have its previous block, shunt it off to holding area until we get it
   /*
  if (!mapBlockIndex.count(pblock->hashPrevBlock))
  {
    printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,20).c_str());
    CBlock* pblock2 = new CBlock(*pblock);
    mapOrphanBlocks.insert(make_pair(hash, pblock2));
    mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

    if (pfrom)
      pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
    return (0);
  }
*/

  // Store to disk
  if (!pblock->AcceptBlock()) {
    return (BLKERR_INVALID_BLOCK);
  }

  // Recursively process any orphan blocks that depended on this one
   /*
  vector<uint256> vWorkQueue;
  vWorkQueue.push_back(hash);
  for (unsigned int i = 0; i < vWorkQueue.size(); i++)
  {
    uint256 hashPrev = vWorkQueue[i];
    for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
        mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
        ++mi)
    {
      CBlock* pblockOrphan = (*mi).second;
      if (pblockOrphan->AcceptBlock())
        vWorkQueue.push_back(pblockOrphan->GetHash());
      mapOrphanBlocks.erase(pblockOrphan->GetHash());
      delete pblockOrphan;
    }
    mapOrphanBlocksByPrev.erase(hashPrev);
  }
*/

  printf("ProcessBlock: ACCEPTED\n");

  return (0);
}

bool QuickCheckWork(CBlock* pblock)
{
  uint256 hash = pblock->GetPoWHash();
  uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        uint256 bhash = Hash(BEGIN(pblock->nVersion), END(pblock->nNonce));
fprintf(stderr, "DEBUG: QuickCheckWork: block hash \"%s\"\n", bhash.GetHex().c_str());
fprintf(stderr, "DEBUG: QuickCheckWork: block data \"%s\"\n", HexStr(BEGIN(pblock->nVersion), END(pblock->nNonce)).c_str());

  //// debug print
  fprintf(stderr, "BitcoinMiner:\n");
  fprintf(stderr, "proof-of-work found  \n  hash: %s (%s) \ntarget: %s\n", hash.GetHex().c_str(), HexStr(hash.begin(), hash.end()).c_str(), hashTarget.GetHex().c_str());
  pblock->print();
  fprintf(stderr, "generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

  if (hash > hashTarget)
    return false;

  return true;
}

int c_submitblock(unsigned int workId, unsigned int nTime, unsigned int nNonce, char *xn_hex)
{
  CBlock *pblock;
bool ok;

  pblock = mapWork[workId];
  if (pblock == NULL)
    return (BLKERR_INVALID_JOB);
        //

  pblock->nTime = nTime;
  pblock->nNonce = nNonce;

  /* set coinbase. */
  SetExtraNonce(pblock, xn_hex);

  /* generate merkle root */
  pblock->hashMerkleRoot = pblock->BuildMerkleTree();


  fprintf(stderr, "DEBUG: submitblock: previousblockhash %s\n", pblock->hashPrevBlock.GetHex().c_str());
  fprintf(stderr, "DEBUG: submitblock: previousblockhash %s\n", HexStr(pblock->hashPrevBlock.begin(), pblock->hashPrevBlock.end()).c_str());


  CTransaction coinbaseTx = pblock->vtx[0];
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION(iface));
  ssTx << coinbaseTx;
  fprintf(stderr, "DEBUG: submitblock: coinbase %s\n", HexStr(ssTx.begin(), ssTx.end()).c_str());
fprintf(stderr, "DEBUG: sigScript: %s\n", HexStr(pblock->vtx[0].vin[0].scriptSig.begin(), pblock->vtx[0].vin[0].scriptSig.end()).c_str());

  /* merkle root */
  //pblock->hashMerkleRoot = pblock->BuildMerkleTree();
  fprintf(stderr, "DEBUG: submitblock: merkleroot %s\n", pblock->hashMerkleRoot.GetHex().c_str());
  fprintf(stderr, "DEBUG: submitblock: merkleroot %s\n", HexStr(pblock->hashMerkleRoot.begin(), pblock->hashMerkleRoot.end()).c_str());

fprintf(stderr, "DEBUG: submitblock: hash %s\n", pblock->GetHash().GetHex().c_str());

fprintf(stderr, "DEBUG: submitblock: target %s\n",  CBigNum().SetCompact(pblock->nBits).GetHex().c_str());

fprintf(stderr, "DEBUG: submitblock: target diff %f\n", 
    (double)0x0000ffff / (double)(pblock->nBits & 0x00ffffff));

ok = QuickCheckWork(pblock);
if (ok)
fprintf(stderr, "DEBUG: QuickCheckWork returned true\n");
else
fprintf(stderr, "DEBUG: QuickCheckWork returned false\n");

  return (c_processblock(pblock));
}


#ifdef __cplusplus
extern "C" {
#endif

#if 0
const char *getblocktemplate(void)
{
  return (c_getblocktemplate());
}
#endif
int submitblock(unsigned int workId, unsigned int nTime, unsigned int nNonce, char *xn_hex)
{
  return (c_submitblock(workId, nTime, nNonce, xn_hex));
}
/*
int submitblock(char *hashPrevBlock, char *hashMerkleRoot, unsigned int nTime, unsigned int nBits, unsigned int nNonce)
{
  return (c_submitblock(hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce));
}
*/



#ifdef __cplusplus
}
#endif

#endif
