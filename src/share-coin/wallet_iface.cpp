
/*
 * @copyright
 *
 *  Copyright 2013 Neo Natura
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

#include "db.h"
#include "walletdb.h"
#include "server/rpc_proto.h"
#include "net.h"
#include "init.h"
#include "util.h"
#include "ui_interface.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include "shcoind.h"

#ifndef WIN32
#include <signal.h>
#endif

using namespace std;
using namespace boost;
using namespace json_spirit;

extern CWallet* pwalletMain;

extern Value ValueFromAmount(int64 amount);

extern int64 GetAccountBalance(CWalletDB& walletdb, const string& strAccount, int nMinDepth);

extern void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret);

extern string JSONRPCReply(const Value& result, const Value& error, const Value& id);

extern void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret);

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
            a.push_back(CBitcoinAddress(addr).ToString());
        obj.push_back(Pair("addresses", a));
        if (whichType == TX_MULTISIG)
            obj.push_back(Pair("sigsrequired", nRequired));
        return obj;
    }
};


string address;

Object stratumerror_obj;
void SetStratumError(Object error)
{
  stratumerror_obj = error;
}
Object GetStratumError(void)
{
  return (stratumerror_obj);
}

static uint256 get_private_key_hash(CKeyID keyId)
{
  CSecret vchSecret;
  bool fCompressed;
  uint256 phash;

  if (!pwalletMain->GetSecret(keyId, vchSecret, fCompressed))
    return (phash);

  string secret = CBitcoinSecret(vchSecret, fCompressed).ToString();

  unsigned char *secret_str = (unsigned char *)secret.c_str();
  size_t secret_len = secret.length();
  SHA256(secret_str, secret_len, (unsigned char*)&phash);

  return (phash);
}


Object JSONAddressInfo(CBitcoinAddress address, bool show_priv)
{
  CTxDestination dest = address.Get();
  string currentAddress = address.ToString();
  Object result;

  result.push_back(Pair("address", currentAddress));

  if (show_priv) {
    CKeyID keyID;
    bool fCompressed;
    CSecret vchSecret;
    uint256 pkey;

    if (!address.GetKeyID(keyID)) {
      throw JSONRPCError(STERR_ACCESS_UNAVAIL,
          "Private key for address " + currentAddress + " is not known");
    }

    pkey = get_private_key_hash(keyID);
    result.push_back(Pair("pkey", pkey.GetHex()));

    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
      throw JSONRPCError(STERR_ACCESS_UNAVAIL,
          "Private key for address " + currentAddress + " is not known");
    }
    result.push_back(Pair("secret", CBitcoinSecret(vchSecret, fCompressed).ToString()));
  }

//    bool fMine = IsMine(*pwalletMain, dest);
  Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
  result.insert(result.end(), detail.begin(), detail.end());
  if (pwalletMain->mapAddressBook.count(dest))
    result.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));

  return (result);
}

int cxx_UpgradeWallet(void)
{
  int nMaxVersion = 0;//GetArg("-upgradewallet", 0);
  if (nMaxVersion == 0) // the -upgradewallet without argument case
  {
    nMaxVersion = CLIENT_VERSION;
    pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
    Debug("using wallet version %d", FEATURE_LATEST);
  }
  else
    printf("Allowing wallet upgrade up to %i\n", nMaxVersion);

  if (nMaxVersion > pwalletMain->GetVersion()) {
    pwalletMain->SetMaxVersion(nMaxVersion);
  }

}

int c_LoadWallet(void)
{
  std::ostringstream strErrors;

  const char* pszP2SH = "/P2SH/";
  COINBASE_FLAGS << std::vector<unsigned char>(pszP2SH, pszP2SH+strlen(pszP2SH));

  if (!bitdb.Open(GetDataDir()))
  {
    fprintf(stderr, "error: unable to open data directory.\n");
    return (-1);
  }

  if (!LoadBlockIndex()) {
    fprintf(stderr, "error: unable to open load block index.\n");
    return (-1);
  }

  bool fFirstRun = true;
  pwalletMain = new CWallet("wallet.dat");
  pwalletMain->LoadWallet(fFirstRun);

  if (fFirstRun)
  {

    // Create new keyUser and set as default key
    RandAddSeedPerfmon();

    CPubKey newDefaultKey;
    if (!pwalletMain->GetKeyFromPool(newDefaultKey, false))
      strErrors << _("Cannot initialize keypool") << "\n";
    pwalletMain->SetDefaultKey(newDefaultKey);
    if (!pwalletMain->SetAddressBookName(pwalletMain->vchDefaultKey.GetID(), ""))
      strErrors << _("Cannot write default address") << "\n";
  }

  printf("%s", strErrors.str().c_str());

  RegisterWallet(pwalletMain);

  CBlockIndex *pindexRescan = pindexBest;
  if (GetBoolArg("-rescan"))
    pindexRescan = pindexGenesisBlock;
  else
  {
    CWalletDB walletdb("wallet.dat");
    CBlockLocator locator;
    if (walletdb.ReadBestBlock(locator))
      pindexRescan = locator.GetBlockIndex();
  }
  if (pindexBest != pindexRescan && pindexBest && pindexRescan && pindexBest->nHeight > pindexRescan->nHeight)
  {
    int64 nStart;

    printf("Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
    nStart = GetTimeMillis();
    pwalletMain->ScanForWalletTransactions(pindexRescan, true);
    printf(" rescan      %15"PRI64d"ms\n", GetTimeMillis() - nStart);
  }

}

/** load peers */
int c_LoadPeers(void)
{
  int64 nStart;

  nStart = GetTimeMillis();
#if 0
  {
    CAddrDB adb;
    if (!adb.Read(addrman))
      printf("Invalid or missing peers.dat; recreating\n");
  }
  printf("Loaded %i addresses from peers.dat  %"PRI64d"ms\n",
      addrman.size(), GetTimeMillis() - nStart);
#endif

  RandAddSeedPerfmon();
  pwalletMain->ReacceptWalletTransactions();
}

CBitcoinAddress GetNewAddress(string strAccount)
{
  if (!pwalletMain->IsLocked())
    pwalletMain->TopUpKeyPool();

  // Generate a new key that is added to wallet
  CPubKey newKey;
  if (!pwalletMain->GetKeyFromPool(newKey, false)) {
    throw JSONRPCError(-12, "Error: Keypool ran out, please call keypoolrefill first");
  }
  CKeyID keyID = newKey.GetID();

  pwalletMain->SetAddressBookName(keyID, strAccount);

  return CBitcoinAddress(keyID);
}

string getnewaddr_str;
const char *cxx_getnewaddress(const char *account)
{
  string strAccount(account);

  if (!pwalletMain->IsLocked())
    pwalletMain->TopUpKeyPool();

  // Generate a new key that is added to wallet
  CPubKey newKey;
  if (!pwalletMain->GetKeyFromPool(newKey, false)) {
    return (NULL);
  }
  CKeyID keyID = newKey.GetID();
  pwalletMain->SetAddressBookName(keyID, strAccount);
  getnewaddr_str = CBitcoinAddress(keyID).ToString();

  return (getnewaddr_str.c_str());
}


CBitcoinAddress GetAddressByAccount(const char *accountName, bool& found)
{
  CBitcoinAddress address;
  string strAccount(accountName);
  Array ret;

  // Find all addresses that have the given account
  found = false;
  BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
  {
    const CBitcoinAddress& acc_address = item.first;
    const string& strName = item.second;
    if (strName == strAccount) {
      address = acc_address;
      found = true;
    }
  }

  return (address);
}

const char *c_getaddressbyaccount(const char *accountName)
{
  bool found = false;
  CBitcoinAddress addr = GetAddressByAccount(accountName, found);
  if (!found || !addr.IsValid())
     return (NULL);
  return (addr.ToString().c_str());
}

/**
 * Sends a reward to a particular address.
 */
int c_setblockreward(const char *accountName, double dAmount)
{
  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strMainAccount("");
  string strAccount(accountName);
  string strComment("sharenet");
  int64 nAmount;
  Array ret;
  int nMinDepth = 1; /* single confirmation requirement */
  int nMinConfirmDepth = 1; /* single confirmation requirement */
  bool found = false;
  int64 nBalance;

  if (pwalletMain->IsLocked()) {
    return (-13);
  }

  const CBitcoinAddress address = GetAddressByAccount(accountName, found);
  if (!found) {
    return (-5);
  }
  if (!address.IsValid()) {
    char errbuf[1024];
    sprintf(errbuf, "setblockreward: account '%s' has invalid usde address.", accountName);
    shcoind_log(errbuf);
    //throw JSONRPCError(-5, "Invalid usde address");
    return (-5);
  }


  if (dAmount <= 0.0 || dAmount > 84000000.0) {
    return (-3);
  }

  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(nAmount)) {
    return (-3);
  }

  nBalance  = GetAccountBalance(walletdb, strMainAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
fprintf(stderr, "DEBUG: c_setblockreward: main account has insufficient funds (%f required).\n", dAmount);
    return (-6);
  }


  CWalletTx wtx;
  wtx.strFromAccount = strMainAccount;
  wtx.mapValue["comment"] = strComment;
  string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
  if (strError != "") {
fprintf(stderr, "DEBUG: '%s' = SendMoneyTo: amount %d\n", strError.c_str(), (int)nAmount);
    //throw JSONRPCError(-4, strError);
    return (-4);
  }


  return (0);
}

/**
 * Transfer currency between two accounts.
 */
static int c_wallet_account_transfer(const char *sourceAccountName,
    const char *accountName, const char *comment, double dAmount)
{

  if (0 == strcmp(sourceAccountName, ""))
    return (-14);

  CWalletDB walletdb(pwalletMain->strWalletFile);
  CBitcoinAddress address;
  string strMainAccount(sourceAccountName);
  string strAccount(accountName);
  string strComment(comment);
  int64 nAmount;
  Array ret;
  int nMinDepth = 1; /* single confirmation requirement */
  int nMinConfirmDepth = 1; /* single confirmation requirement */
  bool found = false;
  int64 nBalance;

  if (pwalletMain->IsLocked()) {
    fprintf(stderr, "DEBUG: wallet is locked.\n");
    return (-13);
  }

  // Find all addresses that have the given account
  BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
  {
    const CBitcoinAddress& acc_address = item.first;
    const string& strName = item.second;
    if (strName == strAccount) {
      address = acc_address;
      found = true;
    }
  }
  if (!found) {
    return (-7);
  }

  if (dAmount <= 0.0 || dAmount > 84000000.0) {
    fprintf(stderr, "DEBUG: invalid amount (%f)\n", dAmount);
    //throw JSONRPCError(-3, "Invalid amount");
    return (-3);
  }

  nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(nAmount)) {
    fprintf(stderr, "DEBUG: invalid amount: !MoneyRange(%d)\n", (int)nAmount);
    //throw JSONRPCError(-3, "Invalid amount");
    return (-3);
  }


  nBalance  = GetAccountBalance(walletdb, strMainAccount, nMinConfirmDepth);
  if (nAmount > nBalance) {
    fprintf(stderr, "DEBUG: account has insufficient funds\n");
    //throw JSONRPCError(-6, "Account has insufficient funds");
    return (-6);
  }

  //address = GetAddressByAccount(accountName);
  if (!address.IsValid()) {
    fprintf(stderr, "DEBUG: invalid usde address destination\n");
    //throw JSONRPCError(-5, "Invalid usde address");
    return (-5);
  }

  CWalletTx wtx;
  wtx.strFromAccount = strMainAccount;
  wtx.mapValue["comment"] = strComment;
  string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
  if (strError != "") {
    fprintf(stderr, "DEBUG: '%s' = SendMoneyTo: amount %d\n", strError.c_str(), (int)nAmount);
    return (-4);
  }

  return (0);
}

double c_getaccountbalance(const char *accountName)
{
  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strAccount(accountName);

  int nMinDepth = 1;
  int64 nBalance = GetAccountBalance(walletdb, strAccount, nMinDepth);

  return ((double)nBalance / (double)COIN);
}

int valid_pkey_hash(string strAccount, uint256 in_pkey)
{
  uint256 acc_pkey;
  int valid;

  valid = 0;
  acc_pkey = 0;
  BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
  {
    const CBitcoinAddress& address = item.first;
    const string& strName = item.second;
    CKeyID keyID;

    if (strName != strAccount)
      continue;
    if (!address.GetKeyID(keyID))
      continue;

    acc_pkey = get_private_key_hash(keyID);
    if (acc_pkey == in_pkey)
      valid++;
else fprintf(stderr, "DEBUG: get_private_key_hash: '%s'\n", acc_pkey.GetHex().c_str());
  }

  return (valid);
}

/**
 * local up to 100 transactions associated with account name.
 * @param duration The range in the past to search for account transactions (in seconds).
 * @returns json string format 
 */
string accounttransactioninfo_json;
static const char *cxx_getaccounttransactioninfo(const char *tx_account, const char *pkey_str, int duration)
{
  string strAccount(tx_account);
  uint256 in_pkey = 0;
  Array result;
  int64 min_t;
  int max = 100;
  int idx;

  try {
    in_pkey.SetHex(pkey_str);
    if (!valid_pkey_hash(strAccount, in_pkey)) {
      throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
    }

    min_t = time(NULL) - duration;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    //for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.end(); it != pwalletMain->mapWallet.begin(); --it) {
      CWalletTx* wtx = &((*it).second);

      if (wtx->GetTxTime() < min_t)
        continue;

      ListTransactions(*wtx, strAccount, 0, true, result);

      idx++;
      if (idx > max)
        break;
    }
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  accounttransactioninfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (accounttransactioninfo_json.c_str());
}

string addressinfo_json;
const char *cxx_getaddressinfo(const char *addr_hash, const char *pkey_str)
{
  string strAddr(addr_hash);
  Object result;

  try {
    CBitcoinAddress address(strAddr);
    CKeyID keyID;

    if (!address.IsValid()) {
      throw JSONRPCError(STERR_INVAL, "Invalid usde destination address");
    }

    if (pkey_str && strlen(pkey_str) > 1) {
      uint256 in_pkey = 0;
      uint256 acc_pkey;

      if (!address.GetKeyID(keyID)) {
        throw JSONRPCError(STERR_ACCESS, "Address does not refer to a key.");
      }

      in_pkey.SetHex(pkey_str);
      acc_pkey = get_private_key_hash(keyID);
      if (acc_pkey != in_pkey) {
        throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
      }
    }

#if 0
    if (pkey_str) { /* optional */
      uint256 in_pkey = 0;
      uint256 acc_pkey;

      if (!address.GetKeyID(keyID)) {
        throw JSONRPCError(STERR_ACCESS, "Address does not refer to a key.");
      }

      in_pkey.SetHex(pkey_str);
      acc_pkey = get_private_key_hash(keyID);
      if (acc_pkey != in_pkey) {
        throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
      }
    }

    CTxDestination dest = address.Get();
    string currentAddress = address.ToString();
    result.push_back(Pair("address", currentAddress));
    if (pkey_str) {
      bool fCompressed;
      CSecret vchSecret;
      if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
        throw JSONRPCError(STERR_ACCESS_UNAVAIL,
            "Private key for address " + currentAddress + " is not known");
      }
      result.push_back(Pair("secret", CBitcoinSecret(vchSecret, fCompressed).ToString()));
    }

//    bool fMine = IsMine(*pwalletMain, dest);
    Object detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
    result.insert(result.end(), detail.begin(), detail.end());
    if (pwalletMain->mapAddressBook.count(dest))
      result.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));
#endif
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  if (pkey_str && strlen(pkey_str) > 1) {
    result = JSONAddressInfo(addr_hash, true);
  } else {
    result = JSONAddressInfo(addr_hash, false);
  }

  addressinfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (addressinfo_json.c_str());
}

bool VerifyLocalAddress(CKeyID vchAddress)
{
  BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
  {
    const CBitcoinAddress& address = item.first;
    const string& strName = item.second;
    CKeyID keyID;
    address.GetKeyID(keyID);
    if (keyID == vchAddress)
      return (true);
  }

  return (false);
}

string createaccount_json;
static const char *c_stratum_create_account(const char *acc_name)
{
  string strAccount(acc_name);
  string coinAddr = "";
  uint256 phash = 0;
  CPubKey newKey;

  try {
    if (strAccount == "" || strAccount == "*") {
      throw JSONRPCError(STERR_INVAL_PARAM, "The account name specified is invalid.");
    }

    bool found = false;
    CBitcoinAddress address = GetAddressByAccount(acc_name, found);
    if (found && address.IsValid()) {
      throw JSONRPCError(STERR_INVAL_PARAM, "Account name is not unique.");
    }

    /* Generate a new key that is added to wallet. */
    if (!pwalletMain->GetKeyFromPool(newKey, false)) {
      if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();
      if (!pwalletMain->GetKeyFromPool(newKey, false)) {
        throw JSONRPCError(STERR_INTERNAL_MAP, "No new keys currently available.");
        return (NULL);
      }
    }

    CKeyID keyId = newKey.GetID();
    pwalletMain->SetAddressBookName(keyId, strAccount);
    coinAddr = CBitcoinAddress(keyId).ToString();
    phash = get_private_key_hash(keyId);
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  Object result;
  result.push_back(Pair("address", coinAddr));
  result.push_back(Pair("key", phash.GetHex()));
  createaccount_json = JSONRPCReply(result, Value::null, Value::null);
  return (createaccount_json.c_str());
}

/**
 * Creates an coin transaction for a single user account. 
 * @note charges 0.1 coins per each transaction to "bank" account.
 */
string transferaccount_json;
static const char *c_stratum_account_transfer(char *account, char *pkey_str, char *dest, double amount)
{
  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strAccount(account);
  string strDestAddress(dest);
  CBitcoinAddress dest_address(strDestAddress);
  CWalletTx wtx;
  int64 nAmount;
  string strAddress;
  CKeyID keyID;
  CSecret vchSecret;
  bool fCompressed;
  uint256 acc_pkey;
  uint256 in_pkey;
  int nMinDepth;
  int64 nBalance;
  int64 nFee = COIN / 10;
  int64 nTxFee = 0;

  try {
    in_pkey = 0;
    nMinDepth = 1;

    if (pwalletMain->IsLocked()) {
      throw JSONRPCError(STERR_ACCESS_NOKEY, "Account transactions are not currently available.");
    }

    if (!dest_address.IsValid()) {
      throw JSONRPCError(STERR_INVAL, "Invalid usde destination address");
    }

    in_pkey.SetHex(pkey_str);
    if (!valid_pkey_hash(strAccount, in_pkey)) {
      throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified.");
    }

    nAmount = roundint64(amount * COIN);
    if (!MoneyRange(nAmount) || nAmount <= nFee) {
      throw JSONRPCError(STERR_INVAL_AMOUNT, "Invalid coin amount.");
    }

    nBalance = GetAccountBalance(walletdb, strAccount, nMinDepth);
    if (nAmount > nBalance) {
      throw JSONRPCError(STERR_FUND_UNAVAIL, "Account has insufficient funds.");
    }

    vector<pair<CScript, int64> > vecSend;
    bool bankAddressFound = false;
    CBitcoinAddress bankAddress;
    CScript scriptPubKey;
    CReserveKey keyChange(pwalletMain);

    /* send fee to main account */
    bankAddress = GetAddressByAccount("", bankAddressFound);
    if (!bankAddressFound || !bankAddress.IsValid()) {
      nFee = 0;
    }

    wtx.strFromAccount = strAccount;
    wtx.mapValue["comment"] = "sharelib.net";
    /* bank */
    if (nFee) {
      scriptPubKey.SetDestination(bankAddress.Get());
      vecSend.push_back(make_pair(scriptPubKey, nFee));
    }
    /* user */
    scriptPubKey.SetDestination(dest_address.Get());
    vecSend.push_back(make_pair(scriptPubKey, nAmount - nFee));
    if (!pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nTxFee)) {
      if (nAmount + nTxFee > pwalletMain->GetBalance())
        throw JSONRPCError(STERR_FUND_UNAVAIL, "Insufficient funds for transaction.");
      throw JSONRPCError(STERR_ACCESS_UNAVAIL, "Transaction creation failure.");
    }
    if (!pwalletMain->CommitTransaction(wtx, keyChange)) {
      throw JSONRPCError(STERR_ACCESS_UNAVAIL, "Transaction commit failed.");
    }
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  Object result;
  result.push_back(Pair("txid", wtx.GetHash().GetHex()));
  result.push_back(Pair("fee", ValueFromAmount(nFee + nTxFee)));
  result.push_back(Pair("amount", ValueFromAmount(nAmount - nFee - nTxFee)));
  transferaccount_json = JSONRPCReply(result, Value::null, Value::null);
  return (transferaccount_json.c_str());
}

string accountinfo_json;
static const char *c_stratum_account_info(const char *acc_name, const char *pkey_str)
{
  CWalletDB walletdb(pwalletMain->strWalletFile);
  string strAccount(acc_name);
  int64 nConfirm;
  int64 nUnconfirm;
  int nMinDepth = 1;
  uint256 in_pkey;
  Object result;
  Array addr_list;
  CBitcoinAddress address;
  uint256 phash;

  try {
    if (strAccount == "" || strAccount == "*") {
      throw JSONRPCError(STERR_INVAL_PARAM, "The account name specified is invalid.");
    }

    in_pkey.SetHex(pkey_str);
    if (!valid_pkey_hash(strAccount, in_pkey)) {
      throw JSONRPCError(STERR_ACCESS, "Invalid private key hash specified for account.");
    }

    nConfirm = GetAccountBalance(walletdb, strAccount, nMinDepth);
    nUnconfirm = GetAccountBalance(walletdb, strAccount, 0) - nConfirm;
    result.push_back(Pair("confirmed", ValueFromAmount(nConfirm)));
    result.push_back(Pair("unconfirmed", ValueFromAmount(nUnconfirm)));

    // Find all addresses that have the given account
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
      const CBitcoinAddress& acc_address = item.first;
      const string& strName = item.second;
      if (strName == strAccount) {
        addr_list.push_back(JSONAddressInfo(acc_address, false));
      }
    }
    result.push_back(Pair("addresses", addr_list));
#if 0
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
      const CBitcoinAddress& acc_address = item.first;
      const string& strName = item.second;
      if (strName == strAccount) {
        addr_list.push_back(acc_address.ToString());

        CKeyID keyID;
        acc_address.GetKeyID(keyID);
        phash = get_private_key_hash(keyID);
      }
    }
    result.push_back(Pair("addresses", addr_list));
#endif
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  accountinfo_json = JSONRPCReply(result, Value::null, Value::null);
  return (accountinfo_json.c_str());
}

string account_import_json;
static const char *cxx_stratum_account_import(const char *acc_name, const char *privaddr_str)
{
  string strLabel(acc_name);
  string strSecret(privaddr_str);
  CBitcoinSecret vchSecret;
  CKeyID vchAddress;
  bool ok;

  try {
    ok = vchSecret.SetString(strSecret);
    if (!ok) {
      throw JSONRPCError(STERR_INVAL, "Invalid private key specified.");
    }

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    vchAddress = key.GetPubKey().GetID();

    if (VerifyLocalAddress(vchAddress)) {
      throw JSONRPCError(STERR_INVAL_PARAM, "Address already registered to local account.");
    }

    {
      LOCK2(cs_main, pwalletMain->cs_wallet);

      pwalletMain->MarkDirty();
      pwalletMain->SetAddressBookName(vchAddress, strLabel);

      if (pwalletMain->AddKey(key)) {
        /* key did not previously exist in wallet db */
        pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
        pwalletMain->ReacceptWalletTransactions();
      }
    }
  } catch(Object& objError) {
    SetStratumError(objError);
    return (NULL);
  }

  Object result;
  CBitcoinAddress addr(vchAddress);

  result.push_back(Pair("address", addr.ToString()));
  account_import_json = JSONRPCReply(result, Value::null, Value::null);
  return (account_import_json.c_str());
}

string stratumerror_json;
const char *c_stratum_error_get(int req_id)
{
  Object error;
  Object reply;
  Value id = req_id;

  error = GetStratumError();
  stratumerror_json = JSONRPCReply(Value::null, error, id);
  return (stratumerror_json.c_str());
}



#ifdef __cplusplus
extern "C" {
#endif

int load_wallet(void)
{
  return (c_LoadWallet());
}

int upgrade_wallet(void)
{
  return (cxx_UpgradeWallet());
}

int load_peers(void)
{
  return (c_LoadPeers());
}

const char *getaddressbyaccount(const char *accountName)
{
  if (accountName || !*accountName)
    return (NULL);
  return (c_getaddressbyaccount(accountName));
}

double getaccountbalance(const char *accountName)
{
  return (c_getaccountbalance(accountName));
}

int setblockreward(const char *accountName, double amount)
{
  if (!*accountName)
    return (-5); /* invalid usde address */
  return (c_setblockreward(accountName, amount));
}

int wallet_account_transfer(const char *sourceAccountName, const char *accountName, const char *comment, double amount)
{
  if (!accountName || !*accountName)
    return (-5); /* invalid usde address */
  return (c_wallet_account_transfer(sourceAccountName, accountName, comment, amount));
}

const char *getaccounttransactioninfo(const char *account, const char *pkey_str, int duration)
{
  if (!account)
    return (NULL);
  return (cxx_getaccounttransactioninfo(account, pkey_str, duration));
}

const char *stratum_getaddressinfo(const char *addr_hash)
{
  if (!addr_hash)
    return (NULL);
  return (cxx_getaddressinfo(addr_hash, NULL));
}
const char *stratum_getaddresssecret(const char *addr_hash, const char *pkey_str)
{
  if (!addr_hash)
    return (NULL);
  return (cxx_getaddressinfo(addr_hash, pkey_str));
}

const char *stratum_create_account(const char *acc_name)
{
  if (!acc_name)
    return (NULL);
  return (c_stratum_create_account(acc_name));
}

const char *stratum_create_transaction(char *account, char *pkey_str, char *dest, double amount)
{
  if (!account || !pkey_str || !dest)
    return (NULL);
  return (c_stratum_account_transfer(account, pkey_str, dest, amount));
}

const char *stratum_getaccountinfo(const char *account, const char *pkey_str)
{
  if (!account || !pkey_str)
    return (NULL);
  return (c_stratum_account_info(account, pkey_str));
}

const char *stratum_error_get(int req_id)
{
  return (c_stratum_error_get(req_id));
}

const char *stratum_importaddress(const char *account, const char *privaddr_str)
{
  if (!account || !privaddr_str)
    return (NULL);
  return (cxx_stratum_account_import(account, privaddr_str));
}

const char *getnewaddress(const char *account)
{
  return (cxx_getnewaddress(account));
}

#ifdef __cplusplus
}
#endif


