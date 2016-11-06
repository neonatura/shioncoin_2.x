
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
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>

using namespace std;
using namespace json_spirit;

#include "block.h"
#include "wallet.h"
#include "certificate.h"
#include "alias.h"


alias_list *GetAliasTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapAlias);
}

alias_list *GetAliasPendingTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapAlias);
}

bool DecodeAliasHash(const CScript& script, int& mode, uint160& hash)
{
  CScript::const_iterator pc = script.begin();
  opcodetype opcode;
  int op;

  if (!script.GetOp(pc, opcode)) {
    return false;
  }
  mode = opcode; /* extension mode (new/activate/update) */
  if (mode < 0xf0 || mode > 0xf9)
    return false;

  if (!script.GetOp(pc, opcode)) { 
    return false;
  }
  if (opcode < OP_1 || opcode > OP_16) {
    return false;
  }
  op = CScript::DecodeOP_N(opcode); /* extension type (alias) */
  if (op != OP_ALIAS) {
    return false;
  }

  vector<unsigned char> vch;
  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  if (opcode != OP_HASH160)
    return (false);

  if (!script.GetOp(pc, opcode, vch)) {
    return false;
  }
  hash = uint160(vch);
  return (true);
}





bool IsAliasOp(int op) {
	return (op == OP_ALIAS);
}


string aliasFromOp(int op) {
	switch (op) {
	case OP_EXT_ACTIVATE:
		return "aliasactivate";
	case OP_EXT_UPDATE:
		return "aliasupdate";
	default:
		return "<unknown alias op>";
	}
}

bool DecodeAliasScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) 
{
	opcodetype opcode;
  int mode;

	if (!script.GetOp(pc, opcode))
		return false;
  mode = opcode; /* extension mode (new/activate/update) */

	if (!script.GetOp(pc, opcode))
		return false;
	if (opcode < OP_1 || opcode > OP_16)
		return false;

	op = CScript::DecodeOP_N(opcode); /* extension type (alias) */
  if (op != OP_ALIAS)
    return false;

	for (;;) {
		vector<unsigned char> vch;
		if (!script.GetOp(pc, opcode, vch))
			return false;
		if (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP)
			break;
		if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
			return false;
		vvch.push_back(vch);
	}

	// move the pc to after any DROP or NOP
	while (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP) {
		if (!script.GetOp(pc, opcode))
			break;
	}

	pc--;

	if ((mode == OP_EXT_ACTIVATE && vvch.size() == 2) ||
      (mode == OP_EXT_UPDATE && vvch.size() >= 1) ||
      (mode == OP_EXT_TRANSFER && vvch.size() >= 1) ||
      (mode == OP_EXT_REMOVE && vvch.size() >= 1))
    return (true);

	return false;
}

bool DecodeAliasScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeAliasScript(script, op, vvch, pc);
}

CScript RemoveAliasScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeAliasScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveAliasScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetAliasOpFee(CIface *iface, int nHeight) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5000 / base * COIN;
  double nDif = 4982 /base * COIN;
  int64 fee = (int64)(nRes - nDif);
  return (MAX(iface->min_tx_fee, fee));
}


int64 GetAliasReturnFee(const CTransaction& tx) 
{
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

bool IsAliasTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_ALIAS)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeAliasHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}


bool IsLocalAlias(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalAlias(CIface *iface, const CTransaction& tx)
{
  if (!IsAliasTx(tx))
    return (false); /* not a alias */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalAlias(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an alias transaction.
 */
bool VerifyAlias(CTransaction& tx)
{
  uint160 hashAlias;
  int nOut;


  /* core verification */
  if (!IsAliasTx(tx)) {
fprintf(stderr, "DEBUG: VerifyAlias: is not alias tx\n");
    return (false); /* tx not flagged as alias */
}

  /* verify hash in pub-script matches alias hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1) {
fprintf(stderr, "DEBUG: VerifyAlias: has no extension output\n");
    return (false); /* no extension output */
}

  int mode;
  if (!DecodeAliasHash(tx.vout[nOut].scriptPubKey, mode, hashAlias)) {
fprintf(stderr, "DEBUG: VerifyAlias: !DecodeAliasHash: %s\n", tx.vout[nOut].scriptPubKey.ToString().c_str());
    return (false); /* no alias hash in output */
}

  if (mode != OP_EXT_ACTIVATE && 
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE) {
fprintf(stderr, "DEBUG: VerifyAlias: invalid mode %d\n", mode);
    return (false);
}

  CAlias *alias = tx.GetAlias();
  if (hashAlias != alias->GetHash()) {
fprintf(stderr, "DEBUG: VerifyAlias: alias hash mismatch: hashAlias(%s) txAlias(%s)\n", hashAlias.GetHex().c_str(), alias->GetHash().GetHex().c_str());
    return (false); /* alias hash mismatch */
}

  return (true);
}



CAlias *GetAliasByName(CIface *iface, string label, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  uint256 hTx;

  if (wallet->mapAlias.count(label) == 0)
    return (NULL);

  hTx = wallet->mapAlias[label];
  if (!GetTransaction(iface, hTx, tx, NULL))
    return (NULL);

  return (&tx.alias);
}

/* for conveience */
bool GetTxOfAlias(CIface *iface, const std::string strTitle, CTransaction& tx) 
{
  return (GetAliasByName(iface, strTitle, tx) != NULL);
}

bool CAlias::GetCoinAddr(CCoinAddr& addrRet)
{

  if (vAddr.size() == 0)
    return (false);

  addrRet = CCoinAddr(stringFromVch(vAddr));
  if (!addrRet.IsValid())
    return (false);

  return (true);
}

void CAlias::SetCoinAddr(CCoinAddr& addr)
{
  char buf[256];

  memset(buf, 0, sizeof(buf));
  strncpy(buf, addr.ToString().c_str(), sizeof(buf)-1);
  vAddr = cbuff(buf, buf + strlen(buf));
}


int init_alias_addr_tx(CIface *iface, const char *title, CCoinAddr& addr, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strTitle(title);

  if(strlen(title) == 0)
    return (SHERR_INVAL);
  if(strlen(title) > 135)
    return (SHERR_INVAL);

  if (wallet->mapAlias.count(strTitle) != 0)
    return (SHERR_NOTUNIQ);

  bool found = false;
  string strAccount;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = CCoinAddr(ifaceIndex, item.first);
    const string& account = item.second;
    if (address == addr) {
      addr = address;
      strAccount = account;
      found = true;
      break;
    }
  }
  if (!found) {
    return (SHERR_NOENT);
  }

  CKeyID key_id;
  if (!addr.GetKeyID(key_id)) {
    return (SHERR_OPNOTSUPP);
  }

  CAlias *alias;

  /* embed alias content into transaction */
  wtx.SetNull();
  alias = wtx.CreateAlias(strTitle, key_id);
  wtx.strFromAccount = strAccount; /* originating account for payment */

  int64 nFee = GetAliasOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (SHERR_AGAIN);
  }

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  uint160 aliasHash = alias->GetHash();
  CScript scriptPubKey;

  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  if (!extAddr.IsValid()) {
fprintf(stderr, "DEBUG: error obtaining address for '%s'\n", strExtAccount.c_str());
    return (SHERR_INVAL);
}

  scriptPubKeyOrig.SetDestination(extAddr.Get());
  scriptPubKey << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_ALIAS) << OP_HASH160 << aliasHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  wallet->mapAlias[strTitle] = wtx.GetHash();

  Debug("SENT:ALIASNEW : title=%s, ref=%s, aliashash=%s, tx=%s\n", title, key_id.GetHex().c_str(), alias->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}

int update_alias_addr_tx(CIface *iface, const char *title, CCoinAddr& addr, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
  string strTitle(title);

  if (strlen(title) > MAX_SHARE_NAME_LENGTH)
    return (SHERR_INVAL);
  if (!addr.IsValid())
    return (SHERR_INVAL);

  CKeyID key_id;
  if (!addr.GetKeyID(key_id))
    return (SHERR_OPNOTSUPP);

  /* verify original alias */
  CTransaction tx;
  if (!GetTxOfAlias(iface, strTitle, tx))
    return (SHERR_NOENT);
  if(!IsLocalAlias(iface, tx))
    return (SHERR_REMOTE);

  if (wallet->mapAlias.count(strTitle) != 0 && /* unique new name */
      tx.alias.GetLabel() != strTitle) /* or just the same name */
    return (SHERR_NOTUNIQ);

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0)
    return (SHERR_REMOTE);

  /* establish account */
  string strAccount;
  if (!GetCoinAddr(wallet, addr, strAccount)) 
    return (SHERR_INVAL);

  /* generate new coin address */
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* generate tx */
  CAlias *alias;
	CScript scriptPubKey;

  wtx.SetNull();
  wtx.strFromAccount = strAccount;

  alias = wtx.CreateAlias(strTitle, key_id);
  uint160 aliasHash = alias->GetHash();

  vector<pair<CScript, int64> > vecSend;
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ALIAS) << OP_HASH160 << aliasHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  int64 nNetFee = GetAliasOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }
#if 0
  if (nNetFee) { /* supplemental tx payment */
    CScript scriptFee;
    scriptFee << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_ALIAS) << OP_HASH160 << aliasHash << OP_2DROP << OP_RETURN;
    vecSend.push_back(make_pair(scriptFee, nNetFee));
  }
#endif

  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend))
    return (SHERR_INVAL);

  wallet->mapAlias[strTitle] = wtx.GetHash();

	return (0);
}


std::string CAlias::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CAlias::ToValue()
{
  return (CIdent::ToValue());
}


