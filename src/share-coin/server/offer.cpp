
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
#include "wallet.h"
#include "offer.h"

using namespace std;
using namespace json_spirit;



offer_list *GetOfferTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapOffer);
}

offer_list *GetOfferPendingTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapOffer);
}

bool DecodeOfferHash(const CScript& script, int& mode, uint160& hash)
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
  op = CScript::DecodeOP_N(opcode); /* extension type (offer) */
  if (op != OP_OFFER &&
      op != OP_OFFER_ACCEPT) {
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


bool IsOfferOp(int op) {
	return (op == OP_OFFER);
}


string offerFromOp(int op) {
	switch (op) {
	case OP_EXT_NEW:
		return "offernew";
	case OP_EXT_UPDATE:
		return "offerupdate";
	default:
		return "<unknown offer op>";
	}
}

bool DecodeOfferScript(const CScript& script, int& op,
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

	op = CScript::DecodeOP_N(opcode); /* extension type (offer) */
  if (op != OP_OFFER &&
      op != OP_OFFER_ACCEPT)
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

	if ((mode == OP_EXT_NEW && vvch.size() == 2) ||
      (mode == OP_EXT_UPDATE && vvch.size() >= 1) ||
      (mode == OP_EXT_TRANSFER && vvch.size() >= 1) ||
      (mode == OP_EXT_PAY && vvch.size() >= 1) ||
      (mode == OP_EXT_REMOVE && vvch.size() >= 1))
    return (true);

	return false;
}

bool DecodeOfferScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeOfferScript(script, op, vvch, pc);
}

CScript RemoveOfferScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeOfferScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveOfferScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetOfferOpFee(CIface *iface, int nHeight) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 4987 / base * COIN;
  double nDif = 4982 /base * COIN;
  int64 fee = (int64)(nRes - nDif);
  return (MAX(iface->min_tx_fee, fee));
}


bool IsOfferTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_OFFER)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeOfferHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

/**
 * Obtain the tx that defines this offer.
 */
bool GetTxOfOffer(CIface *iface, const uint160& hashOffer, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  offer_list *offeres = GetOfferTable(ifaceIndex);
  bool ret;

  if (offeres->count(hashOffer) == 0) {
    return false; /* nothing by that name, sir */
  }

  uint256 hashBlock;
  uint256 hashTx = (*offeres)[hashOffer];
  CTransaction txIn;
  ret = GetTransaction(iface, hashTx, txIn, NULL);
  if (!ret) {
    return false;
  }

  if (!IsOfferTx(txIn)) 
    return false; /* inval; not an offer tx */

#if 0
  if (txIn.offer.IsExpired()) {
    return false;
  }
#endif

  tx.Init(txIn);
  return true;
}

bool IsLocalOffer(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalOffer(CIface *iface, const CTransaction& tx)
{
  if (!IsOfferTx(tx))
    return (false); /* not a offer */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalOffer(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an offer transaction.
 */
bool VerifyOffer(CTransaction& tx)
{
  uint160 hashOffer;
  int nOut;

  /* core verification */
  if (!IsOfferTx(tx))
    return (false); /* tx not flagged as offer */

  /* verify hash in pub-script matches offer hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* no extension output */

  int mode;
  if (!DecodeOfferHash(tx.vout[nOut].scriptPubKey, mode, hashOffer))
    return (false); /* no offer hash in output */

  if (mode != OP_EXT_NEW &&
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_PAY &&
      mode != OP_EXT_REMOVE)
    return (false);

  COffer *offer = &tx.offer;
  if (hashOffer != offer->GetHash())
    return (false); /* offer hash mismatch */

  return (true);
}


#if 0
int init_offer_tx(CIface *iface, string strAccount, int srcIndex, int64 srcValue, int destIndex, int64 destValue, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  string strTitle(title);

  if(strlen(title) == 0)
    return (SHERR_INVAL);
  if(strlen(title) > 135)
    return (SHERR_INVAL);

  bool found = false;
  string strAccount;
  BOOST_FOREACH(const PAIRTYPE(CCoinAddr, string)& item, wallet->mapAddressBook)
  {
    const CCoinAddr& address = item.first;
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

  COffer *offer;
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* embed offer content into transaction */
  wtx.SetNull();
  offer = wtx.CreateOffer(strTitle, key_id);
  offer->setActive(true); /* auto-activate */
  wtx.strFromAccount = strAccount; /* originating account for payment */

  int64 nFee = GetOfferOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (SHERR_AGAIN);
  }

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  uint160 offerHash = offer->GetHash();
  CScript scriptPubKey;

  scriptPubKeyOrig.SetDestination(extAddr.Get());
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_OFFER) << OP_HASH160 << offerHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  /* todo: add to pending instead */
  wallet->mapOffer[strTitle] = wtx.GetHash();

  Debug("SENT:OFFERNEW : title=%s, ref=%s, offerhash=%s, tx=%s\n", title, key_id.GetHex().c_str(), offer->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}



int accept_offer_tx(CIface *iface, string strAccount, uint160 hashOffer, int srcIndex, int64 srcValue, int destIndex, int64 destValue, CWalletTx& wtx)
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

  /* verify original offer */
  CTransaction tx;
  if (!GetTxOfOffer(iface, strTitle, tx))
    return (SHERR_NOENT);
  if(!IsLocalOffer(iface, tx))
    return (SHERR_REMOTE);

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0)
    return (SHERR_REMOTE);

  /* establish account */
  CCoinAddr extAddr;
  string strAccount;
  if (!GetCoinAddr(wallet, addr, strAccount)) 
    return (SHERR_INVAL);

  /* generate new coin address */
  string strExtAccount = "@" + strAccount;
  extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* generate tx */
  COffer *offer;
	CScript scriptPubKey;
  wtx.SetNull();
  offer = wtx.CreateOffer(strTitle, key_id);
  uint160 offerHash = offer->GetHash();

  vector<pair<CScript, int64> > vecSend;
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_OFFER) << OP_HASH160 << offerHash << OP_2DROP;

  int64 nNetFee = GetOfferOpFee(iface, GetBestHeight(iface));
  if (nNetFee) { /* supplemental tx payment */
    CScript scriptFee;
    scriptFee << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_OFFER) << OP_HASH160 << offerHash << OP_2DROP << OP_RETURN;
    vecSend.push_back(make_pair(scriptFee, nNetFee));
  }

  /* ship 'er off */
  CReserveKey reservekey(wallet); /* DEBUG: todo: not actually used */
  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend))
    return (SHERR_INVAL);

/* todo: add to pending instead */
  wallet->mapOffer[strTitle] = wtx.GetHash();


	return (0);
}
#endif


