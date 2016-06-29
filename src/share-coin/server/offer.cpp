
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


extern bool CreateTransactionWithInputTx(CIface *iface, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxIn, int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey);


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
  return (&wallet->mapOfferAccept);
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

int64 GetOfferOpFee(CIface *iface)
{
  return (iface->min_tx_fee * 2);
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

bool AcceptOffer(CIface *iface, COffer *offer, COfferAccept& accept)
{
  int64 payValue = abs(offer->nPayValue);
  int64 xferValue = abs(offer->nXferValue);

  BOOST_FOREACH(const COfferAccept& t_accept, offer->accepts) {
    payValue -= abs(t_accept.nPayValue); 
    xferValue -= abs(t_accept.nXferValue); 
  }

  /* verify limits */
  if (abs(accept.nXferValue) + xferValue > abs(offer->nPayValue))
    return (false);
  if (abs(accept.nPayValue) + payValue > abs(offer->nXferValue))
    return (false);

  /* verify ratio */
  double srate = abs(offer->nPayValue / accept.nXferValue);
  double drate = abs(offer->nXferValue / accept.nPayValue);
  if (srate != drate) {
    /* invalid offer */
    return error(SHERR_INVAL, "AcceptOffer: offer has invalid exchange ratio.");
  }

  offer->accepts.push_back(accept);
  return (true);
}

/* DEBUG: TODO: verify their offer-accept alt->holding transaction */

bool GenerateOffers(CIface *iface, COffer *offer)
{
  int ifaceIndex = GetCoinIndex(iface);
  offer_list *offers = GetOfferPendingTable(ifaceIndex);
  uint160 hashOffer = offer->GetHash();

  map<uint160, uint256>::iterator mi = offers->begin(); 
  while (mi != offers->end()) {
    CTransaction tx;
    const uint160& hashOffer = (*mi).first;
    if (!GetTxOfOffer(iface, hashOffer, tx))
      continue;

    COfferAccept& accept = ((COfferAccept&) tx.offer);
    if (accept.hashOffer != hashOffer)
      continue; /* wrong offer */

    AcceptOffer(iface, offer, accept);
  }

  if (offer->accepts.size() == 0)
    return (false);

  return (true);
}

bool COfferCore::GetPayAddr(int ifaceIndex, CCoinAddr& addr)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  addr = CCoinAddr(stringFromVch(vPayAddr));
  if (!addr.IsValid())
    return (false);
  return (true);
}

bool COfferCore::GetXferAddr(int ifaceIndex, CCoinAddr& addr, std::string& account)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  addr = CCoinAddr(stringFromVch(vXferAddr));
  if (!addr.IsValid())
    return (false);
  if (!GetCoinAddr(wallet, addr, account));
    return (false);
  return (true);
}

static int FindOfferTxOut(int ifaceIndex, uint256 hashTx, CWalletTx& alt_wtxIn, CCoinAddr& payAddr)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  int nOut;
  bool ret;

  if (wallet->mapWallet.count(hashTx) == 0) {
    return (SHERR_REMOTE);
  }

  alt_wtxIn = wallet->mapWallet[hashTx];
 
  for (nOut = 0; nOut < alt_wtxIn.vout.size(); nOut++) {
    CScript& pubKey = alt_wtxIn.vout[nOut].scriptPubKey;
    CTxDestination addr;

    ret = ExtractDestination(pubKey, addr); 
    if (!ret)
      continue;

    if (addr == payAddr.Get())
      return (nOut);
  }

  return (SHERR_INVAL);
}

/**
 * Create an offer between SHC and a supported alternate currency.
 * @note Any coins being offered are moved to a transition account.
 */
int init_offer_tx(CIface *iface, std::string strAccount, int64 srcValue, int destIndex, int64 destValue, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    return (SHERR_INVAL);

  if (srcValue == 0 || destValue == 0 ||
      (srcValue <= 0 && destValue <= 0) ||
      (srcValue >= 0 && destValue >= 0)) {
    return (SHERR_INVAL);
  }

  if (ifaceIndex != TEST_COIN_IFACE && 
      (ifaceIndex == destIndex))
    return (SHERR_INVAL);

  int64 nFee = GetOfferOpFee(iface) + MAX(0, srcValue);
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (SHERR_AGAIN);
  }

  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */
  COffer *offer = wtx.CreateOffer();
  offer->SetActive(true); /* auto-activate */

  string strExtAccount = "@" + strAccount;
  CWallet *altWallet = GetWallet(destIndex);

  CCoinAddr payAddr;
  CCoinAddr xferAddr;
  CCoinAddr extAddr;
  if (srcValue < 0) { /* requesting SHC */
    /* The exchanged (shc) coin payment address. */
    payAddr = GetAccountAddress(wallet, strAccount, false);
    /* The intermediate holding (alt) coin address. */
    xferAddr = GetAccountAddress(altWallet, strExtAccount, true);
    /* The extended operation (shc) destination address */
    extAddr = GetAccountAddress(wallet, strExtAccount, true);
    /* The amount being requested for payment */
    offer->nPayValue = (-1 * srcValue);
    /* The amount being offered. */
    offer->nXferValue = destValue;

    offer->nPayCoin = GetCoinIndex(iface);
    offer->nXferCoin = destIndex;
  } else { /* sending SHC */
    /* The exchanged (alt) coin payment address. */
    payAddr = GetAccountAddress(altWallet, strAccount, false);
    /* The intermediate holding (shc) coin address. */
    xferAddr = GetAccountAddress(wallet, strExtAccount, true);
    /* The extended operation (shc) destination address */
    extAddr = xferAddr;
    /* The amount being requested for payment */
    offer->nPayValue = (-1 * destValue);
    /* The amount being offered. */
    offer->nXferValue = srcValue;

    offer->nPayCoin = destIndex;
    offer->nXferCoin = GetCoinIndex(iface);
  }
  offer->vPayAddr = vchFromString(payAddr.ToString());
  offer->vXferAddr = vchFromString(xferAddr.ToString());

  if (destValue > 0) {
    /* send alt currency to holding addr */
    int64 bal = GetAccountBalance(destIndex, strAccount, 1);
    if (bal < destValue)
      return (SHERR_AGAIN);

    CWalletTx alt_wtx;
    alt_wtx.strFromAccount = strAccount;
    CScript scriptPubKey;
    scriptPubKey.SetDestination(xferAddr.Get());

    // send transaction
    string strError = wallet->SendMoney(scriptPubKey, destValue, alt_wtx, false);
    if (strError != "") {
      error(ifaceIndex, strError.c_str());
      return (SHERR_INVAL);
    }

    offer->vXferTx = vchFromString(alt_wtx.GetHash().GetHex());
  }

  uint160 offerHash = offer->GetHash();

  /* send ext tx */
  CScript scriptPubKeyOrig;
  CScript scriptPubKey;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_OFFER) << OP_HASH160 << offerHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
/* .. send back alt_wtx */
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  /* todo: add to pending instead */
  wallet->mapOffer[offerHash] = wtx.GetHash();

  Debug("SENT:OFFERNEW : offerhash=%s, tx=%s\n", offer->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}

int accept_offer_tx(CIface *iface, string strAccount, uint160 hashOffer, int64 srcValue, int64 destValue, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if (ifaceIndex != TEST_COIN_IFACE &&
      ifaceIndex != SHC_COIN_IFACE)
    return (SHERR_INVAL);

  if (srcValue == 0 || destValue == 0 ||
      (srcValue <= 0 && destValue <= 0) ||
      (srcValue >= 0 && destValue >= 0)) {
    return (SHERR_INVAL);
  }

  int64 nFee = GetOfferOpFee(iface) + MAX(0, srcValue);
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (SHERR_AGAIN);
  }

  /* establish offer tx */
  CTransaction tx;
  if (!GetTxOfOffer(iface, hashOffer, tx))
    return (SHERR_NOENT);

  COffer *offer = &tx.offer; 

  int srcIndex;
  int destIndex;
  if (offer->nPayCoin == GetCoinIndex(iface)) {
    if ((offer->nPayCoin < 0 && srcValue <= 0) ||
        (offer->nXferCoin < 0 && destValue <= 0))
      return (SHERR_INVAL); 

    srcIndex = offer->nPayCoin;
    destIndex = offer->nXferCoin;
  } else {
    if ((offer->nXferCoin < 0 && srcValue <= 0) ||
        (offer->nPayCoin < 0 && destValue <= 0))
      return (SHERR_INVAL); 

    srcIndex = offer->nXferCoin;
    destIndex = offer->nPayCoin;
  }

  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */
  COfferAccept *accept = wtx.AcceptOffer(offer);
  accept->SetActive(true); /* auto-activate */

  string strExtAccount = "@" + strAccount;
  CWallet *altWallet = GetWallet(destIndex);

  CCoinAddr payAddr;
  CCoinAddr xferAddr;
  CCoinAddr extAddr;
  if (srcValue < 0) { /* requesting SHC */
    /* The exchanged (shc) coin payment address. */
    payAddr = GetAccountAddress(wallet, strAccount, false);
    /* The intermediate holding (alt) coin address. */
    xferAddr = GetAccountAddress(altWallet, strExtAccount, true);
    /* The extended operation (shc) destination address */
    extAddr = GetAccountAddress(wallet, strExtAccount, true);
    /* The amount being requested for payment */
    accept->nPayValue = (-1 * srcValue);
    /* The amount being accepted. */
    accept->nXferValue = destValue;
  } else { /* sending SHC */
    /* The exchanged (alt) coin payment address. */
    payAddr = GetAccountAddress(altWallet, strAccount, false);
    /* The intermediate holding (shc) coin address. */
    xferAddr = GetAccountAddress(wallet, strExtAccount, true);
    /* The extended operation (shc) destination address */
    extAddr = xferAddr;
    /* The amount being requested for payment */
    accept->nPayValue = (-1 * destValue);
    /* The amount being accepted. */
    accept->nXferValue = srcValue;
  }
  accept->vPayAddr = vchFromString(payAddr.ToString());
  accept->vXferAddr = vchFromString(xferAddr.ToString());

  if (destValue > 0) {
    /* send alt currency to holding addr */
    int64 bal = GetAccountBalance(destIndex, strAccount, 1);
    if (bal < destValue)
      return (SHERR_AGAIN);

    CWalletTx alt_wtx;
    alt_wtx.strFromAccount = strAccount;
    CScript scriptPubKey;
    scriptPubKey.SetDestination(xferAddr.Get());

    // send transaction
    string strError = wallet->SendMoney(scriptPubKey, destValue, alt_wtx, false);
    if (strError != "") {
      error(ifaceIndex, strError.c_str());
      return (SHERR_INVAL);
    }

    accept->vXferTx = vchFromString(alt_wtx.GetHash().GetHex());
  }

  uint160 hashAccept = accept->GetHash();

  /* send ext tx */
  CScript scriptPubKeyOrig;
  CScript scriptPubKey;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_OFFER) << OP_HASH160 << hashAccept << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
/* .. send back alt_wtx */
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  /* todo: add to pending instead */
  wallet->mapOfferAccept[hashAccept] = wtx.GetHash();

  Debug("SENT:OFFERACCEPT : accepthash=%s, tx=%s\n", accept->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}


int generate_offer_tx(CIface *iface, uint160 hashOffer, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
  bool ret;

  /* verify original offer */
  CTransaction tx;
  if (!GetTxOfOffer(iface, hashOffer, tx))
    return (SHERR_NOENT);
  if(!IsLocalOffer(iface, tx))
    return (SHERR_REMOTE);

  COffer *offerOrig = &tx.offer;


  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0) {
    return (SHERR_REMOTE);
  }
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  int nTxOut = IndexOfExtOutput(wtxIn);
  if (nTxOut == -1)
    return (SHERR_INVAL);

  int64 nFeeValue = wtxIn.vout[nTxOut].nValue;

  wtx.SetNull();
  COffer *offer = wtx.GenerateOffer(offerOrig);

  if (!GenerateOffers(iface, offer))
    return (SHERR_AGAIN);

  CCoinAddr payAddr;
  string strPayAccount;
  vector<pair<CScript, int64> > vecSend;
  if (offer->nPayCoin == ifaceIndex) {
    int altIndex = offer->nXferCoin;
    CIface *altIface = GetCoinByIndex(altIndex);

    if (!altIface || !altIface->enabled)
      return (SHERR_OPNOTSUPP);

    /* offer sending alt */
    if (!offer->GetXferAddr(altIndex, payAddr, strPayAccount))
      return (SHERR_INVAL);

    CWalletTx alt_wtx;
    CWalletTx alt_wtxIn;
    uint256 hashTx(stringFromVch(offer->vXferTx)); /* needs 0x prefix? */
   // bool ret = GetTransaction(altIface, hashTx, tx, NULL);
    int nTxOut = FindOfferTxOut(altIndex, hashTx, alt_wtxIn, payAddr);
    if (nTxOut == -1)
      return (SHERR_INVAL);

    int nAltFeeValue = alt_wtxIn.vout[nTxOut].nValue;
    vector<pair<CScript, int64> > alt_vecSend;
    BOOST_FOREACH(COfferAccept& accept, offer->accepts) {
      int nValue = MAX(0, (-1 * accept.nPayValue));

      /* output - send alt-coin to accept addr */
      CCoinAddr destAddr;
      if (!accept.GetPayAddr(altIndex, destAddr))
        continue; /* print error */

      CScript destPubKey;
      destPubKey.SetDestination(destAddr.Get());
      vecSend.insert(vecSend.begin(), make_pair(destPubKey, nValue));

      nAltFeeValue -= nValue;
      
      if (nAltFeeValue < 0) {
        error(SHERR_CANCELED, "generate_offer_tx: "
            "miscalculation on accept offer payments:");
        wtx.print(); 
        return (SHERR_CANCELED);
      }
    }

    CWallet *altWallet = GetWallet(altIface);
    CReserveKey reservekey(altWallet);
    ret = CreateTransactionWithInputTx(altIface, alt_vecSend, alt_wtxIn, nTxOut, alt_wtx, reservekey);
    if (!ret) {
      return (SHERR_CANCELED);
    }

  } else {
    nFeeValue -= iface->min_tx_fee; /* for GEN op script */

    /* offer sending shc */
    if (!offer->GetXferAddr(ifaceIndex, payAddr, strPayAccount))
      return (SHERR_INVAL);

    BOOST_FOREACH(COfferAccept& accept, offer->accepts) {
      int nValue = MAX(0, (-1 * accept.nPayValue));

      /* output - send SHC to accept addr */
      CCoinAddr destAddr;
      if (!accept.GetPayAddr(ifaceIndex, destAddr))
        continue; /* print error */

      CScript destPubKey;
      destPubKey.SetDestination(destAddr.Get());
      vecSend.insert(vecSend.begin(), make_pair(destPubKey, nValue));

      nFeeValue -= nValue;
      
      if (nFeeValue < 0) {
        error(SHERR_CANCELED, "generate_offer_tx: "
            "miscalculation on accept offer payments:");
        wtx.print(); 
        return (SHERR_CANCELED);
      }
    }

    wtx.strFromAccount = strPayAccount;
  }

  uint160 offerHash = offer->GetHash();
/* offer == offerOrig hash */

  /* ext output - remainder of input is left to block tx fee */
  CScript scriptFee;
  scriptFee << OP_EXT_GENERATE << CScript::EncodeOP_N(OP_OFFER) << OP_HASH160 << offerHash << OP_2DROP << OP_RETURN;
  vecSend.push_back(make_pair(scriptFee, (int64)iface->min_tx_fee));

  CReserveKey reservekey(wallet);
  ret = CreateTransactionWithInputTx(iface, vecSend, wtxIn, nTxOut, wtx, reservekey);
  if (!ret)
    return (SHERR_CANCELED);

  wallet->mapOffer[offerHash] = wtx.GetHash();

	return (0);
}


