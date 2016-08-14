
/*
 * @copyright
 *
 *  Copyright 2016 Neo Natura
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
#include "channel.h"

using namespace std;
using namespace json_spirit;


channel_list *GetChannelTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapChannel);
}

channel_list *GetChannelSpentTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapChannelSpent);
}

bool DecodeChannelHash(const CScript& script, int& mode, uint160& hash)
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
  op = CScript::DecodeOP_N(opcode); /* extension type (channel) */
  if (op != OP_CHANNEL) {
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



bool IsChannelOp(int op) {
	return (op == OP_CHANNEL);
}


string channelFromOp(int op) {
	switch (op) {
	case OP_EXT_NEW:
		return "channelnew";
	case OP_EXT_PAY:
		return "channelpay";
	case OP_EXT_VALIDATE:
		return "channelvalidate";
	case OP_EXT_ACTIVATE:
		return "channelactivate";
	case OP_EXT_GENERATE:
		return "channelgenerate";
	case OP_EXT_REMOVE:
		return "channelgenerate";
	default:
		return "<unknown channel op>";
	}
}

bool DecodeChannelScript(const CScript& script, int& op,
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

	op = CScript::DecodeOP_N(opcode); /* extension type (channel) */
  if (op != OP_CHANNEL)
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

	if ((mode == OP_EXT_NEW && vvch.size() == 1) ||
      (mode == OP_EXT_ACTIVATE && vvch.size() == 1) ||
      (mode == OP_EXT_PAY && vvch.size() == 2) ||
      (mode == OP_EXT_VALIDATE && vvch.size() == 2) ||
      (mode == OP_EXT_GENERATE && vvch.size() == 2) ||
      (mode == OP_EXT_REMOVE && vvch.size() == 2))
    return (true);

	return false;
}

bool DecodeChannelScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeChannelScript(script, op, vvch, pc);
}

CScript RemoveChannelScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeChannelScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveChannelScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetChannelReturnFee(const CTransaction& tx) 
{
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

bool IsChannelTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_CHANNEL)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeChannelHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

/**
 * Obtain the tx that defines this channel.
 */
bool GetTxOfChannel(CIface *iface, const uint160& hashChannel, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  channel_list *channels = GetChannelTable(ifaceIndex);
  bool ret;

  if (channels->count(hashChannel) == 0) {
    return false; /* nothing by that name, sir */
  }

  const CTransaction& txIn = (*channels)[hashChannel];
  if (!IsChannelTx(txIn)) 
    return false; /* inval; not an channel tx */

  tx.Init(txIn);
  return true;
}

bool IsLocalChannel(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalChannel(CIface *iface, const CTransaction& tx)
{
  if (!IsChannelTx(tx))
    return (false); /* not a channel */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalChannel(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an channel transaction.
 */
bool VerifyChannel(CTransaction& tx)
{
  uint160 hashChannel;
  int nOut;

  /* core verification */
  if (!IsChannelTx(tx)) {
fprintf(stderr, "DEBUG: VerifyChannel: !IsChannelTx\n");
    return (false); /* tx not flagged as channel */
}

  /* verify hash in pub-script matches channel hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* no extension output */

  int mode;
  if (!DecodeChannelHash(tx.vout[nOut].scriptPubKey, mode, hashChannel))
    return (false); /* no channel hash in output */

  if (mode != OP_EXT_NEW && 
      mode != OP_EXT_ACTIVATE &&
      mode != OP_EXT_GENERATE &&
      mode != OP_EXT_PAY &&
      mode != OP_EXT_VALIDATE &&
      mode != OP_EXT_REMOVE)
    return (false);

  CChannel channel(tx.channel);
  if (hashChannel != channel.GetHash())
    return error(SHERR_INVAL, "channel hash mismatch");

  return (true);
}

bool OpenChannel(int ifaceIndex, CWalletTx& wtx)
{
  return (true);
}

bool GetOpenChannel(int ifaceIndex, uint160 hChan, CTransaction& tx)
{
  channel_list *channels = GetChannelTable(ifaceIndex);
  bool ret;

  if (channels->count(hChan) == 0)
    return false; 

  const CTransaction& txIn = (*channels)[hChan];
  if (!IsChannelTx(txIn)) 
    return false;

  int nOut = IndexOfExtOutput(txIn);
  if (nOut == -1)
    return (false);

  tx.Init(txIn);
  return (true);
}

bool GetSpentChannel(int ifaceIndex, uint160 hChan, CTransaction& tx)
{
  channel_list *channels = GetChannelSpentTable(ifaceIndex);
  bool ret;

  if (channels->count(hChan) == 0)
    return false; 

  const CTransaction& txIn = (*channels)[hChan];
  if (!IsChannelTx(txIn)) 
    return false;

  int nOut = IndexOfExtOutput(txIn);
  if (nOut == -1)
    return (false);

  tx.Init(txIn);
  return (true);
}

bool GetChannelDestination(CTransaction *tx, CTxDestination& addr, int64& nValue)
{
  int nOut = IndexOfExtOutput(*tx);
  if (nOut == -1)
    return (false);

  nValue = tx->vout[nOut].nValue;
  return (ExtractDestination(tx->vout[nOut].scriptPubKey, addr));
}

#if 0
/**
 * @param ctx The original funding transaction.
 */
int GenerateChannelRevocableTx(CIface *iface, uint160 hChan, CTransaction *prevTx, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CTransaction txChan;
  CChannel chan;
	CScript script;
  int nOut;

  if (!GetOpenChannel(ifaceIndex, hChan, txChan))
    return (SHERR_NOENT);

  if (!IsLocalChannel(iface, txChan))
    return (SHERR_REMOTE);

  chan = txChan.channel;

  CScript redeem;
  chan.GetRedeemScript(redeem);

  nOut = IndexOfExtOutput(txChan);
  if (nOut == -1)
    return (SHERR_INVAL);

  /* create input */
	script << OP_0 << chan.lcl_pubkey << chan.rem_pubkey << redeem << OP_HASH160 << chan.GetHash() << OP_EQUAL;
  wtx.vin.push_back(CTxIn(prevTx->GetHash(), nOut, script, 1));

  /* create output */
  int64 nValue = txChan.vout[nOut].nValue;
  wtx.vout.push_back(CTxOut(nValue, redeem));

  return (0);
}
#endif


std::string CChannel::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CChannel::ToValue()
{
  Object obj = CExtCore::ToValue();

  obj.push_back(Pair("hash", GetHash().GetHex()));
  obj.push_back(Pair("lcl_pubkey", lcl_pubkey.GetHex()));
  obj.push_back(Pair("rem_pubkey", rem_pubkey.GetHex()));
  obj.push_back(Pair("lcl_addr", lcl_addr.GetHex()));
  obj.push_back(Pair("rem_addr", rem_addr.GetHex()));
  obj.push_back(Pair("sequence", (int)nSeq));

  return (obj);
}

bool CChannel::SetHash()
{
  CScript script;
	unsigned char raw[32];
  uint160 hash;

  GetRedeemScript(script);

	/* double hash redeem tx-script */
	uint256 fhash(script);
	memcpy(raw, &fhash, sizeof(fhash));
  cbuff vchHash(raw, raw + 32);
	hRedeem = Hash160(vchHash);

  return (true);
}

void CChannel::GetRedeemScript(CScript& script)
{
	vector<uint160> hash_list;

	hash_list.push_back(lcl_pubkey);
	hash_list.push_back(rem_pubkey);
	sort(hash_list.begin(), hash_list.end());

	script.clear();

	int nRequired = hash_list.size();
	script << CScript::EncodeOP_N(nRequired);
	BOOST_FOREACH(const uint160& hash, hash_list)
		script << hash;
	script << CScript::EncodeOP_N(hash_list.size()) << OP_CHECKMULTISIG;
}

bool CChannel::GetChannelTx(int ifaceIndex, CTransaction& tx)
{
  channel_list *channels = GetChannelTable(ifaceIndex);
  uint160 hChan = GetHash();
  bool ret;

  if (channels->count(hChan) == 0)
    return false; 

  const CTransaction& txIn = (*channels)[hChan];
  if (!IsChannelTx(txIn)) 
    return false;

  tx.Init(txIn);

  return true;
}

int CommitChannelTransaction(CWallet *wallet, CTransaction& tx)
{
  CWalletTx wtx(wallet, tx);
  CReserveKey rkey(wallet);

  if (!wallet->CommitTransaction(wtx, rkey))
    return (SHERR_CANCELED);

  return (0);
}


#if 0
void SignChannelTx(int ifaceIndex, CWalletTx& wtxNew,
    set<pair<const CWalletTx*,unsigned int> > setCoins)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  int nIn = 0;

  BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
    if (!SignSignature(*wallet, *coin.first, wtxNew, nIn++)) {
      txdb.Close();
      return false;
    }
}
#endif

uint160 GenerateChannelPubKey(CWallet *wallet, string strAccount)
{
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  CKeyID ext_pubkey;
  extAddr.GetKeyID(ext_pubkey);

  return ((uint160)ext_pubkey);
}

/**
 * The depth before a revocable channel transaction may be broadcast.
 */
unsigned int GetChannelTxMaturity(CIface *iface, CTransaction& tx)
{
  int ifaceIndex = GetCoinIndex(iface);
  uint160 hChan;
  int t_depth;
  int depth;
  int mode;

  if (!IsChannelTx(tx))
    return (0);

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (0);

  if (!DecodeChannelHash(tx.vout[nOut].scriptPubKey, mode, hChan))
    return (0);

  if (mode != OP_EXT_PAY)
    return (0);

  /* find newest input */
  depth = 0;
  BOOST_FOREACH(const CTxIn& in, tx.vin) {
    CTransaction txIn;
    uint256 hBlock;
    if (!GetTransaction(iface, in.prevout.hash, txIn, &hBlock))
      continue;
    t_depth = txIn.GetDepthInMainChain(ifaceIndex);
    if (t_depth > depth)
      depth = t_depth;
  }

  return (MAX(0, 1000 - depth + 1));
}
  
int init_channel_tx(CIface *iface, string strAccount, int64 nValue, CCoinAddr& rem_addr, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CChannel *channel;

  if (!iface || !iface->enabled)
    return (SHERR_INVAL);

  if (nValue <= (iface->min_tx_fee*2))
    return (SHERR_INVAL);

  if (!rem_addr.IsValid())
    return (SHERR_INVAL);

  /* note: channel tx op re-uses existing addresses in account for payout */
  CCoinAddr addr = GetAccountAddress(wallet, strAccount, false);
  if (!addr.IsValid())
    return (SHERR_INVAL);

  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */
  channel = wtx.CreateChannel(addr, rem_addr, nValue - iface->min_tx_fee); 
  if (!channel)
    return (SHERR_INVAL);

  /* generate funding and transmit public keys for p2sh */
  channel->lcl_pubkey = GenerateChannelPubKey(wallet, strAccount);
  channel->lcl_npubkey = GenerateChannelPubKey(wallet, strAccount);

  /* generate inputs */
  set<pair<const CWalletTx*,unsigned int> > setCoins; /* coins found */
  int64 nValueIn = 0; /* values found */
  if (!wallet->SelectCoins(nValue, setCoins, nValueIn) || nValueIn < nValue)
    return (SHERR_AGAIN); /* not enough coins */
  BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
    wtx.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));
/* DEBUG: TODO: must be marked as spent */

  nValue -= iface->min_tx_fee;

  if (nValueIn > nValue) { /* change from input coins */
    CScript scriptRet;
    scriptRet.SetDestination(addr.Get());
    wtx.vout.push_back(CTxOut(nValueIn - nValue, scriptRet));
  }

  /* counter-party will insert p2sh output and this output will be removed */
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_CHANNEL) << OP_DROP << OP_RETURN;
	wtx.vout.push_back(CTxOut(iface->min_tx_fee, scriptPubKey)); 

  // relay unsigned transaction
	uint256 tx_hash = wtx.GetHash();
	RelayMessage(CInv(ifaceIndex, MSG_TX, tx_hash), (CTransaction)wtx);

  wallet->mapChannel[channel->GetHash()] = (CTransaction)wtx;

  Debug("SENT:CHANNELNEW : channelhash=%s, tx=%s\n", channel->GetHash().GetHex().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}

int activate_channel_tx(CIface *iface, CTransaction *txIn, int64 nValue, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CChannel *channel;

  if (!iface || !iface->enabled)
    return (SHERR_INVAL);

  if (nValue <= (iface->min_tx_fee*2))
    return (SHERR_INVAL);

  string strAccount;
  CCoinAddr addr = txIn->channel.GetPeerAddr();
  if (!GetCoinAddr(wallet, addr, strAccount))
    return (SHERR_NOENT);

  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */
  channel = wtx.ActivateChannel(txIn->channel, nValue);
  if (!channel)
    return (SHERR_INVAL);

  /* generate funding and transmit public keys for p2sh */
  channel->rem_pubkey = GenerateChannelPubKey(wallet, strAccount);
  channel->rem_npubkey = GenerateChannelPubKey(wallet, strAccount);

  wtx.vin = txIn->vin;
  wtx.vout = txIn->vout;

  if (nValue > CENT) {
    /* generate inputs */
    set<pair<const CWalletTx*,unsigned int> > setCoins; /* coins found */
    int64 nValueIn = 0; /* values found */

    if (!wallet->SelectCoins(nValue, setCoins, nValueIn) || nValueIn < nValue)
      return (SHERR_AGAIN); /* not enough coins */
    BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
      wtx.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

    if (nValueIn > nValue) { /* change from input coins */
      CScript scriptRet;
      scriptRet.SetDestination(addr.Get());
      wtx.vout.push_back(CTxOut(nValueIn - nValue, scriptRet));
    }

/* DEBUG: TODO: must be marked as spent */
  }


  /* remove OP_EXT_NEW output */
  int nOut = IndexOfExtOutput(wtx);
  if (nOut != -1)
    wtx.vout.erase(wtx.vout.begin() + nOut);

  /* establish redeem script hash */
  channel->SetHash();

  /* insert p2sh output to channel */
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_CHANNEL) << OP_DROP;
  scriptPubKey << OP_HASH160 << channel->GetHash() << OP_EQUAL;
	wtx.vout.push_back(CTxOut(nValue, scriptPubKey)); 

  // relay unsigned transaction
	uint256 tx_hash = wtx.GetHash();
	RelayMessage(CInv(ifaceIndex, MSG_TX, tx_hash), (CTransaction)wtx);

  wallet->mapChannel[channel->GetHash()] = (CTransaction)wtx;

  Debug("SENT:CHANNELACTIVATE : channelhash=%s, tx=%s\n", channel->GetHash().GetHex().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}

int pay_channel_tx(CIface *iface, string strAccount, uint160 hChan, int64 nValue, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
  CTransaction txSpentIn;
  CTransaction txIn;
  CChannel *channel;
  CCoinAddr addr;
  CCoinAddr peer_addr;
  bool isOrigin;

  if (ifaceIndex != TEST_COIN_IFACE && ifaceIndex != SHC_COIN_IFACE)
    return (SHERR_OPNOTSUPP);

	if (!GetOpenChannel(ifaceIndex, hChan, txIn))
		return (SHERR_NOENT);

  int nOut = IndexOfExtOutput(txIn);
  if (nOut != -1)
    return (SHERR_INVAL);

  CChannel& chanIn = txIn.channel;

  string strChanAccount;
  CCoinAddr lcl_addr = chanIn.GetOriginAddr();
  CCoinAddr rem_addr = chanIn.GetPeerAddr();
  if (!lcl_addr.IsValid() || !rem_addr.IsValid())
    return (SHERR_INVAL);
  if (GetCoinAddr(wallet, lcl_addr, strChanAccount) &&
      strChanAccount == strAccount) {
    addr = lcl_addr; 
    peer_addr = rem_addr;
    isOrigin = true;
  } else if (GetCoinAddr(wallet, rem_addr, strChanAccount) &&
      strChanAccount == strAccount) {
    addr = rem_addr;
    peer_addr = lcl_addr;
    isOrigin = false;
  } else {
    return (SHERR_REMOTE);
  }

  wtx.SetNull();
  channel = wtx.PayChannel(chanIn);

	if (GetSpentChannel(ifaceIndex, hChan, txSpentIn)) {
    /* adjust counter-party balances */
    channel->lcl_value = txSpentIn.channel.lcl_value;
    channel->rem_value = txSpentIn.channel.rem_value;

    /* increment sequence */
    channel->nSeq = txSpentIn.channel.nSeq + 1;

    /* iterate to next set of pubkeys */
    channel->lcl_pubkey = txSpentIn.channel.lcl_npubkey;
    channel->rem_pubkey = txSpentIn.channel.rem_npubkey;
  } else {
    /* iterate to initial set of commit pubkeys */
    channel->lcl_pubkey = chanIn.lcl_npubkey;
    channel->rem_pubkey = chanIn.rem_npubkey;
  }

  if (isOrigin) {
    if (nValue < channel->lcl_value)
      return (SHERR_AGAIN);
    channel->lcl_value -= nValue;
    channel->rem_value += nValue;

    /* generate unique for next commit */
    channel->lcl_npubkey = GenerateChannelPubKey(wallet, strAccount);
  } else {
    if (nValue < channel->rem_value)
      return (SHERR_AGAIN);
    channel->lcl_value += nValue;
    channel->rem_value -= nValue;

    /* generate unique for next commit */
    channel->rem_npubkey = GenerateChannelPubKey(wallet, strAccount);
  }


  /* create input from funding transaction */
  CScript scriptIn;
  CScript redeem;
  chanIn.GetRedeemScript(redeem);
	scriptIn << OP_0 << chanIn.rem_pubkey << chanIn.lcl_pubkey << redeem << OP_HASH160 << chanIn.GetHash() << OP_EQUAL;
  wtx.vin.push_back(CTxIn(txIn.GetHash(), nOut, scriptIn, channel->nSeq));


  int64 nTotalValue = channel->lcl_value + channel->rem_value;
  int64 nCounterValue;
  if (isOrigin)
    nCounterValue = channel->rem_value;
  else
    nCounterValue = channel->lcl_value;

  /* insert p2sh output to channel */
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_PAY << CScript::EncodeOP_N(OP_CHANNEL) << OP_HASH160 << hChan << OP_2DROP;
  scriptPubKey << OP_HASH160 << channel->GetHash() << OP_EQUAL;
	wtx.vout.push_back(CTxOut(nTotalValue - nCounterValue, scriptPubKey)); 

  /* append pubkey output to channel of counter-party remainder */
  CScript scriptPeer;
  scriptPeer.SetDestination(peer_addr.Get());
  wtx.vout.push_back(CTxOut(nCounterValue, scriptPeer)); 

  /* half-sign input */
  if (!SignSignature(*wallet, txIn, wtx, 0))
    return (SHERR_INVAL);
 
  // relay half-signed transaction
	uint256 tx_hash = wtx.GetHash();
	RelayMessage(CInv(ifaceIndex, MSG_TX, tx_hash), (CTransaction)wtx);

#if 0
  /* retain latest commit as official. */
  wallet->mapChannelSpent[hChan] = wtx;
  /* keep previous spent to remit in case of malicious behaviour */
  wallet->mapChannelRedeem[hChan] = txSpentIn;
#endif

  Debug("SENT:CHANNELPAY : channelhash=%s, tx=%s\n", hChan.ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

int validate_channel_tx(CIface *iface, const CTransaction *txCommit, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
  CTransaction txSpentIn;
  CTransaction txIn;
  CChannel *channel;
  CCoinAddr peer_addr;
  CCoinAddr addr;
  string strAccount;
  uint160 hChan;
  int txInMode;
  bool isOrigin;
  int nOut;

  if (ifaceIndex != TEST_COIN_IFACE && ifaceIndex != SHC_COIN_IFACE)
    return (SHERR_OPNOTSUPP);

  nOut = IndexOfExtOutput(*txCommit);
  if (nOut == -1)
    return (SHERR_INVAL);
  if (!DecodeChannelHash(txCommit->vout[nOut].scriptPubKey, txInMode, hChan) ||
      txInMode != OP_EXT_PAY)
    return (SHERR_INVAL);

	if (!GetOpenChannel(ifaceIndex, hChan, txIn))
		return (SHERR_NOENT);


  if (txCommit->vin.size() != 1) {
    return error(SHERR_INVAL, "validate_channel_tx: invalid number of inputs specified in commit transaction.");
  }
  if (txCommit->vout.size() != 2) {
    return error(SHERR_INVAL, "validate_channel_tx: invalid number of outputs specified in commit transaction.");
  }

  nOut = IndexOfExtOutput(txIn);
  if (nOut != 0)
    return error(SHERR_INVAL, "validate_channel_tx: invalid output (#1).");

  /* second output shall be direct remitance to us */
  CTxDestination dest;
  if (!ExtractDestination(txSpentIn.vout[1].scriptPubKey, dest))
    return error(SHERR_INVAL, "validate_channel_tx: invalid out (#2).");
  addr.Set(dest);
  if (!GetCoinAddr(wallet, addr, strAccount))
    return (SHERR_REMOTE);

  CChannel& chanIn = txIn.channel;
  CCoinAddr lcl_addr = chanIn.GetOriginAddr();
  CCoinAddr rem_addr = chanIn.GetPeerAddr();
  if (!lcl_addr.IsValid() || !rem_addr.IsValid())
    return (SHERR_INVAL);
  if (lcl_addr.Get() == addr.Get()) { 
    peer_addr = rem_addr;
    isOrigin = true;
  } else if (rem_addr.Get() == addr.Get()) {
    peer_addr = lcl_addr;
    isOrigin = false;
  } else {
    return error(SHERR_INVAL, "validate_channel_tx: invalid recipient output specified in commit transaction.");
  }

  wtx.SetNull();
//  wtx.vin = txCommit->vin;
  channel = wtx.PayChannel(chanIn);

	if (GetSpentChannel(ifaceIndex, hChan, txSpentIn)) {
    if (isOrigin) {
      if (txCommit->channel.lcl_value < txSpentIn.channel.lcl_value)
        return (SHERR_INVAL); 
      if (txCommit->channel.rem_value > txSpentIn.channel.rem_value)
        return (SHERR_INVAL); 
    } else {
      if (txCommit->channel.rem_value < txSpentIn.channel.rem_value)
        return (SHERR_INVAL); 
      if (txCommit->channel.lcl_value > txSpentIn.channel.lcl_value)
        return (SHERR_INVAL); 
    }

    if (txCommit->channel.nSeq <= txSpentIn.vin[0].nSequence)
      return (SHERR_ILSEQ);

    /* retain previous pubkey */
    if (isOrigin)
      channel->lcl_pubkey = txSpentIn.channel.lcl_pubkey;
    else
      channel->rem_pubkey = txSpentIn.channel.rem_pubkey;
  } else {
    if (isOrigin) {
      if (txCommit->channel.lcl_value < chanIn.lcl_value)
        return (SHERR_INVAL); 
      if (txCommit->channel.rem_value > chanIn.rem_value)
        return (SHERR_INVAL); 
    } else {
      if (txCommit->channel.rem_value < chanIn.rem_value)
        return (SHERR_INVAL); 
      if (txCommit->channel.lcl_value > chanIn.lcl_value)
        return (SHERR_INVAL); 
    }
  }

  /* update balances */
  channel->lcl_value = txCommit->channel.lcl_value;
  channel->rem_value = txCommit->channel.rem_value;

  /* define sequence number. */
  channel->nSeq = txCommit->channel.nSeq;

  /* generate unique pubkey for new commit */
  if (isOrigin) {
    channel->lcl_npubkey = GenerateChannelPubKey(wallet, strAccount);
  } else {
    channel->rem_npubkey = GenerateChannelPubKey(wallet, strAccount);
  }

  /* create input from funding transaction */
  CScript scriptIn;
  CScript redeem;
  chanIn.GetRedeemScript(redeem);
	scriptIn << OP_0 << chanIn.rem_pubkey << chanIn.lcl_pubkey << redeem << OP_HASH160 << chanIn.GetHash() << OP_EQUAL;
  if (!equal(scriptIn.begin(), scriptIn.end(),
        txCommit->vin[0].scriptSig.begin()) ||
      txCommit->vin[0].nSequence != channel->nSeq) {
    /* counter-party specified invalid input for commit transaction. */
    return error(SHERR_INVAL,
        "validate_channel_tx: commit tx has invalid input script.");
  }
  wtx.vin.push_back(CTxIn(txIn.GetHash(), nOut, scriptIn, channel->nSeq));

  int64 nCounterValue;
  if (isOrigin)
    nCounterValue = channel->rem_value;
  else
    nCounterValue = channel->lcl_value;

  /* insert direct counter-party pubkey payment first */
  CScript scriptCounter;
  scriptCounter.SetDestination(peer_addr.Get()); 
  wtx.vout.push_back(CTxOut(nCounterValue, scriptCounter));

  /* insert p2sh output to channel */
  CScript scriptPubKey;
  int64 nTotalValue = channel->lcl_value + channel->rem_value;
  scriptPubKey << OP_EXT_PAY << CScript::EncodeOP_N(OP_CHANNEL) << OP_HASH160 << hChan << OP_2DROP;
  scriptPubKey << OP_HASH160 << channel->GetHash() << OP_EQUAL;
	wtx.vout.push_back(CTxOut(nTotalValue - nCounterValue, scriptPubKey)); 

  /* half-sign input */
  if (!SignSignature(*wallet, txIn, wtx, 0))
    return (SHERR_INVAL);

  // relay our version of half-signed commit transaction
	uint256 tx_hash = wtx.GetHash();
	RelayMessage(CInv(ifaceIndex, MSG_TX, tx_hash), (CTransaction)wtx);

  /* retain counter-party's commit tx as official. */
  wallet->mapChannelSpent[hChan] = *txCommit;

  /* keep previous spent to remit in case of malicious behaviour */
  wallet->mapChannelRedeem[hChan] = txSpentIn;


  Debug("SENT:CHANNELVALIDATE : channelhash=%s, tx=%s\n", hChan.ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

int generate_channel_tx(CIface *iface, uint160 hChan, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);
  CTransaction txSpentIn;
  CTransaction txIn;
  CChannel *channel;
  CCoinAddr peer_addr;
  CCoinAddr addr;
  string strAccount;
  int txInMode;
  bool isOrigin;
  int nOut;

  if (ifaceIndex != TEST_COIN_IFACE && ifaceIndex != SHC_COIN_IFACE)
    return (SHERR_OPNOTSUPP);

	if (!GetOpenChannel(ifaceIndex, hChan, txIn))
		return (SHERR_NOENT);

	if (GetSpentChannel(ifaceIndex, hChan, txSpentIn))
    return (SHERR_AGAIN); /* nothing has been committed .. use remove instead */

  nOut = IndexOfExtOutput(txSpentIn);
  if (nOut == -1)
    return (SHERR_INVAL);
  if (!DecodeChannelHash(txSpentIn.vout[nOut].scriptPubKey, txInMode, hChan) ||
      txInMode != OP_EXT_PAY)
    return (SHERR_INVAL);

  if (txSpentIn.vin.size() != 1) {
    return error(SHERR_INVAL, "validate_channel_tx: invalid number of inputs specified in commit transaction.");
  }
  if (txSpentIn.vout.size() != 2) {
    return error(SHERR_INVAL, "validate_channel_tx: invalid number of outputs specified in commit transaction.");
  }

  nOut = IndexOfExtOutput(txIn);
  if (nOut != 0)
    return error(SHERR_INVAL, "validate_channel_tx: invalid output (#1).");

  /* second output shall be direct remitance to us */
  CTxDestination dest;
  if (!ExtractDestination(txSpentIn.vout[1].scriptPubKey, dest))
    return error(SHERR_INVAL, "validate_channel_tx: invalid out (#2).");
  addr.Set(dest);
  if (!GetCoinAddr(wallet, addr, strAccount))
    return (SHERR_REMOTE);

  CChannel& chanIn = txIn.channel;
  CCoinAddr lcl_addr = chanIn.GetOriginAddr();
  CCoinAddr rem_addr = chanIn.GetPeerAddr();
  if (!lcl_addr.IsValid() || !rem_addr.IsValid())
    return (SHERR_INVAL);
  if (lcl_addr.Get() == addr.Get()) { 
    peer_addr = rem_addr;
    isOrigin = true;
  } else if (rem_addr.Get() == addr.Get()) {
    peer_addr = lcl_addr;
    isOrigin = false;
  } else {
    return error(SHERR_INVAL, "validate_channel_tx: invalid recipient output specified in commit transaction.");
  }

  wtx.SetNull();
  channel = wtx.GenerateChannel(txSpentIn.channel);

  if (channel->nSeq != txSpentIn.vin[0].nSequence)
    return (SHERR_ILSEQ);

  /* create input from funding transaction */
  CScript scriptIn;
  CScript redeem;
  chanIn.GetRedeemScript(redeem);
	scriptIn << OP_0 << chanIn.rem_pubkey << chanIn.lcl_pubkey << redeem << OP_HASH160 << chanIn.GetHash() << OP_EQUAL;
  wtx.vin.push_back(CTxIn(txIn.GetHash(), nOut, scriptIn, channel->nSeq));

  int64 nCounterValue;
  if (isOrigin)
    nCounterValue = channel->rem_value;
  else
    nCounterValue = channel->lcl_value;

  CScript scriptOrigin;
  scriptOrigin.SetDestination(channel->GetOriginAddr().Get());
  wtx.vout.push_back(CTxOut(channel->lcl_value, scriptOrigin));

  CScript scriptPeer;
  scriptPeer.SetDestination(channel->GetPeerAddr().Get());
  wtx.vout.push_back(CTxOut(channel->rem_value, scriptPeer));

  /* half-sign input */
  if (!SignSignature(*wallet, txIn, wtx, 0))
    return (SHERR_INVAL);

  // relay our version of half-signed commit transaction
	uint256 tx_hash = wtx.GetHash();
	RelayMessage(CInv(ifaceIndex, MSG_TX, tx_hash), (CTransaction)wtx);

  /* this is now the 'official' version */
  wallet->mapChannelSpent[hChan] = wtx;

  /* keep previous spent to remit in case of malicious behaviour */
  wallet->mapChannelRedeem[hChan] = txSpentIn;

  Debug("SENT:CHANNELVALIDATE : channelhash=%s, tx=%s\n", hChan.ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}



#if 0
int generate_channel_tx(CIface *iface, const uint160& hashChannel, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  /* verify original channel */
  CTransaction tx;
  if (!GetTxOfChannel(iface, hashChannel, tx)) {
    fprintf(stderr, "DEBUG: update_channel_tx: !GetTxOfChannel\n");
    return (SHERR_NOENT);
  }
  if(!IsLocalChannel(iface, tx)) {
    fprintf(stderr, "DEBUG: update_channel_tx: !IsLocalChannel\n");
    return (SHERR_REMOTE);
  }

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0) {
    return (SHERR_REMOTE);
  }

  /* establish account */
  CCoinAddr addr;

#if 0
  addr = GetAccountAddress(wallet, strAccount, false);
  if (!addr.IsValid()) {
    fprintf(stderr, "DEBUG: update_channel_tx: !addr.IsValid\n");
    return (SHERR_NOENT);
  }

  /* generate tx */
  CCert *channel;
	CScript scriptPubKey;
  wtx.SetNull();
  channel = wtx.RemoveChannel(CChannel(tx.certificate));
  uint160 channelHash = channel->GetHash();

  vector<pair<CScript, int64> > vecSend;
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(addr.Get()); /* back to origin */
	scriptPubKey << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_CHANNEL) << OP_HASH160 << channelHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
#endif

#if 0
  int64 nNetFee = GetChannelOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }
  if (nNetFee) { /* supplemental tx payment */
    CScript scriptFee;
    scriptFee << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_CHANNEL) << OP_HASH160 << channelHash << OP_2DROP << OP_RETURN;
    vecSend.push_back(make_pair(scriptFee, nNetFee));
  }

  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend)) {
fprintf(stderr, "DEBUG: update_channel_tx: !SendMoneyWithExtTx\n"); 
    return (SHERR_INVAL);
}

  wallet->mapChannel[channelHash] = wtx.GetHash();
#endif

	return (0);
}
#endif

int remove_channel_tx(CIface *iface, const uint160& hashChannel, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  /* verify original channel */
  CTransaction tx;
  if (!GetTxOfChannel(iface, hashChannel, tx)) {
    fprintf(stderr, "DEBUG: update_channel_tx: !GetTxOfChannel\n");
    return (SHERR_NOENT);
  }
  if(!IsLocalChannel(iface, tx)) {
    fprintf(stderr, "DEBUG: update_channel_tx: !IsLocalChannel\n");
    return (SHERR_REMOTE);
  }

#if 0
  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0) {
    return (SHERR_REMOTE);
  }

  /* establish account */
  CCoinAddr addr;

  addr = GetAccountAddress(wallet, strAccount, false);
  if (!addr.IsValid()) {
    fprintf(stderr, "DEBUG: update_channel_tx: !addr.IsValid\n");
    return (SHERR_NOENT);
  }

  /* generate tx */
  CCert *channel;
	CScript scriptPubKey;
  wtx.SetNull();
  channel = wtx.RemoveChannel(CChannel(tx.certificate));
  uint160 channelHash = channel->GetHash();

  vector<pair<CScript, int64> > vecSend;
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(addr.Get()); /* back to origin */
	scriptPubKey << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_CHANNEL) << OP_HASH160 << channelHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  int64 nNetFee = GetChannelOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }
  if (nNetFee) { /* supplemental tx payment */
    CScript scriptFee;
    scriptFee << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_CHANNEL) << OP_HASH160 << channelHash << OP_2DROP << OP_RETURN;
    vecSend.push_back(make_pair(scriptFee, nNetFee));
  }

  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend)) {
fprintf(stderr, "DEBUG: update_channel_tx: !SendMoneyWithExtTx\n"); 
return (SHERR_INVAL);
  }

  CScript scriptFee;
  int nNetFee = iface->min_tx_fee;
  scriptFee << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_CHANNEL) << OP_HASH160 << hashChannel << OP_2DROP << OP_RETURN;
    vecSend.push_back(make_pair(scriptFee, nNetFee));
  }

  if (!wallet->CommitTransaction(txRemedy, rkey))
    return (SHERR_INVAL);

  wallet->mapChannel.erase(channelHash);
#endif

	return (0);
}



