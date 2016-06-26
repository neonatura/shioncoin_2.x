
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

using namespace std;
using namespace json_spirit;



cert_list *GetCertTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapCert);
}

cert_list *GetCertPendingTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapCert);
}

bool DecodeCertHash(const CScript& script, int& mode, uint160& hash)
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
  op = CScript::DecodeOP_N(opcode); /* extension type (cert) */
  if (op != OP_CERT) {
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


bool IsCertOp(int op) {
	return (op == OP_CERT);
}


string certFromOp(int op) {
	switch (op) {
	case OP_EXT_NEW:
		return "certnew";
	case OP_EXT_UPDATE:
		return "certupdate";
	case OP_EXT_ACTIVATE:
		return "certactivate";
	default:
		return "<unknown cert op>";
	}
}

bool DecodeCertScript(const CScript& script, int& op,
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

	op = CScript::DecodeOP_N(opcode); /* extension type (cert) */
  if (op != OP_CERT)
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
      (mode == OP_EXT_UPDATE && vvch.size() == 2) ||
      (mode == OP_EXT_TRANSFER && vvch.size() == 2) ||
      (mode == OP_EXT_REMOVE && vvch.size() == 2))
    return (true);

	return false;
}

bool DecodeCertScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeCertScript(script, op, vvch, pc);
}

CScript RemoveCertScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeCertScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveCertScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetCertOpFee(CIface *iface, int nHeight) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5100 / base * COIN;
  double nDif = 4982 /base * COIN;
  int64 fee = (int64)(nRes - nDif);
  return (MAX(iface->min_tx_fee, fee));
}


int64 GetCertReturnFee(const CTransaction& tx) 
{
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

bool IsCertTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_CERTIFICATE)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeCertHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

bool IsCertEntTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_ENTITY)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeCertHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

/**
 * Obtain the tx that defines this cert.
 */
bool GetTxOfCert(CIface *iface, const uint160& hashCert, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  cert_list *certes = GetCertTable(ifaceIndex);
  bool ret;

  if (certes->count(hashCert) == 0) {
    return false; /* nothing by that name, sir */
  }

  uint256 hashBlock;
  uint256 hashTx = (*certes)[hashCert];
  CTransaction txIn;
  ret = GetTransaction(iface, hashTx, txIn, NULL);
  if (!ret) {
    return false;
  }

  if (!IsCertTx(txIn)) 
    return false; /* inval; not an cert tx */

#if 0
  if (txIn.certificate.IsExpired()) {
    return false;
  }
#endif

  tx.Init(txIn);
  return true;
}

bool IsLocalCert(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalCert(CIface *iface, const CTransaction& tx)
{
  if (!IsCertTx(tx))
    return (false); /* not a cert */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalCert(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an cert transaction.
 */
bool VerifyCert(CTransaction& tx)
{
  uint160 hashCert;
  int nOut;

  /* core verification */
  if (!IsCertTx(tx))
    return (false); /* tx not flagged as cert */

  /* verify hash in pub-script matches cert hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* no extension output */

  int mode;
  if (!DecodeCertHash(tx.vout[nOut].scriptPubKey, mode, hashCert))
    return (false); /* no cert hash in output */

  if (mode != OP_EXT_NEW &&
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE)
    return (false);

  CCert *cert = &tx.certificate;
  if (hashCert != cert->GetHash())
    return (false); /* cert hash mismatch */

/* DEBUG: TODO verifyCertInputs() */

  return (true);
}

bool GetCertEntByHash(CIface *iface, uint160 hash, CCertEnt& issuer)
{
  int ifaceIndex = GetCoinIndex(iface);
  cert_list *certs = GetCertTable(ifaceIndex);

  if (certs->count(hash) == 0)
    return (false);

  uint256 hashTx = (*certs)[hash];
  CTransaction tx;
  bool ret = GetTransaction(iface, hashTx, tx, NULL);
  if (!ret)
    return (false);

  if (!IsCertEntTx(tx))
    return (false);

  issuer = tx.entity;
  return (true);
}

int init_cert_tx(CIface *iface, string strAccount, string strTitle, cbuff vchSecret, uint160 hashIssuer, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if(strTitle.length() == 0)
    return (SHERR_INVAL);
  if(strTitle.length() > 135)
    return (SHERR_INVAL);

  CCert *cert;
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  CCertEnt issuer; 
  GetCertEntByHash(iface, hashIssuer, issuer); /* optional */

  /* embed cert content into transaction */
  wtx.SetNull();
  cert = wtx.CreateCert(&issuer, strTitle.c_str(), vchSecret);
  wtx.strFromAccount = strAccount; /* originating account for payment */

  int64 nFee = GetCertOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
    return (SHERR_AGAIN);
  }

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  uint160 certHash = cert->GetHash();
  CScript scriptPubKey;

  scriptPubKeyOrig.SetDestination(extAddr.Get());
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_CERT) << OP_HASH160 << certHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  /* todo: add to pending instead */
  wallet->mapCert[certHash] = wtx.GetHash();

  Debug("SENT:CERTNEW : title=%s, certhash=%s, tx=%s\n", strTitle.c_str(), cert->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}



