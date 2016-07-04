
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

cert_list *GetLicenseTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapLicense);
}

bool DecodeIdentHash(const CScript& script, int& mode, uint160& hash)
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
  if (op != OP_IDENT) {
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

bool DecodeLicenseHash(const CScript& script, int& mode, uint160& hash)
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
  if (op != OP_LICENSE) {
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

bool IsIdentTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_IDENT)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeIdentHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
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

bool IsLicenseTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_LICENSE)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeLicenseHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

#if 0
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
#endif

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

bool VerifyIdent(CTransaction& tx)
{
  uint160 hashIdent;
  int nOut;

  /* core verification */
  if (!IsIdentTx(tx))
    return (false); /* tx not flagged as ident */

  /* verify hash in pub-script matches ident hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* no extension output */

  int mode;
  if (!DecodeIdentHash(tx.vout[nOut].scriptPubKey, mode, hashIdent))
    return (false); /* no ident hash in output */

  if (mode != OP_EXT_NEW &&
      mode != OP_EXT_GENERATE &&
      mode != OP_EXT_PAY)
    return (false);

  CIdent *ident = (CIdent *)&tx.certificate;
  if (hashIdent != ident->GetHash())
    return (false); /* ident hash mismatch */

  return (true);
}

/**
 * Verify the integrity of an certificate.
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

  return (true);
}

/**
 * Verify the integrity of a license
 */
bool VerifyLicense(CTransaction& tx)
{
  uint160 hashLicense;
  int nOut;

  /* core verification */
  if (!IsLicenseTx(tx)) {
tx.print();
    return (false); /* tx not flagged as cert */
}

  /* verify hash in pub-script matches cert hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1) {
    return (false); /* no extension output */
}

  int mode;
  if (!DecodeLicenseHash(tx.vout[nOut].scriptPubKey, mode, hashLicense)) {
    return (false); /* no cert hash in output */
}

  if (mode != OP_EXT_NEW &&
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE) {
    return (false);
}

  CLicense *lic = &tx.license;
  if (hashLicense != lic->GetHash()) {
    return (false); /* cert hash mismatch */
}


  return (true);
}

#if 0
bool GetCertEntByHash(CIface *iface, uint160 hash, CIdent& issuer)
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
#endif

/**
 * Obtain the block-chain tx that encapsulates a certificate
 * @param hash The certificate hash.
 */
bool GetTxOfCert(CIface *iface, const uint160& hash, CTransaction& tx)
{
  int ifaceIndex = GetCoinIndex(iface);
  cert_list *certs = GetCertTable(ifaceIndex);

  if (certs->count(hash) == 0)
    return (false);

  uint256 hashTx = (*certs)[hash];
  bool ret = GetTransaction(iface, hashTx, tx, NULL);
  if (!ret)
    return (false);

  if (!IsCertTx(tx)) {
    return (false);
}

  tx.certificate.SetActive(true);
  return (true);
}

/**
 * Obtain the block-chain tx that encapsulates a license.
 * @param hash The license hash.
 */
bool GetTxOfLicense(CIface *iface, const uint160& hash, CTransaction& tx)
{
  int ifaceIndex = GetCoinIndex(iface);
  cert_list *licenses = GetLicenseTable(ifaceIndex);

  if (licenses->count(hash) == 0)
    return (false);

  uint256 hashTx = (*licenses)[hash];
  bool ret = GetTransaction(iface, hashTx, tx, NULL);
  if (!ret)
    return (false);

  if (!IsLicenseTx(tx)) {
    return (false);
}

  return (true);
}

int init_cert_tx(CIface *iface, string strAccount, string strTitle, cbuff vchSecret, int64 nLicenseFee, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  if(strTitle.length() == 0)
    return (SHERR_INVAL);
  if(strTitle.length() > 135)
    return (SHERR_INVAL);

  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
  if (!addr.IsValid())
    return (SHERR_INVAL);

  CCert *cert;
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* embed cert content into transaction */
  wtx.SetNull();
  cert = wtx.CreateCert(strTitle.c_str(), vchSecret, nLicenseFee);
  cert->SetActive(true); /* auto-activate */
  cert->vAddr = vchFromString(addr.ToString());
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

/**
 * A license tranaction pays back it's fee to the address which certifies it. 
 * @param iface The coin service interface.
 * @param strAccount The coin account name to conduct the transaction with.
 * @param vchSecret Private data which is
 * @note A license is not modifable after it has been issued.
 */
int init_license_tx(CIface *iface, string strAccount, uint160 hashCert, uint64_t nCrc, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);


  CTransaction tx;
  bool hasCert = GetTxOfCert(iface, hashCert, tx);
  if (!hasCert)
    return (SHERR_NOENT);

  /* destination (certificate owner) */
  CCoinAddr certAddr(stringFromVch(tx.certificate.vAddr));
  if (!certAddr.IsValid())
    return (SHERR_INVAL);
  
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* embed cert content into transaction */
  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */

  CLicense *lic = wtx.CreateLicense(&tx.certificate, nCrc);
  if (!lic) {
    return (SHERR_INVAL);
}

  int64 nCertFee = lic->nFee; 
  int64 nTxFee = GetCertOpFee(iface, GetBestHeight(iface));

  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < (nCertFee + nTxFee))
    return (SHERR_AGAIN);

  /* send to extended tx storage account */
  uint160 licHash = lic->GetHash();

  /* send license fee (from cert) to cert owner */
  CWalletTx l_wtx;
  CScript certPubKey;
  certPubKey.SetDestination(certAddr.Get());
  string strError = wallet->SendMoney(certPubKey, nCertFee, l_wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  /* send license fee (of tx op) to nowhere. */
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_LICENSE) << OP_HASH160 << licHash << OP_2DROP << OP_RETURN;
  string certStrError = wallet->SendMoney(scriptPubKey, nTxFee, wtx, false);
  if (certStrError != "") {
    error(ifaceIndex, certStrError.c_str());
    return (SHERR_INVAL);
  }

  /* todo: add to pending instead */
  wallet->mapLicense[licHash] = wtx.GetHash();

  Debug("SENT:LICENSENEW : lichash=%s, tx=%s\n", lic->GetHash().ToString().c_str(), wtx.GetHash().GetHex().c_str());

  return (0);
}



void CLicense::NotifySharenet(int ifaceIndex)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface || !iface->enabled) return;
  //memcpy(&license.lic_cert, cert->GetHash().GetKey(), sizeof(license.lic_cert.code));

//  shnet_inform(iface, TX_LICENSE, &license, sizeof(license));
}


/**
 * Submits an amount of coins as a transaction fee.
 * @hashCert An optional certificate reference to associate with the donation.
 * @note A block depth of two must be reached before donation occurs.
 */
int init_ident_donate_tx(CIface *iface, string strAccount, uint64_t nValue, uint160 hashCert, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CIdent *ident;

  if (ifaceIndex != TEST_COIN_IFACE && ifaceIndex != SHC_COIN_IFACE)
    return (SHERR_OPNOTSUPP);

  if (!wallet || !iface->enabled)
    return (SHERR_OPNOTSUPP);

  int64 nFee = nValue - iface->min_tx_fee;
  if (nFee < 0) {
    return (SHERR_INVAL);
  }

  CTransaction tx;
  bool hasCert = GetTxOfCert(iface, hashCert, tx);

  CWalletTx t_wtx;
  if (hasCert) {
    ident = t_wtx.CreateIdent((CIdent *)&tx.certificate);
  } else {
    ident = t_wtx.CreateIdent();
  }
  if (!ident) {
    return (SHERR_INVAL);
}

  uint160 hashIdent = ident->GetHash();

  /* sent to intermediate account. */
  CReserveKey rkey(wallet);
  t_wtx.strFromAccount = strAccount;

  CPubKey vchPubKey = rkey.GetReservedKey();
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(vchPubKey.GetID());
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_IDENT) << OP_HASH160 << hashIdent << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
//  string strError = wallet->SendMoney(scriptPubKey, nValue, t_wtx, false);
  int64 nFeeRequired;
  if (!wallet->CreateTransaction(scriptPubKey, nValue, t_wtx, rkey, nFeeRequired)) {
    return (SHERR_CANCELED);
}

  if (!wallet->CommitTransaction(t_wtx, rkey)) {
    return (SHERR_CANCELED);
}

  /* deduct intermediate tx fee */
  nFee -= nFeeRequired;
  nFee = MAX(iface->min_tx_fee, nFee);

  /* send from intermediate as tx fee */
  wtx.SetNull();
  wtx.strFromAccount = strAccount;
  wtx.CreateIdent(ident);
  CScript feePubKey;
  vector<pair<CScript, int64> > vecSend;

  wtx.strFromAccount = strAccount;
  feePubKey << OP_EXT_GENERATE << CScript::EncodeOP_N(OP_IDENT) << OP_HASH160 << hashIdent << OP_2DROP << OP_RETURN;
  if (!SendMoneyWithExtTx(iface, t_wtx, wtx, feePubKey, vecSend, nFee)) { 
fprintf(stderr, "DEBUG: init_ident_donate_tx:: !SendMoneyWithExtTx()\n");
    return (SHERR_INVAL);
}

  return (0);
}

int init_ident_certcoin_tx(CIface *iface, string strAccount, uint64_t nValue, uint160 hashCert, CCoinAddr addrDest, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CIdent *ident;

  if (ifaceIndex != TEST_COIN_IFACE && ifaceIndex != SHC_COIN_IFACE)
    return (SHERR_OPNOTSUPP);

  if (!wallet || !iface->enabled)
    return (SHERR_OPNOTSUPP);

  if (!addrDest.IsValid())
    return (SHERR_INVAL);

  if (nValue < iface->min_tx_fee) {
    return (SHERR_INVAL);
  }

  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nValue) {
    return (SHERR_AGAIN);
  }

  CTransaction tx;
  bool hasCert = GetTxOfCert(iface, hashCert, tx);

  wtx.SetNull();
  if (hasCert) {
    ident = wtx.CreateIdent((CIdent *)&tx.certificate);
  } else {
    ident = wtx.CreateIdent();
  }
  if (!ident) {
fprintf(stderr, "DEBUG: init_ident_donate_tx: !ident\n");
    return (SHERR_INVAL);
}

  uint160 hashIdent = ident->GetHash();

  /* sent to intermediate account. */
  CReserveKey rkey(wallet);
  wtx.strFromAccount = strAccount;

  CPubKey vchPubKey = rkey.GetReservedKey();
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(vchPubKey.GetID());
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_PAY << CScript::EncodeOP_N(OP_IDENT) << OP_HASH160 << hashIdent << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;
  int64 nFeeRequired;
  if (!wallet->CreateTransaction(scriptPubKey, nValue, wtx, rkey, nFeeRequired)) {
    return (SHERR_CANCELED);
  }
  if (!wallet->CommitTransaction(wtx, rkey)) {
    return (SHERR_CANCELED);
  }

  nValue -= nFeeRequired;
  nValue = MAX(iface->min_tx_fee, nValue);

  /* send from intermediate to desination specified */
  CWalletTx t_wtx;
  t_wtx.SetNull();
  t_wtx.strFromAccount = strAccount;
  t_wtx.CreateIdent(ident);

  vector<pair<CScript, int64> > vecSend;
  CScript destPubKey;
  destPubKey.SetDestination(addrDest.Get());
  
  if (!SendMoneyWithExtTx(iface, wtx, t_wtx, destPubKey, vecSend)) { 
    fprintf(stderr, "DEBUG: init_ident_donate_tx:: !SendMoneyWithExtTx()\n");
    return (SHERR_INVAL);
  }

  return (0);
}


/**
 * Generate a signature unique to this identify in relation to an external context. Only call after the "origin" signature has been generated.
 * @param vchSecret The external context that the signature was generated from.
 * @note In contrast to the CExtCore.origin field; this signature is meant specifically to reference external information as opposed to internally generated context.
 * @see CExtCore.origin
 * @todo Allow for blank vchSecret.
 */
bool CIdent::Sign(cbuff vchSecret)
{

  if (!vchSecret.data())
    return (false);

  void *raw = (void *)vchSecret.data();
  size_t raw_len = vchSecret.size();

  shkey_t s_key;
  memset(&s_key, 0, sizeof(s_key));
  if (origin.data() != NULL) {
    shkey_t *t_key = shkey_bin((char *)origin.data(), origin.size());
    memcpy(&s_key, t_key, sizeof(s_key));
    shkey_free(&t_key);
  }

  shkey_t *key = shkey_cert(&s_key, shcrc(raw, raw_len), tExpire);
  memcpy(&sig_key, key, sizeof(sig_key));
  shkey_free(&key);

  return (true);
}

/**
 * Verify an identity's signature.
 * @param vchSecret The external context that the signature was generated from.
 */
bool CIdent::VerifySignature(cbuff vchSecret)
{
  if (!vchSecret.data())
    return (false);

  shkey_t s_key;
  memset(&s_key, 0, sizeof(s_key));
  if (origin.data() != NULL) {
    shkey_t *t_key = shkey_bin((char *)origin.data(), origin.size());
    memcpy(&s_key, t_key, sizeof(s_key));
    shkey_free(&t_key);
  }

  void *raw = (void *)vchSecret.data();
  size_t raw_len = vchSecret.size();
  uint64_t crc = shcrc(raw, raw_len);
  shkey_t *key = shkey_cert(&s_key, crc, tExpire);
  bool ret = false;

  if (shkey_cmp(key, &sig_key))
    ret = true;
  shkey_free(&key);

  return (ret);
}
