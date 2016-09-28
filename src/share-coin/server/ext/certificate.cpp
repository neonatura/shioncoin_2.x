
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


extern json_spirit::Value ValueFromAmount(int64 amount);

cert_list *GetCertTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapCert);
}

cert_list *GetIdentTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapIdent);
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

int GetTotalCertificates(int ifaceIndex)
{
  cert_list *certs = GetCertTable(ifaceIndex);
  return (certs->size());
}

bool InsertCertTable(CIface *iface, CTransaction& tx, unsigned int nHeight, bool fUpdate)
{
  CWallet *wallet = GetWallet(iface);

  if (!wallet)
    return (false);

  if (!VerifyCert(iface, tx, nHeight))
    return (false);

  CCert& cert = tx.certificate;
  const uint160& hCert = cert.GetHash();
  int count = wallet->mapCert.count(hCert);

  if (count) {
    const uint256& o_tx = wallet->mapCert[hCert]; 
    if (o_tx == tx.GetHash())
      return (true); /* already assigned */
  }

  if (!fUpdate) {
    int ifaceIndex = GetCoinIndex(iface);
    cert_list *certs = GetCertTable(ifaceIndex);
    if (count) {
      wallet->mapCertArch[tx.GetHash()] = hCert;
      return (false); /* suppress overwrite */
    }
  }

  /* reassign previous */
  if (count) {
    const uint256& o_tx = wallet->mapCert[hCert]; 
    wallet->mapCertArch[o_tx] = hCert;
  }

  wallet->mapCert[hCert] = tx.GetHash();
  wallet->mapCertLabel[cert.GetLabel()] = hCert;

  return (true);
}

bool InsertIdentTable(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  int mode;

  if (!wallet)
    return (false);

  if (!VerifyIdent(tx, mode))
    return (false);

  if (mode == OP_EXT_NEW) { /* ident stamp */
    CIdent& ident = (CIdent&)tx.certificate;
    const uint160& hIdent = ident.GetHash();
    wallet->mapIdent[hIdent] = tx.GetHash();
  }

  return (true);
}

bool GetCertByName(CIface *iface, string name, CCert& cert)
{
  CWallet *wallet = GetWallet(iface);

  if (wallet->mapCertLabel.count(name) == 0)
    return (false);

  CTransaction tx;
  const uint160& hash = wallet->mapCertLabel[name];
  bool ret = GetTxOfCert(iface, hash, tx);
  if (!ret)
    return (false);

  cert = tx.certificate;
  return (true);
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
	case OP_EXT_ACTIVATE:
		return "certactivate";
	case OP_EXT_UPDATE:
		return "certupdate";
	case OP_EXT_TRANSFER:
		return "certtransfer";
	case OP_EXT_REMOVE:
		return "certremove";
	case OP_EXT_GENERATE:
		return "certgenerate";
	case OP_EXT_PAY:
		return "certpay";
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
      (mode == OP_EXT_ACTIVATE && vvch.size() == 2) ||
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

  /* round down */
  fee /= 1000;
  fee *= 1000;

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

bool GetCertAccount(CIface *iface, const CTransaction& tx, string& strAccount)
{
  CWallet *wallet = GetWallet(iface);

  if (!IsCertTx(tx))
    return (false); /* not a cert */

  CCoinAddr addr(stringFromVch(tx.certificate.vAddr));
  return (GetCoinAddr(wallet, addr, strAccount));
}

bool IsCertAccount(CIface *iface, CTransaction& tx, string strAccount)
{
  bool ret;
  string strCertAccount;

  ret = GetCertAccount(iface, tx, strCertAccount);
  if (!ret)
    return (false);

  if (strCertAccount.length() > 0 && strCertAccount.at(0) == '@')
    strCertAccount.erase(0, 1);

  return (strAccount == strCertAccount);
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
bool IsLocalIdent(CIface *iface, const CTransaction& tx)
{
  if (!IsIdentTx(tx))
    return (false); /* not a cert */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalCert(iface, tx.vout[nOut]));
}

bool VerifyIdent(CTransaction& tx, int& mode)
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

  if (!DecodeIdentHash(tx.vout[nOut].scriptPubKey, mode, hashIdent))
    return (false); /* no ident hash in output */

  if (mode != OP_EXT_NEW &&
      mode != OP_EXT_ACTIVATE &&
      mode != OP_EXT_GENERATE &&
      mode != OP_EXT_PAY) {
fprintf(stderr, "DEBUG: VerifyIdent: invalid mode %d\n",  mode);
    return (false);
}

  CIdent *ident = (CIdent *)&tx.certificate;
  if (hashIdent != ident->GetHash()) {
fprintf(stderr, "DEBUG: VerifyIdent: invalid hash '%s' vs '%s'\n", ident->GetHash().GetHex().c_str(), hashIdent.GetHex().c_str());
    return (false); /* ident hash mismatch */
}

  return (true);
}

/**
 * Verify the integrity of an certificate.
 */
bool VerifyCert(CIface *iface, CTransaction& tx, int nHeight)
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
      mode != OP_EXT_ACTIVATE &&
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE)
    return (false);

  if (tx.vout[nOut].nValue < GetCertOpFee(iface, nHeight))
    return false;//error(SHERR_INVAL, "VerifyCert: insufficient fee (%f of %f) for block accepted at height %d.", FormatMoney(tx.vout[nOut].nValue), GetCertOpFee(iface, nHeight));

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
//tx.print();
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
      mode != OP_EXT_ACTIVATE &&
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE) {
    return (false);
}

  CLicense lic(tx.certificate);
  if (hashLicense != lic.GetHash())
    return error(SHERR_INVAL, "license certificate hash mismatch");

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

  return (true);
}

bool GetTxOfIdent(CIface *iface, const uint160& hash, CTransaction& tx)
{
  int ifaceIndex = GetCoinIndex(iface);
  cert_list *idents = GetIdentTable(ifaceIndex);

  if (idents->count(hash) == 0)
    return (false);

  uint256 hashTx = (*idents)[hash];
  bool ret = GetTransaction(iface, hashTx, tx, NULL);
  if (!ret)
    return (false);

  if (!IsIdentTx(tx)) {
    return (false);
  }

  return (true);
}

bool VerifyCertHash(CIface *iface, const uint160& hash)
{
  int ifaceIndex = GetCoinIndex(iface);
  cert_list *certs = GetCertTable(ifaceIndex);

  if (certs->count(hash) == 0)
    return (false);

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
  cert = wtx.CreateCert(ifaceIndex, strTitle.c_str(), addr, vchSecret, nLicenseFee);
  wtx.strFromAccount = strAccount; /* originating account for payment */
 
  /* generate unique 128-bit serial number */
  unsigned char raw_ser[16];
  uint64_t *raw_val = (uint64_t *)raw_ser;
  raw_val[0] = shrand();
  raw_val[1] = shrand();
  cert->vContext = cbuff(raw_val, raw_val + 16);

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

  /* send certificate transaction */
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  /* add as direct const reference */
  const uint160& mapHash = cert->GetHash();
  wallet->mapCert[certHash] = wtx.GetHash();
  wallet->mapCertLabel[cert->GetLabel()] = certHash;

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
int init_license_tx(CIface *iface, string strAccount, uint160 hashCert, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);


  CTransaction tx;
  bool hasCert = GetTxOfCert(iface, hashCert, tx);
  if (!hasCert) {
    return (SHERR_NOENT);
}

  /* destination (certificate owner) */
  CCoinAddr certAddr(stringFromVch(tx.certificate.vAddr));
  if (!certAddr.IsValid()) {
fprintf(stderr, "DEBUG: init_license_tx: certAddr '%s' is invalid: %s\n", certAddr.ToString().c_str(), tx.certificate.ToString().c_str());
    return (SHERR_INVAL);
  }
  
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);
  if (!extAddr.IsValid()) {
fprintf(stderr, "DEBUG: error generating ext account addr\n");
    return (SHERR_INVAL);
}

  /* embed cert content into transaction */
  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */

  CCert *lic = wtx.CreateLicense(&tx.certificate);
  if (!lic) {
fprintf(stderr, "DEBUG: !wtx.CreateLicense\n");
    return (SHERR_INVAL);
}

  int64 nCertFee = lic->nFee;
  int64 nOpFee = MAX(iface->min_tx_fee, 
      GetCertOpFee(iface, GetBestHeight(iface)));
  int64 nTxFee =  nOpFee + nCertFee;
  nTxFee = MAX(iface->min_tx_fee, nTxFee);

  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nTxFee)
    return (SHERR_AGAIN);

  /* send to extended tx storage account */
  uint160 licHash = lic->GetHash();

  /* send license tx to intermediate address */
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_LICENSE) << OP_HASH160 << licHash << OP_2DROP;
  if (nCertFee >= (int64)iface->min_tx_fee) {
    CScript scriptPubKeyDest;
    scriptPubKeyDest.SetDestination(extAddr.Get());
    scriptPubKey += scriptPubKeyDest;
  } else {
    /* no fee required */
    scriptPubKey << OP_RETURN;
  }
  string certStrError = wallet->SendMoney(scriptPubKey, nTxFee, wtx, false);
  if (certStrError != "") {
    error(ifaceIndex, certStrError.c_str());
    return (SHERR_CANCELED);
  }

  if (nCertFee >= (int64)iface->min_tx_fee) {
    int nTxOut = 0; /* tx only had one output */
    CWalletTx l_wtx;
    vector<pair<CScript, int64> > vecSend;

    l_wtx.SetNull();
    l_wtx.strFromAccount = strAccount;
    CScript scriptPubKeyFee;
    scriptPubKeyFee.SetDestination(certAddr.Get());
    vecSend.push_back(make_pair(scriptPubKeyFee, nCertFee));

    CReserveKey rkey(wallet);
    int64 nRetFee = MAX(iface->min_tx_fee, wtx.vout[0].nValue - nCertFee);
    if (!CreateTransactionWithInputTx(iface,
          vecSend, wtx, nTxOut, l_wtx, rkey, nRetFee) ||
        !wallet->CommitTransaction(l_wtx, rkey)) {
      error(SHERR_CANCELED, "error paying certificate owner the license fee.");
      return (SHERR_CANCELED);
    }
  }


#if 0
  /* send license fee (from cert) to cert owner */
  CWalletTx l_wtx;
  l_wtx.strFromAccount = strAccount;
  CScript certPubKey;
  certPubKey.SetDestination(certAddr.Get());
  string strError = wallet->SendMoney(certPubKey, nCertFee, l_wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_CANCELED);
  }

  /* send license fee (of tx op) to nowhere. */
  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_LICENSE) << OP_HASH160 << licHash << OP_2DROP << OP_RETURN;
  string certStrError = wallet->SendMoney(scriptPubKey, nTxFee, wtx, false);
  if (certStrError != "") {
    error(ifaceIndex, certStrError.c_str());
    return (SHERR_CANCELED);
  }
#endif


//  wallet->mapLicenseArch[licHash] = tx.GetHash();
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
 * @param strAccount The account to donate funds from.
 * @param nValue A coin amount more than 0.0000101.
 * @param hashCert An optional certificate reference to associate with the donation.
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
  if (nFee < iface->min_input) {
    return (SHERR_INVAL);
  }

  CTransaction tx;
  bool hasCert = GetTxOfCert(iface, hashCert, tx);

  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
  if (!addr.IsValid())
    return (SHERR_INVAL);

  CWalletTx t_wtx;
  if (hasCert) {
    if (!IsCertAccount(iface, tx, strAccount)) { 
      error(SHERR_ACCESS, "init_ident_donate_tx: certificate is not local.");
      return (SHERR_ACCESS);
    }

    CIdent& c_ident = (CIdent&)tx.certificate;
    ident = t_wtx.CreateIdent(&c_ident);
  } else {
    ident = t_wtx.CreateIdent(ifaceIndex, addr);
  }
  if (!ident)
    return (SHERR_INVAL);

  uint160 hashIdent = ident->GetHash();

  /* sent to intermediate account. */
  CReserveKey rkey(wallet);
  t_wtx.strFromAccount = strAccount;

  //CPubKey vchPubKey = rkey.GetReservedKey();
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(addr.Get());
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

/**
 * Submits a geodetic trackable time-stamp.
 */
int init_ident_stamp_tx(CIface *iface, std::string strAccount, std::string strComment, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  CIdent *ident;

  if (ifaceIndex != TEST_COIN_IFACE && ifaceIndex != SHC_COIN_IFACE)
    return (SHERR_OPNOTSUPP);

  if (!wallet || !iface->enabled)
    return (SHERR_OPNOTSUPP);

  if (strComment.length() > 135)
    return (SHERR_INVAL);

  int64 nFee = iface->min_tx_fee;

  CCoinAddr addr = GetAccountAddress(wallet, strAccount, true);
  if (!addr.IsValid())
    return (SHERR_INVAL);

  ident = wtx.CreateIdent(ifaceIndex, addr);
  if (!ident)
    return (SHERR_INVAL);

  if (strComment.substr(0, 4) == "geo:") { /* geodetic uri */
    shnum_t lat, lon;
    int n = sscanf(strComment.c_str(), "geo:%Lf,%Lf", &lat, &lon);
    if (n == 2 &&
        (lat >= -90 && lat <= 90) &&
        (lon >= -180 && lon <= 180))
      shgeo_set(&ident->geo, lat, lon, 0);
  }
  ident->SetLabel(strComment);

  const uint160 hashIdent = ident->GetHash();

  /* sent to intermediate account. */
  CReserveKey rkey(wallet);
  wtx.strFromAccount = strAccount;

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_IDENT) << OP_HASH160 << hashIdent << OP_2DROP << OP_RETURN;
  int64 nFeeRequired;
  if (!wallet->CreateTransaction(scriptPubKey, nFee, wtx, rkey, nFeeRequired)) {
    return (SHERR_CANCELED);
  }

  if (!wallet->CommitTransaction(wtx, rkey)) {
    return (SHERR_CANCELED);
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
  if (!hasCert) {
    error(SHERR_INVAL, "init_ident_certcoin_tx: invalid certificate specified.");
    return (SHERR_INVAL);
  }

  wtx.SetNull();
  if (!IsCertAccount(iface, tx, strAccount)) { 
    error(SHERR_ACCESS, "init_ident_certcoin_tx: certificate is not local.");
    return (SHERR_ACCESS);
  }

  CIdent& s_cert = (CIdent&)tx.certificate;
  ident = wtx.CreateIdent(&s_cert);
  if (!ident) {
    fprintf(stderr, "DEBUG: init_ident_donate_tx: !ident\n");
    return (SHERR_INVAL);
  }

  uint160 hashIdent = ident->GetHash();

  /* send to intermediate account. */
  CReserveKey rkey(wallet);
  wtx.strFromAccount = strAccount;

  /* careful here to not collect change as reservekey is being used as an intermediate account adddress and also as the "change addr". doing both would result in multiple outputs to the same address in single tx which is taboo */
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
bool CCert::Sign(int ifaceIndex, CCoinAddr& addr, cbuff vchSecret)
{
  bool ret;

  if (!vchSecret.data())
    return (false);

  if (!vchSecret.data()) {
    unsigned char empty[64];
    memset(empty, 0, sizeof(empty));
    ret = signature.Sign(ifaceIndex, addr, empty, 0);
  } else {
    unsigned char *raw = (unsigned char *)vchSecret.data();
    size_t raw_len = vchSecret.size();

    ret = signature.Sign(ifaceIndex, addr, vchSecret.data(), vchSecret.size());
  }
  if (!ret)
    return error(SHERR_INVAL, "CSign::Sign: error signing with addr '%s'\n", addr.ToString().c_str());

  vAddr = vchFromString(addr.ToString());
  return (true);
}

/**
 * Verify an identity's signature.
 * @param vchSecret The external context that the signature was generated from.
 */
bool CCert::VerifySignature(cbuff vchSecret)
{

  if (!vchSecret.data())
    return (false);

  unsigned char *raw = (unsigned char *)vchSecret.data();
  size_t raw_len = vchSecret.size();

  CCoinAddr addr(stringFromVch(vAddr));
  return (signature.Verify(addr, vchSecret.data(), vchSecret.size()));
}

std::string CIdent::ToString()
{
  return (write_string(Value(ToValue()), false));
}

std::string CCert::ToString()
{
  return (write_string(Value(ToValue()), false));
}

std::string CLicense::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CIdent::ToValue()
{
  Object obj = CExtCore::ToValue();
  char sig[256];
  char loc[256];
  shnum_t x, y;

//  obj.push_back(Pair("identhash", GetHash().GetHex()));

  shgeo_loc(&geo, &x, &y, NULL);
  if (x != 0.0000 || y != 0.0000) {
    sprintf(loc, "%f,%f", (double)x, (double)y);
    string strGeo(loc);
    obj.push_back(Pair("geo", strGeo));
  }

  if (nType != 0) {
    obj.push_back(Pair("type", (int64_t)nType));
  }

  obj.push_back(Pair("addr", stringFromVch(vAddr)));

  return (obj);
}

Object CCert::ToValue()
{
  Object obj = CIdent::ToValue();

  obj.push_back(Pair("certhash", GetHash().GetHex()));
  if (hashIssuer.size() != 0)
    obj.push_back(Pair("issuer", hashIssuer.GetHex()));
  if (vContext.size() != 0)
    obj.push_back(Pair("serialno", GetSerialNumber().c_str()));
  if (nFee != 0)
    obj.push_back(Pair("fee", ValueFromAmount(nFee)));
  if (nFlag != 0)
    obj.push_back(Pair("flags", nFlag));
  obj.push_back(Pair("signature", signature.GetHash().GetHex()));
  obj.push_back(Pair("sigpubkey", signature.GetHash().GetHex()));
  
  return (obj);
}

Object CLicense::ToValue()
{
  Object obj = CCert::ToValue();
  obj.push_back(Pair("hash", GetHash().GetHex()));
  return (obj);
}

void CLicense::Sign(int ifaceIndex, CCoinAddr& addr)
{
  signature.SignOrigin(ifaceIndex, addr);
}

bool CLicense::VerifySignature(CCoinAddr& addr)
{
  return (signature.VerifyOrigin(addr));
}

bool DisconnectCertificate(CIface *iface, CTransaction& tx)
{
  CWallet *wallet = GetWallet(iface);
  CCert& cert = tx.certificate;
  const uint160 hCert = cert.GetHash();

  if (wallet->mapCert.count(hCert) == 0)
    return (false);

  const uint256& o_tx = wallet->mapCert[hCert];
  if (o_tx != tx.GetHash())
    return (false);

/* NOTE: order matters here. last = best */
  uint256 n_tx;
  bool found = false;
  for(map<uint256,uint160>::iterator it = wallet->mapCertArch.begin(); it != wallet->mapCertArch.end(); ++it) {
    const uint256& hash2 = (*it).first;
    const uint160& hash1 = (*it).second;
    if (hash1 == hCert) {
      n_tx = hash2;
      found = true;
    }
  }
  
  if (found) {
    /* transition current entry to archive */
    const uint160& o_cert = hCert;
    wallet->mapCertArch[o_tx] = o_cert;

    wallet->mapCert[hCert] = n_tx; 
    wallet->mapCertLabel[cert.GetLabel()] = hCert;
  } else {
    wallet->mapCert.erase(hCert);
    wallet->mapCertLabel.erase(cert.GetLabel());
  }

  return (true);
}


