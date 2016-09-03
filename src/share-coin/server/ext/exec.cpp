
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
#include "sexe.h"
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include <boost/xpressive/xpressive_dynamic.hpp>
#include "wallet.h"
#include "exec.h"

using namespace std;
using namespace json_spirit;

shpool_t *pool;

void InitExecPool()
{
  if (pool) return;

  unsigned int idx;
  pool = shpool_init();
  (void)shpool_get(pool, &idx);
}

static cbuff GetExecPoolData(uint32_t idx)
{
  unsigned char *raw;
  size_t raw_len;
  shbuf_t *buff;

  InitExecPool();

  buff = shpool_get_index(pool, idx);
  if (!buff)
    return (cbuff());

  raw = shbuf_data(buff);
  raw_len = shbuf_size(buff);
  return (cbuff(raw, raw + raw_len));
}

static unsigned int SetExecPoolData(cbuff vData)
{
  shbuf_t *buff;
  unsigned int indexPool;

  InitExecPool();

  buff = shpool_get(pool, &indexPool);
  shbuf_clear(buff);
  shbuf_cat(buff, vData.data(), vData.size());
  
  return (indexPool);
}

exec_list *GetExecTable(int ifaceIndex)
{
  if (ifaceIndex < 0 || ifaceIndex >= MAX_COIN_IFACE)
    return (NULL);
  CWallet *wallet = GetWallet(ifaceIndex);
  if (!wallet)
    return (NULL);
  return (&wallet->mapExec);
}

bool DecodeExecHash(const CScript& script, int& mode, uint160& hash)
{
  CScript::const_iterator pc = script.begin();
  opcodetype opcode;
  int op;

  if (!script.GetOp(pc, opcode)) {
    return false;
  }
  mode = opcode; /* extension mode (new/update/remove) */
  if (mode < 0xf0 || mode > 0xf9)
    return false;

  if (!script.GetOp(pc, opcode)) { 
    return false;
  }
  if (opcode < OP_1 || opcode > OP_16) {
    return false;
  }
  op = CScript::DecodeOP_N(opcode); /* extension type (exec) */
  if (op != OP_EXEC) {
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



bool IsExecOp(int op) {
	return (op == OP_EXEC);
}


string execFromOp(int op) {
	switch (op) {
	case OP_EXT_NEW:
		return "execnew";
	case OP_EXT_UPDATE:
		return "execupdate";
	case OP_EXT_REMOVE:
		return "execremove";
	default:
		return "<unknown exec op>";
	}
}

bool DecodeExecScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) 
{
	opcodetype opcode;
  int mode;

	if (!script.GetOp(pc, opcode))
		return false;
  mode = opcode; /* extension mode (new/update/remove) */

	if (!script.GetOp(pc, opcode))
		return false;
	if (opcode < OP_1 || opcode > OP_16)
		return false;

	op = CScript::DecodeOP_N(opcode); /* extension type (exec) */
  if (op != OP_EXEC)
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
      (mode == OP_EXT_REMOVE && vvch.size() == 2))
    return (true);

	return false;
}

bool DecodeExecScript(const CScript& script, int& op,
		vector<vector<unsigned char> > &vvch) {
	CScript::const_iterator pc = script.begin();
	return DecodeExecScript(script, op, vvch, pc);
}

CScript RemoveExecScriptPrefix(const CScript& scriptIn) 
{
	int op;
	vector<vector<unsigned char> > vvch;
	CScript::const_iterator pc = scriptIn.begin();

	if (!DecodeExecScript(scriptIn, op, vvch, pc))
		throw runtime_error("RemoveExecScriptPrefix() : could not decode name script");

	return CScript(pc, scriptIn.end());
}

int64 GetExecOpFee(CIface *iface, int nHeight) 
{
  double base = ((nHeight+1) / 10240) + 1;
  double nRes = 5040 / base * COIN;
  double nDif = 5000 /base * COIN;
  int64 fee = (int64)(nRes - nDif);

  /* floor */
  fee /= 1000;
  fee *= 1000;

  return (MAX(iface->min_tx_fee*2, fee));
}


int64 GetExecReturnFee(const CTransaction& tx) 
{
	int64 nFee = 0;
	for (unsigned int i = 0; i < tx.vout.size(); i++) {
		const CTxOut& out = tx.vout[i];
		if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
			nFee += out.nValue;
	}
	return nFee;
}

bool IsExecTx(const CTransaction& tx)
{
  int tot;

  if (!tx.isFlag(CTransaction::TXF_EXEC)) {
    return (false);
  }

  tot = 0;
  BOOST_FOREACH(const CTxOut& out, tx.vout) {
    uint160 hash;
    int mode;

    if (DecodeExecHash(out.scriptPubKey, mode, hash)) {
      tot++;
    }
  }
  if (tot == 0) {
    return false;
  }

  return (true);
}

/**
 * Obtain the tx that defines this exec.
 */
bool GetTxOfExec(CIface *iface, const uint160& hashExec, CTransaction& tx) 
{
  int ifaceIndex = GetCoinIndex(iface);
  exec_list *execes = GetExecTable(ifaceIndex);
  bool ret;

  if (execes->count(hashExec) == 0) {
    return false; /* nothing by that name, sir */
  }

  CTransaction& txIn = (*execes)[hashExec];
  if (!IsExecTx(txIn)) 
    return false; /* inval; not an exec tx */

#if 0
  if (txIn.exec.IsExpired()) {
    return false;
  }
#endif

  tx.Init(txIn);
  return true;
}

bool IsLocalExec(CIface *iface, const CTxOut& txout) 
{
  CWallet *pwalletMain = GetWallet(iface);
  return (IsMine(*pwalletMain, txout.scriptPubKey)); 
}

bool IsLocalExec(CIface *iface, const CTransaction& tx)
{
  if (!IsExecTx(tx))
    return (false); /* not a exec */

  int nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* invalid state */

  return (IsLocalExec(iface, tx.vout[nOut]));
}


/**
 * Verify the integrity of an exec transaction.
 */
bool VerifyExec(CTransaction& tx, int& mode)
{
  uint160 hashExec;
  int nOut;

  /* core verification */
  if (!IsExecTx(tx)) {
    return (false); /* tx not flagged as exec */
  }

  /* verify hash in pub-script matches exec hash */
  nOut = IndexOfExtOutput(tx);
  if (nOut == -1)
    return (false); /* no extension output */

  if (!DecodeExecHash(tx.vout[nOut].scriptPubKey, mode, hashExec))
    return (false); /* no exec hash in output */

  if (mode != OP_EXT_NEW && 
      mode != OP_EXT_ACTIVATE &&
      mode != OP_EXT_UPDATE &&
      mode != OP_EXT_TRANSFER &&
      mode != OP_EXT_REMOVE)
    return (false);

  CExec exec(tx.certificate);
  if (hashExec != exec.GetHash())
    return error(SHERR_INVAL, "exec hash mismatch");

  return (true);
}

std::string CExec::ToString()
{
  return (write_string(Value(ToValue()), false));
}

Object CExec::ToValue()
{
  Object obj = CIdent::ToValue();

  if (GetStack().size() != 0) {
    string str((const char *)GetStack().data());
    obj.push_back(Pair("stack", str));
  }

  if (nFlag != 0)
    obj.push_back(Pair("flags", nFlag));

  obj.push_back(Pair("signature", signature.GetHash().GetHex()));

  obj.push_back(Pair("hash", GetHash().GetHex()));
  return (obj);
}

#if 0
bool CExec::Sign(uint160 sigCertIn)
{
  hashIssuer = sigCertIn;
  signature.SignContext(hashIssuer);
  return true;
}
bool CExec::VerifySignature()
{
  return (signature.VerifyContext(hashIssuer));
}
#endif
bool CExec::SignContext()
{
  cbuff data;
  if (!GetData(data))
    return (false);
  return (signature.SignContext(data.data(), data.size()));
}
bool CExec::VerifyContext()
{
  cbuff data;
  if (!GetData(data))
    return (false);
  return (signature.VerifyContext(data.data(), data.size()));
}

bool CExec::SetData(cbuff data)
{
  indexPool = SetExecPoolData(data);
  return (true);
}

bool CExec::GetData(cbuff& data)
{

  data = GetExecPoolData(indexPool);
  if (data.size() == 0)
    return (false);

  return (true);
}

bool CExec::LoadData(string path)
{
  shbuf_t *buff;
  int err;

  buff = shbuf_init();
  err = shfs_mem_read((char *)path.c_str(), buff);
  if (err) {
    shbuf_free(&buff);
    return error(err, "CExec.LoadData: failure loading path \"%s\".", path.c_str());
  }

  unsigned char *raw = shbuf_data(buff);
  size_t raw_len = shbuf_size(buff);

  {
    sexe_mod_t *mod = (sexe_mod_t *)raw;
    if (0 != memcmp(mod->sig, SEXE_SIGNATURE, sizeof(mod->sig))) {
      shbuf_free(&buff);
      return error(SHERR_ILSEQ, "CExec.LoadData: path \"%s\" has an invalid file format.", path.c_str());
    }

    SetLabel(string(mod->name));
  }

  cbuff data(raw, raw + raw_len);
  shbuf_free(&buff);

  return (SetData(data));
}

/* run program and call 'init' event to gather external decl var/func. */
bool CExec::SetStack()
{
  shjson_t *json;
  shjson_t *def_json;
  shjson_t *u_json;
  shjson_t *jret;
  shbuf_t *buff;
  sexe_t *S;
  cbuff data;
  char *str;
  int err;

  data = GetExecPoolData(indexPool);
  if (data.size() == 0) {
    return error(SHERR_NOENT, "CExec.SetStack: pool index #%d has no content.", indexPool);
  }

  /* prepare args */
  json = shjson_init(NULL);
  shjson_str_add(json, "version", PACKAGE_STRING); 

  /* prepare runtime */
  buff = shbuf_init();
  shbuf_cat(buff, data.data(), data.size());
  err = sexe_exec_popen(buff, json, &S);
  shbuf_free(&buff);
  shjson_free(&json);
  if (err) {
    return error(err, "CExec.SetStack: error executing code.");
  }

  /* load stack */
  err = sexe_exec_prun(S);
  if (err) {
    error(err, "CExec.SetStack: sexe_exec_prun");
    return (false);
  }

  CCoinAddr send_addr(stringFromVch(vAddr));

  /* execute method */
  json = shjson_init(NULL);
  shjson_str_add(json, "version", PACKAGE_STRING); 
  shjson_str_add(json, "sender", (char *)send_addr.ToString().c_str());
  err = sexe_exec_pcall(S, "init", json);
  shjson_free(&json);
  if (err) {
    error(err, "CExec.SetStack: sexe_exec_pcall");
    return (false);
  }

  /* persistent user data */
  u_json = NULL;
  err = sexe_exec_pget(S, "arg", &u_json);
  if (err) {
    return error(err, "CExec.SetStack: error obtaining user-data.");
  }
fprintf(stderr, "DEBUG: EXEC: USRDATA: \"%s\"\n", shjson_print(u_json));
  shjson_free(&u_json);

  def_json = NULL;
  err = sexe_exec_pgetdef(S, "arg", &def_json);
  sexe_exec_pclose(S);
  if (err) {
    return error(err, "CExec.SetStack: error obtaining user-data.");
  }
fprintf(stderr, "DEBUG: EXEC: DEFDATA: \"%s\"\n", shjson_print(def_json));

  str = shjson_print(def_json);
  shjson_free(&def_json);
  if (!str)
    return error(SHERR_INVAL, "CExec.SetStack: error parsing json");
  SetStack(cbuff(str, str + strlen(str)));
  free(str);

  return (true);
}

int ProcessExecActivateTx(CIface *iface, CExec *execIn, CExec *exec)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  /* establish coin addr */
  string strAccount;
  CCoinAddr addr = exec->GetCoinAddr();
  if (!GetCoinAddr(wallet, addr, strAccount))
    return (SHERR_NOENT);

  /* establish ext coin addr */
  string strExtAccount;
  CCoinAddr extAddr = exec->GetExecAddr();
  if (!GetCoinAddr(wallet, addr, strExtAccount))
    return (SHERR_INVAL);

  /* load sexe code */
// exec->LoadData();

  /* verify sig */
  if (!exec->VerifyContext())
    return (SHERR_ACCESS);

  /* prepare user-data */

  /* execute */

  /* post tx commit */

/* push back data to pool, temporary alloc */

  return (0);
}

int ProcessExecTx(CIface *iface, CNode *pfrom, CTransaction& tx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CExec& exec = (CExec&)tx.certificate;
  uint160 hExec = exec.GetIdentHash();
  CKeyID inkey;
  CKeyID key;
  int err;

  /* validate */
  int tx_mode;
  if (!VerifyExec(tx, tx_mode))
    return (SHERR_INVAL);

/* .. metric .. */

  if (tx_mode == OP_EXT_ACTIVATE ||
      tx_mode == OP_EXT_UPDATE) {
    /* only applies to local server */
    if (!IsLocalExec(iface, tx))
      return (SHERR_REMOTE);
  }

  /* obtain 'primary' exec tx */
  CTransaction txIn;
  if (!GetTxOfExec(iface, hExec, txIn))
    return (SHERR_NOENT);
  CExec& execIn = (CExec&)txIn.certificate;

  execIn.GetCoinAddr().GetKeyID(inkey);
  exec.GetCoinAddr().GetKeyID(key);
  if (inkey != key)
    return (SHERR_INVAL);

  if (tx_mode != OP_EXT_UPDATE) {
    execIn.GetExecAddr().GetKeyID(inkey);
    exec.GetExecAddr().GetKeyID(key);
    if (execIn != exec)
      return (SHERR_INVAL);
  } 

  if (tx_mode == OP_EXT_ACTIVATE) {
    err = ProcessExecActivateTx(iface, &execIn, &exec);
    if (err)
      return (err);
  }

  if (tx_mode == OP_EXT_NEW || 
      tx_mode == OP_EXT_UPDATE) {
    /* [re]insert into ExecTable */
  } else if (tx_mode == OP_EXT_REMOVE) {
    /* remove from ExecTable */
  }

  return (0);
}

int init_exec_tx(CIface *iface, string strAccount, string strPath, int64 nExecFee, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  int64 nFee = GetExecOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
fprintf(stderr, "DEBUG: init_exec_tx: insufficient balance (%llu) .. %llu required\n", bal, nFee);
    return (SHERR_AGAIN);
  }

  CExec *exec;
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* embed exec content into transaction */
  wtx.SetNull();
  exec = wtx.CreateExec();
  exec->vAddr = cbuff(vchFromString(extAddr.ToString()));
  exec->SetFee(MAX(iface->min_tx_fee, nExecFee));
  wtx.strFromAccount = strAccount; /* originating account for payment */

  if (!exec->LoadData(strPath))
    return (SHERR_INVAL);
fprintf(stderr, "DEBUG: EXECTX: LOAD: \"%s\"\n", strPath.c_str());


  if (!exec->SetStack()) {
    return (SHERR_INVAL);
  }
if (exec->GetStack().size() != 0) fprintf(stderr, "DEBUG: EXECTX: STACK: \"%s\"\n", exec->GetStack().data());
else fprintf(stderr, "DEBUG: EXECTX: STACK: <empty>\n");

  exec->SignContext();

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << exec->GetHash() << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  /* identify tx using hash that does not take into account context */
  uint160 execHash = exec->GetIdentHash();
  uint256 txHash = wtx.GetHash();
  Debug("SENT:EXECNEW : title=%s, exechash=%s, tx=%s\n", exec->GetLabel().c_str(), execHash.ToString().c_str(), txHash.GetHex().c_str());
  wallet->mapExec[execHash] = wtx;

  return (0);
}


/* prob should require removal of original first to update */
int update_exec_tx(CIface *iface, const uint160& hashExec, string strPath, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  /* verify original exec */
  CTransaction tx;
  if (!GetTxOfExec(iface, hashExec, tx)) {
fprintf(stderr, "DEBUG: update_exec_tx: !GetTxOfExec\n");
    return (SHERR_NOENT);
}
  if(!IsLocalExec(iface, tx)) {
fprintf(stderr, "DEBUG: update_exec_tx: !IsLocalExec\n");
    return (SHERR_REMOTE);
}

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0) {
    return (SHERR_REMOTE);
}

  /* establish account */
  CExec& execIn = (CExec&)tx.certificate;

  string strAccount;
  CCoinAddr addr = execIn.GetCoinAddr();
  if (!GetCoinAddr(wallet, addr, strAccount))
    return (SHERR_NOENT);

  CCoinAddr extAddr = execIn.GetExecAddr();
  if (!extAddr.IsValid())
    return (SHERR_INVAL);

  int64 nNetFee = GetExecOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }

  /* generate tx */
  CExec *exec;
	CScript scriptPubKey;
  wtx.SetNull();
  wtx.strFromAccount = strAccount;

  exec = wtx.UpdateExec(execIn);

  /* generate new ext addr */
  string strExtAccount = "@" + strAccount;
  extAddr = GetAccountAddress(wallet, strExtAccount, true);
  exec->SetExecAddr(extAddr);

  /* load new sexe code */
  if (!exec->LoadData(strPath))
    return (SHERR_INVAL);

  /* initialize code */
  if (!exec->SetStack())
    return (SHERR_INVAL);

  /* sign code */
  exec->SignContext();


  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());
	scriptPubKey << OP_EXT_UPDATE << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << exec->GetHash() << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  vector<pair<CScript, int64> > vecSend;
  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend)) {
    fprintf(stderr, "DEBUG: update_exec_tx: !SendMoneyWithExtTx\n"); 
    return (SHERR_INVAL);
  }

  uint160 execHash = exec->GetIdentHash();
  wallet->mapExec[execHash] = wtx;
  Debug("SENT:EXECUPDATE : title=%s, exechash=%s, tx=%s\n", exec->GetLabel().c_str(), execHash.ToString().c_str(), wtx.GetHash().GetHex().c_str());

	return (0);
}

int activate_exec_tx(CIface *iface, string strAccount, uint160 hExec, string strFunc, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);
  char buf[256];

  /* obtain primary exec tx */
  CTransaction tx;
  if (!GetTxOfExec(iface, hExec, tx))
    return (SHERR_NOENT);
  CExec& execIn = (CExec&)tx.certificate;

  /* ensure sufficient funds are available to invoke call */
  int64 nFee = execIn.GetFee();
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
fprintf(stderr, "DEBUG: activate_exec_tx: insufficient balance (%llu) .. %llu required\n", bal, nFee);
    return (SHERR_AGAIN);
  }

  /* define "sender" address. */
  CCoinAddr sendAddr = GetAccountAddress(wallet, strAccount, false);
  if (!sendAddr.IsValid())
    return (false);

  /* define "execution" address. */
  CCoinAddr recvAddr = execIn.GetExecAddr();
  if (!recvAddr.IsValid())
    return (false);

  /* init tx */
  wtx.SetNull();
  wtx.strFromAccount = strAccount; /* originating account for payment */
  CExec *exec = wtx.ActivateExec(execIn);

  /* set "stack" */
  sprintf(buf, "%s {\"sender\":\"%s\",\"value\":%s}", strFunc.c_str(), sendAddr.ToString().c_str(), ((double)nFee / (double)COIN));  
  exec->SetStack(cbuff(buf, buf + strlen(buf)));

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(execIn.GetExecAddr().Get());

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_ACTIVATE << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << exec->GetHash() << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  /* identify tx using hash that does not take into account context */
  uint160 execHash = exec->GetIdentHash();
  uint256 txHash = wtx.GetHash();
  Debug("SENT:EXECNEW : title=%s, exechash=%s, tx=%s\n", exec->GetLabel().c_str(), execHash.ToString().c_str(), txHash.GetHex().c_str());
  wallet->mapExec[execHash] = wtx;

  return (0);
}

#if 0
int activate_exec_tx(CIface *iface, string strAccount, string strPath, CWalletTx& wtx)
{
  CWallet *wallet = GetWallet(iface);
  int ifaceIndex = GetCoinIndex(iface);

  int64 nFee = GetExecOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nFee) {
fprintf(stderr, "DEBUG: init_exec_tx: insufficient balance (%llu) .. %llu required\n", bal, nFee);
    return (SHERR_AGAIN);
  }

  CExec *exec;
  string strExtAccount = "@" + strAccount;
  CCoinAddr extAddr = GetAccountAddress(wallet, strExtAccount, true);

  /* embed exec content into transaction */
  wtx.SetNull();
  exec = wtx.CreateExec();
  exec->vAddr = cbuff(vchFromString(extAddr.ToString()));
  wtx.strFromAccount = strAccount; /* originating account for payment */

  if (!exec->LoadData(strPath))
    return (SHERR_INVAL);
fprintf(stderr, "DEBUG: EXECTX: LOAD: \"%s\"\n", strPath.c_str());


  if (!exec->SetStack()) {
    return (SHERR_INVAL);
  }
if (exec->GetStack().size() != 0) fprintf(stderr, "DEBUG: EXECTX: STACK: \"%s\"\n", exec->GetStack().data());
else fprintf(stderr, "DEBUG: EXECTX: STACK: <empty>\n");

  exec->SignContext();

  /* send to extended tx storage account */
  CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(extAddr.Get());

  CScript scriptPubKey;
  scriptPubKey << OP_EXT_NEW << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << exec->GetHash() << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  // send transaction
  string strError = wallet->SendMoney(scriptPubKey, nFee, wtx, false);
  if (strError != "") {
    error(ifaceIndex, strError.c_str());
    return (SHERR_INVAL);
  }

  /* identify tx using hash that does not take into account context */
  uint160 execHash = exec->GetIdentHash();
  uint256 txHash = wtx.GetHash();
  Debug("SENT:EXECNEW : title=%s, exechash=%s, tx=%s\n", exec->GetLabel().c_str(), execHash.ToString().c_str(), txHash.GetHex().c_str());
  wallet->mapExec[execHash] = wtx.GetHash();

  return (0);
}
#endif


/**
 * Removes a pre-existing exec on the block-chain. 
 * @param hashExec The exec hash from it's last tx op.
 * @param strAccount The account that has ownership over the exec.
 * @param wtx The new transaction to be filled in.
 * @note The previous exec tx fee is returned to the account, and the current fee is burned.
 */
int remove_exec_tx(CIface *iface, string strAccount, const uint160& hashExec, CWalletTx& wtx)
{
  int ifaceIndex = GetCoinIndex(iface);
  CWallet *wallet = GetWallet(iface);

  /* verify original exec */
  CTransaction tx;
  if (!GetTxOfExec(iface, hashExec, tx)) {
    fprintf(stderr, "DEBUG: update_exec_tx: !GetTxOfExec\n");
    return (SHERR_NOENT);
  }
  if(!IsLocalExec(iface, tx)) {
    fprintf(stderr, "DEBUG: update_exec_tx: !IsLocalExec\n");
    return (SHERR_REMOTE);
  }

  /* establish original tx */
  uint256 wtxInHash = tx.GetHash();
  if (wallet->mapWallet.count(wtxInHash) == 0) {
    return (SHERR_REMOTE);
  }

  /* establish account */
  CCoinAddr addr;

  addr = GetAccountAddress(wallet, strAccount, false);
  if (!addr.IsValid()) {
    fprintf(stderr, "DEBUG: update_exec_tx: !addr.IsValid\n");
    return (SHERR_NOENT);
  }

  /* generate tx */
  CExec *exec;
	CScript scriptPubKey;
  wtx.SetNull();
  exec = wtx.RemoveExec(CExec(tx.certificate));
  uint160 execHash = exec->GetHash();

  vector<pair<CScript, int64> > vecSend;
  CWalletTx& wtxIn = wallet->mapWallet[wtxInHash];

  /* generate output script */
	CScript scriptPubKeyOrig;
  scriptPubKeyOrig.SetDestination(addr.Get()); /* back to origin */
	scriptPubKey << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << execHash << OP_2DROP;
  scriptPubKey += scriptPubKeyOrig;

  int64 nNetFee = GetExecOpFee(iface, GetBestHeight(iface));
  int64 bal = GetAccountBalance(ifaceIndex, strAccount, 1);
  if (bal < nNetFee) {
    return (SHERR_AGAIN);
  }
  if (nNetFee) { /* supplemental tx payment */
    CScript scriptFee;
    scriptFee << OP_EXT_REMOVE << CScript::EncodeOP_N(OP_EXEC) << OP_HASH160 << execHash << OP_2DROP << OP_RETURN;
    vecSend.push_back(make_pair(scriptFee, nNetFee));
  }

  if (!SendMoneyWithExtTx(iface, wtxIn, wtx, scriptPubKey, vecSend)) {
fprintf(stderr, "DEBUG: update_exec_tx: !SendMoneyWithExtTx\n"); 
    return (SHERR_INVAL);
}

  wallet->mapExec[execHash] = wtx;

	return (0);
}


