
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

using namespace std;

std::map<uint160, uint256> mapCertIssuers;

uint64 GetCertFeeSubsidy(unsigned int nHeight) 
{
  return ( (1 * COIN) / ((nHeight / 1000000) + 1) );
}

int64 GetCertNetworkFee(int nHeight) 
{
  int64 nRes = 48 * COIN;
  int64 nDif = 34 * COIN;
  int nTargetHeight = 2081280;
fprintf(stderr, "DEBUG: GEtCertNetworkFee: %llu\n", (unsigned long long)(nRes - ( (nHeight/nTargetHeight) * nDif )));
  return nRes - ( (nHeight/nTargetHeight) * nDif );
}

bool IsCertOp(int op) {
    return op == OP_CERTISSUER_NEW
        || op == OP_CERTISSUER_ACTIVATE
        || op == OP_CERTISSUER_UPDATE
        || op == OP_CERT_NEW
        || op == OP_CERT_TRANSFER;
}

bool DecodeCertScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch) {
    CScript::const_iterator pc = script.begin();
    return DecodeCertScript(script, op, vvch, pc);
}

bool DecodeCertScript(const CScript& script, int& op, vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) 
{
  opcodetype opcode;
  if (!script.GetOp(pc, opcode)) return false;
  if (opcode < OP_1 || opcode > OP_16) return false;
  op = CScript::DecodeOP_N(opcode);

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

#if 0
  if ((op == OP_CERTISSUER_NEW && vvch.size() == 1)
      || (op == OP_CERTISSUER_ACTIVATE && vvch.size() == 3)
      || (op == OP_CERTISSUER_UPDATE && vvch.size() == 2)
      || (op == OP_CERT_NEW && vvch.size() == 3)
      || (op == OP_CERT_TRANSFER && vvch.size() == 2))
    return true;
#endif
  if ((op == OP_CERTISSUER_NEW && vvch.size() == 1)
      || (op == OP_CERTISSUER_ACTIVATE && vvch.size() == 2)
      || (op == OP_CERTISSUER_UPDATE && vvch.size() == 2)
      || (op == OP_CERT_NEW && vvch.size() == 3)
      || (op == OP_CERT_TRANSFER && vvch.size() == 2))
    return true;
  return false;
}

#if 0 /* DEBUG: */
bool DecodeCertTx(const CTransaction& tx, int& op, int& nOut,
    vector<vector<unsigned char> >& vvch, int nHeight) 
{
  bool found = false;

  // Strict check - bug disallowed
  for (unsigned int i = 0; i < tx.vout.size(); i++) {
    const CTxOut& out = tx.vout[i];
    vector<vector<unsigned char> > vvchRead;
    if (DecodeCertScript(out.scriptPubKey, op, vvchRead)) {
      nOut = i; found = true; vvch = vvchRead;
      break;
    }
  }
  if (!found) vvch.clear();
  return found && IsCertOp(op);
}

int IndexOfCertIssuerOutput(const CTransaction& tx) 
{
  vector<vector<unsigned char> > vvch;
  int op, nOut;
  if (!DecodeCertTx(tx, op, nOut, vvch, -1))
    throw runtime_error("IndexOfCertIssuerOutput() : certissuer output not found");
  return nOut;
}


bool CreateCertTransactionWithInputTx(CWallet *wallet, const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxIn, int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
    int64 nValue = 0;
    BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
        if (nValue < 0)
            return false;
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
        return false;

    wtxNew.BindWallet(wallet);
    {
        LOCK2(cs_main, wallet->cs_wallet);

        nFeeRet = nTransactionFee;
        loop {
            wtxNew.vin.clear();
            wtxNew.vout.clear();
            wtxNew.fFromMe = true;
//            wtxNew.data = vchFromString(txData);

            int64 nTotalValue = nValue + nFeeRet;
            printf("CreateCertTransactionWithInputTx: total value = %d\n",
                    (int) nTotalValue);
            double dPriority = 0;

            // vouts to the payees
            BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
                wtxNew.vout.push_back(CTxOut(s.second, s.first));

            int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

            // Choose coins to use
            set<pair<const CWalletTx*, unsigned int> > setCoins;
            int64 nValueIn = 0;
            printf( "CreateCertTransactionWithInputTx: SelectCoins(%s), nTotalValue = %s, nWtxinCredit = %s\n",
                    FormatMoney(nTotalValue - nWtxinCredit).c_str(),
                    FormatMoney(nTotalValue).c_str(),
                    FormatMoney(nWtxinCredit).c_str());
            if (nTotalValue - nWtxinCredit > 0) {
                if (!wallet->SelectCoins(nTotalValue - nWtxinCredit,
                        setCoins, nValueIn))
                    return false;
            }

            printf( "CreateCertTransactionWithInputTx: selected %d tx outs, nValueIn = %s\n",
                    (int) setCoins.size(), FormatMoney(nValueIn).c_str());

            vector<pair<const CWalletTx*, unsigned int> > vecCoins(
                    setCoins.begin(), setCoins.end());

            BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
                int64 nCredit = coin.first->vout[coin.second].nValue;
                dPriority += (double) nCredit
                        * coin.first->GetDepthInMainChain();
            }

            vecCoins.insert(vecCoins.begin(), make_pair(&wtxIn, nTxOut));

            nValueIn += nWtxinCredit;
            dPriority += (double) nWtxinCredit * wtxIn.GetDepthInMainChain();

            // Fill a vout back to self with any change
            int64 nChange = nValueIn - nTotalValue;
            if (nChange >= CENT) {
                // Note: We use a new key here to keep it from being obvious which side is the change.
                //  The drawback is that by not reusing a previous key, the change may be lost if a
                //  backup is restored, if the backup doesn't have the new private key for the change.
                //  If we reused the old key, it would be possible to add code to look for and
                //  rediscover unknown transactions that were written with keys of ours to recover
                //  post-backup change.

                // Reserve a new key pair from key pool
                CPubKey pubkey;
                assert(reservekey.GetReservedKey(pubkey));

                // -------------- Fill a vout to ourself, using same address type as the payment
                // Now sending always to hash160 (GetBitcoinAddressHash160 will return hash160, even if pubkey is used)
                CScript scriptChange;
                if (Hash160(vecSend[0].first) != 0)
                    scriptChange.SetDestination(pubkey.GetID());
                else
                    scriptChange << pubkey << OP_CHECKSIG;

                // Insert change txn at random position:
                vector<CTxOut>::iterator position = wtxNew.vout.begin()
                        + GetRandInt(wtxNew.vout.size());
                wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
            } else
                reservekey.ReturnKey();

            // Fill vin

            BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
                wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

            // Sign
            int nIn = 0;
            BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
                if (coin.first == &wtxIn
                        && coin.second == (unsigned int) nTxOut) {
                    if (!SignCertIssuerSignature(*coin.first, wtxNew, nIn++))
                        throw runtime_error("could not sign certissuer coin output");
                } else {
                    if (!SignSignature(*wallet, *coin.first, wtxNew, nIn++))
                        return false;
                }
            }

            // Limit size
            unsigned int nBytes = ::GetSerializeSize(*(CTransaction*) &wtxNew,
                    SER_NETWORK, PROTOCOL_VERSION);
            if (nBytes >= MAX_BLOCK_SIZE_GEN / 5)
                return false;
            dPriority /= nBytes;

            // Check that enough fee is included
            int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
            bool fAllowFree = CTransaction::AllowFree(dPriority);
            int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree);
            if (nFeeRet < max(nPayFee, nMinFee)) {
                nFeeRet = max(nPayFee, nMinFee);
                printf( "CreateCertTransactionWithInputTx: re-iterating (nFreeRet = %s)\n",
                        FormatMoney(nFeeRet).c_str());
                continue;
            }

            // Fill vtxPrev by copying from previous transactions vtxPrev
            wtxNew.AddSupportingTransactions();
            wtxNew.fTimeReceivedIsTxTime = true;

            break;
        }
    }

    printf("CreateCertTransactionWithInputTx succeeded:\n%s",
            wtxNew.ToString().c_str());
    return true;
}
#endif
