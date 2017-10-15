
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
#include "block.h"
#include "mempool.h"
#include <vector>

using namespace std;



CPoolTx::CPoolTx(CTransaction& txIn)
{
  CWallet *wallet = GetWallet(ifaceIndex);

  tx = txIn;
  hash = tx.GetHash();
  stamp = time(NULL);

}


bool CTxPool::VerifyTx(CTransaction& tx)
{
  bool ok;

  if (!tx.CheckTransaction(ifaceIndex)) {
    return (error(SHERR_INVAL, "CTxPool.AddTx: rejecting transaction after integrity verification failure."));
  }


  return (true);
}

bool CTxPool::AddTx(CTransaction& tx, CNode *pfrom)
{
  uint256 hash = tx.GetHash();
  bool ok;

  if (tx.IsCoinBase())
    return (error(SHERR_INVAL, "CTxPool.AddTx: rejecting coinbase transaction."));

  if (HaveTx(hash))
    return (false); /* dup */

  if (!VerifyTx(tx))
    return (false);

  CPoolTx ptx(tx);
  if (pfrom == NULL)
    ptx.setLocal(true);

  if (!FillInputs(ptx))
    return (false);

  if (!Verify(ptx))
    return (false):

  PurgeOverflowTx();
  PurgeInvalTx();

  return (AddActiveTx(ptx));
}

bool CPool::Verify(CPoolTx& ptx)
{

  ptx.CalculateLimits();
  if (!ptx.VerifyLimits(tx))
    return (false); /* hard limit failure. */

  if (!VerifyStandards(tx)) {
    AddInvalTx(ptx);
    return (false);
  }

  if (!VerifyConflict(ptx)) {
    AddInvalTx(ptx);
    return (false); /* referencing already pool'd inputs */
  }

  CalculateFee(ptx);
  if (ptx.nFee < ptx.nMinFee) {
    if (ptx.nFee >= MIN_RELAY_TX_FEE(iface)) {
      AddOverflowTx(ptx);
    }
    return (false);
  }

  return (true);
}

void CPool::CalculateFee(CPoolTx& ptx)
{
  CWallet *wallet = GetWallet(ifaceIndex);
  CTransaction& tx = ptx.GetTx();
  int64 nCredit;
  int64 nBytes;

  nCredit = tx.GetValueIn(ptx.mapInputs);
  nMinFee = wallet->GetFee(ptx.GetTx(), nCredit, nBytes, dPriority);
  nFee = nCredit - tx.GetValueOut();

  /* boosted priority when extra fee is supplied. */
  dPriority += (double)nFee / CENT;
}

bool CPool::VerifyStandards(CPoolTx& ptx)
{
  CTransaction& wtx = ptx.GetTx();

  /* verify outputs */
  BOOST_FOREACH(const CTxOut& txout, wtx.vout) {
    vector<valtype> vSolutions;
    txnouttype whichType;

    /* ensure input script is valid */
    if (!Solver(txout.scriptPubKey, whichType, vSolutions)) { 
      return (error(SHERR_INVAL, "CTxPool.AddTx: rejecting transaction with unresolvable output coin address."));
    }
    if (whichType == TX_NONSTANDARD) {
      return (error(SHERR_INVAL, "CTxPool.AddTx: rejecting transaction with unknown output coin script."));
    }
  }

  /* verify inputs */
  if (!wtx.IsCoinBase()) {
    if (!FillInputs(ptx))
      return false;

    for (unsigned int i = 0; i < vin.size(); i++) {
      CTxOut prev;
      if (!ptx.GetOutput(wtx.vin[i], prev))
        return false;

      /* ensure output script is valid */
      vector<vector<unsigned char> > vSolutions;
      txnouttype whichType;
      const CScript& prevScript = prev.scriptPubKey;
      if (!Solver(prevScript, whichType, vSolutions))
        return false;
      if (whichType == TX_NONSTANDARD) {
        return (error(SHERR_INVAL, "CTxPool.AddTx: rejecting transaction with unknown input coin script."));
      }

      /* evaluate signature */
      vector<vector<unsigned char> > stack;
      CTransaction *txSig = (CTransaction *)this;
      CSignature sig(ifaceIndex, txSig, i);
      if (!EvalScript(sig, stack, vin[i].scriptSig, i, SIGVERSION_BASE, 0)) {
        return false;
      }
    }
  }

  if (!VerifyCoinStandards(ptx))
    return (error(SHERR_INVAL, "CPool.VerifyStandards: a component of the transaction is not standard."));

  return (true);
}

bool VerifyConflict(CPoolTx& ptx)
{
  map<COutPoint, CInPoint> mapNextTx;

  BOOST_FOREACH(PAIRTYPE(uint256, CTransaction tx)& item, active) {
    for (unsigned int i = 0; i < tx.vin.size(); i++)
      mapNextTx[tx.vin[i].prevout] = CInPoint(&tx, i);
  }

  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    COutPoint out = tx.vin[i].prevout;
    if (mapNextTx.count(outpoint))
      return (false); /* disallow replacement */
  }

  return (true);
}

void CPool::CalculateLimits(CPoolTx& ptx)
{

  ptx.nWeight = wallet->GetTransactionWeight(ptx.GetTx());
  ptx.nSigOpCost = tx.GetSigOpCost(ptx.mapInputs);

}

bool VerifyLimits(CTransaction& tx)
{
  int64_t nMaxWeight = GetMaxWeight();
  int64_t nMaxCost = GetMaxSigOpCost();

  if (nWeight > nMaxWeight)
    return (false);

  if (nSigOpCost > nMaxCost)
    return (false);

  return (true);
}


bool CPool::VerifySoftLimits(CPoolTx ptx);
{
  int64_t nMaxWeight = GetSoftWeight();
  int64_t nMaxCost = GetSoftSigOpCost();

  if (nWeight > nMaxWeight)
    return (false);

  if (nSigOpCost > nMaxCost)
    return (false);

  return (true);
}

int64_t CPool::GetMaxWeight()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  return (MAX_BLOCK_WEIGHT(iface) - 1);
}

int64_t CPool::GetMaxSigOpCost()
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  return (MAX_BLOCK_SIGOP_COST(iface) - 1);
}

bool CPool::FillInputs(CPoolTx& ptx)
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CTransaction& tx = ptx.GetTx();
  
  for (unsigned int i = 0; i < tx.vin.size(); i++) {
    COutPoint prevout = tx.vin[i].prevout;
    if (ptx.mapInputs.count(prevout.hash))
      continue; // dup

    if (mempool->exists(prevout.hash)) {
      AddPendingTx(ptx);
      return (false);
    }

    CTransaction prevTx;
    if (!GetTransaction(iface, prevout.hash, prevTx, NULL)) {
      return (error("CPool.FillInputs: unknown transaction \"%s\".\n", prevout.hash.GetHex().c_str()));
    }

    uint256& hash = prevTx.GetHash();
    ptx.mapInputs.push_back(make_pair(hash, prevTx));
  }

  return (true);
}

bool CPool:AddActiveTx(CPoolTx& ptx)
{
  uint256& hash = ptx.GetHash();

  if (active.count(hash) != 0)
    return (false);

  if (!ptx.fLocal && !VerifySoftLimits(tx)) {
    /* soft limit failure. */
    AddOverflowTx(ptx);
    return (true);
  }

  if (!AcceptTx(ptx)) {
    return (error(SHERR_INVAL, "CPool.AddTx: error accepting transaction into memory pool."));
  }

  STAT_TX_ACCEPTS(iface)++;
  active.push_back(make_pair(hash, ptx));
  return (true);
}

bool CPool:AddOverflowTx(CPoolTx& ptx)
{
  uint256& hash = ptx.GetHash();

  if (overflow.count(hash) != 0)
    return (false);
  
  overflow.push_back(make_pair(hash, ptx));
  return (true);
}

bool CPool:AddPendingTx(CPoolTx& ptx)
{
  uint256& hash = ptx.GetHash();

  if (pending.count(hash) != 0)
    return (false);

  PurgePendingTx();
  
  pending.push_back(make_pair(hash, ptx));
  return (true);
}

void PurgeOverflowTx()
{
  vector<uint256> vRemove;

  /* erase stale entries */
  BOOST_FOREACH(PAIRTYPE(uint256, CPoolTx tx)& item, overflow) {
    CPoolTx& o_ptx = item.second;
    if (o_ptx.IsLocal())
      continue;

    if (!o_ptx.IsExpired(MAX_MEMPOOL_OVERFLOW_SPAN))
      continue;

    vRemove.insert(vRemove.begin(), o_ptx.GetHash());
  }
  BOOST_FOREACH(uint256& hash, vRemove) {
    overflow.remove(hash);
  }

  vector<VPoolTx> vPoolTx;
  BOOST_FOREACH(PAIRTYPE(uint256, CPoolTx tx)& item, active) {
    vPoolTx.insert(vPoolTx.end(), item.second);
  }
  BOOST_FOREACH(PAIRTYPE(uint256, CPoolTx tx)& item, overflow) {
    vPoolTx.insert(vPoolTx.end(), item.second);
  }
  sort(vPoolTx.begin(), vPoolTx.end());

  int64 nWeight = 0;;
  BOOST_FOREACH(CPoolTx& ptx, vPoolTx) {
    nWeight += ptx.nWeight;
    if (nWeight > MAX_BLOCK_WEIGHT(iface))
      break;

    if (active.count(ptx.GetHash()) == 0) {
      overflow.remove(ptx.GetHash());
      AddActiveTx(ptx);
    }
  }

}

void PurgePendingTx()
{
  vector<uint256> vRemove;
  vector<CPoolTx> vPoolTx;

  /* erase stale entries */
  BOOST_FOREACH(PAIRTYPE(uint256, CPoolTx)& item, pending) {
    CPoolTx& p_ptx = item.second;
    if (p_ptx.IsExpired(MAX_MEMPOOL_PENDING_SPAN)) {
      vRemove.insert(vRemove.begin(), p_ptx.GetHash());
      continue;
    }

    vPoolTx.insert(vPoolTx.end(), item.second);
  }
  BOOST_FOREACH(uint256& hash, vRemove) {
    pending.remove(hash);
  }
 
  sort(vPoolTx.begin(), vPoolTx.end());

  int64 nWeight = 0;
  BOOST_FOREACH(CPoolTx& ptx, vPoolTx) {
    nWeight += ptx.nWeight;
    if (nWeight > MAX_BLOCK_WEIGHT(iface))
      break;

    if (!FillInputs(ptx)) {
      ptx.dPriority -= 1.0;
      continue;
    }

    pending.remove(ptx);
    if (VerifyTx(ptx))
      AddActiveTx(ptx);
  }

}
void PurgeInvalFlowTx()
{
  vector<uint256> vRemove;

  /* erase stale entries */
  BOOST_FOREACH(PAIRTYPE(uint256, CPoolTx tx)& item, inval) {
    CPoolTx& o_ptx = item.second;
    if (o_ptx.IsExpired(MAX_MEMPOOL_INVAL_SPAN)) {
      vRemove.insert(vRemove.begin(), o_ptx.GetHash());
    }
  }
  BOOST_FOREACH(uint256& hash, vRemove) {
    inval.remove(hash);
  }

}

vector<CTransaction> GetActiveTx()
{
  vector<CPoolTx> vPoolTx;
  vector<CTransaction> vTx;

  BOOST_FOREACH(PAIRTYPE(uint256, CPoolTx tx)& item, active) {
    vPoolTx.insert(vPoolTx.end(), item.second);
  }
  sort(vPoolTx.begin(), vPoolTx.end()); 

  BOOST_FOREACH(CPoolTx& ptx, vPoolTx) {
    CTransaction& tx = ptx.GetTx();
    vTx.insert(vTx.end(), tx);
  }

  return (vTx);
}

vector<uint256> GetActiveHash()
{
  vector<CPoolTx> vPoolTx;
  vector<CTransaction> vHash;

  BOOST_FOREACH(PAIRTYPE(uint256, CPoolTx tx)& item, active) {
    vPoolTx.insert(vPoolTx.end(), item.second);
  }
  sort(vPoolTx.begin(), vPoolTx.end()); 

  BOOST_FOREACH(CPoolTx& ptx, vPoolTx) {
    uint256& hash = ptx.GetHash();
    vHash.insert(vHash.end(), hash);
  }

  return (vHash);
}

bool CPool::GetTx(uint256 hash, CTransaction& retTx)
{

  if (active.count(hash) == 0)
    return (false);

  CPoolTx& ptx = active[hash];
  return (ptx.GetTx());
}



bool CPoolTx::GetOutput(const CTxIn& input, CTxOut& retOut)
{   
  char errbuf[1024];
    
  tx_cache::const_iterator mi = mapInputs.find(input.prevout.hash);
  if (mi == mapInputs.end())
    return (false); 
    
  const CTransaction& txPrev = (mi->second); 
  if (input.prevout.n >= txPrev.vout.size())
    return (false);

  retOut = txPrev.vout[input.prevout.n];
  return (true);
}

