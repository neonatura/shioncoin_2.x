
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

#include "db.h"
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"

#ifdef WIN32
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef fcntl
#undef fcntl
#endif

#include <boost/array.hpp>
#include <share.h>

using namespace std;
using namespace boost;


static CBigNum bnProofOfWorkLimit(~uint256(0) >> 20); // usde: starting difficulty is 1 / 2^12


class SHCOrphan
{
  public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;

    SHCOrphan(CTransaction* ptxIn)
    {
      ptx = ptxIn;
      dPriority = 0;
    }

    void print() const
    {
      printf("SHCOrphan(hash=%s, dPriority=%.1f)\n", ptx->GetHash().ToString().substr(0,10).c_str(), dPriority);
      BOOST_FOREACH(uint256 hash, setDependsOn)
        printf("   setDependsOn %s\n", hash.ToString().substr(0,10).c_str());
    }
};

static unsigned int KimotoGravityWell(const CBlockIndex* pindexLast, const CBlock *pblock, uint64 TargetBlocksSpacingSeconds, uint64 PastBlocksMin, uint64 PastBlocksMax) 
{
  const CBlockIndex *BlockLastSolved	= pindexLast;
  const CBlockIndex *BlockReading	= pindexLast;
  uint64	PastBlocksMass	= 0;
  int64	PastRateActualSeconds	= 0;
  int64	PastRateTargetSeconds	= 0;
  double	PastRateAdjustmentRatio	= double(1);
  CBigNum	PastDifficultyAverage;
  CBigNum	PastDifficultyAveragePrev;
  double	EventHorizonDeviation;
  double	EventHorizonDeviationFast;
  double	EventHorizonDeviationSlow;

  if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64)BlockLastSolved->nHeight < PastBlocksMin) { return bnProofOfWorkLimit.GetCompact(); }

  int64 LatestBlockTime = BlockLastSolved->GetBlockTime();

  for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
    if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
    PastBlocksMass++;

    if (i == 1)	{ PastDifficultyAverage.SetCompact(BlockReading->nBits); }
    else	{ PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev; }
    PastDifficultyAveragePrev = PastDifficultyAverage;

    if (LatestBlockTime < BlockReading->GetBlockTime() && BlockReading->nHeight > 144000) {
      LatestBlockTime = BlockReading->GetBlockTime();
    }

    PastRateActualSeconds                   = LatestBlockTime - BlockReading->GetBlockTime();
    PastRateTargetSeconds	= TargetBlocksSpacingSeconds * PastBlocksMass;
    PastRateAdjustmentRatio	= double(1);

    if (BlockReading->nHeight > 144000 && PastRateActualSeconds < 1) // HARD Fork block number
      PastRateActualSeconds = 1;
    else if (PastRateActualSeconds < 0) 
      PastRateActualSeconds = 0; 

    if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
      PastRateAdjustmentRatio	= double(PastRateTargetSeconds) / double(PastRateActualSeconds);
    }
    EventHorizonDeviation	= 1 + (0.7084 * pow((double(PastBlocksMass)/double(144)), -1.228));
    EventHorizonDeviationFast	= EventHorizonDeviation;
    EventHorizonDeviationSlow	= 1 / EventHorizonDeviation;

    if (PastBlocksMass >= PastBlocksMin) {
      if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) { assert(BlockReading); break; }
    }
    if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
    BlockReading = BlockReading->pprev;
  }

  CBigNum bnNew(PastDifficultyAverage);
  if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
    bnNew *= PastRateActualSeconds;
    bnNew /= PastRateTargetSeconds;
  }
  if (bnNew > bnProofOfWorkLimit) { bnNew = bnProofOfWorkLimit; }


#if 0
  /// debug print
  printf("Difficulty Retarget - Kimoto Gravity Well\n");
  printf("PastRateAdjustmentRatio = %g\n", PastRateAdjustmentRatio);
  printf("Before: %08x %s\n", BlockLastSolved->nBits, CBigNum().SetCompact(BlockLastSolved->nBits).getuint256().ToString().c_str());
  printf("After: %08x %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
#endif

  return bnNew.GetCompact();
}

unsigned int shc_GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlock *pblock)
{
  int nHeight = pindexLast->nHeight + 1;

  int64 nInterval;
  int64 nActualTimespanMax;
  int64 nActualTimespanMin;
  int64 nTargetTimespanCurrent;

  // Genesis block
  if (pindexLast == NULL)
    return (bnProofOfWorkLimit.GetCompact());

  static const int64	BlocksTargetSpacing	= 1.0 * 60; // 1.0 minutes
  unsigned int	TimeDaySeconds	= 60 * 60 * 24;
  int64	PastSecondsMin	= TimeDaySeconds * 0.10;
  int64	PastSecondsMax	= TimeDaySeconds * 2.8;
  uint64	PastBlocksMin	= PastSecondsMin / BlocksTargetSpacing;
  uint64	PastBlocksMax	= PastSecondsMax / BlocksTargetSpacing;	

  return KimotoGravityWell(pindexLast, pblock, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax);
}

int64 shc_GetBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = 4000 * COIN;
  int base = nHeight;

  base /= 9; /* 1.6tril cap. */

  nSubsidy >>= (base / 139604);

  /* reduces max coin cap to 320bil */
  nSubsidy /= 5;

  return nSubsidy + nFees;
}

CBlock* shc_CreateNewBlock(CReserveKey& reservekey)
{
  CBlockIndex* pindexPrev = pindexBest;

  // Create new block
  //auto_ptr<CBlock> pblock(new CBlock());
  auto_ptr<CBlock> pblock(new SHCBlock());
  if (!pblock.get())
    return NULL;

  // Create coinbase tx
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vin[0].prevout.SetNull();
  txNew.vout.resize(1);
  txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;

  // Add our coinbase tx as first transaction
  pblock->vtx.push_back(txNew);

  // Collect memory pool transactions into the block
  int64 nFees = 0;
  {
    LOCK2(cs_main, mempool.cs);
    CTxDB txdb("r");

    // Priority order to process transactions
    list<SHCOrphan> vOrphan; // list memory doesn't move
    map<uint256, vector<SHCOrphan*> > mapDependers;
    multimap<double, CTransaction*> mapPriority;
    for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
    {
      CTransaction& tx = (*mi).second;
      if (tx.IsCoinBase() || !tx.IsFinal())
        continue;

      SHCOrphan* porphan = NULL;
      double dPriority = 0;
      BOOST_FOREACH(const CTxIn& txin, tx.vin)
      {
        // Read prev transaction
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
        {
          // Has to wait for dependencies
          if (!porphan)
          {
            // Use list for automatic deletion
            vOrphan.push_back(SHCOrphan(&tx));
            porphan = &vOrphan.back();
          }
          mapDependers[txin.prevout.hash].push_back(porphan);
          porphan->setDependsOn.insert(txin.prevout.hash);
          continue;
        }
        int64 nValueIn = txPrev.vout[txin.prevout.n].nValue;

        // Read block header
        int nConf = txindex.GetDepthInMainChain();

        dPriority += (double)nValueIn * nConf;

        if (fDebug && GetBoolArg("-printpriority"))
          printf("priority     nValueIn=%-12"PRI64d" nConf=%-5d dPriority=%-20.1f\n", nValueIn, nConf, dPriority);
      }

      // Priority is sum(valuein * age) / txsize
      dPriority /= ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

      if (porphan)
        porphan->dPriority = dPriority;
      else
        mapPriority.insert(make_pair(-dPriority, &(*mi).second));

      if (fDebug && GetBoolArg("-printpriority"))
      {
        printf("priority %-20.1f %s\n%s", dPriority, tx.GetHash().ToString().substr(0,10).c_str(), tx.ToString().c_str());
        if (porphan)
          porphan->print();
        printf("\n");
      }
    }

    // Collect transactions into block
    map<uint256, CTxIndex> mapTestPool;
    uint64 nBlockSize = 1000;
    uint64 nBlockTx = 0;
    int nBlockSigOps = 100;
    while (!mapPriority.empty())
    {
      // Take highest priority transaction off priority queue
      double dPriority = -(*mapPriority.begin()).first;
      CTransaction& tx = *(*mapPriority.begin()).second;
      mapPriority.erase(mapPriority.begin());

      // Size limits
      unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
      if (nBlockSize + nTxSize >= MAX_BLOCK_SIZE_GEN)
        continue;

      // Legacy limits on sigOps:
      unsigned int nTxSigOps = tx.GetLegacySigOpCount();
      if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
        continue;

      // Transaction fee required depends on block size
      // shcd: Reduce the exempted free transactions to 500 bytes (from Bitcoin's 3000 bytes)
      bool fAllowFree = (nBlockSize + nTxSize < 1500 || CTransaction::AllowFree(dPriority));
      int64 nMinFee = tx.GetMinFee(nBlockSize, fAllowFree, GMF_BLOCK);

      // Connecting shouldn't fail due to dependency on other memory pool transactions
      // because we're already processing them in order of dependency
      map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
      MapPrevTx mapInputs;
      bool fInvalid;
      if (!tx.FetchInputs(txdb, mapTestPoolTmp, false, true, mapInputs, fInvalid))
        continue;

      int64 nTxFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
      if (nTxFees < nMinFee)
        continue;

      nTxSigOps += tx.GetP2SHSigOpCount(mapInputs);
      if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
        continue;

      if (!tx.ConnectInputs(mapInputs, mapTestPoolTmp, CDiskTxPos(1,1,1), pindexPrev, false, true))
        continue;
      mapTestPoolTmp[tx.GetHash()] = CTxIndex(CDiskTxPos(1,1,1), tx.vout.size());
      swap(mapTestPool, mapTestPoolTmp);

      // Added
      pblock->vtx.push_back(tx);
      nBlockSize += nTxSize;
      ++nBlockTx;
      nBlockSigOps += nTxSigOps;
      nFees += nTxFees;

      // Add transactions that depend on this one to the priority queue
      uint256 hash = tx.GetHash();
      if (mapDependers.count(hash))
      {
        BOOST_FOREACH(SHCOrphan* porphan, mapDependers[hash])
        {
          if (!porphan->setDependsOn.empty())
          {
            porphan->setDependsOn.erase(hash);
            if (porphan->setDependsOn.empty())
              mapPriority.insert(make_pair(-porphan->dPriority, porphan->ptx));
          }
        }
      }
    }

#if 0
    nLastBlockTx = nBlockTx;
    nLastBlockSize = nBlockSize;
    //printf("CreateNewBlock(): total size %lu\n", nBlockSize);
#endif

  }
  pblock->vtx[0].vout[0].nValue = shc_GetBlockValue(pindexPrev->nHeight+1, nFees);

  // Fill in header
  pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
  pblock->hashMerkleRoot = pblock->BuildMerkleTree();
  pblock->UpdateTime(pindexPrev);
  pblock->nBits          = shc_GetNextWorkRequired(pindexPrev, pblock.get());
  pblock->nNonce         = 0;

  return pblock.release();
}


