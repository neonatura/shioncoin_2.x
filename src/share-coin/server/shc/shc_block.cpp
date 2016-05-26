
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
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "ui_interface.h"
#include "shc_block.h"
#include "shc_wallet.h"
#include "shc_txidx.h"

#ifdef WIN32
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef fcntl
#undef fcntl
#endif


using namespace std;
using namespace boost;


uint256 shc_hashGenesisBlock("0xf4319e4e89b35b5f26ec0363a09d29703402f120cf1bf8e6f535548d5ec3c5cc");
static uint256 shc_hashGenesisMerkle("0xd3f4bbe7fe61bda819369b4cd3a828f3ad98d971dda0c20a466a9ce64846c321");
static CBigNum SHC_bnProofOfWorkLimit(~uint256(0) >> 20); // starting difficulty is 1 / 2^12

map<uint256, SHCBlock*> SHC_mapOrphanBlocks;
multimap<uint256, SHCBlock*> SHC_mapOrphanBlocksByPrev;
map<uint256, map<uint256, CDataStream*> > SHC_mapOrphanTransactionsByPrev;
map<uint256, CDataStream*> SHC_mapOrphanTransactions;

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

  if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64)BlockLastSolved->nHeight < PastBlocksMin) { return SHC_bnProofOfWorkLimit.GetCompact(); }

  int64 LatestBlockTime = BlockLastSolved->GetBlockTime();

  for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
    if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
    PastBlocksMass++;

    if (i == 1)	{ PastDifficultyAverage.SetCompact(BlockReading->nBits); }
    else	{ PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev; }
    PastDifficultyAveragePrev = PastDifficultyAverage;

    if (LatestBlockTime < BlockReading->GetBlockTime())
      LatestBlockTime = BlockReading->GetBlockTime();

    PastRateActualSeconds                   = LatestBlockTime - BlockReading->GetBlockTime();
    PastRateTargetSeconds	= TargetBlocksSpacingSeconds * PastBlocksMass;
    PastRateAdjustmentRatio	= double(1);

    if (PastRateActualSeconds < 1)
      PastRateActualSeconds = 1;

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
  if (bnNew > SHC_bnProofOfWorkLimit) { bnNew = SHC_bnProofOfWorkLimit; }


#if 0
  /// debug print
  printf("Difficulty Retarget - Kimoto Gravity Well\n");
  printf("PastRateAdjustmentRatio = %g\n", PastRateAdjustmentRatio);
  printf("Before: %08x %s\n", BlockLastSolved->nBits, CBigNum().SetCompact(BlockLastSolved->nBits).getuint256().ToString().c_str());
  printf("After: %08x %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
#endif

  return bnNew.GetCompact();
}

unsigned int SHCBlock::GetNextWorkRequired(const CBlockIndex* pindexLast)
{
  int nHeight = pindexLast->nHeight + 1;

  int64 nInterval;
  int64 nActualTimespanMax;
  int64 nActualTimespanMin;
  int64 nTargetTimespanCurrent;

  // Genesis block
  if (pindexLast == NULL)
    return (SHC_bnProofOfWorkLimit.GetCompact());

  static const int64	BlocksTargetSpacing	= 1.0 * 60; // 1.0 minutes
  unsigned int	TimeDaySeconds	= 60 * 60 * 24;
  int64	PastSecondsMin	= TimeDaySeconds * 0.10;
  int64	PastSecondsMax	= TimeDaySeconds * 2.8;
  uint64	PastBlocksMin	= PastSecondsMin / BlocksTargetSpacing;
  uint64	PastBlocksMax	= PastSecondsMax / BlocksTargetSpacing;	

  return KimotoGravityWell(pindexLast, this, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax);
}

int64 shc_GetBlockValue(int nHeight, int64 nFees)
{
  uint64 nSubsidy = 2000 * COIN;
  int base = nHeight;

  if (nHeight == 0) {
    /* burnt coins */
    nSubsidy = 4000 * COIN;
    base /= 9; /* 800bil cap. */
    nSubsidy >>= (base / 139604);
    nSubsidy /= 5;
    return ((int64)nSubsidy + nFees);
  }

  base /= 9; /* base on 800bil cap. */

  nSubsidy >>= (base / 139604);

  /* reduces max coin cap to 80bil */
  nSubsidy /= 10;

  return ((int64)nSubsidy + nFees);
}

namespace SHC_Checkpoints
{
  typedef std::map<int, uint256> MapCheckpoints;

  //
  // What makes a good checkpoint block?
  // + Is surrounded by blocks with reasonable timestamps
  //   (no blocks before with a timestamp after, none after with
  //    timestamp before)
  // + Contains no strange transactions
  //
  static MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    ( 0, uint256("0xf4319e4e89b35b5f26ec0363a09d29703402f120cf1bf8e6f535548d5ec3c5cc") )
    ( 320, uint256("0x97b2a43e1d7bfaebb947d8fe4d0615fe767040c0ef83deb5c3f7f62852184276") )

    ;


  bool CheckBlock(int nHeight, const uint256& hash)
  {
    if (fTestNet) return true; // Testnet has no checkpoints

    MapCheckpoints::const_iterator i = mapCheckpoints.find(nHeight);
    if (i == mapCheckpoints.end()) return true;
    return hash == i->second;
  }

  int GetTotalBlocksEstimate()
  {
    if (fTestNet) return 0;
    return mapCheckpoints.rbegin()->first;
  }

  CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
  {
    if (fTestNet) return NULL;

    BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, mapCheckpoints)
    {
      const uint256& hash = i.second;
      std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
      if (t != mapBlockIndex.end())
        return t->second;
    }
    return NULL;
  }

}

static bool shc_ConnectInputs(CTransaction *tx, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fStrictPayToScriptHash=true)
{

  if (tx->IsCoinBase())
    return (true);

  // Take over previous transactions' spent pointers
  // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
  // fMiner is true when called from the internal shc miner
  // ... both are false when called from CTransaction::AcceptToMemoryPool

  int64 nValueIn = 0;
  int64 nFees = 0;
  for (unsigned int i = 0; i < tx->vin.size(); i++)
  {
    COutPoint prevout = tx->vin[i].prevout;
    assert(inputs.count(prevout.hash) > 0);
    CTxIndex& txindex = inputs[prevout.hash].first;
    CTransaction& txPrev = inputs[prevout.hash].second;

    if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
      return error(SHERR_INVAL, "ConnectInputs() : %s prevout.n out of range %d %d %d prev tx %s\n%s", tx->GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str());

    // If prev is coinbase, check that it's matured
    if (txPrev.IsCoinBase())
      for (const CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < SHC_COINBASE_MATURITY; pindex = pindex->pprev)
        //if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
        if (pindex->nHeight == txindex.pos.nBlockPos)// && pindex->nFile == txindex.pos.nFile)
          return error(SHERR_INVAL, "ConnectInputs() : tried to spend coinbase at depth %d", pindexBlock->nHeight - pindex->nHeight);

    // Check for negative or overflow input values
    nValueIn += txPrev.vout[prevout.n].nValue;
    if (!MoneyRange(SHC_COIN_IFACE, txPrev.vout[prevout.n].nValue) || !MoneyRange(SHC_COIN_IFACE, nValueIn))
      return error(SHERR_INVAL, "ConnectInputs() : txin values out of range");

  }
  // The first loop above does all the inexpensive checks.
  // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
  // Helps prevent CPU exhaustion attacks.
  for (unsigned int i = 0; i < tx->vin.size(); i++)
  {
    COutPoint prevout = tx->vin[i].prevout;
    assert(inputs.count(prevout.hash) > 0);
    CTxIndex& txindex = inputs[prevout.hash].first;
    CTransaction& txPrev = inputs[prevout.hash].second;

    // Check for conflicts (double-spend)
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!txindex.vSpent[prevout.n].IsNull())
      return fMiner ? false : error(SHERR_INVAL, "ConnectInputs() : %s prev tx already used at %s", tx->GetHash().ToString().substr(0,10).c_str(), txindex.vSpent[prevout.n].ToString().c_str());

    // Skip ECDSA signature verification when connecting blocks (fBlock=true)
    // before the last blockchain checkpoint. This is safe because block merkle hashes are
    // still computed and checked, and any change will be caught at the next checkpoint.
    if (!(fBlock && (GetBestHeight(SHC_COIN_IFACE) < SHC_Checkpoints::GetTotalBlocksEstimate())))
    {
      // Verify signature
      if (!VerifySignature(txPrev, *tx, i, fStrictPayToScriptHash, 0))
      {
        // only during transition phase for P2SH: do not invoke anti-DoS code for
        // potentially old clients relaying bad P2SH transactions
        if (fStrictPayToScriptHash && VerifySignature(txPrev, *tx, i, false, 0))
          return error(SHERR_INVAL, "ConnectInputs() : %s P2SH VerifySignature failed", tx->GetHash().ToString().substr(0,10).c_str());

        return error(SHERR_INVAL, "ConnectInputs() : %s VerifySignature failed", tx->GetHash().ToString().substr(0,10).c_str());
      }
    }

    // Mark outpoints as spent
    txindex.vSpent[prevout.n] = posThisTx;

    // Write back
    if (fBlock || fMiner)
    {
      mapTestPool[prevout.hash] = txindex;
    }
  }

  if (nValueIn < tx->GetValueOut())
    return error(SHERR_INVAL, "ConnectInputs() : %s value in < value out", tx->GetHash().ToString().substr(0,10).c_str());

  // Tally transaction fees
  int64 nTxFee = nValueIn - tx->GetValueOut();
  if (nTxFee < 0)
    return error(SHERR_INVAL, "ConnectInputs() : %s nTxFee < 0", tx->GetHash().ToString().substr(0,10).c_str());
  nFees += nTxFee;
  if (!MoneyRange(SHC_COIN_IFACE, nFees))
    return error(SHERR_INVAL, "ConnectInputs() : nFees out of range");

  return true;
}

#if 0
bool shc_FetchInputs(CTransaction *tx, CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool, bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
{
  // FetchInputs can return false either because we just haven't seen some inputs
  // (in which case the transaction should be stored as an orphan)
  // or because the transaction is malformed (in which case the transaction should
  // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
  fInvalid = false;

  if (tx->IsCoinBase())
    return true; // Coinbase transactions have no inputs to fetch.

  for (unsigned int i = 0; i < tx->vin.size(); i++)
  {
    COutPoint prevout = tx->vin[i].prevout;
    if (inputsRet.count(prevout.hash))
      continue; // Got it already

    // Read txindex
    CTxIndex& txindex = inputsRet[prevout.hash].first;
    bool fFound = true;
    if ((fBlock || fMiner) && mapTestPool.count(prevout.hash))
    {
      // Get txindex from current proposed changes
      txindex = mapTestPool.find(prevout.hash)->second;
    }
    else
    {
      // Read txindex from txdb
      fFound = txdb.ReadTxIndex(prevout.hash, txindex);
    }
    if (!fFound && (fBlock || fMiner))
      return fMiner ? false : error(SHERR_INVAL, "FetchInputs() : %s prev tx %s index entry not found", tx->GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());

    // Read txPrev
    CTransaction& txPrev = inputsRet[prevout.hash].second;
    if (!fFound || txindex.pos == CDiskTxPos(0,0,0))
    {
      // Get prev tx from single transactions in memory
      {
        LOCK(SHCBlock::mempool.cs);
        if (!SHCBlock::mempool.exists(prevout.hash))
          return error(SHERR_INVAL, "FetchInputs() : %s SHCBlock::mempool Tx prev not found %s", tx->GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
        txPrev = SHCBlock::mempool.lookup(prevout.hash);
      }
      if (!fFound)
        txindex.vSpent.resize(txPrev.vout.size());
    }
    else
    {
      // Get prev tx from disk
      if (!txPrev.ReadFromDisk(txindex.pos))
        return error(SHERR_INVAL, "FetchInputs() : %s ReadFromDisk prev tx %s failed", tx->GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
    }
  }

  // Make sure all prevout.n's are valid:
  for (unsigned int i = 0; i < tx->vin.size(); i++)
  {
    const COutPoint prevout = tx->vin[i].prevout;
    assert(inputsRet.count(prevout.hash) != 0);
    const CTxIndex& txindex = inputsRet[prevout.hash].first;
    const CTransaction& txPrev = inputsRet[prevout.hash].second;
    if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
    {
      // Revisit this if/when transaction replacement is implemented and allows
      // adding inputs:
      fInvalid = true;
      return error(SHERR_INVAL, "FetchInputs() : %s prevout.n out of range %d %d %d prev tx %s\n%s", tx->GetHash().ToString().substr(0,10).c_str(), prevout.n, txPrev.vout.size(), txindex.vSpent.size(), prevout.hash.ToString().substr(0,10).c_str(), txPrev.ToString().c_str());
    }
  }

  return true;
}
#endif


CBlock* shc_CreateNewBlock(CReserveKey& reservekey)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  CBlockIndex* pindexPrev = GetBestBlockIndex(iface);

if (!pindexPrev) {
fprintf(stderr, "DEBUG: error: shc_CreateNewBlock: no Best Block Index established.\n");
return (NULL);
}

  // Create new block
  //auto_ptr<CBlock> pblock(new CBlock());
  auto_ptr<SHCBlock> pblock(new SHCBlock());
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
    LOCK2(cs_main, SHCBlock::mempool.cs);
    SHCTxDB txdb;

    // Priority order to process transactions
    list<SHCOrphan> vOrphan; // list memory doesn't move
    map<uint256, vector<SHCOrphan*> > mapDependers;
    multimap<double, CTransaction*> mapPriority;
    for (map<uint256, CTransaction>::iterator mi = SHCBlock::mempool.mapTx.begin(); mi != SHCBlock::mempool.mapTx.end(); ++mi)
    {
      CTransaction& tx = (*mi).second;
      if (tx.IsCoinBase() || !tx.IsFinal(SHC_COIN_IFACE))
        continue;

      SHCOrphan* porphan = NULL;
      double dPriority = 0;
      BOOST_FOREACH(const CTxIn& txin, tx.vin)
      {
        // Read prev transaction
        CTransaction txPrev;
        if (!txPrev.ReadTx(SHC_COIN_IFACE, txin.prevout.hash)) {
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
if (txPrev.vout.size() <= txin.prevout.n) {
fprintf(stderr, "DEBUG: shc_CreateNewBlock: txPrev.vout.size() %d <= txin.prevout.n %d [tx %s]\n", 
 txPrev.vout.size(),
 txin.prevout.n,
txPrev.GetHash().GetHex().c_str());
continue;
}
        int64 nValueIn = txPrev.vout[txin.prevout.n].nValue;

        // Read block header
        //int nConf = txindex.GetDepthInMainChain();
        int nConf = GetTxDepthInMainChain(iface, txPrev.GetHash());

        dPriority += (double)nValueIn * nConf;

        if (fDebug && GetBoolArg("-printpriority"))
          printf("priority     nValueIn=%-12"PRI64d" nConf=%-5d dPriority=%-20.1f\n", nValueIn, nConf, dPriority);
      }

      // Priority is sum(valuein * age) / txsize
      dPriority /= ::GetSerializeSize(tx, SER_NETWORK, SHC_PROTOCOL_VERSION);

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
      unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, SHC_PROTOCOL_VERSION);
      if (nBlockSize + nTxSize >= MAX_BLOCK_SIZE_GEN(iface))
        continue;

      // Legacy limits on sigOps:
      unsigned int nTxSigOps = tx.GetLegacySigOpCount();
      if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS(iface))
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
      if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS(iface))
        continue;

      if (!shc_ConnectInputs(&tx, mapInputs, mapTestPoolTmp, CDiskTxPos(0,0,0), pindexPrev, false, true))
        continue;
      mapTestPoolTmp[tx.GetHash()] = CTxIndex(CDiskTxPos(0,0,0), tx.vout.size());
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
  pblock->nBits          = pblock->GetNextWorkRequired(pindexPrev);
  pblock->nNonce         = 0;

  return pblock.release();
}

bool shc_CreateGenesisBlock()
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  bool ret;


  if (blockIndex->count(shc_hashGenesisBlock) != 0)
    return (true); /* already created */

#if 0
  if (!fAllowNew)
    return false;
#endif

  // Genesis block
  const char* pszTimestamp = "Neo Natura (share-coin) 2016";
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vout.resize(1);
  txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
  txNew.vout[0].nValue = shc_GetBlockValue(0, 0);
  txNew.vout[0].scriptPubKey = CScript() << ParseHex("04a5814813115273a109cff99907ba4a05d951873dae7acb6c973d0c9e7c88911a3dbc9aa600deac241b91707e7b4ffb30ad91c8e56e695a1ddf318592988afe0a") << OP_CHECKSIG;
  SHCBlock block;
  block.vtx.push_back(txNew);
  block.hashPrevBlock = 0;
  block.hashMerkleRoot = block.BuildMerkleTree();
  block.nVersion = SHCBlock::CURRENT_VERSION;
  block.nTime    = 1461974400; /* 04/30/16 12:00am */
  block.nBits    = 0x1e0ffff0;
  block.nNonce   = 3293840;


  assert(block.hashMerkleRoot == shc_hashGenesisMerkle);

#if 0
  // If genesis block hash does not match, then generate new genesis hash.
  if (block.GetHash() != shc_hashGenesisBlock)
  {
    printf("Searching for genesis block...\n");
    // This will figure out a valid hash and Nonce if you're
    // creating a different genesis block:
    uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
    uint256 thash;
    char scratchpad[SCRYPT_SCRATCHPAD_SIZE];

    block.nNonce--;
    loop
    {
      scrypt_1024_1_1_256_sp(BEGIN(block.nVersion), BEGIN(thash), scratchpad);
      if (thash <= hashTarget)
        break;
      if ((block.nNonce & 0xFFF) == 0)
      {
        printf("nonce %08X: hash = %s (target = %s)\n", block.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
      }
      ++block.nNonce;
      if (block.nNonce == 0)
      {
        printf("NONCE WRAPPED, incrementing time\n");
        ++block.nTime;
      }
    }
    fprintf(stderr, "block.nTime = %u \n", block.nTime);
    fprintf(stderr, "block.nNonce = %u \n", block.nNonce);
    fprintf(stderr, "block.GetHash = %s\n", block.GetHash().ToString().c_str());
    fprintf(stderr, "block.merkleRoot = %s\n", block.hashMerkleRoot.ToString().c_str());
  }
  shc_hashGenesisBlock = block.GetHash(); /* DEBUG: */
#endif

  block.print();
  assert(block.GetHash() == shc_hashGenesisBlock);

#if 0
  unsigned int nFile = 0;
  unsigned int nBlockPos = 0;
  // Start new block file
  if (!block.WriteToDisk(nFile, nBlockPos))
    return error(SHERR_INVAL, "LoadBlockIndex() : writing genesis block to disk failed");
  if (!block.AddToBlockIndex(nFile, nBlockPos))
    return error(SHERR_INVAL, "LoadBlockIndex() : genesis block not accepted");
#endif

  if (!block.WriteBlock(0)) {
    return (false);
  }

  ret = block.AddToBlockIndex();
  if (!ret) {
    return (false);
  }

CBlockIndex *pindex = (*blockIndex)[block.GetHash()];
if (!pindex) {
fprintf(stderr, "DEBUG: shc_CreateGenesisBlock: hash '%s' not found in block-index.\n", block.GetHash().GetHex().c_str()); 
  return (false);
}
SHCTxDB txdb;
block.SetBestChain(txdb, pindex);
txdb.Close();
/*
SetBestBlockIndex(iface, pindex); 
SetBestHeight(iface, 0);
*/


  return (true);
}

static bool shc_IsFromMe(CTransaction& tx)
{
  BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
    if (pwallet->IsFromMe(tx))
      return true;
  return false;
}

static void shc_EraseFromWallets(uint256 hash)
{
  BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
    pwallet->EraseFromWallet(hash);
}

bool SHC_CTxMemPool::accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs)
{
  if (pfMissingInputs)
    *pfMissingInputs = false;

  if (!tx.CheckTransaction(SHC_COIN_IFACE))
    return error(SHERR_INVAL, "CTxMemPool::accept() : CheckTransaction failed");

  // Coinbase is only valid in a block, not as a loose transaction
  if (tx.IsCoinBase())
    return tx.DoS(100, error(SHERR_INVAL, "CTxMemPool::accept() : coinbase as individual tx"));

  // To help v0.1.5 clients who would see it as a negative number
  if ((int64)tx.nLockTime > std::numeric_limits<int>::max())
    return error(SHERR_INVAL, "CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

  // Rather not work on nonstandard transactions (unless -testnet)
  if (!fTestNet && !tx.IsStandard())
    return error(SHERR_INVAL, "CTxMemPool::accept() : nonstandard transaction type");

  // Do we already have it?
  uint256 hash = tx.GetHash();
  {
    LOCK(cs);
    if (mapTx.count(hash))
      return false;
  }
  if (fCheckInputs)
    if (txdb.ContainsTx(hash))
      return false;

  // Check for conflicts with in-memory transactions
  CTransaction* ptxOld = NULL;
  for (unsigned int i = 0; i < tx.vin.size(); i++)
  {
    COutPoint outpoint = tx.vin[i].prevout;
    if (mapNextTx.count(outpoint))
    {
      // Disable replacement feature for now
      return false;

      // Allow replacing with a newer version of the same transaction
      if (i != 0)
        return false;
      ptxOld = mapNextTx[outpoint].ptx;
      if (ptxOld->IsFinal(SHC_COIN_IFACE))
        return false;
      if (!tx.IsNewerThan(*ptxOld))
        return false;
      for (unsigned int i = 0; i < tx.vin.size(); i++)
      {
        COutPoint outpoint = tx.vin[i].prevout;
        if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
          return false;
      }
      break;
    }
  }

  if (fCheckInputs)
  {
    MapPrevTx mapInputs;
    map<uint256, CTxIndex> mapUnused;
    bool fInvalid = false;
    if (!tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
    {
      if (fInvalid)
        return error(SHERR_INVAL, "CTxMemPool::accept() : FetchInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
      if (pfMissingInputs)
        *pfMissingInputs = true;
      return false;
    }

    // Check for non-standard pay-to-script-hash in inputs
    if (!tx.AreInputsStandard(mapInputs) && !fTestNet)
      return error(SHERR_INVAL, "CTxMemPool::accept() : nonstandard transaction input");

    // Note: if you modify this code to accept non-standard transactions, then
    // you should add code here to check that the transaction does a
    // reasonable number of ECDSA signature verifications.

    int64 nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
    unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, SHC_PROTOCOL_VERSION);

    // Don't accept it if it can't get into a block
    if (nFees < tx.GetMinFee(1000, true, GMF_RELAY))
      return error(SHERR_INVAL, "CTxMemPool::accept() : not enough fees");

    // Continuously rate-limit free transactions
    // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
    // be annoying or make other's transactions take longer to confirm.
    if (nFees < SHC_MIN_RELAY_TX_FEE)
    {
      static CCriticalSection cs;
      static double dFreeCount;
      static int64 nLastTime;
      int64 nNow = GetTime();

      {
        LOCK(cs);
        // Use an exponentially decaying ~10-minute window:
        dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
        nLastTime = nNow;
        // -limitfreerelay unit is thousand-bytes-per-minute
        // At default rate it would take over a month to fill 1GB
        if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000 && !shc_IsFromMe(tx))
          return error(SHERR_INVAL, "CTxMemPool::accept() : free transaction rejected by rate limiter");
        Debug("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
        dFreeCount += nSize;
      }
    }

    // Check against previous transactions
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.
    if (!shc_ConnectInputs(&tx, mapInputs, mapUnused, CDiskTxPos(0,0,0), GetBestBlockIndex(SHC_COIN_IFACE), false, false)) {
      return error(SHERR_INVAL, "CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
    }
  }

  // Store transaction in memory
  {
    LOCK(cs);
    if (ptxOld)
    {
      Debug("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
      remove(*ptxOld);
    }
    addUnchecked(hash, tx);
  }

  ///// are we sure this is ok when loading transactions or restoring block txes
  // If updated, erase old tx from wallet
  if (ptxOld)
    shc_EraseFromWallets(ptxOld->GetHash());

  Debug("CTxMemPool::accept() : accepted %s (poolsz %u)\n",
      hash.ToString().substr(0,10).c_str(),
      mapTx.size());
  return true;
}

bool SHC_CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);

  // Add to memory pool without checking anything.  Don't call this directly,
  // call CTxMemPool::accept to properly check the transaction first.
  {
    mapTx[hash] = tx;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
      mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
    iface->tx_tot++;
  }
  return true;
}


bool SHC_CTxMemPool::remove(CTransaction &tx)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  // Remove transaction from memory pool
  {
    LOCK(cs);
    uint256 hash = tx.GetHash();
    if (mapTx.count(hash))
    {
      BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapNextTx.erase(txin.prevout);
      mapTx.erase(hash);
      iface->tx_tot++;
    }
  }
  return true;
}

void SHC_CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}



#if 0
bool shc_InitBlockIndex()
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  SHCTxDB txdb;

  /* load attributes */
  if (!txdb.ReadHashBestChain(SHC_hashBestChain))
  {
    if (SHC_pindexGenesisBlock == NULL)
      return true;
    return error(SHERR_IO, "SHCTxDB::LoadBlockIndex() : hashBestChain not loaded");
  }

  if (!blockIndex->count(SHC_hashBestChain))
    return error(SHERR_IO, "SHCTxDB::LoadBlockIndex() : hashBestChain not found in the block index");

  SHC_pindexBest = (*blockIndex)[SHC_hashBestChain];
  SHC_nBestHeight = SHC_pindexBest->nHeight;
  SHCBlock::bnBestChainWork = SHC_pindexBest->bnChainWork;
  txdb.ReadBestInvalidWork(SHCBlock::bnBestInvalidWork);

  txdb.Close();

  /* verify */
  int nCheckDepth = 2500;
  if (nCheckDepth > SHC_nBestHeight)
    nCheckDepth = SHC_nBestHeight;

  CBlockIndex* pindexFork = NULL;
  map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
  for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
  {
    if (pindex->nHeight < SHC_nBestHeight-nCheckDepth)
      break;

    CBlock *block = GetBlockByHash(iface, pindex->GetBlockHash());
    if (!block)
      return error(SHERR_IO, "LoadBlockIndex() : block.ReadFromDisk failed");

    if (!block->CheckBlock())
    {
      printf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
      pindexFork = pindex->pprev;
    }

  }

  /* establish best chain */
  if (pindexFork) {
    CBlock *block = GetBlockByHash(iface, pindexFork->GetBlockHash());
    if (!block)
      return error(SHERR_IO, "LoadBlockIndex() : block.ReadFromDisk failed");
    SHCTxDB txdb;
    block->SetBestChain(txdb, pindexFork);
    txdb.Close();
  }

  return (true);
}
#endif



uint256 shc_GetOrphanRoot(const CBlock* pblock)
{

  // Work back to the first block in the orphan chain
  while (SHC_mapOrphanBlocks.count(pblock->hashPrevBlock))
    pblock = SHC_mapOrphanBlocks[pblock->hashPrevBlock];
  return pblock->GetHash();

}

// minimum amount of work that could possibly be required nTime after
// minimum work required was nBase
//
static unsigned int shc_ComputeMinWork(unsigned int nBase, int64 nTime)
{
  static int64 nTargetTimespan = 2 * 60 * 60;
  static int64 nTargetSpacing = 60;

  CBigNum bnResult;
  bnResult.SetCompact(nBase);
  while (nTime > 0 && bnResult < SHC_bnProofOfWorkLimit)
  {
    // Maximum 136% adjustment...
    bnResult = (bnResult * 75) / 55; 
    // ... in best-case exactly 4-times-normal target time
    nTime -= nTargetTimespan*4;
  }
  if (bnResult > SHC_bnProofOfWorkLimit)
    bnResult = SHC_bnProofOfWorkLimit;
  return bnResult.GetCompact();
}

bool shc_ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  int ifaceIndex = SHC_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  shtime_t ts;

  // Check for duplicate
  uint256 hash = pblock->GetHash();
  if (blockIndex->count(hash))
    return Debug("ProcessBlock() : already have block %d %s", (*blockIndex)[hash]->nHeight, hash.ToString().substr(0,20).c_str());
  if (SHC_mapOrphanBlocks.count(hash))
    return Debug("ProcessBlock() : already have block (orphan) %s", hash.ToString().substr(0,20).c_str());

  // Preliminary checks
  if (!pblock->CheckBlock()) {
    return error(SHERR_INVAL, "ProcessBlock() : CheckBlock FAILED");
  }

  CBlockIndex* pcheckpoint = SHC_Checkpoints::GetLastCheckpoint(*blockIndex);
  if (pcheckpoint && pblock->hashPrevBlock != GetBestBlockChain(iface)) {
    // Extra checks to prevent "fill up memory by spamming with bogus blocks"
    int64 deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
    if (deltaTime < 0)
    {
      if (pfrom)
        pfrom->Misbehaving(100);
      return error(SHERR_INVAL, "ProcessBlock() : block with timestamp before last checkpoint");
    }
    CBigNum bnNewBlock;
    bnNewBlock.SetCompact(pblock->nBits);
    CBigNum bnRequired;
    bnRequired.SetCompact(shc_ComputeMinWork(pcheckpoint->nBits, deltaTime));
    if (bnNewBlock > bnRequired)
    {
      if (pfrom)
        pfrom->Misbehaving(100);
      return error(SHERR_INVAL, "ProcessBlock() : block with too little proof-of-work");
    }
  }


  // If don't already have its previous block, shunt it off to holding area until we get it
  if (!blockIndex->count(pblock->hashPrevBlock))
  {
    Debug("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,20).c_str());
    //CBlock* pblock2 = new CBlock(*pblock);
    SHCBlock* pblock2 = new SHCBlock(*pblock);
    SHC_mapOrphanBlocks.insert(make_pair(hash, pblock2));
    SHC_mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

    /* request missing blocks */
    if (pfrom)
      pfrom->PushGetBlocks(GetBestBlockIndex(SHC_COIN_IFACE), shc_GetOrphanRoot(pblock2));
    iface->net_invalid = time(NULL);
    return true;
  }

  // Store to disk

  timing_init("AcceptBlock", &ts);
  if (!pblock->AcceptBlock()) {
    return error(SHERR_INVAL, "ProcessBlock() : AcceptBlock FAILED");
  }
  timing_term("AcceptBlock", &ts);
  iface->net_valid = time(NULL);

  // Recursively process any orphan blocks that depended on this one
  vector<uint256> vWorkQueue;
  vWorkQueue.push_back(hash);
  for (unsigned int i = 0; i < vWorkQueue.size(); i++)
  {
    uint256 hashPrev = vWorkQueue[i];
    for (multimap<uint256, SHCBlock*>::iterator mi = SHC_mapOrphanBlocksByPrev.lower_bound(hashPrev);
        mi != SHC_mapOrphanBlocksByPrev.upper_bound(hashPrev);
        ++mi)
    {
      CBlock* pblockOrphan = (*mi).second;
      if (pblockOrphan->AcceptBlock())
        vWorkQueue.push_back(pblockOrphan->GetHash());

      SHC_mapOrphanBlocks.erase(pblockOrphan->GetHash());

      delete pblockOrphan;
    }
    SHC_mapOrphanBlocksByPrev.erase(hashPrev);
  }

  return true;
}

bool shc_CheckProofOfWork(uint256 hash, unsigned int nBits)
{
  CBigNum bnTarget;
  bnTarget.SetCompact(nBits);

  // Check range
  if (bnTarget <= 0 || bnTarget > SHC_bnProofOfWorkLimit)
    return error(SHERR_INVAL, "CheckProofOfWork() : nBits below minimum work");

  // Check proof of work matches claimed amount
  if (hash > bnTarget.getuint256())
    return error(SHERR_INVAL, "CheckProofOfWork() : hash doesn't match nBits");

  return true;
}

/**
 * @note These are checks that are independent of context that can be verified before saving an orphan block.
 */
bool SHCBlock::CheckBlock()
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);

#if 0
  if (vtx[0].GetValueOut() > shc_GetBlockValue(nHeight, nFees)) {
    return (false);
  }
#endif

#if 0
  // Size limits
  if (vtx.empty() || 
      vtx.size() > MAX_BLOCK_SIZE || Block::GetSerializeSize(*block, SER_NETWORK, SHC_PROTOCOL_VERSION) > MAX_BLOCK_SIZE) {
    return error(SHERR_INVAL, "CheckBlock() : size limits failed");
  }
#endif
  if (vtx.empty() || !vtx[0].IsCoinBase())
    return error(SHERR_INVAL, "CheckBlock() : first tx is not coinbase");

  // Check proof of work matches claimed amount
  if (!shc_CheckProofOfWork(GetPoWHash(), nBits)) {
    return error(SHERR_INVAL, "CheckBlock() : proof of work failed");
  }

  // Check timestamp
  if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60) {
    return error(SHERR_INVAL, "CheckBlock() : block timestamp too far in the future");
  }

  for (unsigned int i = 1; i < vtx.size(); i++)
    if (vtx[i].IsCoinBase()) {
      return error(SHERR_INVAL, "CheckBlock() : more than one coinbase");
    }

  // Check transactions
  BOOST_FOREACH(const CTransaction& tx, vtx)
    if (!tx.CheckTransaction(SHC_COIN_IFACE)) {
      return error(SHERR_INVAL, "CheckBlock() : CheckTransaction failed");
    }

  // Check for duplicate txids. This is caught by ConnectInputs(),
  // but catching it earlier avoids a potential DoS attack:
  set<uint256> uniqueTx;
  BOOST_FOREACH(const CTransaction& tx, vtx)
  {
    uniqueTx.insert(tx.GetHash());
  }
  if (uniqueTx.size() != vtx.size()) {
    return error(SHERR_INVAL, "CheckBlock() : duplicate transaction");
  }

  unsigned int nSigOps = 0;
  BOOST_FOREACH(const CTransaction& tx, vtx)
  {
    nSigOps += tx.GetLegacySigOpCount();
  }
  if (nSigOps > MAX_BLOCK_SIGOPS(iface)) {
    return error(SHERR_INVAL, "CheckBlock() : out-of-bounds SigOpCount");
  }

  // Check merkleroot
  if (hashMerkleRoot != BuildMerkleTree()) {
    return error(SHERR_INVAL, "CheckBlock() : hashMerkleRoot mismatch");
  }

  return true;
}







bool static SHC_Reorganize(CTxDB& txdb, CBlockIndex* pindexNew, SHC_CTxMemPool *mempool)
{
  unet_log(txdb.ifaceIndex, "REORGANIZE\n");

  // Find the fork
  CBlockIndex* pfork = GetBestBlockIndex(SHC_COIN_IFACE);
  CBlockIndex* plonger = pindexNew;
  while (pfork != plonger)
  {
    while (plonger->nHeight > pfork->nHeight)
      if (!(plonger = plonger->pprev))
        return error(SHERR_INVAL, "Reorganize() : plonger->pprev is null");
    if (pfork == plonger)
      break;
    if (!(pfork = pfork->pprev))
      return error(SHERR_INVAL, "Reorganize() : pfork->pprev is null");
  }

  // List of what to disconnect
  CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);
  vector<CBlockIndex*> vDisconnect;
  for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
    vDisconnect.push_back(pindex);

  // List of what to connect
  vector<CBlockIndex*> vConnect;
  for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
    vConnect.push_back(pindex);
  reverse(vConnect.begin(), vConnect.end());

  //unet_log(txdb.ifaceIndex, "REORGANIZE: Disconnect %i blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
  //unet_log(txdb.ifaceIndex, "REORGANIZE: Connect %i blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

  // Disconnect shorter branch
  vector<CTransaction> vResurrect;
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
  {
    SHCBlock block;
    if (!block.ReadFromDisk(pindex))
      return error(SHERR_IO, "Reorganize() : ReadFromDisk for disconnect failed");
    if (!block.DisconnectBlock(txdb, pindex))
      return error(SHERR_INVAL, "Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

    // Queue memory transactions to resurrect
    BOOST_FOREACH(const CTransaction& tx, block.vtx)
      if (!tx.IsCoinBase())
        vResurrect.push_back(tx);
  }

  // Connect longer branch
  vector<CTransaction> vDelete;
  for (unsigned int i = 0; i < vConnect.size(); i++)
  {
    CBlockIndex* pindex = vConnect[i];
    SHCBlock block;
    if (!block.ReadFromDisk(pindex))
      return error(SHERR_INVAL, "Reorganize() : ReadFromDisk for connect failed");
    if (!block.ConnectBlock(txdb, pindex))
    {
      // Invalid block
      return error(SHERR_INVAL, "Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
    }

    // Queue memory transactions to delete
    BOOST_FOREACH(const CTransaction& tx, block.vtx)
      vDelete.push_back(tx);
  }
  if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
    return error(SHERR_INVAL, "Reorganize() : WriteHashBestChain failed");

  // Make sure it's successfully written to disk before changing memory structure
  if (!txdb.TxnCommit())
    return error(SHERR_INVAL, "Reorganize() : TxnCommit failed");

  // Disconnect shorter branch
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    if (pindex->pprev)
      pindex->pprev->pnext = NULL;

  // Connect longer branch
  BOOST_FOREACH(CBlockIndex* pindex, vConnect)
    if (pindex->pprev)
      pindex->pprev->pnext = pindex;

  // Resurrect memory transactions that were in the disconnected branch
  BOOST_FOREACH(CTransaction& tx, vResurrect)
    tx.AcceptToMemoryPool(txdb, false);

  // Delete redundant memory transactions that are in the connected branch
  BOOST_FOREACH(CTransaction& tx, vDelete)
    mempool->remove(tx);

  unet_log(txdb.ifaceIndex, "REORGANIZE: done\n");

  return true;
}

void SHCBlock::InvalidChainFound(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  char errbuf[1024];

  if (pindexNew->bnChainWork > bnBestInvalidWork)
  {
    bnBestInvalidWork = pindexNew->bnChainWork;
    SHCTxDB txdb;
    txdb.WriteBestInvalidWork(bnBestInvalidWork);
    txdb.Close();
    //    uiInterface.NotifyBlocksChanged();
  }

  
  sprintf(errbuf, "SHC: InvalidChainFound: invalid block=%s  height=%d  work=%s  date=%s\n", pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight, pindexNew->bnChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
  unet_log(SHC_COIN_IFACE, errbuf);

  CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);

  fprintf(stderr, "critical: InvalidChainFound:  current best=%s  height=%d  work=%s  date=%s\n", GetBestBlockChain(iface).ToString().substr(0,20).c_str(), GetBestHeight(SHC_COIN_IFACE), bnBestChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());
  if (pindexBest && bnBestInvalidWork > bnBestChainWork + pindexBest->GetBlockWork() * 6)
    unet_log(SHC_COIN_IFACE, "InvalidChainFound: WARNING: Displayed transactions may not be correct!  You may need to upgrade, or other nodes may need to upgrade.\n");
}

bool SHCBlock::SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew)
{
  uint256 hash = GetHash();
  bc_t *bc = GetBlockChain(GetCoinByIndex(SHC_COIN_IFACE));

  if ((bc_idx_next(bc)-1) != pindexNew->nHeight) {
fprintf(stderr, "DEBUG: SHCBlock::SetBestChainInner: warning: next blockchain db height (%d) != new block index height (%d)\n", (int)bc_idx_next(bc), (int)pindexNew->nHeight); 
}

  // Adding to current best branch
  if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
  {
fprintf(stderr, "DEBUG: SHCBlock::SetBestChainInner: error connecting block.\n");
/* truncate block-chain to failed block height. */
// bc_truncate(bc, pindexNew->nHeight);
    txdb.TxnAbort();
    InvalidChainFound(pindexNew);
    return false;
  }
  if (!txdb.TxnCommit())
    return error(SHERR_IO, "SetBestChain() : TxnCommit failed");

  // Add to current best branch
  pindexNew->pprev->pnext = pindexNew;

  // Delete redundant memory transactions
  BOOST_FOREACH(CTransaction& tx, vtx)
    mempool.remove(tx);

  return true;
}

// notify wallets about a new best chain
void static SHC_SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}


bool SHCBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  uint256 hash = GetHash();

  if (!txdb.TxnBegin())
    return error(SHERR_INVAL, "SetBestChain() : TxnBegin failed");

  if (SHCBlock::pindexGenesisBlock == NULL && hash == shc_hashGenesisBlock)
  {
    txdb.WriteHashBestChain(hash);
    if (!txdb.TxnCommit())
      return error(SHERR_INVAL, "SetBestChain() : TxnCommit failed");
    SHCBlock::pindexGenesisBlock = pindexNew;
  }
  else if (hashPrevBlock == GetBestBlockChain(iface))
  {
    if (!SetBestChainInner(txdb, pindexNew))
      return error(SHERR_INVAL, "SetBestChain() : SetBestChainInner failed");
  }
  else
  {
    // the first block in the new chain that will cause it to become the new best chain
    CBlockIndex *pindexIntermediate = pindexNew;

    // list of blocks that need to be connected afterwards
    std::vector<CBlockIndex*> vpindexSecondary;

    // Reorganize is costly in terms of db load, as it works in a single db transaction.
    // Try to limit how much needs to be done inside
    
    while (pindexIntermediate->pprev && pindexIntermediate->pprev->bnChainWork > GetBestBlockIndex(SHC_COIN_IFACE)->bnChainWork)
    {
      vpindexSecondary.push_back(pindexIntermediate);
      pindexIntermediate = pindexIntermediate->pprev;
    }

    if (!vpindexSecondary.empty())
      Debug("Postponing %i reconnects\n", vpindexSecondary.size());

    // Switch to new best branch
    if (!SHC_Reorganize(txdb, pindexIntermediate, &mempool))
    {
fprintf(stderr, "DEBUG: SHC_Reorganize(): error reorganizing.\n");
      txdb.TxnAbort();
      InvalidChainFound(pindexNew);
      return error(SHERR_INVAL, "SetBestChain() : Reorganize failed");
    }

    // Connect futher blocks
    BOOST_REVERSE_FOREACH(CBlockIndex *pindex, vpindexSecondary)
    {
      SHCBlock block;
      if (!block.ReadFromDisk(pindex))
      {
        error(SHERR_IO, "SetBestChain() : ReadFromDisk failed\n");
        break;
      }
      if (!txdb.TxnBegin()) {
        error(SHERR_INVAL, "SetBestChain() : TxnBegin 2 failed\n");
        break;
      }
      // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
      if (!block.SetBestChainInner(txdb, pindex))
        break;
    }
  }

  // Update best block in wallet (so we can detect restored wallets)
  bool fIsInitialDownload = IsInitialBlockDownload(SHC_COIN_IFACE);
  if (!fIsInitialDownload)
  {
    const CBlockLocator locator(SHC_COIN_IFACE, pindexNew);
    SHC_SetBestChain(locator);
  }

  // New best block
//  SHCBlock::hashBestChain = hash;
  SetBestBlockIndex(SHC_COIN_IFACE, pindexNew);
 // SetBestHeight(iface, pindexNew->nHeight);
  bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();
  iface->tx_tot++;

  //    Debug("SetBestChain: new best=%s  height=%d  work=%s  date=%s\n", hashBestChain.ToString().substr(0,20).c_str(), nBestHeight, bnBestChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S", SHCBlock::pindexBest->GetBlockTime()).c_str());

  // Check the version of the last 100 blocks to see if we need to upgrade:
  if (!fIsInitialDownload)
  {
    int nUpgraded = 0;
    const CBlockIndex* pindex = GetBestBlockIndex(SHC_COIN_IFACE);
    for (int i = 0; i < 100 && pindex != NULL; i++)
    {
      if (pindex->nVersion > CURRENT_VERSION)
        ++nUpgraded;
      pindex = pindex->pprev;
    }
    if (nUpgraded > 0)
      Debug("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, CURRENT_VERSION);
    //        if (nUpgraded > 100/2)
    // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
    //            strMiscWarning = _("Warning: this version is obsolete, upgrade required");
  }

  std::string strCmd = GetArg("-blocknotify", "");

  if (!fIsInitialDownload && !strCmd.empty())
  {
    boost::replace_all(strCmd, "%s", GetBestBlockChain(iface).GetHex());
    boost::thread t(runCommand, strCmd); // thread runs free
  }

  return true;
}


bool SHCBlock::IsBestChain()
{
  CBlockIndex *pindexBest = GetBestBlockIndex(SHC_COIN_IFACE);
  return (pindexBest && GetHash() == pindexBest->GetBlockHash());
}

bool shc_AcceptBlock(SHCBlock *pblock)
{
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  int ifaceIndex = SHC_COIN_IFACE;
  NodeList &vNodes = GetNodeList(ifaceIndex);
  bc_t *bc = GetBlockChain(GetCoinByIndex(ifaceIndex));
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
  shtime_t ts;
  bool ret;

  uint256 hash = pblock->GetHash();
  if (blockIndex->count(hash)) {
    return error(SHERR_INVAL, "SHCBlock::AcceptBlock() : block already in block table.");
  }
  if (0 == bc_find(bc, hash.GetRaw(), NULL)) {
    return error(SHERR_INVAL, "AcceptBlock() : block already in block table.");
  }

  // Get prev block index
  map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(pblock->hashPrevBlock);
  if (mi == blockIndex->end())
    return error(SHERR_INVAL, "AcceptBlock() : prev block not found");
  CBlockIndex* pindexPrev = (*mi).second;
  int nHeight = pindexPrev->nHeight+1;

  // Check proof of work
  if (pblock->nBits != pblock->GetNextWorkRequired(pindexPrev)) {
    return error(SHERR_INVAL, "AcceptBlock() : incorrect proof of work");
  }

  if (!CheckDiskSpace(::GetSerializeSize(*pblock, SER_DISK, CLIENT_VERSION))) {
    return error(SHERR_IO, "AcceptBlock() : out of disk space");
  }

  // Check timestamp against prev
  if (pblock->GetBlockTime() <= pindexPrev->GetMedianTimePast()) {
    return error(SHERR_INVAL, "AcceptBlock() : block's timestamp is too early");
  }

  // Check that all transactions are finalized
  BOOST_FOREACH(const CTransaction& tx, pblock->vtx)
    if (!tx.IsFinal(SHC_COIN_IFACE, nHeight, pblock->GetBlockTime())) {
      return error(SHERR_INVAL, "AcceptBlock() : contains a non-final transaction");
    }

  // Check that the block chain matches the known block chain up to a checkpoint
  if (!SHC_Checkpoints::CheckBlock(nHeight, hash)) {
    return error(SHERR_INVAL, "AcceptBlock() : rejected by checkpoint lockin at %d", nHeight);
  }

  if (!pblock->WriteBlock(nHeight)) {
    return error(SHERR_INVAL, "SHC: AcceptBlock(): error writing block to height %d", nHeight);
  }

  ret = pblock->AddToBlockIndex();
  if (!ret) {
    return error(SHERR_IO, "AcceptBlock() : AddToBlockIndex failed");
  }

  /* Relay inventory, but don't relay old inventory during initial block download */
  int nBlockEstimate = SHC_Checkpoints::GetTotalBlocksEstimate();
  if (GetBestBlockChain(iface) == hash)
  {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
      if (GetBestHeight(SHC_COIN_IFACE) > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
        pnode->PushInventory(CInv(ifaceIndex, MSG_BLOCK, hash));
  }

  return true;
}

bool SHCBlock::AcceptBlock()
{
  bool ret = shc_AcceptBlock(this);
  if (!ret)
    return (false);

  /* Recursively process any orphan blocks that depended on this one */
  uint256 hash = GetHash();
  vector<uint256> vWorkQueue;
  vWorkQueue.push_back(hash);
  for (unsigned int i = 0; i < vWorkQueue.size(); i++)
  {
    uint256 hashPrev = vWorkQueue[i];
    for (multimap<uint256, SHCBlock*>::iterator mi = SHC_mapOrphanBlocksByPrev.lower_bound(hashPrev);
        mi != SHC_mapOrphanBlocksByPrev.upper_bound(hashPrev);
        ++mi)
    {
      SHCBlock* pblockOrphan = (*mi).second;
      if (shc_AcceptBlock(pblockOrphan))
        vWorkQueue.push_back(pblockOrphan->GetHash());
      SHC_mapOrphanBlocks.erase(pblockOrphan->GetHash());
      delete pblockOrphan;
    }
    SHC_mapOrphanBlocksByPrev.erase(hashPrev);
  }

  return true;
}

CScript SHCBlock::GetCoinbaseFlags()
{
  return (SHC_COINBASE_FLAGS);
}

static void shc_UpdatedTransaction(const uint256& hashTx)
{
  BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
    pwallet->UpdatedTransaction(hashTx);
}

bool SHCBlock::AddToBlockIndex()
{
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  shtime_t ts;

  // Check for duplicate
  uint256 hash = GetHash();
  if (blockIndex->count(hash))
    return error(SHERR_INVAL, "AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());

  // Construct new block index object
  CBlockIndex* pindexNew = new CBlockIndex(*this);
  if (!pindexNew)
    return error(SHERR_INVAL, "AddToBlockIndex() : new CBlockIndex failed");
  map<uint256, CBlockIndex*>::iterator mi = blockIndex->insert(make_pair(hash, pindexNew)).first;
  pindexNew->phashBlock = &((*mi).first);
  map<uint256, CBlockIndex*>::iterator miPrev = blockIndex->find(hashPrevBlock);
  if (miPrev != blockIndex->end())
  {
    pindexNew->pprev = (*miPrev).second;
    pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
  }
  pindexNew->bnChainWork = (pindexNew->pprev ? pindexNew->pprev->bnChainWork : 0) + pindexNew->GetBlockWork();

  SHCTxDB txdb;
#if 0
  if (!txdb.TxnBegin())
    return false;
  txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
  if (!txdb.TxnCommit())
    return false;
#endif

  // New best
  if (pindexNew->bnChainWork > bnBestChainWork) {
    if (!SetBestChain(txdb, pindexNew)) {
fprintf(stderr, "DEBUG: AddToBlockIndex: SetBestChain failure @ height %d\n", pindexNew->nHeight); 
      return false;
}
  }

  txdb.Close();
fprintf(stderr, "DEBUG: CBlock::AddToBlockIndex: txdb saved @ nHeight(%d)\n", pindexNew->nHeight);

  if (pindexNew == GetBestBlockIndex(SHC_COIN_IFACE))
  {
    // Notify UI to display prev block's coinbase if it was ours
    static uint256 hashPrevBestCoinBase;
    shc_UpdatedTransaction(hashPrevBestCoinBase);
    hashPrevBestCoinBase = vtx[0].GetHash();
  }

  return true;
}

bool SHCBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{

  /* redundant */
  if (!CheckBlock())
    return false;

  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  bc_t *bc = GetBlockTxChain(iface);
  unsigned int nFile = SHC_COIN_IFACE;
  unsigned int nBlockPos = pindex->nHeight;;
  bc_hash_t b_hash;
  int err;

fprintf(stderr, "DEBUG: SHCBlock::ConnectBlock: nHeight(%d) hash(%s)\n", pindex->nHeight, pindex->GetBlockHash().GetHex().c_str());


  // Do not allow blocks that contain transactions which 'overwrite' older transactions,
  // unless those are already completely spent.
  // If such overwrites are allowed, coinbases and transactions depending upon those
  // can be duplicated to remove the ability to spend the first instance -- even after
  // being sent to another address.
  // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
  // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
  // already refuses previously-known transaction id's entirely.
  // This rule applies to all blocks whose timestamp is after October 1, 2012, 0:00 UTC.
  int64 nBIP30SwitchTime = 1349049600;
  bool fEnforceBIP30 = (pindex->nTime > nBIP30SwitchTime);

  // BIP16 didn't become active until October 1 2012
  int64 nBIP16SwitchTime = 1349049600;
  bool fStrictPayToScriptHash = (pindex->nTime >= nBIP16SwitchTime);

  map<uint256, CTxIndex> mapQueuedChanges;
  int64 nFees = 0;
  unsigned int nSigOps = 0;
  BOOST_FOREACH(CTransaction& tx, vtx)
  {
    uint256 hashTx = tx.GetHash();
    int nTxPos;

    if (fEnforceBIP30) {
      CTxIndex txindexOld;
      if (txdb.ReadTxIndex(hashTx, txindexOld)) {
        BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent)
          if (pos.IsNull()) {
fprintf(stderr, "DEBUG: SHCBlock::ConnectBlock: null disk pos, ret false\n");
            return false;
          }
      }
    }

    nSigOps += tx.GetLegacySigOpCount();
    if (nSigOps > MAX_BLOCK_SIGOPS(iface))
      return error(SHERR_INVAL, "ConnectBlock() : too many sigops");

    memcpy(b_hash, tx.GetHash().GetRaw(), sizeof(bc_hash_t));
    err = bc_find(bc, b_hash, &nTxPos); 
    if (err) {
      return error(SHERR_INVAL, "SHCBlock::ConncetBlock: error finding tx hash.");
    }

    MapPrevTx mapInputs;
    CDiskTxPos posThisTx(SHC_COIN_IFACE, nBlockPos, nTxPos);
    if (!tx.IsCoinBase())
    {
      bool fInvalid;
      if (!tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid)) {
fprintf(stderr, "DEBUG: SHCBlock::ConnectBlock: shc_FetchInputs()\n"); 
        return false;
      }

      if (fStrictPayToScriptHash)
      {
        // Add in sigops done by pay-to-script-hash inputs;
        // this is to prevent a "rogue miner" from creating
        // an incredibly-expensive-to-validate block.
        nSigOps += tx.GetP2SHSigOpCount(mapInputs);
        if (nSigOps > MAX_BLOCK_SIGOPS(iface)) {
          return error(SHERR_INVAL, "ConnectBlock() : too many sigops");
        }
      }

      nFees += tx.GetValueIn(mapInputs)-tx.GetValueOut();

      if (!shc_ConnectInputs(&tx, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fStrictPayToScriptHash)) {
fprintf(stderr, "DEBUG: shc_ConnectInputs failure\n");
        return false;
      }
    }

    mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
  }

  // Write queued txindex changes
  for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
  {
    if (!txdb.UpdateTxIndex((*mi).first, (*mi).second)) {
      return error(SHERR_INVAL, "ConnectBlock() : UpdateTxIndex failed");
    }
  }
if (vtx.size() == 0) {
fprintf(stderr, "DEBUG: ConnectBlock: vtx.size() == 0\n");
return false;
}

  if (vtx[0].GetValueOut() > shc_GetBlockValue(pindex->nHeight, nFees)) {
fprintf(stderr, "DEBUG: SHCBlock::ConnectBlock: critical: coinbaseValueOut(%llu) > BlockValue(%llu) @ height %d [fee %llu]\n", (unsigned long long)vtx[0].GetValueOut(), (unsigned long long)shc_GetBlockValue(pindex->nHeight, nFees), pindex->nHeight, (unsigned long long)nFees); 
    return false;
  }

  if (pindex->pprev)
  {
    /* DEBUG: */
    pindex->pprev->pnext = pindex;
#if 0
    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    CDiskBlockIndex blockindexPrev(pindex->pprev);
    blockindexPrev.hashNext = pindex->GetBlockHash();
    if (!txdb.WriteBlockIndex(blockindexPrev))
      return error(SHERR_INVAL, "ConnectBlock() : WriteBlockIndex failed");
#endif
  }

  // Watch for transactions paying to me
  BOOST_FOREACH(CTransaction& tx, vtx)
    SyncWithWallets(iface, tx, this);

  return true;
}

bool SHCBlock::ReadBlock(uint64_t nHeight)
{
int ifaceIndex = SHC_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  CDataStream sBlock(SER_DISK, CLIENT_VERSION);
  size_t sBlockLen;
  unsigned char *sBlockData;
  char errbuf[1024];
  bc_t *bc;
  int err;

  bc = GetBlockChain(iface);
  if (!bc)
    return (false);

  err = bc_get(bc, nHeight, &sBlockData, &sBlockLen);
  if (err) {
    sprintf(errbuf, "CBlock::ReadBlock[height %d]: %s (sherr %d).",
      (int)nHeight, sherrstr(err), err);
    unet_log(ifaceIndex, errbuf);
    return (false);
  }

  /* serialize binary data into block */
  sBlock.write((const char *)sBlockData, sBlockLen);
  sBlock >> *this;
  free(sBlockData);

#if 0
  uint256 cur_hash = GetHash();
  {
    uint256 t_hash;
    bc_hash_t b_hash;
    memcpy(b_hash, cur_hash.GetRaw(), sizeof(bc_hash_t));
    t_hash.SetRaw(b_hash);
    if (!bc_hash_cmp(t_hash.GetRaw(), cur_hash.GetRaw())) {
      fprintf(stderr, "DEBUG: ReadBlock: error comparing self-hash ('%s' / '%s')\n", cur_hash.GetHex().c_str(), t_hash.GetHex().c_str());
    }
  }

  {
    uint256 db_hash;
    bc_hash_t ret_hash;
    err = bc_get_hash(bc, nHeight, ret_hash);
    if (err) {
      fprintf(stderr, "DEBUG: CBlock::ReadBlock: bc_get_hash err %d\n", err); 
      return (false);
    }
    db_hash.SetRaw((unsigned int *)ret_hash);

    if (!bc_hash_cmp(db_hash.GetRaw(), cur_hash.GetRaw())) {
      fprintf(stderr, "DEBUG: CBlock::ReadBlock: hash '%s' from loaded block at pos %d has invalid hash of '%s'\n", db_hash.GetHex().c_str(), nHeight, cur_hash.GetHex().c_str());
      print();
      SetNull();

      return (false);
    }
  }
#endif

#if 0
  if (!CheckBlock()) {
    unet_log(ifaceIndex, "CBlock::ReadBlock: block validation failure.");
    return (false);
  }
#endif

  return (true);
}

bool SHCBlock::IsOrphan()
{
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  uint256 hash = GetHash();

  if (blockIndex->count(hash))
    return (false);

  if (!SHC_mapOrphanBlocks.count(hash))
    return (false);

  return (true);
}


bool SHCBlock::Truncate()
{
  blkidx_t *blockIndex = GetBlockTable(SHC_COIN_IFACE);
  CIface *iface = GetCoinByIndex(SHC_COIN_IFACE);
  bc_t *bc = GetBlockChain(iface);
  CBlockIndex *cur_index;
  int err;

  cur_index = (*blockIndex)[GetHash()];
  if (!cur_index)
    return error(SHERR_INVAL, "Erase: block not found in block-index.");

#if 0
  CBlockIndex *pindex;
  pindex = GetBestBlockIndex(iface);
  if (!pindex)
    return error(SHERR_INVAL, "Erase: no established tail of block-chain.");

  SHCTxDB txdb;
  while (pindex && pindex->nHeight >= cur_index->nHeight) {
    SHCBlock block;
    if (block.ReadBlock(pindex->nHeight)) {
      block.DisconnectBlock(txdb, pindex);
    }
    pindex = pindex->pprev;
  }
  if (pindex) {
    SHCBlock block;
    if (block.ReadBlock(pindex->nHeight)) {
      pindex->pnext = NULL;
      block.SetBestChain(txdb, pindex);
    }
  }

  txdb.Close();
#endif
  CBlockIndex *pindex = cur_index->pprev;
  if (pindex) {
    SHCBlock block;
    if (block.ReadFromDisk(pindex)) {
      SHCTxDB txdb;
      block.SetBestChain(txdb, pindex);
      txdb.Close();
    }
  }

  err = BlockChainErase(iface, cur_index->nHeight);
  if (err)
    return error(err, "BlockChainErase[SHC]");

  return (true);
}
