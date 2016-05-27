
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
#include "usde_block.h"
#include "usde_txidx.h"
#include "usde_wallet.h"

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
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>


using namespace std;
using namespace boost;


uint256 usde_hashGenesisBlock("0x33abc26f9a026f1279cb49600efdd63f42e7c2d3a15463ad8090505d3e967752");
static CBigNum USDE_bnProofOfWorkLimit(~uint256(0) >> 20); // usde: starting difficulty is 1 / 2^12

map<uint256, USDEBlock*> USDE_mapOrphanBlocks;
multimap<uint256, USDEBlock*> USDE_mapOrphanBlocksByPrev;
map<uint256, map<uint256, CDataStream*> > USDE_mapOrphanTransactionsByPrev;
map<uint256, CDataStream*> USDE_mapOrphanTransactions;

class USDEOrphan
{
  public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;

    USDEOrphan(CTransaction* ptxIn)
    {
      ptx = ptxIn;
      dPriority = 0;
    }

    void print() const
    {
      printf("USDEOrphan(hash=%s, dPriority=%.1f)\n", ptx->GetHash().ToString().substr(0,10).c_str(), dPriority);
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

  if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64)BlockLastSolved->nHeight < PastBlocksMin) { return USDE_bnProofOfWorkLimit.GetCompact(); }

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
  if (bnNew > USDE_bnProofOfWorkLimit) { bnNew = USDE_bnProofOfWorkLimit; }


#if 0
  /// debug print
  printf("Difficulty Retarget - Kimoto Gravity Well\n");
  printf("PastRateAdjustmentRatio = %g\n", PastRateAdjustmentRatio);
  printf("Before: %08x %s\n", BlockLastSolved->nBits, CBigNum().SetCompact(BlockLastSolved->nBits).getuint256().ToString().c_str());
  printf("After: %08x %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
#endif

  return bnNew.GetCompact();
}

unsigned int USDEBlock::GetNextWorkRequired(const CBlockIndex* pindexLast)
{
  int nHeight = pindexLast->nHeight + 1;

  int64 nInterval;
  int64 nActualTimespanMax;
  int64 nActualTimespanMin;
  int64 nTargetTimespanCurrent;


  if (nHeight > 91000)
  {
    static const int64	BlocksTargetSpacing	= 1.0 * 60; // 1.0 minutes
    unsigned int	TimeDaySeconds	= 60 * 60 * 24;
    int64	PastSecondsMin	= TimeDaySeconds * 0.10;
    int64	PastSecondsMax	= TimeDaySeconds * 2.8;
    uint64	PastBlocksMin	= PastSecondsMin / BlocksTargetSpacing;
    uint64	PastBlocksMax	= PastSecondsMax / BlocksTargetSpacing;	

    return KimotoGravityWell(pindexLast, this, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax);
  }

  if (nHeight > 27000)
  {   //Fixed
    nTargetTimespan = 2 * 60 * 60; // Retarget every 120 blocks (10 minutes)
    nTargetSpacing = 1 * 60; // 60 seconds
    nInterval = nTargetTimespan / nTargetSpacing;

    nActualTimespanMax = nTargetTimespan * 100/125; //25% Up
    nActualTimespanMin = nTargetTimespan * 2; //50% down
  }   
  else
  {   //Old Protocol
    nTargetTimespan = 2 * 60 * 60; // Retarget every 120 blocks (2 hour).. Since digitalcoin used inflation it was actually 1200 blocks
    nTargetSpacing = 1 * 60; // 60 seconds
    nTargetTimespanCurrent =  (nTargetTimespan*5);
    nInterval = (nTargetTimespanCurrent / (nTargetSpacing / 2));


  }

  unsigned int nProofOfWorkLimit = USDE_bnProofOfWorkLimit.GetCompact();

  // Genesis block
  if (pindexLast == NULL)
    return nProofOfWorkLimit;

  // Only change once per interval
  if ((pindexLast->nHeight+1) % nInterval != 0)
  {
    // Special difficulty rule for testnet:
    if (fTestNet)
    {
      // If the new block's timestamp is more than 2* 10 minutes
      // then allow mining of a min-difficulty block.
      if (nTime > pindexLast->nTime + nTargetSpacing*2)
        return nProofOfWorkLimit;
      else
      {
        // Return the last non-special-min-difficulty-rules-block
        const CBlockIndex* pindex = pindexLast;
        while (pindex->pprev && pindex->nHeight % nInterval != 0 && pindex->nBits == nProofOfWorkLimit)
          pindex = pindex->pprev;
        return pindex->nBits;
      }
    }

    return pindexLast->nBits;
  }

  // StableCoin: This fixes an issue where a 51% attack can change difficulty at will.
  // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
  int blockstogoback = nInterval-1;
  if ((pindexLast->nHeight+1) != nInterval)
    blockstogoback = nInterval;

  // Go back by what we want to be 14 days worth of blocks
  const CBlockIndex* pindexFirst = pindexLast;
  for (int i = 0; pindexFirst && i < blockstogoback; i++)
    pindexFirst = pindexFirst->pprev;
  assert(pindexFirst);

  int64 nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();

  if (nHeight > 27000)
  {   //Fixed
    //printf("  nActualTimespan = %"PRI64d"  before bounds\n", nActualTimespan);
    if (nActualTimespan < nActualTimespanMax)
      nActualTimespan = nActualTimespanMax;
    if (nActualTimespan > nActualTimespanMin)
      nActualTimespan = nActualTimespanMin;
  }   
  else
  {   
    //old protocol
    nActualTimespanMax =  (nTargetTimespanCurrent*4);
    nActualTimespanMin =  (nTargetTimespanCurrent/4);


    if (nActualTimespan > nActualTimespanMax)
      nActualTimespan = nActualTimespanMax;	
    if (nActualTimespan < nActualTimespanMin)
      nActualTimespan = nActualTimespanMin;


    nTargetTimespan = nTargetTimespanCurrent;
  }


  // Limit adjustment step


  // Retarget
  CBigNum bnNew;
  bnNew.SetCompact(pindexLast->nBits);
  bnNew *= nActualTimespan;
  bnNew /= nTargetTimespan;

  if (bnNew > USDE_bnProofOfWorkLimit)
    bnNew = USDE_bnProofOfWorkLimit;

#if 0
  /// debug print
  printf("GetNextWorkRequired RETARGET\n");
  printf("nTargetTimespan = %"PRI64d"    nActualTimespan = %"PRI64d"\n", nTargetTimespan, nActualTimespan);
  printf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
  printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
#endif

  return bnNew.GetCompact();
}


static int64 usde_GetInitialBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = 4000 * COIN;

  if ((nHeight % 100) == 1)
  {
    nSubsidy = 100000 * COIN; //100k
  }else if ((nHeight % 50) == 1)
  {
    nSubsidy = 50000 * COIN; //50k
  }else if ((nHeight % 20) == 1)
  {
    nSubsidy = 20000 * COIN; //20k
  }else if ((nHeight % 10) == 1)
  {
    nSubsidy = 10000 * COIN; //10k
  }else if ((nHeight % 5) == 1)
  {
    nSubsidy = 5000 * COIN; //5k
  }
  
  //limit first blocks to protect against instamine.
  if (nHeight < 2){
    nSubsidy = 24000000 * COIN; // 1.5%
  }else if(nHeight < 500)
  {
    nSubsidy = 100 * COIN;
  }
  else if(nHeight < 1000)
  {
    nSubsidy = 500 * COIN;
  } 
    
  nSubsidy >>= (nHeight / 139604);
    
  return (nSubsidy + nFees);
}

int64 usde_GetBlockValue(int nHeight, int64 nFees)
{
  int64 nSubsidy = 4000 * COIN;
  int base = nHeight;

  if (nHeight < 107500) {
    return (usde_GetInitialBlockValue(nHeight, nFees));
  }

  nSubsidy >>= (base / 139604);

  return nSubsidy + nFees;
}

namespace USDE_Checkpoints
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
    ( 0, uint256("0x33abc26f9a026f1279cb49600efdd63f42e7c2d3a15463ad8090505d3e967752"))
    ( 1, uint256("0xec9c4d88a04ede4cd777234ac504084c36cb25080c45b4741e2cfc0d5994359a"))
    ( 50, uint256("0x253e145aae6b516ac47b9f6855675bea6f589922b74195cee77b31df1ebbc8c7"))
    ( 3000, uint256("0xb0bf45beaad4446c666158baee04488267e622fabc49e6686b798ccd122018fe"))
    ( 8000, uint256("0xde808d01865606385726824fd9f1466aacb94f233cd9713dc989333bcea15312"))
    ( 10000, uint256("0xb5bab4cfa3e92985302a95afeb1b42755d6c240e73af61deb2599cb72aba991e"))
    ( 20000, uint256("0x2f35019fbf04de7287aaa18b4010d2317779aac0a875183ff52934b8a3fee685"))
    ( 135798, uint256("0xbd8423b7e21e1422953008db6ab7197b71b4cfabb9d9e69cc0cbcdcd7dd86b30"))
    ( 1000, uint256("0xa59b03d739edd29c98cf563a1f7b57e7da8306abcae4e18397bd1e320fa79007"))
    ( 100000, uint256("0x9376d399b8b3f34549d05b6858f4cba534e78cba2306c414117dcaa057c23081"))
    ( 250000, uint256("0x7e86b4d451fcfdf4c59e7f0a8081b33366a50a82b276073c55b758d7769333bf"))
    ( 444444, uint256("0xd4b76e38fe481aef65e4dcc52703f34187aff8dcd037b1ab7abe7b7429af7d95"))
    ( 500000, uint256("0x17a3060325e40e311b42763d44574b3f63a3525f1f7644588fe00ca824c7b21e"))
    ( 750000, uint256("0xa3b1c4f90225299fef3a43851be960b49ca70e8500d1891612e2836cfbeed188"))
    ( 888888, uint256("0x96d7bf79871c8d6d887e098c444071cfda4548e502d1965e255b1b0e71c93c7a"))
    ( 1000000, uint256("0xd444bebec6a7f1345e6bee094d913bdfff0b7ae833c3e3f17b90c98fdc899aa4"))

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

#if 0
bool usde_FetchInputs(CTransaction *tx, CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool, bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
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
        LOCK(USDEBlock::mempool.cs);
        if (!USDEBlock::mempool.exists(prevout.hash))
          return error(SHERR_INVAL, "FetchInputs() : %s USDEBlock::mempool Tx prev not found %s", tx->GetHash().ToString().substr(0,10).c_str(),  prevout.hash.ToString().substr(0,10).c_str());
        txPrev = USDEBlock::mempool.lookup(prevout.hash);
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

static bool usde_ConnectInputs(CTransaction *tx, MapPrevTx inputs, map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, bool fBlock, bool fMiner, bool fStrictPayToScriptHash=true)
{

  if (tx->IsCoinBase())
    return (true);

  // Take over previous transactions' spent pointers
  // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
  // fMiner is true when called from the internal usde miner
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
      for (const CBlockIndex* pindex = pindexBlock; pindex && pindexBlock->nHeight - pindex->nHeight < USDE_COINBASE_MATURITY; pindex = pindex->pprev)
        //if (pindex->nBlockPos == txindex.pos.nBlockPos && pindex->nFile == txindex.pos.nFile)
        if (pindex->nHeight == txindex.pos.nBlockPos)// && pindex->nFile == txindex.pos.nFile)
          return error(SHERR_INVAL, "ConnectInputs() : tried to spend coinbase at depth %d", pindexBlock->nHeight - pindex->nHeight);

    // Check for negative or overflow input values
    nValueIn += txPrev.vout[prevout.n].nValue;
    if (!MoneyRange(USDE_COIN_IFACE, txPrev.vout[prevout.n].nValue) || !MoneyRange(USDE_COIN_IFACE, nValueIn))
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
    if (!(fBlock && (GetBestHeight(USDE_COIN_IFACE < USDE_Checkpoints::GetTotalBlocksEstimate()))))
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
  if (!MoneyRange(USDE_COIN_IFACE, nFees))
    return error(SHERR_INVAL, "ConnectInputs() : nFees out of range");

  return true;
}

CBlock* usde_CreateNewBlock(CReserveKey& reservekey)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  CBlockIndex* pindexPrev = GetBestBlockIndex(iface);

  // Create new block
  //auto_ptr<CBlock> pblock(new CBlock());
  auto_ptr<USDEBlock> pblock(new USDEBlock());
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
    LOCK2(cs_main, USDEBlock::mempool.cs);
    USDETxDB txdb; 

    // Priority order to process transactions
    list<USDEOrphan> vOrphan; // list memory doesn't move
    map<uint256, vector<USDEOrphan*> > mapDependers;
    multimap<double, CTransaction*> mapPriority;
    for (map<uint256, CTransaction>::iterator mi = USDEBlock::mempool.mapTx.begin(); mi != USDEBlock::mempool.mapTx.end(); ++mi)
    {
      CTransaction& tx = (*mi).second;
      if (tx.IsCoinBase() || !tx.IsFinal(USDE_COIN_IFACE))
        continue;

      USDEOrphan* porphan = NULL;
      double dPriority = 0;
      BOOST_FOREACH(const CTxIn& txin, tx.vin)
      {
        // Read prev transaction
        CTransaction txPrev;
        if (!txPrev.ReadTx(USDE_COIN_IFACE, txin.prevout.hash)) {
          // Has to wait for dependencies
          if (!porphan)
          {
            // Use list for automatic deletion
            vOrphan.push_back(USDEOrphan(&tx));
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
        int nConf = GetTxDepthInMainChain(iface, txPrev.GetHash());

        dPriority += (double)nValueIn * nConf;

        if (fDebug && GetBoolArg("-printpriority"))
          printf("priority     nValueIn=%-12"PRI64d" nConf=%-5d dPriority=%-20.1f\n", nValueIn, nConf, dPriority);
      }

      // Priority is sum(valuein * age) / txsize
      dPriority /= ::GetSerializeSize(tx, SER_NETWORK, USDE_PROTOCOL_VERSION);

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
      unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, USDE_PROTOCOL_VERSION);
      if (nBlockSize + nTxSize >= MAX_BLOCK_SIZE_GEN(iface))
        continue;

      // Legacy limits on sigOps:
      unsigned int nTxSigOps = tx.GetLegacySigOpCount();
      if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS(iface))
        continue;

      // Transaction fee required depends on block size
      // usded: Reduce the exempted free transactions to 500 bytes (from Bitcoin's 3000 bytes)
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

      if (!usde_ConnectInputs(&tx, mapInputs, mapTestPoolTmp, CDiskTxPos(0,0,0), pindexPrev, false, true))
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
        BOOST_FOREACH(USDEOrphan* porphan, mapDependers[hash])
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

    txdb.Close();

#if 0
    nLastBlockTx = nBlockTx;
    nLastBlockSize = nBlockSize;
    //printf("CreateNewBlock(): total size %lu\n", nBlockSize);
#endif

  }
  pblock->vtx[0].vout[0].nValue = usde_GetBlockValue(pindexPrev->nHeight+1, nFees);

  // Fill in header
  pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
  pblock->hashMerkleRoot = pblock->BuildMerkleTree();
  pblock->UpdateTime(pindexPrev);
  pblock->nBits          = pblock->GetNextWorkRequired(pindexPrev);
  pblock->nNonce         = 0;

  return pblock.release();
}


bool usde_CreateGenesisBlock()
{
  blkidx_t *blockIndex = GetBlockTable(USDE_COIN_IFACE);
  bool ret;

  if (!blockIndex->empty())
    return (true);


  // Genesis block
  const char* pszTimestamp = "USDE founded 1/1/2014";
  CTransaction txNew;
  txNew.vin.resize(1);
  txNew.vout.resize(1);
  txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
  txNew.vout[0].nValue = 50 * COIN;
  txNew.vout[0].scriptPubKey = CScript() << ParseHex("04a5814813115273a109cff99907ba4a05d951873dae7acb6c973d0c9e7c88911a3dbc9aa600deac241b91707e7b4ffb30ad91c8e56e695a1ddf318592988afe0a") << OP_CHECKSIG;
  USDEBlock block;
  block.vtx.push_back(txNew);
  block.hashPrevBlock = 0;
  block.hashMerkleRoot = block.BuildMerkleTree();
  block.nVersion = 1;
  block.nTime    = 1365048244;
  block.nBits    = 0x1e0ffff0;
  block.nNonce   = 134453;

  if (fTestNet)
  {
    block.nTime    = 0;             //test net not supported
    block.nNonce   = 0;
  }

  //// debug print
  printf("%s\n", block.GetHash().ToString().c_str());
  printf("%s\n", usde_hashGenesisBlock.ToString().c_str());
  printf("%s\n", block.hashMerkleRoot.ToString().c_str());

  assert(block.hashMerkleRoot == uint256("0x1f42509b6d35a6aa60af4ec9b98d8ce4ffbe46c076d4c2da933e87550ab775f2"));

  // If genesis block hash does not match, then generate new genesis hash.
  if (false && block.GetHash() != usde_hashGenesisBlock)
  {
    printf("Searching for genesis block...\n");
    // This will figure out a valid hash and Nonce if you're
    // creating a different genesis block:
    uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
    uint256 thash;
    char scratchpad[SCRYPT_SCRATCHPAD_SIZE];

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
    printf("block.nTime = %u \n", block.nTime);
    printf("block.nNonce = %u \n", block.nNonce);
    printf("block.GetHash = %s\n", block.GetHash().ToString().c_str());
  }

  //block.print();
  assert(block.GetHash() == usde_hashGenesisBlock);

#if 0
  // Start new block file
  unsigned int nFile;
  unsigned int nBlockPos;
  if (!block.WriteToDisk(nFile, nBlockPos))
    return error(SHERR_INVAL, "LoadBlockIndex() : writing genesis block to disk failed");
  if (!block.AddToBlockIndex(nFile, nBlockPos))
    return error(SHERR_INVAL, "LoadBlockIndex() : genesis block not accepted");
#endif


  if (!block.WriteBlock(0)) {
    return (false);
  }

  ret = block.AddToBlockIndex();
  if (!ret)
    return (false);

  return (true);
}











static bool usde_IsFromMe(CTransaction& tx)
{
  BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
    if (pwallet->IsFromMe(tx))
      return true;
  return false;
}

static void usde_EraseFromWallets(uint256 hash)
{
  BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
    pwallet->EraseFromWallet(hash);
}

bool USDE_CTxMemPool::accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs)
{
  if (pfMissingInputs)
    *pfMissingInputs = false;

  if (!tx.CheckTransaction(USDE_COIN_IFACE))
    return error(SHERR_INVAL, "CTxMemPool::accept() : CheckTransaction failed");

  // Coinbase is only valid in a block, not as a loose transaction
  if (tx.IsCoinBase())
    return error(SHERR_INVAL, "CTxMemPool::accept() : coinbase as individual tx");

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
      if (ptxOld->IsFinal(USDE_COIN_IFACE))
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
    unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, USDE_PROTOCOL_VERSION);

    // Don't accept it if it can't get into a block
    if (nFees < tx.GetMinFee(1000, true, GMF_RELAY))
      return error(SHERR_INVAL, "CTxMemPool::accept() : not enough fees");

    // Continuously rate-limit free transactions
    // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
    // be annoying or make other's transactions take longer to confirm.
    if (nFees < USDE_MIN_RELAY_TX_FEE)
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
        if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000 && !usde_IsFromMe(tx))
          return error(SHERR_INVAL, "CTxMemPool::accept() : free transaction rejected by rate limiter");
        Debug("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
        dFreeCount += nSize;
      }
    }

    // Check against previous transactions
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.

    if (!usde_ConnectInputs(&tx, mapInputs, mapUnused, CDiskTxPos(0,0,0), GetBestBlockIndex(USDE_COIN_IFACE), false, false))
    {
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
    usde_EraseFromWallets(ptxOld->GetHash());

  Debug("CTxMemPool::accept() : accepted %s (poolsz %u)\n",
      hash.ToString().substr(0,10).c_str(),
      mapTx.size());
  return true;
}

bool USDE_CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);

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


bool USDE_CTxMemPool::remove(CTransaction &tx)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);

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

void USDE_CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}


#if 0
bool usde_InitBlockIndex()
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  blkidx_t *blockIndex = GetBlockTable(USDE_COIN_IFACE);
  USDETxDB txdb;

  /* load attributes */
  if (!txdb.ReadHashBestChain(USDEBlock::hashBestChain))
  {
    if (USDE_pindexGenesisBlock == NULL)
      return true;
    return error(SHERR_IO, "USDETxDB::LoadBlockIndex() : hashBestChain not loaded");
  }

  if (!blockIndex->count(USDEBlock::hashBestChain))
    return error(SHERR_IO, "USDETxDB::LoadBlockIndex() : hashBestChain not found in the block index");

  USDEBlock::pindexBest = (*blockIndex)[USDEBlock::hashBestChain];
  USDEBlock::nBestHeight = USDEBlock::pindexBest->nHeight;
  USDE_bnBestChainWork = USDEBlock::pindexBest->bnChainWork;
  txdb.ReadBestInvalidWork(USDE_bnBestInvalidWork);

  txdb.Close();

  /* verify */
  int nCheckDepth = 2500;
  if (nCheckDepth > USDEBlock::nBestHeight)
    nCheckDepth = USDEBlock::nBestHeight;

  CBlockIndex* pindexFork = NULL;
  map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
  for (CBlockIndex* pindex = USDEBlock::pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
  {
    if (pindex->nHeight < USDEBlock::nBestHeight-nCheckDepth)
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
    USDETxDB txdb;
    block->SetBestChain(txdb, pindexFork);
    txdb.Close();
  }

  return (true);
}
#endif


uint256 usde_GetOrphanRoot(const CBlock* pblock)
{

  // Work back to the first block in the orphan chain
  while (USDE_mapOrphanBlocks.count(pblock->hashPrevBlock))
    pblock = USDE_mapOrphanBlocks[pblock->hashPrevBlock];
  return pblock->GetHash();

}

// minimum amount of work that could possibly be required nTime after
// minimum work required was nBase
//
static unsigned int usde_ComputeMinWork(unsigned int nBase, int64 nTime)
{
  CBigNum bnResult;
  bnResult.SetCompact(nBase);
  while (nTime > 0 && bnResult < USDE_bnProofOfWorkLimit)
  {
    // Maximum 136% adjustment...
    bnResult = (bnResult * 75) / 55; 
    // ... in best-case exactly 4-times-normal target time
    nTime -= USDEBlock::nTargetTimespan*4;
  }
  if (bnResult > USDE_bnProofOfWorkLimit)
    bnResult = USDE_bnProofOfWorkLimit;
  return bnResult.GetCompact();
}

bool usde_ProcessBlock(CNode* pfrom, CBlock* pblock)
{
  int ifaceIndex = USDE_COIN_IFACE;
  CIface *iface = GetCoinByIndex(ifaceIndex);
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
  shtime_t ts;

  // Check for duplicate
  uint256 hash = pblock->GetHash();
  if (blockIndex->count(hash))
    return Debug("ProcessBlock() : already have block %d %s", (*blockIndex)[hash]->nHeight, hash.ToString().substr(0,20).c_str());
  if (USDE_mapOrphanBlocks.count(hash))
    return Debug("ProcessBlock() : already have block (orphan) %s", hash.ToString().substr(0,20).c_str());

  // Preliminary checks
  if (!pblock->CheckBlock()) {
    iface->net_invalid = time(NULL);
    return error(SHERR_INVAL, "ProcessBlock() : CheckBlock FAILED");
  }

  CBlockIndex* pcheckpoint = USDE_Checkpoints::GetLastCheckpoint(*blockIndex);
  if (pcheckpoint && pblock->hashPrevBlock != GetBestBlockChain(iface))
  {
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
    bnRequired.SetCompact(usde_ComputeMinWork(pcheckpoint->nBits, deltaTime));
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
    Debug("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.GetHex().c_str());
    //CBlock* pblock2 = new CBlock(*pblock);
    USDEBlock* pblock2 = new USDEBlock(*pblock);
    USDE_mapOrphanBlocks.insert(make_pair(hash, pblock2));
    USDE_mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

    // Ask this guy to fill in what we're missing
    if (pfrom) {
      pfrom->PushGetBlocks(GetBestBlockIndex(USDE_COIN_IFACE), usde_GetOrphanRoot(pblock2));
}

    iface->net_invalid = time(NULL);
    return true;
  }

  // Store to disk

  timing_init("AcceptBlock", &ts);
  if (!pblock->AcceptBlock()) {
    iface->net_invalid = time(NULL);
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
    for (multimap<uint256, USDEBlock*>::iterator mi = USDE_mapOrphanBlocksByPrev.lower_bound(hashPrev);
        mi != USDE_mapOrphanBlocksByPrev.upper_bound(hashPrev);
        ++mi)
    {
      CBlock* pblockOrphan = (*mi).second;
      if (pblockOrphan->AcceptBlock())
        vWorkQueue.push_back(pblockOrphan->GetHash());

      USDE_mapOrphanBlocks.erase(pblockOrphan->GetHash());

      delete pblockOrphan;
    }
    USDE_mapOrphanBlocksByPrev.erase(hashPrev);
  }

  return true;
}

bool usde_CheckProofOfWork(uint256 hash, unsigned int nBits)
{
  CBigNum USDE_bnTarget;
  USDE_bnTarget.SetCompact(nBits);

  // Check range
  if (USDE_bnTarget <= 0 || USDE_bnTarget > USDE_bnProofOfWorkLimit)
    return error(SHERR_INVAL, "CheckProofOfWork() : nBits below minimum work");

  // Check proof of work matches claimed amount
  if (hash > USDE_bnTarget.getuint256())
    return error(SHERR_INVAL, "CheckProofOfWork() : hash doesn't match nBits");

  return true;
}

/**
 * @note These are checks that are independent of context that can be verified before saving an orphan block.
 */
bool USDEBlock::CheckBlock()
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);

#if 0 /* DEBUG: */
  // Size limits
  if (vtx.empty() || 
      vtx.size() > MAX_BLOCK_SIZE || 
      CBlock::GetSerializeSize((CBlock)*block, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE) {
    return error(SHERR_INVAL, "CheckBlock() : size limits failed");
  }
#endif
  if (vtx.empty() || !vtx[0].IsCoinBase())
    return error(SHERR_INVAL, "CheckBlock() : first tx is not coinbase");

  // Check proof of work matches claimed amount
  if (!usde_CheckProofOfWork(GetPoWHash(), nBits)) {
    return error(SHERR_INVAL, "CheckBlock() : proof of work failed");
  }

  // Check timestamp
  if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60) {
    return error(SHERR_INVAL, "CheckBlock() : block timestamp too far in the future");
  }

  // First transaction must be coinbase, the rest must not be
  for (unsigned int i = 1; i < vtx.size(); i++)
    if (vtx[i].IsCoinBase()) {
      return error(SHERR_INVAL, "CheckBlock() : more than one coinbase");
    }

  // Check transactions
  BOOST_FOREACH(const CTransaction& tx, vtx) {
    if (!tx.CheckTransaction(USDE_COIN_IFACE)) {
      return error(SHERR_INVAL, "CheckBlock() : CheckTransaction failed");
    }
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




bool static USDE_Reorganize(CTxDB& txdb, CBlockIndex* pindexNew, USDE_CTxMemPool *mempool)
{

fprintf(stderr, "DEBUG: USDE_Reorganize()\n");

  // Find the fork
  CBlockIndex* pindexBest = GetBestBlockIndex(USDE_COIN_IFACE);
  CBlockIndex* pfork = pindexBest;
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
  vector<CBlockIndex*> vDisconnect;
  for (CBlockIndex* pindex = GetBestBlockIndex(USDE_COIN_IFACE); pindex != pfork; pindex = pindex->pprev)
    vDisconnect.push_back(pindex);

  // List of what to connect
  vector<CBlockIndex*> vConnect;
  for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
    vConnect.push_back(pindex);
  reverse(vConnect.begin(), vConnect.end());

pindexBest = GetBestBlockIndex(USDE_COIN_IFACE);
fprintf(stderr, "DEBUG: REORGANIZE: Disconnect %i blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
fprintf(stderr, "DEBUG: REORGANIZE: Connect %i blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

  // Disconnect shorter branch
  vector<CTransaction> vResurrect;
  BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
  {
    USDEBlock block;
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
    USDEBlock block;
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

  return true;
}

void USDEBlock::InvalidChainFound(CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);

  if (pindexNew->bnChainWork > bnBestInvalidWork)
  {
    bnBestInvalidWork = pindexNew->bnChainWork;
    USDETxDB txdb;
    txdb.WriteBestInvalidWork(bnBestInvalidWork);
    txdb.Close();
    //    uiInterface.NotifyBlocksChanged();
  }
  error(SHERR_INVAL, "USDE: InvalidChainFound: invalid block=%s  height=%d  work=%s  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      pindexNew->bnChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S",
        pindexNew->GetBlockTime()).c_str());
  CBlockIndex *pindexBest = GetBestBlockIndex(USDE_COIN_IFACE); 
  fprintf(stderr, "critical: InvalidChainFound:  current best=%s  height=%d  work=%s  date=%s\n", 
GetBestBlockChain(iface).ToString().substr(0,20).c_str(), GetBestHeight(USDE_COIN_IFACE), bnBestChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());
  if (pindexBest && bnBestInvalidWork > bnBestChainWork + pindexBest->GetBlockWork() * 6)
    unet_log(USDE_COIN_IFACE, "InvalidChainFound: WARNING: Displayed transactions may not be correct!  You may need to upgrade, or other nodes may need to upgrade.\n");
}

bool USDEBlock::SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew)
{
  uint256 hash = GetHash();

  // Adding to current best branch
  if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
  {
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
void static USDE_SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

#if 0
/* if block is over one day old than consider it history. */
static bool USDE_IsInitialBlockDownload()
{

  if (pindexBest == NULL || GetBestHeight(USDE_COIN_IFACE) < USDE_Checkpoints::GetTotalBlocksEstimate())
    return true;

  static int64 nLastUpdate;
  static CBlockIndex* pindexLastBest;
  if (pindexBest != pindexLastBest)
  {
    pindexLastBest = pindexBest;
    nLastUpdate = GetTime();
  }
  return (GetTime() - nLastUpdate < 15 &&
      pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60);
}
#endif

bool USDEBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  uint256 hash = GetHash();

  if (!txdb.TxnBegin())
    return error(SHERR_INVAL, "SetBestChain() : TxnBegin failed");

  if (USDEBlock::pindexGenesisBlock == NULL && hash == usde_hashGenesisBlock)
  {
    txdb.WriteHashBestChain(hash);
    if (!txdb.TxnCommit())
      return error(SHERR_INVAL, "SetBestChain() : TxnCommit failed");
    USDEBlock::pindexGenesisBlock = pindexNew;
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
    while (pindexIntermediate->pprev && pindexIntermediate->pprev->bnChainWork > GetBestBlockIndex(USDE_COIN_IFACE)->bnChainWork)
    {
      vpindexSecondary.push_back(pindexIntermediate);
      pindexIntermediate = pindexIntermediate->pprev;
    }

    if (!vpindexSecondary.empty())
      Debug("Postponing %i reconnects\n", vpindexSecondary.size());

    // Switch to new best branch
    if (!USDE_Reorganize(txdb, pindexIntermediate, &mempool))
    {
      txdb.TxnAbort();
      InvalidChainFound(pindexNew);
      return error(SHERR_INVAL, "SetBestChain() : Reorganize failed");
    }

    // Connect futher blocks
    BOOST_REVERSE_FOREACH(CBlockIndex *pindex, vpindexSecondary)
    {
      USDEBlock block;
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
  bool fIsInitialDownload = IsInitialBlockDownload(USDE_COIN_IFACE);
  if (!fIsInitialDownload)
  {
    const CBlockLocator locator(USDE_COIN_IFACE, pindexNew);
    USDE_SetBestChain(locator);
  }

  // New best block
//  USDEBlock::hashBestChain = hash;
  SetBestBlockIndex(USDE_COIN_IFACE, pindexNew);
//  SetBestHeight(iface, pindexNew->nHeight);
  bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();
  iface->tx_tot++;

//fprintf(stderr, "DEBUG: USDE/SetBestChain: new best=%s  height=%d  work=%s  date=%s\n", hashBestChain.ToString().substr(0,20).c_str(), nBestHeight, bnBestChainWork.ToString().c_str(), DateTimeStrFormat("%x %H:%M:%S", USDEBlock::pindexBest->GetBlockTime()).c_str());

  // Check the version of the last 100 blocks to see if we need to upgrade:
  if (!fIsInitialDownload)
  {
    int nUpgraded = 0;
    const CBlockIndex* pindex = GetBestBlockIndex(USDE_COIN_IFACE);
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

bool USDEBlock::IsBestChain()
{
  CBlockIndex *pindexBest = GetBestBlockIndex(USDE_COIN_IFACE);
  return (pindexBest && GetHash() == pindexBest->GetBlockHash());
}

bool usde_AcceptBlock(USDEBlock *pblock)
{
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  int ifaceIndex = USDE_COIN_IFACE;
  NodeList &vNodes = GetNodeList(ifaceIndex);
  bc_t *bc = GetBlockChain(GetCoinByIndex(ifaceIndex));
  blkidx_t *blockIndex = GetBlockTable(ifaceIndex);
  shtime_t ts;
  bool ret;

  uint256 hash = pblock->GetHash();
  if (blockIndex->count(hash)) {
    return error(SHERR_INVAL, "USDEBlock::AcceptBlock() : block already in block table.");
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
    if (!tx.IsFinal(USDE_COIN_IFACE, nHeight, pblock->GetBlockTime())) {
      return error(SHERR_INVAL, "AcceptBlock() : contains a non-final transaction");
    }

  // Check that the block chain matches the known block chain up to a checkpoint
  if (!USDE_Checkpoints::CheckBlock(nHeight, hash)) {
    return error(SHERR_INVAL, "AcceptBlock() : rejected by checkpoint lockin at %d", nHeight);
  }

 if (!pblock->WriteBlock(nHeight)) {
    return error(SHERR_INVAL, "USDE: AcceptBlock(): error writing block to height %d", nHeight);
  }

  ret = pblock->AddToBlockIndex();
  if (!ret) {
    return error(SHERR_IO, "AcceptBlock() : AddToBlockIndex failed");
  }

  /* Relay inventory, but don't relay old inventory during initial block download */
  int nBlockEstimate = USDE_Checkpoints::GetTotalBlocksEstimate();
  if (GetBestBlockChain(iface) == hash)
  {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
      if (GetBestHeight(USDE_COIN_IFACE) > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
        pnode->PushInventory(CInv(ifaceIndex, MSG_BLOCK, hash));
  }

  return true;
}

bool USDEBlock::AcceptBlock()
{
  bool ret = usde_AcceptBlock(this);
  if (!ret)
    return (false);

  /* Recursively process any orphan blocks that depended on this one */
  uint256 hash = GetHash();
  vector<uint256> vWorkQueue;
  vWorkQueue.push_back(hash);
  for (unsigned int i = 0; i < vWorkQueue.size(); i++)
  {
    uint256 hashPrev = vWorkQueue[i];
    for (multimap<uint256, USDEBlock*>::iterator mi = USDE_mapOrphanBlocksByPrev.lower_bound(hashPrev);
        mi != USDE_mapOrphanBlocksByPrev.upper_bound(hashPrev);
        ++mi)
    {
      USDEBlock* pblockOrphan = (*mi).second;
      if (usde_AcceptBlock(pblockOrphan))
        vWorkQueue.push_back(pblockOrphan->GetHash());
      USDE_mapOrphanBlocks.erase(pblockOrphan->GetHash());
      delete pblockOrphan;
    }
    USDE_mapOrphanBlocksByPrev.erase(hashPrev);
  }

  return true;
}

CScript USDEBlock::GetCoinbaseFlags()
{
  return (USDE_COINBASE_FLAGS);
}

static void usde_UpdatedTransaction(const uint256& hashTx)
{
  BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
    pwallet->UpdatedTransaction(hashTx);
}


bool USDEBlock::AddToBlockIndex()
{
  blkidx_t *blockIndex = GetBlockTable(USDE_COIN_IFACE);
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

  USDETxDB txdb;
#if 0
  if (!txdb.TxnBegin())
    return false;
  txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
  if (!txdb.TxnCommit())
    return false;
#endif

  // New best
  if (pindexNew->bnChainWork > bnBestChainWork) {
    if (!SetBestChain(txdb, pindexNew))
      return false;
  }

  txdb.Close();

  if (pindexNew == GetBestBlockIndex(USDE_COIN_IFACE)) {
    // Notify UI to display prev block's coinbase if it was ours
    static uint256 hashPrevBestCoinBase;
    usde_UpdatedTransaction(hashPrevBestCoinBase);
    hashPrevBestCoinBase = vtx[0].GetHash();
  }

  return true;
}

bool USDEBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{

  /* redundant */
  if (!CheckBlock())
    return false;

  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
  bc_t *bc = GetBlockTxChain(iface);
  unsigned int nFile = USDE_COIN_IFACE;
  unsigned int nBlockPos = pindex->nHeight;;
  bc_hash_t b_hash;
  int err;

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
fprintf(stderr, "DEBUG: USDEBlock::ConnectBlock: null disk pos, ret false\n");
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
      return error(SHERR_INVAL, "USDEBlock::ConncetBlock: error finding tx hash.");
    }

    MapPrevTx mapInputs;
    CDiskTxPos posThisTx(USDE_COIN_IFACE, nBlockPos, nTxPos);
    if (!tx.IsCoinBase())
    {
      bool fInvalid;
      if (!tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid)) {
fprintf(stderr, "DEBUG: USDEBlock::ConnectBlock: usde_FetchInputs()\n"); 
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

      if (!usde_ConnectInputs(&tx, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fStrictPayToScriptHash)) {
fprintf(stderr, "DEBUG: usde_ConnectInputs failure\n");
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
  if (vtx[0].GetValueOut() > usde_GetBlockValue(pindex->nHeight, nFees)) {
fprintf(stderr, "DEBUG: ConnectBlock: vtx[0].GetValueOut() > usde_GetBlockValue(height %d)\n", pindex->nHeight);
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

bool USDEBlock::ReadBlock(uint64_t nHeight)
{
int ifaceIndex = USDE_COIN_IFACE;
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

  uint256 cur_hash = GetHash();
#if 0
  {
    uint256 t_hash;
    bc_hash_t b_hash;
    memcpy(b_hash, cur_hash.GetRaw(), sizeof(bc_hash_t));
    t_hash.SetRaw(b_hash);
    if (!bc_hash_cmp(t_hash.GetRaw(), cur_hash.GetRaw())) {
      fprintf(stderr, "DEBUG: ReadBlock: error comparing self-hash ('%s' / '%s')\n", cur_hash.GetHex().c_str(), t_hash.GetHex().c_str());
    }
  }
#endif
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

#if 0
  if (!CheckBlock()) {
    unet_log(ifaceIndex, "CBlock::ReadBlock: block validation failure.");
    return (false);
  }
#endif

  return (true);
}

bool USDEBlock::IsOrphan()
{
  blkidx_t *blockIndex = GetBlockTable(USDE_COIN_IFACE);
  uint256 hash = GetHash();

  if (blockIndex->count(hash))
    return (false);

  if (!USDE_mapOrphanBlocks.count(hash))
    return (false);

  return (true);
}


bool USDEBlock::Truncate()
{
  blkidx_t *blockIndex = GetBlockTable(USDE_COIN_IFACE);
  CIface *iface = GetCoinByIndex(USDE_COIN_IFACE);
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

  USDETxDB txdb;
  while (pindex && pindex->nHeight >= cur_index->nHeight) {
    USDEBlock block;
    if (block.ReadBlock(pindex->nHeight)) {
      block.DisconnectBlock(txdb, pindex);
    }
    pindex = pindex->pprev;
  }
  if (pindex) {
    USDEBlock block;
    if (block.ReadBlock(pindex->nHeight)) {
      pindex->pnext = NULL;
      block.SetBestChain(txdb, pindex);
    }
  }
  txdb.Close();
#endif
  CBlockIndex *pindex = cur_index->pprev;
  {
    USDEBlock block;
    if (block.ReadFromDisk(pindex)) {
      USDETxDB txdb;
//      pindex->pnext = NULL;
      block.SetBestChain(txdb, pindex);
      txdb.Close();
    }
  }

  err = BlockChainErase(iface, cur_index->nHeight);
  if (err)
    return error(err, "BlockChainErase[USDE]");

  return (true);
}

