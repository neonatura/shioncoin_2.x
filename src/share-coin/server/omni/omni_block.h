
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

#ifndef __OMNI_BLOCK_H__
#define __OMNI_BLOCK_H__


/**
 * @ingroup sharecoin_omni
 * @{
 */

#include <boost/assign/list_of.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <share.h>




class OMNI_CTxMemPool : public CTxMemPool
{

  public:
    bool accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs);
    bool addUnchecked(const uint256& hash, CTransaction &tx);
    bool remove(CTransaction &tx);
    void queryHashes(std::vector<uint256>& vtxid);

};

class OMNIBlock : public CBlock
{
public:
    // header
    static const int CURRENT_VERSION=2;
    static OMNI_CTxMemPool mempool; 
    static CBlockIndex *pindexBest;
    static CBlockIndex *pindexGenesisBlock;
    static CBigNum bnBestChainWork;
    static CBigNum bnBestInvalidWork;
    static int64 nTimeBestReceived;

    OMNIBlock()
    {
        ifaceIndex = OMNI_COIN_IFACE;
        SetNull();
    }

    OMNIBlock(const CBlock &block)
    {
        ifaceIndex = OMNI_COIN_IFACE;
        SetNull();
        *((CBlock*)this) = block;
    }

    void SetNull()
    {
      nVersion = OMNIBlock::CURRENT_VERSION;
      CBlock::SetNull();
    }

    bool SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew);
    void InvalidChainFound(CBlockIndex* pindexNew);
    unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast);
    bool AcceptBlock();
    bool IsBestChain();
    CScript GetCoinbaseFlags();
    bool AddToBlockIndex();
    bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool CheckBlock();
    bool ReadBlock(uint64_t nHeight);
    bool ReadArchBlock(uint256 hash);
    bool IsOrphan();
    bool Truncate();
    bool VerifyCheckpoint(int nHeight);
    uint64_t GetTotalBlocksEstimate();
    bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);

  protected:
    bool SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew);
};



/**
 * A memory pool where an inventory of pending block transactions are stored.
 */
extern OMNI_CTxMemPool OMNI_mempool;

/**
 * The best known tail of the OMNI block-chain.
 */
extern CBlockIndex* OMNI_pindexBest;

/**
 * The initial block in the OMNI block-chain's index reference.
 */
extern CBlockIndex* OMNI_pindexGenesisBlock;

/**
 * The block hash of the initial block in the OMNI block-chain.
 */
extern uint256 omni_hashGenesisBlock;


extern int OMNI_nBestHeight;
extern CBigNum OMNI_bnBestChainWork;
extern CBigNum OMNI_bnBestInvalidWork;
extern uint256 OMNI_hashBestChain;
extern int64 OMNI_nTimeBestReceived;

extern std::map<uint256, OMNIBlock*> OMNI_mapOrphanBlocks;
extern std::multimap<uint256, OMNIBlock*> OMNI_mapOrphanBlocksByPrev;
extern std::map<uint256, std::map<uint256, CDataStream*> > OMNI_mapOrphanTransactionsByPrev;
extern std::map<uint256, CDataStream*> OMNI_mapOrphanTransactions;




/**
 * Create a block template with pending inventoried transactions.
 */
CBlock* omni_CreateNewBlock(CReserveKey& reservekey);

/**
 * Generate the inital OMNI block in the block-chain.
 */
bool omni_CreateGenesisBlock();

/**
 * Set the best known block hash.
 */
bool omni_SetBestChain(CBlock *block);

/**
 * Attempt to process an incoming block from a remote OMNI coin service.
 */
bool omni_ProcessBlock(CNode* pfrom, CBlock* pblock);

/**
 * Get the first block in the best "alternate" chain not currently in the main block-chain.
 */
uint256 omni_GetOrphanRoot(const CBlock* pblock);



/**
 * @}
 */

#endif /* ndef __OMNI_BLOCK_H__ */
