

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

#ifndef __TEST__TEST_BLOCK_H__
#define __TEST__TEST_BLOCK_H__





class TEST_CTxMemPool : public CTxMemPool
{

  public:
    bool accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs);
    bool addUnchecked(const uint256& hash, CTransaction &tx);
    bool remove(CTransaction &tx);
    void queryHashes(std::vector<uint256>& vtxid);

};


class TESTBlock : public CBlock
{
public:
    // header
    static const int CURRENT_VERSION=1;
    static TEST_CTxMemPool mempool; 
    static CBlockIndex *pindexBest;
    static CBlockIndex *pindexGenesisBlock;// = NULL;
    static CBigNum bnBestChainWork;// = 0;
    static CBigNum bnBestInvalidWork;// = 0;
    static int64 nTimeBestReceived ;//= 0;

    static int64 nTargetTimespan;
    static int64 nTargetSpacing;

    TESTBlock()
    {
        ifaceIndex = TEST_COIN_IFACE;
        SetNull();
    }
    TESTBlock(const CBlock &block)
    {
        ifaceIndex = TEST_COIN_IFACE;
        SetNull();
        *((CBlock*)this) = block;
    }

    void SetNull()
    {
      nVersion = TESTBlock::CURRENT_VERSION;
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

  protected:
    bool SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew);
};



extern TEST_CTxMemPool TEST_mempool;

extern CBlockIndex* TEST_pindexGenesisBlock;
extern int TEST_nBestHeight;
extern CBigNum TEST_bnBestChainWork;
extern CBigNum TEST_bnBestInvalidWork;
extern uint256 TEST_hashBestChain;
extern CBlockIndex* TEST_pindexBest;
extern int64 TEST_nTimeBestReceived;

extern std::map<uint256, TESTBlock*> TEST_mapOrphanBlocks;
extern std::multimap<uint256, TESTBlock*> TEST_mapOrphanBlocksByPrev;
extern std::map<uint256, std::map<uint256, CDataStream*> > TEST_mapOrphanTransactionsByPrev;
extern std::map<uint256, CDataStream*> TEST_mapOrphanTransactions;
extern uint256 test_hashGenesisBlock;



CBlock* test_CreateNewBlock(CReserveKey& reservekey);

bool test_CreateGenesisBlock();

bool test_SetBestChain(CBlock *block);


bool test_ProcessBlock(CNode* pfrom, CBlock* pblock);

bool test_CheckBlock(CBlock *block);

uint256 test_GetOrphanRoot(const CBlock* pblock);

void test_SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate);

CBlock *test_GenerateBlock();

#endif /* ndef __TEST__TEST_BLOCK_H__ */
