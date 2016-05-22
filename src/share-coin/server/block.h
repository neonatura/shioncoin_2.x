
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

#ifndef __SERVER__BLOCK_H__
#define __SERVER__BLOCK_H__

//#include "shcoind.h"
#include <boost/foreach.hpp>

#include "uint256.h"
#include "serialize.h"
#include "util.h"
#include "scrypt.h"
#include "protocol.h"
#include "net.h"
#include "script.h"
#include "coin_proto.h"
#include <vector>

typedef std::vector<uint256> HashList;


class CTxDB;


bc_t *GetBlockChain(CIface *iface);

bc_t *GetBlockTxChain(CIface *iface);;

void CloseBlockChains(void);



bool GetTransaction(CIface *iface, const uint256 &hash, CTransaction &tx, uint256 &hashBlock);



/* block_iface.cpp */
int GetBlockDepthInMainChain(CIface *iface, uint256 blockHash);
int GetTxDepthInMainChain(CIface *iface, uint256 txHash);




extern FILE* AppendBlockFile(unsigned int& nFileRet);
extern bool IsInitialBlockDownload();
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode);



enum GetMinFee_mode
{
    GMF_BLOCK,
    GMF_RELAY,
    GMF_SEND,
};

static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC


#if 0
/* 1MEG Max Block Size */
#define MAX_BLOCK_SIZE USDE_MAX_BLOCK_SIZE
#define MAX_BLOCK_SIGOPS USDE_MAX_BLOCK_SIGOPS
#define MIN_TX_FEE USDE_MIN_TX_FEE
#define MIN_RELAY_TX_FEE USDE_MIN_RELAY_TX_FEE
#define MAX_MONEY USDE_MAX_MONEY
#define COINBASE_MATURITY USDE_COINBASE_MATURITY
#endif

#if 0
static const unsigned int MAX_BLOCK_SIZE = 1000000;
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE/2;
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
static const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE/100;
static const int64 MIN_TX_FEE = 10000000;
static const int64 MIN_RELAY_TX_FEE = MIN_TX_FEE;
#if CLIENT_VERSION_REVISION > 4
static const int64 MAX_MONEY = 320000000000 * COIN; /* 320bil */
#else
static const int64 MAX_MONEY = 1600000000 * COIN; /* 1.6bil */
#endif
static const int COINBASE_MATURITY = 100;
#endif


inline bool MoneyRange(CIface *iface, int64 nValue) 
{ 
  if (!iface) return (false);
  return (nValue >= 0 && nValue <= iface->max_money);
}
inline bool MoneyRange(int ifaceIndex, int64 nValue) 
{
  CIface *iface = GetCoinByIndex(ifaceIndex);
  if (!iface) return (false);
  return (nValue >= 0 && nValue <= iface->max_money);
}


/** Reference to a specific block transaction. */
class CDiskTxPos
{
public:
    unsigned int nFile;
    unsigned int nBlockPos;
    unsigned int nTxPos;
    mutable uint256 hashBlock;
    mutable uint256 hashTx;

    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
    {
      SetNull();
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
    }
#if 0
    CDiskTxPos(uint256 hash, uint256 tx_hash)
    {
      SetNull();
hashBlock = hash;
hashTx = tx_hash;
    }
#endif

    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { nFile = (unsigned int) -1; nBlockPos = 0; nTxPos = 0; }
    bool IsNull() const { return (nFile == (unsigned int) -1); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
#if 0
        return (a.hashBlock == b.hashBlock &&
                a.hashTx    == b.hashTx);
#endif
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        if (IsNull())
            return "null";
        else
            return strprintf("(nTxHeight=%d, nBlockHeight=%d, nTxPos=%d)", nFile, nBlockPos, nTxPos);
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};


/**  A txdb record that contains the disk location of a transaction and the
 * locations of transactions that spend its outputs.  vSpent is really only
 * used as a flag, but having the location is very helpful for debugging.
 */
class CTxIndex
{
public:
    CDiskTxPos pos;
    std::vector<CDiskTxPos> vSpent;

    CTxIndex()
    {
        SetNull();
    }

    CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
    {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    )

    void SetNull()
    {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull()
    {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex& a, const CTxIndex& b)
    {
        return (a.pos    == b.pos &&
                a.vSpent == b.vSpent);
    }

    friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
    {
        return !(a == b);
    }
//    int GetDepthInMainChain() const;
 
};
typedef std::map<uint256, std::pair<CTxIndex, CTransaction> > MapPrevTx;



/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
public:
    CTransaction* ptx;
    unsigned int n;

    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = (unsigned int) -1; }
    bool IsNull() const { return (ptx == NULL && n == (unsigned int) -1); }
};



/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE( READWRITE(FLATDATA(*this)); )
    void SetNull() { hash = 0; n = (unsigned int) -1; }
    bool IsNull() const { return (hash == 0 && n == (unsigned int) -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        return strprintf("COutPoint(%s, %d)", hash.ToString().substr(0,10).c_str(), n);
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};



/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    unsigned int nSequence;

    CTxIn()
    {
        nSequence = std::numeric_limits<unsigned int>::max();
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max())
    {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max())
    {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    )

    bool IsFinal() const
    {
        return (nSequence == std::numeric_limits<unsigned int>::max());
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        std::string str;
        str += "CTxIn(";
        str += prevout.ToString();
        if (prevout.IsNull())
            str += strprintf(", coinbase %s", HexStr(scriptSig).c_str());
        else
            str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24).c_str());
        if (nSequence != std::numeric_limits<unsigned int>::max())
            str += strprintf(", nSequence=%u", nSequence);
        str += ")";
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    int64 nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(int64 nValueIn, CScript scriptPubKeyIn)
    {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    )

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull()
    {
        return (nValue == -1);
    }

    uint256 GetHash() const
    {
      return SerializeHash(*this);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        if (scriptPubKey.size() < 6)
            return "CTxOut(error)";
        return strprintf("CTxOut(nValue=%"PRI64d".%08"PRI64d", scriptPubKey=%s)", nValue / COIN, nValue % COIN, scriptPubKey.ToString().substr(0,30).c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

class CBlockIndex;
typedef std::map<uint256, CBlockIndex*> blkidx_t;

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    static const int TX_VERSION = (1 << 0);
    int nFlag;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    unsigned int nLockTime;

    // Denial-of-service detection:
    mutable int nDoS;
    bool DoS(int nDoSIn, bool fIn) const { nDoS += nDoSIn; return fIn; }

    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        //READWRITE(this->nVersion);
        READWRITE(this->nFlag);
        nVersion = 1;//this->nVersion;
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    )

    void Init(CTransaction tx)
    {
      nFlag = tx.nFlag;
      vin = tx.vin;
      vout = tx.vout;
      nLockTime = tx.nLockTime;
    }

    void SetNull()
    {
        nFlag = CTransaction::TX_VERSION;
        vin.clear();
        vout.clear();
        nLockTime = 0;
        nDoS = 0;  // Denial-of-service prevention
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    bool isFlag(int flag) const
    {
      if ( (nFlag & flag) ) {
        return (true);
      } 
      return (false);
    }

    uint256 GetHash() const
    {
      return SerializeHash(*this);
    }

    bool IsFinal(int ifaceIndex, int nBlockHeight=0, int64 nBlockTime=0) const;

    bool IsNewerThan(const CTransaction& old) const
    {
        if (vin.size() != old.vin.size())
            return false;
        for (unsigned int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != old.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = std::numeric_limits<unsigned int>::max();
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            if (vin[i].nSequence != old.vin[i].nSequence)
            {
                if (vin[i].nSequence <= nLowest)
                {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest)
                {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    /** Check for standard transaction types
        @return True if all outputs (scriptPubKeys) use only standard transaction forms
    */
    bool IsStandard() const;

    /** Check for standard transaction types
        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return True if all inputs (scriptSigs) use only standard transaction forms
        @see CTransaction::FetchInputs
    */
    bool AreInputsStandard(const MapPrevTx& mapInputs) const;

    /** Count ECDSA signature operations the old-fashioned (pre-0.6) way
        @return number of sigops this transaction's outputs will produce when spent
        @see CTransaction::FetchInputs
    */
    unsigned int GetLegacySigOpCount() const;

    /** Count ECDSA signature operations in pay-to-script-hash inputs.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return maximum number of sigops required to validate this transaction's inputs
        @see CTransaction::FetchInputs
     */
    unsigned int GetP2SHSigOpCount(const MapPrevTx& mapInputs) const;

    /** Amount of bitcoins spent by this transaction.
        @return sum of all outputs (note: does not include fees)
     */
    int64 GetValueOut() const
    {
        int64 nValueOut = 0;
        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            nValueOut += txout.nValue;
#if 0
            if (!MoneyRange(iface, txout.nValue) || !MoneyRange(iface, nValueOut))
                throw std::runtime_error("CTransaction::GetValueOut() : value out of range");
#endif
        }
        return nValueOut;
    }

    /** Amount of bitcoins coming in to this transaction
        Note that lightweight clients may not know anything besides the hash of previous transactions,
        so may not be able to calculate this.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return	Sum of value of all inputs (scriptSigs)
        @see CTransaction::FetchInputs
     */
    int64 GetValueIn(const MapPrevTx& mapInputs) const;

    static bool AllowFree(double dPriority)
    {
        // Large (in bytes) low-priority (new, small-coin) transactions
        // need a fee.
        return dPriority > COIN * 700 / 250; // usde: 480 blocks found a day. Priority cutoff is 1 usde day / 250 bytes.
    }

    int64 GetMinFee(int ifaceIndex, unsigned int nBlockSize=1, bool fAllowFree=true, enum GetMinFee_mode mode=GMF_BLOCK) const
    {
      CIface *iface = GetCoinByIndex(ifaceIndex);
      if (!iface)
        return (0);

      // Base fee is either MIN_TX_FEE or MIN_RELAY_TX_FEE
      //int64 nBaseFee = (mode == GMF_RELAY) ? MIN_RELAY_TX_FEE : MIN_TX_FEE;
      int64 nBaseFee = (mode == GMF_RELAY) ? iface->min_relay_tx_fee : iface->min_tx_fee;

      unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION(iface));
      unsigned int nNewBlockSize = nBlockSize + nBytes;
      int64 nMinFee = (1 + (int64)nBytes / 1000) * nBaseFee;

      if (fAllowFree)
      {
        if (nBlockSize == 1)
        {
          // Transactions under 10K are free
          // (about 4500bc if made of 50bc inputs)
          if (nBytes < 10000)
            nMinFee = 0;
        }
        else
        {
          // Free transaction area
          if (nNewBlockSize < 27000)
            nMinFee = 0;
        }
      }

      // To limit dust spam, add MIN_TX_FEE/MIN_RELAY_TX_FEE for any output that is less than 0.01
      BOOST_FOREACH(const CTxOut& txout, vout)
        if (txout.nValue < CENT)
          nMinFee += nBaseFee;

      // Raise the price as the block approaches full
      if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN(iface)/2)
      {
        if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN(iface))
          return (iface->max_money);
        nMinFee *= MAX_BLOCK_SIZE_GEN(iface) / (MAX_BLOCK_SIZE_GEN(iface) - nNewBlockSize);
      }

      if (!MoneyRange(iface, nMinFee))
        nMinFee = iface->max_money;
      return nMinFee;
    }

#if 0
    bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
    {
        CAutoFile filein = CAutoFile(OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb"), SER_DISK, CLIENT_VERSION);
        if (!filein)
            return error(SHERR_IO, "CTransaction::ReadFromDisk() : OpenBlockFile failed");

        // Read transaction
        if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
            return error(SHERR_IO, "CTransaction::ReadFromDisk() : fseek failed");

        try {
            filein >> *this;
        }
        catch (std::exception &e) {
            return error(SHERR_IO, "%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
        }

        // Return file pointer
        if (pfileRet)
        {
            if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
                return error(SHERR_IO, "CTransaction::ReadFromDisk() : second fseek failed");
            *pfileRet = filein.release();
        }
        return true;
    }
#endif

#if 0
    bool ReadFromDisk(int ifaceIndex, CDiskTxPos pos)
    {
      ReadTx(ifaceIndex, pos.hashTx);
    }
#endif

    bool ReadTx(int ifaceIndex, uint256 txHash);

    bool ReadTx(int ifaceIndex, uint256 txHash, uint256 &hashBlock);

    bool WriteTx(int ifaceIndex, uint64_t blockHeight);

    bool ReadFromDisk(CDiskTxPos pos);
    bool ReadFromDisk(int ifaceIndex, COutPoint prevout);

    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet);

    bool FillTx(int ifaceIndex, CDiskTxPos &pos);



    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nFlag  == b.nFlag &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }


    std::string ToString() const
    {
        std::string str;
        str += strprintf("CTransaction(hash=%s, flag=%d, vin.size=%d, vout.size=%d, nLockTime=%d)\n",
            GetHash().ToString().substr(0,10).c_str(),
            nFlag,
            vin.size(),
            vout.size(),
            nLockTime);
        for (unsigned int i = 0; i < vin.size(); i++)
            str += "    " + vin[i].ToString() + "\n";
        for (unsigned int i = 0; i < vout.size(); i++)
            str += "    " + vout[i].ToString() + "\n";
        return str;
    }

    void print() const
    {
        fprintf(stderr, "%s", ToString().c_str());
    }


    bool DisconnectInputs(CTxDB& txdb);

    /** 
     * Fetch from memory and/or disk. inputsRet keys are transaction hashes.
     *
     * @param[in] txdb  Transaction database
     * @param[in] mapTestPool List of pending changes to the transaction index database
     * @param[in] fBlock  True if being called to add a new best-block to the chain
     * @param[in] fMiner  True if being called by CreateNewBlock
     * @param[out] inputsRet  Pointers to this transaction's inputs
     * @param[out] fInvalid returns true if transaction is invalid
     * @return  Returns true if all inputs are in txdb or mapTestPool
     */
    bool FetchInputs(CTxDB& txdb, const std::map<uint256, CTxIndex>& mapTestPool, bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid);



    bool ClientConnectInputs(int ifaceIndex);
    bool CheckTransaction(int ifaceIndex) const;
    bool AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs=true, bool* pfMissingInputs=NULL);

protected:
    const CTxOut& GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const;
};

class CBlockCore
{
  public:
    mutable int nDoS;

    CBlockCore()
    {
      SetNull();
    }

    void SetNull()
    {
      nDoS = 0;
    }

    bool DoS(int nDoSIn, bool fIn) const 
    {
      nDoS += nDoSIn;
      return fIn;
    }
};

class CBlockHeader : public CBlockCore
{
public:
    /* block header */
    int nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    CBlockHeader()
    {
      nVersion = 1;
      SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    )

    void SetNull()
    {
      CBlockCore::SetNull();
      hashPrevBlock = 0;
      hashMerkleRoot = 0;
      nTime = 0;
      nBits = 0;
      nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const
    {
        return Hash(BEGIN(nVersion), END(nNonce));
    }

    int64 GetBlockTime() const
    {
        return (int64)nTime;
    }
};


/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlock : public CBlockHeader
{
  public:
    std::vector<CTransaction> vtx;
    mutable std::vector<uint256> vMerkleTree; /* mem only */
    mutable int ifaceIndex;
    mutable CNode *originPeer;

    CBlock()
    {
      SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
      SetNull();
      *((CBlockHeader*)this) = header;
    }

    IMPLEMENT_SERIALIZE
      (
       READWRITE(*(CBlockHeader*)this);
       READWRITE(vtx);
      )

    void SetNull()
    {
      CBlockHeader::SetNull();
      vtx.clear();
      vMerkleTree.clear();
    }

    bool IsNull() const
    {
      return (nBits == 0);
    }

    uint256 GetPoWHash() const
    {
      uint256 thash;
      scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
      return thash;
    }

    /* block_merkle.cpp */
    uint256 BuildMerkleTree() const;
    std::vector<uint256> GetMerkleBranch(int nIndex) const;
    uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);

#if 0
    bool WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
    {
      // Open history file to append
      CAutoFile fileout = CAutoFile(AppendBlockFile(nFileRet), SER_DISK, CLIENT_VERSION);
      if (!fileout)
        return error(SHERR_IO, "CBlock::WriteToDisk() : AppendBlockFile failed");

      // Write index header
      unsigned int nSize = fileout.GetSerializeSize(*this);
      fileout << FLATDATA(pchMessageStart) << nSize;

      // Write block
      long fileOutPos = ftell(fileout);
      if (fileOutPos < 0)
        return error(SHERR_IO, "CBlock::WriteToDisk() : ftell failed");
      nBlockPosRet = fileOutPos;
      fileout << *this;

      // Flush stdio buffers and commit to disk before returning
      fflush(fileout);
      if (!IsInitialBlockDownload() || (nBestHeight+1) % 500 == 0)
        FileCommit(fileout);

      return true;
    }
#endif



    void print() const
    {
      fprintf(stderr, "CBlock(hash=%s, PoW=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%lu)\n",
          GetHash().ToString().substr(0,20).c_str(),
          GetPoWHash().ToString().substr(0,20).c_str(),
          nVersion,
          hashPrevBlock.ToString().substr(0,20).c_str(),
          hashMerkleRoot.ToString().substr(0,10).c_str(),
          nTime, nBits, nNonce,
          vtx.size());
      for (unsigned int i = 0; i < vtx.size(); i++)
      {
        printf("  ");
        vtx[i].print();
      }
      printf("  vMerkleTree: ");
      for (unsigned int i = 0; i < vMerkleTree.size(); i++)
        printf("%s ", vMerkleTree[i].ToString().substr(0,10).c_str());
      printf("\n");
    }

    //bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos);
//    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions=true);

    void UpdateTime(const CBlockIndex* pindexPrev);
    bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool WriteBlock(uint64_t nHeight);
    bool ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions=true);
    const CTransaction *GetTx(uint256 hash);

    virtual bool ReadBlock(uint64_t nHeight) = 0;
    virtual bool CheckBlock() = 0;
    virtual bool SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew) = 0;
    virtual bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex) = 0;
    virtual bool IsBestChain() = 0;
    virtual unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast) = 0;
    virtual CScript GetCoinbaseFlags() = 0;
    virtual bool AcceptBlock() = 0;
    virtual bool IsOrphan() = 0;
    virtual bool AddToBlockIndex() = 0;
    virtual void InvalidChainFound(CBlockIndex* pindexNew) = 0;

  protected:
    virtual bool SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew) = 0;
};

CBlock *GetBlankBlock(CIface *iface);

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block.  pprev and pnext link a path through the
 * main/longest chain.  A blockindex may have multiple pprev pointing back
 * to it, but pnext will only point forward to the longest branch, or will
 * be null if the block is not part of the longest chain.
 */
class CBlockIndex : public CBlockHeader
{
  public:
    const uint256* phashBlock;
    CBlockIndex* pprev;
    CBlockIndex* pnext;
    //    unsigned int nFile;
    //    unsigned int nBlockPos;
    int nHeight;
    CBigNum bnChainWork;

#if 0
    // block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;
#endif


    CBlockIndex()
    {
      phashBlock = NULL;
      pprev = NULL;
      pnext = NULL;
      //       nFile = 0;
      //        nBlockPos = 0;
      nHeight = 0;
      bnChainWork = 0;

      nVersion       = 0;
      hashMerkleRoot = 0;
      nTime          = 0;
      nBits          = 0;
      nNonce         = 0;
    }

#if 0
    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
    {
      phashBlock = NULL;
      pprev = NULL;
      pnext = NULL;
      nFile = nFileIn;
      nBlockPos = nBlockPosIn;
      nHeight = 0;
      bnChainWork = 0;

      nVersion       = block.nVersion;
      hashMerkleRoot = block.hashMerkleRoot;
      nTime          = block.nTime;
      nBits          = block.nBits;
      nNonce         = block.nNonce;
    }
#endif

    CBlockIndex(CBlock& block)
    {
      phashBlock = NULL;
      pprev = NULL;
      pnext = NULL;
      //        nFile = nFileIn;
      //       nBlockPos = nBlockPosIn;
      nHeight = 0;
      bnChainWork = 0;

      nVersion       = block.nVersion;
      hashMerkleRoot = block.hashMerkleRoot;
      nTime          = block.nTime;
      nBits          = block.nBits;
      nNonce         = block.nNonce;
    }

    CBlockHeader GetBlockHeader() const
    {
      CBlockHeader block;
      block.nVersion       = nVersion;
      if (pprev)
        block.hashPrevBlock = pprev->GetBlockHash();
      block.hashMerkleRoot = hashMerkleRoot;
      block.nTime          = nTime;
      block.nBits          = nBits;
      block.nNonce         = nNonce;
      return block;
    }

    uint256 GetBlockHash() const
    {
      return *phashBlock;
    }

    int64 GetBlockTime() const
    {
      return (int64)nTime;
    }

    CBigNum GetBlockWork() const
    {
      CBigNum bnTarget;
      bnTarget.SetCompact(nBits);
      if (bnTarget <= 0)
        return 0;
      return (CBigNum(1)<<256) / (bnTarget+1);
    }

    //bool IsInMainChain() const;
    bool IsInMainChain(int ifaceIndex) const;

    bool CheckIndex() const
    {
      return true; // CheckProofOfWork(GetBlockHash(), nBits);
    }

    enum { nMedianTimeSpan=11 };

    int64 GetMedianTimePast() const
    {
      int64 pmedian[nMedianTimeSpan];
      int64* pbegin = &pmedian[nMedianTimeSpan];
      int64* pend = &pmedian[nMedianTimeSpan];

      const CBlockIndex* pindex = this;
      for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
        *(--pbegin) = pindex->GetBlockTime();

      std::sort(pbegin, pend);
      return pbegin[(pend - pbegin)/2];
    }

    int64 GetMedianTime() const
    {
      const CBlockIndex* pindex = this;
      for (int i = 0; i < nMedianTimeSpan/2; i++)
      {
        if (!pindex->pnext)
          return GetBlockTime();
        pindex = pindex->pnext;
      }
      return pindex->GetMedianTimePast();
    }



    std::string ToString() const
    {
      return strprintf("CBlockIndex(nprev=%08x, pnext=%08x, nHeight=%d, merkle=%s, hashBlock=%s)",
          pprev, pnext, nHeight,
          hashMerkleRoot.ToString().c_str(),
          GetBlockHash().ToString().c_str());
    }

    void print() const
    {
      printf("%s\n", ToString().c_str());
    }
};

class USDE_CTxMemPool;
class USDEBlock : public CBlock
{
public:
    // header
    static const int CURRENT_VERSION=1;
    static USDE_CTxMemPool mempool; 
    static uint256 hashBestChain;
    static CBlockIndex *pindexBest;
    static CBlockIndex *pindexGenesisBlock;// = NULL;
    static CBigNum bnBestChainWork;// = 0;
    static CBigNum bnBestInvalidWork;// = 0;
    static int64 nTimeBestReceived ;//= 0;

    static int64 nTargetTimespan;
    static int64 nTargetSpacing;

    USDEBlock()
    {
        ifaceIndex = USDE_COIN_IFACE;
        SetNull();
    }
    USDEBlock(const CBlock &block)
    {
        ifaceIndex = USDE_COIN_IFACE;
        SetNull();
        *((CBlock*)this) = block;
    }

    void SetNull()
    {
      nVersion = USDEBlock::CURRENT_VERSION;
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
    bool IsOrphan();

  protected:
    bool SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew);
};

#if 0
class GMCBlock : public CBlock
{
public:
    // header
    static const int CURRENT_VERSION=2;

    GMCBlock()
    {
//        ifaceIndex = GMC_COIN_IFACE;
        SetNull();
    }

    void SetNull()
    {
      nVersion = GMCBlock::CURRENT_VERSION;
      CBlock::SetNull();
    }
};
#endif

class SHC_CTxMemPool;
class SHCBlock : public CBlock
{
public:
    // header
    static const int CURRENT_VERSION=2;
    static SHC_CTxMemPool mempool; 
    static uint256 hashBestChain;
    static CBlockIndex *pindexBest;
    static CBlockIndex *pindexGenesisBlock;
    static CBigNum bnBestChainWork;
    static CBigNum bnBestInvalidWork;
    static int64 nTimeBestReceived;

    SHCBlock()
    {
        ifaceIndex = SHC_COIN_IFACE;
        SetNull();
    }

    SHCBlock(const CBlock &block)
    {
        ifaceIndex = SHC_COIN_IFACE;
        SetNull();
        *((CBlock*)this) = block;
    }

    void SetNull()
    {
      nVersion = SHCBlock::CURRENT_VERSION;
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
    bool IsOrphan();

  protected:
    bool SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew);
};

class CTxMemPool
{
public:
    mutable CCriticalSection cs;
    std::map<uint256, CTransaction> mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;

    virtual bool accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs) = 0;

    unsigned long size()
    {
        LOCK(cs);
        return mapTx.size();
    }

    bool exists(uint256 hash)
    {
        return (mapTx.count(hash) != 0);
    }

    CTransaction& lookup(uint256 hash)
    {
        return mapTx[hash];
    }

    virtual void queryHashes(std::vector<uint256>& vtxid) = 0;
};

blkidx_t *GetBlockTable(int ifaceIndex);

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
class CBlockLocator
{
  protected:
    std::vector<uint256> vHave;
    mutable int ifaceIndex;
  public:

    CBlockLocator(int ifaceIndexIn)
    {
      ifaceIndex = ifaceIndexIn;
    }

    explicit CBlockLocator(int ifaceIndexIn, const CBlockIndex* pindex)
    {
      ifaceIndex = ifaceIndexIn;
      Set(pindex);
    }

    explicit CBlockLocator(int ifaceIndexIn, uint256 hashBlock)
    {
      ifaceIndex = ifaceIndexIn;
      blkidx_t *blockIndex = GetBlockTable(ifaceIndex); 
      std::map<uint256, CBlockIndex*>::iterator mi = blockIndex->find(hashBlock);
      if (mi != blockIndex->end())
        Set((*mi).second);
    }

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
      vHave = vHaveIn;
    }

    IMPLEMENT_SERIALIZE
      (
       if (!(nType & SER_GETHASH))
       READWRITE(nVersion);
       READWRITE(vHave);
      )

      void SetNull()
      {
        vHave.clear();
      }

    bool IsNull()
    {
      return vHave.empty();
    }

    void Set(const CBlockIndex* pindex);

    int GetDistanceBack();

    CBlockIndex* GetBlockIndex();

    uint256 GetBlockHash();

    int GetHeight();
};



CBlock *GetBlockByHeight(CIface *iface, int nHeight);

CBlock *GetBlockByHash(CIface *iface, const uint256 hash);

CBlock *GetBlockByTx(CIface *iface, const uint256 hash);

CBlock *CreateBlockTemplate(CIface *iface);

CTxMemPool *GetTxMemPool(CIface *iface);

uint256 GetBlockBestChain(CIface *iface);

void SetBlockBestChain(CIface *iface, CBlock *block);

bool ProcessBlock(CNode* pfrom, CBlock* pblock);

int64 GetBestHeight(CIface *iface);

void SetBestHeight(CIface *iface, int nBestHeight);

int64 GetBestHeight(int ifaceIndex);

bool IsInitialBlockDownload(int ifaceIndex);

uint256 GetBestBlockChain(CIface *iface);

CBlockIndex *GetGenesisBlockIndex(CIface *iface);


void SetBestBlockIndex(CIface *iface, CBlockIndex *pindex);

void SetBestBlockIndex(int ifaceIndex, CBlockIndex *pindex);

CBlockIndex *GetBestBlockIndex(CIface *iface);

CBlockIndex *GetBestBlockIndex(int ifaceIndex);

bool BlockTxExists(CIface *iface, uint256 hashTx);


#endif /* ndef __SERVER_BLOCK_H__ */




