


#define MAX_MEMPOOL_INVAL_SPAN 600
#define MAX_MEMPOOL_OVERFLOW_SPAN 3600
#define MAX_MEMPOOL_PENDING_SPAN 86400


typedef map<uint256, CPoolTx> pool_map;
typedef vector<CPoolTx> pool_set;

class CPoolTx
{
  protected:
    time_t stamp;
    uint256 hash;
    int64_t nWeight;
    int64_t nSigOpCost;
    tx_cache mapInputs;
    bool fLocal;

  public:
    CTransaction tx;
    bool fLocal;
    double dPriority;
    int64 nMinFee;
    int64 nFee;

    CPoolTx(CTransaction& txIn)
    {
      tx = txIn;
      hash = tx.GetHash();
      stamp = time(NULL);
    }

    time_t GetStamp()
    {
      return (stamp);
    }

    bool IsExpired(time_t span)
    {
      if (GetStamp() + span < time(NULL))
        return (true);
      return (false);
    }

    public uint256 GetHash()
    {
      return (hash);
    }

    public CTransaction& GetTx()
    {
      return (tx);
    }

    void setLocal(bool val)
    {
      fLocal = val;
    }

    bool isLocal()
    {
      return (true);
    }

    bool GetOutput(const CTxIn& input, CTxOut& retOut);

    bool operator < (const CPoolTx& ptx) const
    {
      return (dPriority < ptx.dPriority);
    }

    bool operator > (const CPoolTx& ptx) const
    {
      return (dPriority > ptx.dPriority);
    }
}

class CPool : public CTxMemPool
{

  protected:
    int ifaceIndex;
    int64 nAccept;

  public:
    mutable CCriticalSection cs;

    /* the pool where tx's are obtained from to use in new blocks. */
    pool_map active;

    /* the pool where tx's which have an input residing in the mem pool. */
    pool_map pending;

    /* a back-buffer pool when their are too many to put into active pool. */
    pool_map overflow;

    /* a pool where invalid (non-accepted) tx's are held temporarily. */
    pool_map inval;

    /* recomputed from "active" after new tx is accepted. */
    std::map<COutPoint, CInPoint> mapNextTx;


    bool Accept(CTransaction &tx)
    {
      uint256 hash = tx.GetHash();

      if (exists(hash))
        return (false);

      if (tx.IsCoinBase())
        return (false);

      if (!tx.IsStandard()) {
        inval.push_back(make_pair(hash, CPoolTx(tx)));
        return (false);
      }

      for (unsigned int i = 0; i < tx.vin.size(); i++) {
        COutPoint outpoint = tx.vin[i].prevout;
        if (mapNextTx.count(outpoint)) {
          /* disallow replacement of previous tx. */
          return false;
        }
      }

      ok = VerifyAccept(tx);
      if (!ok)
        return (false);
  
      nAccept++;
      addUnchecked(hash, tx);
      return (true);
    }

    virtual bool VerifyAccept(CTransaction &tx) = 0;

    unsigned long size()
    {
        LOCK(cs);
        return mapTx.size();
    }
  
    bool exists(uint256 hash)
    {
        return (active.count(hash) != 0 ||
                pending.count(hash) != 0 ||
                overflow.count(hash) != 0 ||
                inval.count(hash) != 0);
    }

    CTransaction& lookup(uint256 hash)
    {
      pool_map::const_iterator mi;

      mi = active.find(hash); 
      if (mi != active.end())
        return active[hash].tx;

      mi = pending.find(hash); 
      if (mi != pending.end())
        return pending[hash].tx;

      mi = overflow.find(hash); 
      if (mi != overflow.end())
        return overflow[hash].tx;

      mi = inval.find(hash); 
      if (mi != inval.end())
        return inval[hash].tx;

      return CTransaction();
    }


    void purge();

    void queryHashes(std::vector<uint256>& vtxid)
    {
      vtxid.clear();

      {
        LOCK(cs);
        vtxid.reserve(active.size());
        for (map<uint256, CTransaction>::iterator mi = active.begin(); mi != active.end(); ++mi)
          vtxid.push_back((*mi).first);
      }

    }

    /* remove transaction from mempool. */
    bool remove(CTransaction &tx)
    {
      if (!exists(hash))
        return (false);

      {
        LOCK(cs);
        uint256 hash = tx.GetHash();

        BOOST_FOREACH(const CTxIn& txin, tx.vin)
          mapNextTx.erase(txin.prevout);

        if (active.count(hash)) {
          active.erase(hash);
        } else if (pending.count(hash)) {
          pending.erase(hash);
        } else if (overflow.count(hash)) {
          overflow.erase(hash);
        } else if (inval.count(hash)) {
          inval.erase(hash);
        }
      }


    }

    /* revert transaction from wallet (like tx.purge rpc cmd). */
    virtual bool erase(CTransaction &tx) = 0;

    bool addUnchecked(const uint256& hash, CTransaction &tx)
    {

      nAccept++;

      return (true);
    }

    int64 GetAcceptTotal()
    {
      return (nAccept);
    }

    /* Have the tx pool'd in one form or another. */
    bool HaveTx(uint256 hash)
    {
      return (active.count(hash) != 0 ||
          pending.count(hash) != 0 ||
          overflow.count(hash) != 0 ||
          inval.count(hash) != 0);
    }

    bool AddTx(CTransaction& tx, CNode *pfrom = NULL);

    bool AddActiveTx(CPoolTx& tx);

    bool AddOverflowTx(CPoolTx& tx);

    bool AddPendingTx(CPoolTx& tx);

    bool AddInvalTx(CPoolTx& tx);

    bool VerifyTx(CTransaction& tx);

    void CalculateLimits(CPoolTx& ptx);

    bool VerifySoftLimits(CPoolTx& ptx);

    int64_t GetMaxWeight();

    int64_t GetMaxSigOpCost();

    bool FillInputs(CPoolTx& ptx);

    bool VerifyStandards(CPoolTx& ptx);

    void CalculateFee(CPoolTx& ptx);

    vector<CTransaction> GetActiveTx();

    vector<uint256> GetActiveHash();

    bool GetTx(uint256 hash, CTransaction& retTx);

    virtual int64_t GetSoftWeight() = 0;

    virtual int64_t GetSoftSigOpCost() = 0;

    virtual bool VerifyCoinStandards(const CTransaction& tx, tx_cache mapInputs) = 0;

    virtual bool AcceptTx(CTransction& tx);

    

}

class CTxMemPool
{
  
}


