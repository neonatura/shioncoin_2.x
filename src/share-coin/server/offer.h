

#ifndef __OFFER_H__
#define __OFFER_H__


typedef std::map<uint160, uint256> offer_list; /* hashOffer -> hashTx */

class CCoinAddr;

class COfferCore : public CExtCore 
{
  public:
    cbuff vPayAddr;
    cbuff vXferAddr;
    cbuff vXferTx;
    int64 nPayValue;
    int64 nXferValue;

    COfferCore() { 
      SetNull();
    }

    COfferCore(const COfferCore& offerIn)
    {
      SetNull();
      Init(offerIn);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(CExtCore *)this);
      READWRITE(vPayAddr);
      READWRITE(vXferAddr);
      READWRITE(vXferTx);
      READWRITE(nPayValue);
      READWRITE(nXferValue);
    )


    friend bool operator==(const COfferCore &a, const COfferCore &b) {
      return (
          ((CExtCore&) a) == ((CExtCore&) b) &&
          a.vPayAddr == b.vPayAddr &&
          a.vXferAddr == b.vXferAddr &&
          a.vXferTx == b.vXferTx &&
          a.nPayValue == b.nPayValue &&
          a.nXferValue == b.nXferValue 
          );
    }

    void Init(const COfferCore& b)
    {
      CExtCore::Init(b);
      vPayAddr = b.vPayAddr;
      vXferAddr = b.vXferAddr;
      vXferTx = b.vXferTx;
      nPayValue = b.nPayValue;
      nXferValue = b.nXferValue;
    }

    COfferCore operator=(const COfferCore &b)
    {
      Init(b);
      return *this;
    }

    friend bool operator!=(const COfferCore &a, const COfferCore &b) {
        return !(a == b);
    }
    
    void SetNull() 
    {
      CExtCore::SetNull();
      vPayAddr.clear(); 
      vXferAddr.clear(); 
      vXferTx.clear(); 
      nPayValue = 0;
      nXferValue = 0;
    }

    bool IsNull() const 
    {
      return (nPayValue == 0 || nXferValue == 0);
    }

    const uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }


    bool GetPayAddr(int ifaceIndex, CCoinAddr& addr);
    bool GetXferAddr(int ifaceIndex, CCoinAddr& addr, std::string& account);
};

class COfferAccept : public COfferCore 
{
  public:
    uint160 hashOffer;

    COfferAccept() {
      SetNull();
    }

    COfferAccept(const COfferAccept& b)
    {
      SetNull();
      Init(b);
    }

    COfferAccept(COfferCore& b)
    {
      SetNull();
      COfferCore::Init(b);
      hashOffer = b.GetHash();
    }

    COfferAccept(const uint160& hashOfferIn, int64 srcValueIn, int64 destValueIn)
    {
      hashOffer = hashOfferIn;
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(COfferCore *)this);
      READWRITE(hashOffer);
    )

    friend bool operator==(const COfferAccept &a, const COfferAccept &b) {
      return (
          ((COfferCore&) a) == ((COfferCore&) b) &&
          a.hashOffer == b.hashOffer
          );
    }

    COfferAccept operator=(const COfferAccept &b) 
    {
      Init(b);
      return *this;
    }

    friend bool operator!=(const COfferAccept &a, const COfferAccept &b) {
        return !(a == b);
    }

    void Init(const COfferAccept& b)
    {
      COfferCore::Init(b);
      hashOffer = b.hashOffer;
    }

    void SetNull()
    {
      COfferCore::SetNull();
      hashOffer = 0;
    }

    bool IsNull() const 
    {
      return (COfferCore::IsNull());
    }

    const uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }
    
};

class COffer : public COfferAccept
{
  public:
    int nPayCoin;
    int nXferCoin;
    unsigned int nType;
    std::vector<COfferAccept>accepts;

    COffer() {
      SetNull();
    }

    COffer(const COffer& offerIn)
    {
      SetNull();
      Init(offerIn);
    }
    COffer(const COfferAccept& accept)
    {
      SetNull();
      COfferAccept::Init(accept);
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(COfferAccept *)this);
        READWRITE(this->nPayCoin);
        READWRITE(this->nXferCoin);
        READWRITE(this->nType);
        READWRITE(this->vXferTx);
        READWRITE(this->accepts);
        )

      friend bool operator==(const COffer &a, const COffer &b) {
        return (
            ((COfferAccept&) a) == ((COfferAccept&) b) &&
            a.nPayCoin == b.nPayCoin &&
            a.nXferCoin == b.nXferCoin &&
            a.nType == b.nType &&
            a.vXferTx == b.vXferTx &&
            a.accepts == b.accepts
            );
      }

    COffer operator=(const COffer &b) {
      COfferAccept::Init(b);
      nPayCoin = b.nPayCoin;
      nXferCoin = b.nXferCoin;
      nType = b.nType;
      vXferTx = b.vXferTx;
      accepts = b.accepts;
      return *this;
    }

    friend bool operator!=(const COffer &a, const COffer &b) {
      return !(a == b);
    }

    void SetNull()
    {
      COfferAccept::SetNull();
      nPayCoin = -1;
      nXferCoin = -1;
      nType = 16; /* reserved */
      vXferTx.clear();
      accepts.clear();
    }

    bool IsNull() const 
    {
      return (COfferAccept::IsNull());
    }

    CIface *GetPayIface()
    {
      return (GetCoinByIndex(nPayCoin));
    }

    CIface *GetXferIface()
    {
      return (GetCoinByIndex(nXferCoin));
    }
};




bool VerifyOffer(CTransaction& tx);

/**
 * The coin cost to initiate a offer or offer-accept transaction.
 * @note This is effectively minimized to the smallest possible expense.
 */
int64 GetOfferOpFee(CIface *iface);

/**
 * @param iface The primary coin interface
 * @param strAccount The account name to conduct transactions for.
 * @param srcValue A positive (offering) or negative (requesting) coin value.
 * @param destIndex The counter-coin interface index.
 * @param destValue The counter-coin value being offered (+) or requested (-).
 * @param wtx Filled with the offer transaction being performed.
 * @note One of the coin values must be negative and the other positive.
 */
int init_offer_tx(CIface *iface, std::string strAccount, int64 srcValue, int destIndex, int64 destValue, CWalletTx& wtx);



#endif /* ndef __OFFER_H__ */
