

#ifndef __OFFER_H__
#define __OFFER_H__


typedef std::map<uint160, uint256> offer_list; /* hashOffer -> hashTx */

class CCoinAddr;

class COfferCore : public CExtCore 
{
  public:
    cbuff vSrcAddr;
    cbuff vDestAddr;
    int64 nSrcValue;
    int64 nDestValue;

    mutable bool bPaid;
    mutable std::string strAccount;

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
      READWRITE(vSrcAddr);
      READWRITE(vDestAddr);
      READWRITE(nSrcValue);
      READWRITE(nDestValue);
    )


    friend bool operator==(const COfferCore &a, const COfferCore &b) {
      return (
          ((CExtCore&) a) == ((CExtCore&) b) &&
          a.vSrcAddr == b.vSrcAddr &&
          a.vDestAddr == b.vDestAddr &&
          a.nSrcValue == b.nSrcValue &&
          a.nDestValue == b.nDestValue 
          );
    }

    void Init(const COfferCore& b)
    {
      CExtCore::Init(b);
      vSrcAddr = b.vSrcAddr;
      vDestAddr = b.vDestAddr;
      nSrcValue = b.nSrcValue;
      nDestValue = b.nDestValue;
      strAccount = b.strAccount;
      bPaid = b.bPaid;
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
      vSrcAddr.clear(); 
      vDestAddr.clear(); 
      nSrcValue = 0;
      nDestValue = 0;

      strAccount.clear();
      bPaid = false;
    }

    bool IsNull() const 
    {
      return (nSrcValue == 0 && nDestValue == 0);
    }

    const uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    bool IsPaid()
    {
      return (bPaid);
    }

    void SetPaid(bool bPaidIn)
    {
      bPaid = bPaidIn;
    }

    std::string GetAccount()
    {
      return (strAccount);
    }

    void SetAccount(std::string strAccountIn)
    {
      strAccount = strAccountIn;
    }
};

class COfferAccept : public COfferCore 
{
  public:
    uint160 hashOffer;
    shtime_t nTime;

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
      vSrcAddr.clear();
      vDestAddr.clear();
    }

    COfferAccept(const uint160& hashOfferIn, int64 srcValueIn, int64 destValueIn)
    {
      hashOffer = hashOfferIn;
      nSrcValue = srcValueIn;
      nDestValue = destValueIn;
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(COfferCore *)this);
      READWRITE(hashOffer);
      READWRITE(this->nTime);
    )

    friend bool operator==(const COfferAccept &a, const COfferAccept &b) {
      return (
          ((COfferCore&) a) == ((COfferCore&) b) &&
          a.nTime == b.nTime &&
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
      nTime = b.nTime;
      hashOffer = b.hashOffer;
    }

    void SetNull()
    {
      COfferCore::SetNull();
      hashOffer = 0;
      nTime = shtime();
    }

    bool IsNull() const 
    {
      return (nTime == 0 && hashOffer == 0);
    }

    
};

class COffer : public COfferCore 
{
  protected:
    int nSrcCoin;
    int nDestCoin;
    unsigned int nType;

  public:
    std::vector<COfferAccept>accepts;

    COffer() {
      SetNull();
    }

    COffer(std::string strAccountIn, int srcIndex, int64 srcValue, int destIndex, int64 destValue)
    {
      SetAccount(strAccountIn);
      nSrcValue = srcValue;
      nDestValue = destValue;

      nSrcCoin = srcIndex;
      nDestCoin = destIndex;
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(COfferCore *)this);
        READWRITE(this->nSrcCoin);
        READWRITE(this->nDestCoin);
        READWRITE(this->accepts);
        READWRITE(this->nType);
    )

    friend bool operator==(const COffer &a, const COffer &b) {
      return (
          ((COfferCore&) a) == ((COfferCore&) b) &&
          a.accepts == b.accepts
          );
    }

    COffer operator=(const COffer &b) {
      COfferCore::Init(b);
      accepts = b.accepts; 
      return *this;
    }

    friend bool operator!=(const COffer &a, const COffer &b) {
      return !(a == b);
    }

    void SetNull()
    {
      COfferCore::SetNull();
      nSrcCoin = -1;
      nDestCoin = -1;
      accepts.clear();
      nType = 16; /* reserved */
    }

    bool IsNull() const 
    {
      return (COfferCore::IsNull());
    }

    CIface *GetSrcIface()
    {
      return (GetCoinByIndex(nSrcCoin));
    }

    CIface *GetDestIface()
    {
      return (GetCoinByIndex(nDestCoin));
    }
};

bool VerifyOffer(CTransaction& tx);

int64 GetOfferOpFee(CIface *iface, int nHeight); 



#endif /* ndef __OFFER_H__ */
