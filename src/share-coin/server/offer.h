

#ifndef __OFFER_H__
#define __OFFER_H__


typedef std::map<uint160, uint256> offer_list; /* hashOffer -> hashTx */

class CCoinAddr;

class COfferAccept : public CExtCore 
{
  public:
    cbuff vPayAddr;
    cbuff vXferAddr;
    int64 nPayValue;
    int64 nXferValue;
    uint160 hashOffer;
    uint256 hXferTx;

    COfferAccept() { 
      SetNull();
    }

    COfferAccept(const COfferAccept& offerIn)
    {
      SetNull();
      Init(offerIn);
    }

    IMPLEMENT_SERIALIZE (
      READWRITE(*(CExtCore *)this);
      READWRITE(vPayAddr);
      READWRITE(vXferAddr);
      READWRITE(nPayValue);
      READWRITE(nXferValue);
      READWRITE(hashOffer);
      READWRITE(hXferTx);
    )


    friend bool operator==(const COfferAccept &a, const COfferAccept &b) {
      return (
          ((CExtCore&) a) == ((CExtCore&) b) &&
          a.vPayAddr == b.vPayAddr &&
          a.vXferAddr == b.vXferAddr &&
          a.nPayValue == b.nPayValue &&
          a.nXferValue == b.nXferValue && 
          a.hashOffer == b.hashOffer &&
          a.hXferTx == b.hXferTx
          );
    }

    void Init(const COfferAccept& b)
    {
      CExtCore::Init(b);
      vPayAddr = b.vPayAddr;
      vXferAddr = b.vXferAddr;
      nPayValue = b.nPayValue;
      nXferValue = b.nXferValue;
      hashOffer = b.hashOffer;
      hXferTx = b.hXferTx;
    }

    COfferAccept operator=(const COfferAccept &b)
    {
      Init(b);
      return *this;
    }

    friend bool operator!=(const COfferAccept &a, const COfferAccept &b) {
        return !(a == b);
    }
    
    void SetNull() 
    {
      CExtCore::SetNull();

      vPayAddr.clear(); 
      vXferAddr.clear(); 
      nPayValue = 0;
      nXferValue = 0;
      hashOffer = 0;
      hXferTx = 0;
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

    void print();
    std::string ToString();
    void print_json(shjson_t *json);
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
        READWRITE(this->accepts);
        )

      friend bool operator==(const COffer &a, const COffer &b) {
        return (
            ((COfferAccept&) a) == ((COfferAccept&) b) &&
            a.nPayCoin == b.nPayCoin &&
            a.nXferCoin == b.nXferCoin &&
            a.nType == b.nType &&
            a.accepts == b.accepts
            );
      }

    COffer operator=(const COffer &b) {
      COfferAccept::Init(b);
      nPayCoin = b.nPayCoin;
      nXferCoin = b.nXferCoin;
      nType = b.nType;
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

    void print_json(shjson_t *json);
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

extern bool GetTxOfOffer(CIface *iface, const uint160& hash, CTransaction& tx);

extern int init_offer_tx(CIface *iface, std::string strAccount, int64 srcValue, int destIndex, int64 destValue, CWalletTx& wtx);
extern int accept_offer_tx(CIface *iface, std::string strAccount, uint160 hashOffer, int64 srcValue, int64 destValue, CWalletTx& wtx);
extern int generate_offer_tx(CIface *iface, uint160 hashOffer, CWalletTx& wtx);

extern int pay_offer_tx(CIface *iface, uint160 hashAccept, CWalletTx& wtx);



#endif /* ndef __OFFER_H__ */
