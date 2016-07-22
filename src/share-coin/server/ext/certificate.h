
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

#ifndef __SERVER__CERTIFICATE_H__
#define __SERVER__CERTIFICATE_H__






class CIdent : public CExtCore
{
  public:
    shgeo_t geo;
    cbuff vAddr;
    unsigned int nType;

    CIdent()
    {
      SetNull();
    }

    CIdent(const CIdent& ent)
    {
      SetNull();
      Init(ent);
    }

    CIdent(string labelIn)
    {
      SetNull();
      SetLabel(labelIn);
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(CExtCore *)this);
        READWRITE(FLATDATA(geo));
        READWRITE(this->vAddr);
        READWRITE(this->nType);
    )

    friend bool operator==(const CIdent &a, const CIdent &b)
    {
      return (
          ((CExtCore&) a) == ((CExtCore&) b) &&
          0 == memcmp(&a.geo, &b.geo, sizeof(shgeo_t)) &&
          a.nType == b.nType &&
          a.vAddr == b.vAddr
          );
    }

    CIdent operator=(const CIdent &b)
    {
      SetNull();
      Init(b);
      return *this;
    }

    void SetNull()
    {
      CExtCore::SetNull();
      memset(&geo, 0, sizeof(geo));
      vAddr.clear();
      nType = 0;
    }

    void Init(const CIdent& b)
    {
      CExtCore::Init(b);
      memcpy(&geo, &b.geo, sizeof(geo));
      vAddr = b.vAddr;
      nType = b.nType;
    }


/*
    uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }
*/

/*
    void FillEntity(SHCertEnt *entity)
    {
      memset(entity, 0, sizeof(entity));
      if (vchSecret.data()) {
        entity->ent_len = MIN(sizeof(entity->ent_data), vchSecret.size());
        memcpy(entity->ent_data, vchSecret.data(), entity->ent_len);
      }
      string strLabel = GetLabel();
      strncpy(entity->ent_name, strLabel.c_str(), sizeof(entity->ent_name)-1);
      memcpy(&entity->ent_peer, &peer.peer, sizeof(entity->ent_peer));
      memcpy(&entity->ent_sig, &sig.sig, sizeof(entity->ent_sig));
    }
*/


    bool IsLocalRegion()
    {
      shgeo_t lcl_geo;
      bool ret = false;

      memset(&lcl_geo, 0, sizeof(lcl_geo));
      shgeo_local(&lcl_geo, SHGEO_PREC_REGION);
      if (shgeo_cmp(&geo, &lcl_geo, SHGEO_PREC_REGION))
        ret = true;

      return (ret);
    }

    void SetType(int nTypeIn)
    {
      nType = nTypeIn;
    }

    unsigned int GetType()
    {
      return (nType);
    }

    uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    std::string ToString();

    Object ToValue();

};

class CCert : public CIdent
{
  public:
    static const int CERTF_CHAIN = SHCERT_CERT_CHAIN;

    uint160 hashIssuer;
    CSign signature;
    cbuff vSerial;
    int64 nFee;
    int nFlag;

    CCert()
    {
      SetNull();
    }

    CCert(const CIdent& identIn)
    {
      SetNull();
      CIdent::Init(identIn);
    }

    CCert(const CCert& certIn)
    {
      SetNull();
      Init(certIn);
    }

    /**
     * Create a certificate authority.
     * @param hashEntity The entity being issued a certificate.
     * @param vSer A 16-byte (128-bit) serial number.
     */
    CCert(string strTitle)
    {
      SetNull();
      SetLabel(strTitle);
    }

    bool SetIssuer(CCert& issuer)
    {

      if (issuer.nFlag & CERTF_CHAIN)
        return (false); /* cannot chain a chain'd cert */

      nFlag |= CERTF_CHAIN;
      hashIssuer = issuer.GetHash();
      return (true);
    }

    void SetLicenseFee(int64 nFeeIn)
    {
      nFee = (uint64_t)nFeeIn; 
    }

    void SetSerialNumber()
    {
      SetSerialNumber(GenerateSerialNumber());
    }

    void SetSerialNumber(cbuff vSerialIn)
    {
      vSerial = vSerialIn;
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(CIdent *)this);
        READWRITE(this->hashIssuer);
        READWRITE(this->signature);
        READWRITE(this->vSerial);
        READWRITE(this->nFee);
        READWRITE(this->nFlag);
    )

    void Init(const CCert& b)
    {
      CIdent::Init(b);
      hashIssuer = b.hashIssuer;
      signature = b.signature;
      vSerial = b.vSerial;
      nFee = b.nFee;
      nFlag = b.nFlag;
    }

    friend bool operator==(const CCert &a, const CCert &b) {
      return (
          ((CIdent&) a) == ((CIdent&) b) &&
          a.hashIssuer == b.hashIssuer &&
          a.signature == b.signature &&
          a.vSerial == b.vSerial &&
          a.nFee == b.nFee &&
          a.nFlag == b.nFlag
          );
    }

    CCert operator=(const CCert &b) {
      Init(b);
      return *this;
    }

    friend bool operator!=(const CCert &a, const CCert &b) {
      return !(a == b);
    }

    void SetNull()
    {
      CIdent::SetNull();
      signature.SetNull();

      vSerial.clear();
      nFee = 0;

      /* x509 prep */
      nFlag = SHCERT_ENT_ORGANIZATION | SHCERT_CERT_DIGITAL | SHCERT_CERT_SIGN;
    }

    int GetFlags()
    {
      return (nFlag);
    }

    int64 GetLicenseFee()
    {
      return (nFee);
    }

    /* a 128-bit binary context converted into a 160bit hexadecimal number. */
    std::string GetSerialNumber()
    {
      uint160 hash(vSerial);
      return (hash.GetHex());
    }

    uint160 GetIssuerHash()
    {
      return (hashIssuer);
    }

    uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    /**
     * @note The signature does not take into account the geo-detic address (although the underlying certificate hash does).
     */
    bool Sign(int ifaceIndex, CCoinAddr& addr, cbuff vchSecret);

    /**
     * Verify the integrity of a signature.
     */
    bool VerifySignature(cbuff vchSecret);

    /**
     * Create a randomized serial number suitable for a certificate.
     */
    static cbuff GenerateSerialNumber()
    {
      unsigned char raw[16];
      uint64_t rand1 = shrand();
      uint64_t rand2 = shrand();
      memcpy(raw, &rand1, sizeof(uint64_t));
      memcpy(raw + sizeof(uint64_t), &rand2, sizeof(uint64_t));

      return (cbuff(raw, raw+16));
    }

    std::string ToString();

    Object ToValue();

};

/**
 * A license is a specific type of certification.
 * @note A license is not capable of having contextual data.
 */
class CLicense : public CCert
{
  public:
    CLicense()
    {
      SetNull();
    }

    CLicense(const CLicense& lic)
    {
      SetNull();
      Init(lic);
    }

    CLicense(const CCert& cert)
    {
      SetNull();
      CCert::Init(cert);
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(CCert *)this);
    )

    void SetNull()
    {
      CCert::SetNull();
    }

    friend bool operator==(const CLicense &a, const CLicense &b) {
      return (
          ((CCert&) a) == ((CCert&) b)
          );
    }

    CLicense operator=(const CLicense &b) 
    {
      Init(b);
      return *this;
    }

    friend bool operator!=(const CLicense &a, const CLicense &b) {
      return !(a == b);
    }

    void Init(const CLicense& b)
    {
      CCert::Init(b);
    }

    void Sign(int ifaceIndex, CCoinAddr& addr);

    bool VerifySignature(CCoinAddr& addr);

    const uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    void NotifySharenet(int ifaceIndex);

    std::string ToString();

    Object ToValue();

};

class CWalletTx;


bool VerifyCert(CIface *iface, CTransaction& tx, int nHeight);

int64 GetCertOpFee(CIface *iface, int nHeight);

extern int init_cert_tx(CIface *iface, string strAccount, string strTitle, cbuff vchSecret, int64 nLicenseFee, CWalletTx& wtx);

int init_ident_stamp_tx(CIface *iface, std::string strAccount, std::string strComment, CWalletTx& wtx);

int init_license_tx(CIface *iface, string strAccount, uint160 hashCert, CWalletTx& wtx);

bool VerifyLicense(CTransaction& tx);

bool VerifyCertHash(CIface *iface, const uint160& hash);

extern bool GetTxOfCert(CIface *iface, const uint160& hash, CTransaction& tx);

extern bool GetTxOfLicense(CIface *iface, const uint160& hash, CTransaction& tx);

extern int init_ident_donate_tx(CIface *iface, string strAccount, uint64_t nValue, uint160 hashCert, CWalletTx& wtx);

extern int init_ident_certcoin_tx(CIface *iface, string strAccount, uint64_t nValue, uint160 hashCert, CCoinAddr addrDest, CWalletTx& wtx);

extern bool VerifyIdent(CTransaction& tx);

int GetTotalCertificates(int ifaceIndex);

cert_list *GetCertTable(int ifaceIndex);

cert_list *GetIdentTable(int ifaceIndex);

cert_list *GetLicenseTable(int ifaceIndex);

bool IsCertTx(const CTransaction& tx);

bool InsertCertTable(CIface *iface, CTransaction& tx, unsigned int nHeight, bool fUpdate = true);

bool GetCertAccount(CIface *iface, const CTransaction& tx, string& strAccount);

bool IsCertAccount(CIface *iface, CTransaction& tx, string strAccount);

bool DisconnectCertificate(CIface *iface, CTransaction& tx);

bool GetCertByName(CIface *iface, string name, CCert& cert);

bool GetTxOfIdent(CIface *iface, const uint160& hash, CTransaction& tx);



#endif /* ndef __SERVER__CERTIFICATE_H__ */


