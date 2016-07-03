
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

using namespace std;


typedef map<uint160, uint256> cert_list;


class CIdent : public CExtCore
{

  protected:
    shgeo_t geo;
    shkey_t sig_key;
    shkey_t sig_peer;

  public:
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
        READWRITE(FLATDATA(sig_key));
        READWRITE(FLATDATA(sig_peer));
    )

    friend bool operator==(const CIdent &a, const CIdent &b)
    {
      return (
        ((CExtCore&) a) == ((CExtCore&) b) &&
        0 == memcmp(&a.geo, &b.geo, sizeof(shgeo_t)) &&
        0 == memcmp(&a.sig_key, &b.sig_key, sizeof(shkey_t)) &&
        0 == memcmp(&a.sig_peer, &b.sig_peer, sizeof(shkey_t))
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
      memset(&geo, 0, sizeof(geo));
      memset(&sig_key, 0, sizeof(sig_key));
      memset(&sig_peer, 0, sizeof(sig_peer));

      /* default location */
      shgeo_local(&geo, SHGEO_PREC_REGION);
    }

    void Init(const CIdent& b)
    {
      CExtCore::Init(b);
      memcpy(&geo, &b.geo, sizeof(geo));
      memcpy(&sig_key, &b.sig_key, sizeof(sig_key));
      memcpy(&sig_peer, &b.sig_peer, sizeof(sig_peer));
    }

    /**
     * @note The signature does not take into account the geo-detic address (although the underlying certificate hash does).
     */
    bool Sign(cbuff vchSecret)
    {

      if (!vchSecret.data())
        return (false);

      void *raw = (void *)vchSecret.data();
      size_t raw_len = vchSecret.size();

      /* The privileged key of the 'default' peer is unique per network hwaddr */
      shpeer_t *peer = shpeer_init(NULL, NULL);
      memcpy(&sig_peer, shpeer_kpriv(peer), sizeof(sig_peer));
      shpeer_free(&peer);

      shkey_t *key = shkey_cert(&sig_peer, shcrc(raw, raw_len), tExpire);
      memcpy(&sig_key, key, sizeof(sig_key));
      shkey_free(&key);

      return (true);
    }

    bool VerifySignature(cbuff vchSecret)
    {
      if (!vchSecret.data())
        return (false);

      void *raw = (void *)vchSecret.data();
      size_t raw_len = vchSecret.size();
      uint64_t crc = shcrc(raw, raw_len);
      shkey_t *key = shkey_cert(&sig_peer, crc, tExpire);
      bool ret = false;

      if (shkey_cmp(key, &sig_key))
        ret = true;
      shkey_free(&key);

      return (ret);
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

    bool IsLocalOrigin()
    {
      shkey_t sig_peer;
      bool ret = false;

      shpeer_t *peer = shpeer_init(NULL, NULL);
      if (0 == memcmp(&sig_peer, shpeer_kpriv(peer), sizeof(sig_peer)))
        ret = true;
      shpeer_free(&peer);

      return (ret);
    }

    bool IsLocalRegion()
    {
      shgeo_t lcl_geo;
      bool ret = false;

      memset(&lcl_geo, 0, sizeof(lcl_geo));
      shgeo_local_set(&lcl_geo);
      if (shgeo_cmp(&geo, &lcl_geo, SHGEO_PREC_REGION))
        ret = true;

      return (ret);
    }

    uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

};

class CCert : public CIdent
{
  public:

    static const int CERTF_CHAIN = SHCERT_CERT_CHAIN;

    uint160 hashIssuer;
    cbuff vSerial;
    cbuff vAddr;
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
        READWRITE(this->vSerial);
        READWRITE(this->vAddr);
        READWRITE(this->nFee);
        READWRITE(this->nFlag);
    )

    void Init(const CCert& b)
    {
      CIdent::Init(b);
      hashIssuer = b.hashIssuer;
      vSerial = b.vSerial;
      vAddr = b.vAddr;
      nFee = b.nFee;
      nFlag = b.nFlag;
    }

    friend bool operator==(const CCert &a, const CCert &b) {
      return (
          ((CIdent&) a) == ((CIdent&) b) &&
          a.hashIssuer == b.hashIssuer &&
          a.vSerial == b.vSerial &&
          a.vAddr == b.vAddr &&
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

      vSerial.clear();
      vAddr.clear();
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
};

class CLicense : public CExtCore
{
  public:
    shkey_t kPeer;
    shkey_t kSig;
    uint160 hCert;
    uint64_t nCrc;
    int64 nFee;

    CLicense()
    {
      SetNull();
    }

    CLicense(const CLicense& lic)
    {
      SetNull();
      Init(lic);
    }

    CLicense(CCert *cert, uint64_t crc)
    {
      SetNull();
      SetCert(cert, crc);
    }
    IMPLEMENT_SERIALIZE (
        READWRITE(*(CExtCore *)this);
        READWRITE(FLATDATA(kPeer));
        READWRITE(FLATDATA(kSig));
        READWRITE(this->hCert);
        READWRITE(this->nCrc);
        READWRITE(this->nFee);
    )

    void SetNull()
    {
      CExtCore::SetNull();
      memcpy(&kPeer, ashkey_blank(), sizeof(kPeer));
      memcpy(&kSig, ashkey_blank(), sizeof(kSig));
      hCert = 0;
      nCrc = 0;
      nFee = 0;
    }

    friend bool operator==(const CLicense &a, const CLicense &b) {
      return (
          ((CExtCore&) a) == ((CExtCore&) b) &&
          0 == memcmp(&a.kPeer, &b.kPeer, sizeof(shkey_t)) &&
          0 == memcmp(&a.kSig, &b.kSig, sizeof(shkey_t)) &&
          a.hCert == b.hCert &&
          a.nFee && b.nFee
          );
    }

    CLicense operator=(const CLicense &b) {
      Init(b);
      return *this;
    }

    friend bool operator!=(const CLicense &a, const CLicense &b) {
      return !(a == b);
    }

    void Init(const CLicense& b)
    {
      CExtCore::Init(b);
      memcpy(&kPeer, &b.kPeer, sizeof(shkey_t));
      memcpy(&kSig, &b.kSig, sizeof(shkey_t));
      hCert = b.hCert;
      nCrc = b.nCrc;
      nFee = b.nFee;
    }

    void SetCert(CCert *cert, uint64_t crc)
    {
      double lic_span;

      /* identify the certificate being licensed. */
      hCert = cert->GetHash();

      /* expires when certificate expires */
      lic_span = MAX(0, cert->GetExpireTime() - time(NULL) - 1);
      SetExpireTime(shtime_adj(shtime(), lic_span));

      /* record cost of license */
      nFee = cert->GetLicenseFee();

      /* generate signature from an externally derived checksum. */
      Sign(crc);
    }

    void Sign()
    {
      Sign(0);
    }

    /**
     * Generate a digital signature for use with licensed content.
     * @param crc A checksum of the content being licensed. For example, a software program's executable file checksum.
     */
    void Sign(uint64_t crcIn)
    {
      nCrc = crcIn;

      shpeer_t *peer = shpeer_init(NULL, NULL);
      memcpy(&kPeer, shpeer_kpriv(peer), sizeof(kPeer));
      shpeer_free(&peer);

      shkey_t *key = shkey_cert(&kPeer, nCrc, tExpire);
      memcpy(&kSig, key, sizeof(kSig));
      shkey_free(&key);
    }

    bool VerifySignature()
    {
      shkey_t *key = shkey_cert(&kPeer, nCrc, tExpire);
      bool ret = false;

      if (shkey_cmp(key, &kSig))
        ret = true;
      shkey_free(&key);

      return (ret);
    }

    const uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    void NotifySharenet(int ifaceIndex);

};


bool VerifyCert(CTransaction& tx);

int64 GetCertOpFee(CIface *iface, int nHeight);

extern int init_cert_tx(CIface *iface, string strAccount, string strTitle, cbuff vchSecret, int64 nLicenseFee, CWalletTx& wtx);

extern int init_license_tx(CIface *iface, string strAccount, uint160 hashCert, uint64_t nCrc, CWalletTx& wtx);

bool VerifyLicense(CTransaction& tx);



#endif /* ndef __SERVER__CERTIFICATE_H__ */


