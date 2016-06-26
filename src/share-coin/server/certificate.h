
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


class CCertEnt : public CExtCore
{

  protected:
    SHPeer peer;
    SHSig sig;

    mutable cbuff vchSecret;

  public:

    CCertEnt()
    {
      SetNull();
    }

    CCertEnt(const CCertEnt& ent)
    {
      SetNull();
      Init(ent);
    }

    CCertEnt(string labelIn, cbuff secretIn)
    {

      SetNull();

      SetLabel(labelIn);
      peer = SHPeer();
      sig = SHSig();
      vchSecret = secretIn;

      Sign();
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(CExtCore *)this);
        READWRITE(peer);
        READWRITE(sig);
    )

    friend bool operator==(const CCertEnt &a, const CCertEnt &b)
    {
      return (
        ((CExtCore&) a) == ((CExtCore&) b) &&
        a.peer == b.peer &&
        a.sig == b.sig
        );
    }

    CCertEnt operator=(const CCertEnt &b)
    {
      SetNull();
      Init(b);
      return *this;
    }

    void SetNull()
    {
      CExtCore::SetNull();
      peer.SetNull();
      sig.SetNull();
    }

    void Init(const CCertEnt& b)
    {
      CExtCore::Init(b);
      peer = b.peer;
      sig = b.sig;
      vchSecret = b.vchSecret;
    }

    std::string GetName()
    {
      return (GetLabel());
    }

    const cbuff& GetSecret()
    {
      return (vchSecret);
    }

    bool hasSecret()
    {
      if (vchSecret.size() == 0)
        return (false);
      return (true);
    }

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

    void Sign()
    {
      SHCertEnt entity;
      shkey_t *key;

      FillEntity(&entity);

      entity.ent_sig.sig_stamp = shtime_adj(shtime(), -1);
      entity.ent_sig.sig_expire = 
        shtime_adj(entity.ent_sig.sig_stamp, SHARE_DEFAULT_EXPIRE_TIME);

      entity.ent_sig.sig_key.alg = SHKEY_ALG_SHR;
      key = shkey_cert(shpeer_kpub(&entity.ent_peer), 
          shcrc(entity.ent_data, entity.ent_len), entity.ent_sig.sig_stamp);
      //memcpy(&entity.ent_sig.sig_key, key, sizeof(shkey_t));
      memcpy(&sig.sig.sig_key, key, sizeof(shkey_t));
      shkey_free(&key);
    }

    uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }
/*
    uint160 GetHash()
    {
      SHCertEnt entity;

      FillEntity(&entity);
      unsigned char *raw_data = (unsigned char *)&entity;
      vector<unsigned char> vchHash(raw_data, raw_data + sizeof(entity));
      return (Hash160(vchHash));
    }
*/


};

class CCert : public CExtCore
{

  protected:
    SHCert cert;
    CCertEnt ent_sub;
    CCertEnt ent_iss;

  public:
    CCert()
    {
      SetNull();
    }

    CCert(const CCert& certIn)
    {
      SetNull();
      Init(certIn);
    }

    /**
     * Create a certificate authority.
     * @param entity The entity being issued a certificate.
     * @param vSer A 16-byte (128-bit) serial number.
     */
    CCert(CCertEnt *entity, cbuff vSer, int64 nLicenseFee = 0)
    {
      SetNull();

      uint64_t rand1 = shrand();
      uint64_t rand2 = shrand();
      memcpy(cert.cert_ser, &rand1, sizeof(uint64_t));
      memcpy(cert.cert_ser + sizeof(uint64_t), &rand2, sizeof(uint64_t));

      ent_sub = *entity;

      /* x509 prep */
      cert.cert_ver = 3;
      cert.cert_flag = SHCERT_ENT_ORGANIZATION | SHCERT_CERT_DIGITAL | SHCERT_CERT_SIGN;
      cert.cert_fee = nLicenseFee;
    }

    /**
     * Create a issued certificate.
     * @param issuer The issuer (certificate authority) of the certificate.
     * @param entity The entity being issued a certificate.
     * @param vSer A 16-byte (128-bit) serial number.
     */
    CCert(CCertEnt *issuer, CCertEnt *entity, cbuff vSer, int64 nLicenseFee = 0)
    {
      SetNull();

      const char *raw = (const char *)vSer.data();
      if (raw)
        memcpy(&cert.cert_ser, raw, MIN(sizeof(cert.cert_ser), vSer.size()));

      ent_iss = *issuer;
      ent_sub = *entity;

      /* x509 prep */
      cert.cert_ver = 3;
      cert.cert_flag = SHCERT_ENT_ORGANIZATION | SHCERT_CERT_CHAIN | SHCERT_CERT_DIGITAL;
      cert.cert_fee = nLicenseFee;
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(*(CExtCore *)this);
        READWRITE(ent_sub);
        READWRITE(ent_iss);
        READWRITE(FLATDATA(cert.cert_ser));
        READWRITE(cert.cert_fee);
        READWRITE(cert.cert_flag);
        READWRITE(cert.cert_ver);
    )

    void Init(const CCert& b)
    {
      CExtCore::Init(b);
      memcpy(&cert, &b.cert, sizeof(SHCert));
      ent_sub = b.ent_sub;
      ent_iss = b.ent_iss;
    }

    friend bool operator==(const CCert &a, const CCert &b) {
      return (
          ((CExtCore&) a) == ((CExtCore&) b) &&
          0 == memcmp(&a.cert, &b.cert, sizeof(SHCert)) &&
          a.ent_sub == b.ent_sub &&
          a.ent_iss == b.ent_iss
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
      CExtCore::SetNull();
      memset(&cert, 0, sizeof(cert));
    }

    int GetVersion()
    {
      return ((int)cert.cert_ver);
    }

    int GetFlags()
    {
      return ((int)cert.cert_flag);
    }

    int64 GetFee()
    {
      return ((int64)cert.cert_fee);
    }

    /* a 128-bit binary context converted into a 160bit hexadecimal number. */
    std::string GetSerialNumber()
    {
      const char *raw = (const char *)cert.cert_ser; 
      cbuff vch(raw, raw+sizeof(cert.cert_ser));
      uint160 hash(vch);
      return (hash.GetHex());
    }

    CCertEnt *GetIssuerEntity()
    {
      return (&ent_iss);
    }

    CCertEnt *GetSubjectEntity()
    {
      return (&ent_sub);
    }

    uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    double GetLicenseFee()
    {
      return ((double)GetLicenseCoins() / (double)COIN);
    }

    int64 GetLicenseCoins()
    {
      return ((int64)cert.cert_fee);
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
  protected:
    shlic_t license;
    int64 nFee;

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

    CLicense(CCert *cert, uint64_t crc)
    {
      SetNull();
      SetCert(cert, crc);
    }
    IMPLEMENT_SERIALIZE (
        READWRITE(*(CExtCore *)this);
        READWRITE(FLATDATA(license));
        READWRITE(this->nFee);
    )

    void SetNull()
    {
      CExtCore::SetNull();
      memset(&license, 0, sizeof(license));
      nFee = 0;
    }

    friend bool operator==(const CLicense &a, const CLicense &b) {
      return (
          ((CExtCore&) a) == ((CExtCore&) b) &&
          0 == memcmp(&a.license, &b.license, sizeof(shlic_t))
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
      memcpy(&license, &b.license, sizeof(license));
    }

    void SetCert(CCert *cert, uint64_t crc)
    {
      double lic_span;

      /* identify the certificate being licensed. */
      memcpy(&license.lic_cert,
          cert->GetHash().GetKey(), sizeof(license.lic_cert.code));

      /* for sharefs file licensing */
      shpeer_t *peer = shpeer_init(NULL, NULL);
      memcpy(&license.lic_fs, shpeer_kpriv(peer), sizeof(shkey_t)); 
      shpeer_free(&peer);

      /* expires when certificate expires */
      lic_span = MAX(0, cert->GetExpireTime() - time(NULL) - 1);
      SetExpireTime(shtime_adj(shtime(), lic_span));

      /* record cost of license */
      nFee = cert->GetLicenseCoins();

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
    void Sign(uint64_t crc)
    {
      license.lic_crc = crc;
      memcpy(&license.lic_sig, ashkey_blank(), sizeof(shkey_t));
      uint160 hash = GetHash();
      memcpy(&license.lic_sig, hash.GetKey(), sizeof(shkey_t)); 
    }

    const uint160 GetHash()
    {
      uint256 hash = SerializeHash(*this);
      unsigned char *raw = (unsigned char *)&hash;
      cbuff rawbuf(raw, raw + sizeof(hash));
      return Hash160(rawbuf);
    }

    void NotifySharenet(int ifaceIndex)
    {
      CIface *iface = GetCoinByIndex(ifaceIndex);
      if (!iface || !iface->enabled) return;

      shnet_inform(iface, TX_LICENSE, &license, sizeof(license));
    }

};


bool VerifyCert(CTransaction& tx);

int64 GetCertOpFee(CIface *iface, int nHeight);




#endif /* ndef __SERVER__CERTIFICATE_H__ */


